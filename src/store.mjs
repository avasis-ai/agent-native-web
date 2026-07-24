import { EventEmitter } from 'node:events';
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';
import { actionDefinitions } from './contract.mjs';
import { HttpError, clone, integer, jsonDigest, jsonPatch, newId } from './util.mjs';

const MAX_EVENTS = 1_000;
const PREVIEW_TTL_MS = 5 * 60 * 1_000;

function initialState() {
  return {
    sequence: 0,
    products: [
      {
        id: 'product:trailpack-blue',
        type: 'Product',
        revision: 1,
        name: 'Trailpack 28L — Blue',
        description: 'A waterproof 28-litre day pack with a padded laptop sleeve and two front pockets.',
        price: { currency: 'USD', minor: 12900 },
        availability: { stock: 7 },
        attributes: { colour: 'blue', capacity_litres: 28, waterproof: true, weight_grams: 920 },
        media: ['media:trailpack-blue:hero']
      },
      {
        id: 'product:trailpack-orange',
        type: 'Product',
        revision: 1,
        name: 'Trailpack 20L — Orange',
        description: 'A compact weather-resistant day pack with a hydration sleeve.',
        price: { currency: 'USD', minor: 8900 },
        availability: { stock: 4 },
        attributes: { colour: 'orange', capacity_litres: 20, waterproof: false, weight_grams: 680 },
        media: ['media:trailpack-orange:hero']
      }
    ],
    cart: { id: 'cart:current', revision: 0, currency: 'USD', items: [], total_minor: 0 },
    orders: [],
    events: []
  };
}

function validateState(value) {
  if (!value || typeof value !== 'object' || !Array.isArray(value.products) || !value.cart || !Array.isArray(value.orders)) {
    throw new Error('Persisted state has an invalid shape');
  }
  value.events ??= [];
  value.sequence ??= 0;
  return value;
}

function domainView(state) {
  const productEntities = Object.fromEntries(state.products.map((product) => [product.id, clone(product)]));
  const cartItems = Object.fromEntries(state.cart.items.map((item) => [item.product_id, clone(item)]));
  const orderEntities = Object.fromEntries(state.orders.map((order) => [order.id, clone(order)]));
  return {
    catalog: { entities: productEntities, order: state.products.map((product) => product.id) },
    cart: {
      id: state.cart.id,
      revision: state.cart.revision,
      currency: state.cart.currency,
      items: cartItems,
      item_order: state.cart.items.map((item) => item.product_id),
      total_minor: state.cart.total_minor
    },
    orders: { entities: orderEntities, order: state.orders.map((order) => order.id) }
  };
}

function productById(state, id) {
  const product = state.products.find((candidate) => candidate.id === id);
  if (!product) throw new HttpError(404, 'PRODUCT_NOT_FOUND', `Unknown product: ${id}`);
  return product;
}

function cartTotal(cart) {
  return cart.items.reduce((sum, item) => sum + item.unit_price_minor * item.quantity, 0);
}

function validateExactKeys(args, allowed) {
  for (const key of Object.keys(args)) {
    if (!allowed.includes(key)) throw new HttpError(400, 'INVALID_ARGUMENT', `Unknown action argument: ${key}`);
  }
}

export class AgentStore extends EventEmitter {
  constructor({ dataFile = null, clock = () => Date.now() } = {}) {
    super();
    this.dataFile = dataFile;
    this.clock = clock;
    this.previews = new Map();
    this.receipts = new Map();
    this.idempotency = new Map();
    this.state = initialState();
    if (dataFile && existsSync(dataFile)) {
      const persisted = JSON.parse(readFileSync(dataFile, 'utf8'));
      this.state = validateState(persisted.state);
      for (const receipt of persisted.receipts ?? []) this.receipts.set(receipt.receipt_id, receipt);
      for (const item of persisted.idempotency ?? []) this.idempotency.set(item.key, item.value);
    }
  }

  persist() {
    if (!this.dataFile) return;
    mkdirSync(dirname(this.dataFile), { recursive: true });
    const temporary = `${this.dataFile}.${process.pid}.tmp`;
    const payload = JSON.stringify({
      state: this.state,
      receipts: [...this.receipts.values()],
      idempotency: [...this.idempotency.entries()].map(([key, value]) => ({ key, value }))
    }, null, 2);
    writeFileSync(temporary, payload, { mode: 0o600 });
    renameSync(temporary, this.dataFile);
  }

  listProducts(query = '') {
    const terms = query.trim().toLocaleLowerCase().split(/[^\p{L}\p{N}]+/u).filter(Boolean);
    const products = terms.length
      ? this.state.products.filter((product) => {
          const searchable = [product.name, product.description, ...Object.values(product.attributes)].join(' ').toLocaleLowerCase();
          return terms.every((term) => searchable.includes(term));
        })
      : this.state.products;
    return clone(products);
  }

  product(id) {
    return clone(productById(this.state, id));
  }

  snapshot(scope = 'all') {
    const document = domainView(this.state);
    const scoped = scope === 'all' ? document : document[scope];
    if (scoped === undefined) throw new HttpError(400, 'INVALID_SCOPE', `Unknown state scope: ${scope}`);
    return {
      protocol: 'agent-state-channel',
      sequence: this.state.sequence,
      scope,
      state: clone(scoped),
      observed_at: new Date(this.clock()).toISOString()
    };
  }

  eventsSince(sequence) {
    integer(sequence, 'since', { min: 0 });
    const oldest = this.state.events.at(0)?.sequence ?? this.state.sequence;
    if (sequence > this.state.sequence) {
      throw new HttpError(400, 'INVALID_SEQUENCE', `Sequence ${sequence} is ahead of current sequence ${this.state.sequence}`);
    }
    if (this.state.events.length && sequence < oldest - 1) {
      throw new HttpError(409, 'RESYNC_REQUIRED', 'Requested events are no longer retained', {
        requested_sequence: sequence,
        oldest_available_sequence: oldest,
        current_sequence: this.state.sequence
      });
    }
    return clone(this.state.events.filter((event) => event.sequence > sequence));
  }

  actionList() {
    return Object.values(actionDefinitions).map((definition) => ({
      ...clone(definition),
      available: definition.name !== 'checkout.place' || this.state.cart.items.length > 0,
      ...(definition.name === 'checkout.place' && this.state.cart.items.length === 0 ? { unavailable_reason: 'Cart is empty' } : {})
    }));
  }

  preview(action, args, principal, { runId = null, requestId = null } = {}) {
    const definition = actionDefinitions[action];
    if (!definition) throw new HttpError(404, 'ACTION_NOT_FOUND', `Unknown action: ${action}`);
    if (!args || typeof args !== 'object' || Array.isArray(args)) throw new HttpError(400, 'INVALID_ARGUMENT', 'arguments must be an object');

    const before = domainView(this.state);
    const simulated = clone(this.state);
    const orderId = action === 'checkout.place' ? newId('order') : undefined;
    const summary = this.#apply(simulated, action, clone(args), orderId);
    const after = domainView(simulated);
    const baseRevisions = this.#revisionsFor(action, args);
    const createdAt = this.clock();
    const preview = {
      preview_id: newId('preview'),
      action,
      arguments: clone(args),
      principal: clone(principal),
      run_id: runId,
      request_id: requestId,
      risk: definition.risk,
      requires_confirmation: definition.requires_confirmation,
      base_sequence: this.state.sequence,
      base_revisions: baseRevisions,
      effect: { summary, patch: jsonPatch(before, after) },
      created_at: new Date(createdAt).toISOString(),
      expires_at: new Date(createdAt + PREVIEW_TTL_MS).toISOString(),
      order_id: orderId
    };
    preview.digest = jsonDigest({ ...preview, digest: undefined });
    this.previews.set(preview.preview_id, preview);
    return clone(preview);
  }

  commit({ previewId, idempotencyKey, confirmation = false, principal, runId = null, requestId = null }) {
    if (typeof idempotencyKey !== 'string' || idempotencyKey.length < 8 || idempotencyKey.length > 200) {
      throw new HttpError(400, 'IDEMPOTENCY_KEY_REQUIRED', 'Idempotency-Key must contain 8 to 200 characters');
    }
    const requestDigest = jsonDigest({ previewId, confirmation, principal });
    const replay = this.idempotency.get(idempotencyKey);
    if (replay) {
      if (replay.request_digest !== requestDigest) {
        throw new HttpError(409, 'IDEMPOTENCY_CONFLICT', 'The idempotency key was already used for a different commit');
      }
      return { ...clone(this.receipts.get(replay.receipt_id)), replayed: true };
    }

    const preview = this.previews.get(previewId);
    if (!preview) throw new HttpError(404, 'PREVIEW_NOT_FOUND', `Unknown or expired preview: ${previewId}`);
    if (jsonDigest(preview.principal) !== jsonDigest(principal)) throw new HttpError(403, 'PREVIEW_PRINCIPAL_MISMATCH', 'Only the principal that created a preview may commit it');
    if (this.clock() >= Date.parse(preview.expires_at)) {
      this.previews.delete(previewId);
      throw new HttpError(409, 'PREVIEW_EXPIRED', 'The preview has expired; create a new preview');
    }
    if (preview.requires_confirmation && confirmation !== true) {
      throw new HttpError(409, 'CONFIRMATION_REQUIRED', 'This high-risk action requires explicit confirmation');
    }
    this.#assertRevisions(preview.base_revisions);

    const before = domainView(this.state);
    const beforeRevisions = this.#currentRevisions(preview.base_revisions);
    const summary = this.#apply(this.state, preview.action, clone(preview.arguments), preview.order_id);
    const after = domainView(this.state);
    const baseSequence = this.state.sequence;
    this.state.sequence += 1;
    const receiptId = newId('receipt');
    const event = {
      base_sequence: baseSequence,
      sequence: this.state.sequence,
      type: `action.${preview.action}.committed`,
      principal: clone(principal),
      patch: jsonPatch(before, after),
      caused_by_receipt: receiptId,
      occurred_at: new Date(this.clock()).toISOString()
    };
    this.state.events.push(event);
    if (this.state.events.length > MAX_EVENTS) this.state.events.splice(0, this.state.events.length - MAX_EVENTS);

    const receipt = {
      receipt_id: receiptId,
      status: 'committed',
      sequence: this.state.sequence,
      action: preview.action,
      arguments: clone(preview.arguments),
      arguments_digest: jsonDigest(preview.arguments),
      principal: clone(principal),
      preview_run_id: preview.run_id,
      commit_run_id: runId,
      request_id: requestId,
      policy_decision: { allowed: true, confirmation_required: preview.requires_confirmation, confirmation_observed: confirmation === true },
      summary,
      effect: { patch: clone(event.patch) },
      before_revisions: beforeRevisions,
      after_revisions: this.#currentRevisions(preview.base_revisions),
      preview_id: preview.preview_id,
      preview_digest: preview.digest,
      idempotency_key: idempotencyKey,
      committed_at: event.occurred_at,
      replayed: false
    };
    this.receipts.set(receipt.receipt_id, receipt);
    this.idempotency.set(idempotencyKey, { request_digest: requestDigest, receipt_id: receipt.receipt_id });
    this.previews.delete(preview.preview_id);
    this.persist();
    this.emit('event', clone(event));
    return clone(receipt);
  }

  receipt(id) {
    const receipt = this.receipts.get(id);
    if (!receipt) throw new HttpError(404, 'RECEIPT_NOT_FOUND', `Unknown receipt: ${id}`);
    return clone(receipt);
  }

  #revisionsFor(action, args) {
    const revisions = { cart: this.state.cart.revision, products: {} };
    if (action === 'checkout.place') {
      for (const item of this.state.cart.items) {
        const product = productById(this.state, item.product_id);
        revisions.products[product.id] = product.revision;
      }
    } else {
      const product = productById(this.state, args.product_id);
      revisions.products[product.id] = product.revision;
    }
    return revisions;
  }

  #currentRevisions(shape) {
    const current = { cart: this.state.cart.revision, products: {} };
    for (const id of Object.keys(shape.products)) current.products[id] = productById(this.state, id).revision;
    return current;
  }

  #assertRevisions(expected) {
    const current = this.#currentRevisions(expected);
    if (jsonDigest(current) !== jsonDigest(expected)) {
      throw new HttpError(409, 'STALE_PREVIEW', 'Relevant state changed after preview; create a new preview', { expected, current });
    }
  }

  #apply(state, action, args, orderId) {
    if (action === 'cart.add') {
      validateExactKeys(args, ['product_id', 'quantity']);
      integer(args.quantity, 'quantity', { min: 1, max: 10 });
      const product = productById(state, args.product_id);
      const existing = state.cart.items.find((item) => item.product_id === product.id);
      const resultingQuantity = (existing?.quantity ?? 0) + args.quantity;
      if (resultingQuantity > 10) throw new HttpError(409, 'CART_LIMIT', 'At most 10 units of one product may be placed in the cart');
      if (resultingQuantity > product.availability.stock) throw new HttpError(409, 'INSUFFICIENT_STOCK', 'Requested quantity exceeds available stock');
      if (existing) existing.quantity = resultingQuantity;
      else state.cart.items.push({ product_id: product.id, name: product.name, quantity: args.quantity, unit_price_minor: product.price.minor });
      state.cart.items.sort((a, b) => a.product_id.localeCompare(b.product_id));
      state.cart.total_minor = cartTotal(state.cart);
      state.cart.revision += 1;
      return `Added ${args.quantity} × ${product.name} to the cart`;
    }

    if (action === 'cart.remove') {
      validateExactKeys(args, ['product_id', 'quantity']);
      integer(args.quantity, 'quantity', { min: 1, max: 10 });
      productById(state, args.product_id);
      const index = state.cart.items.findIndex((item) => item.product_id === args.product_id);
      if (index < 0) throw new HttpError(409, 'NOT_IN_CART', 'The product is not in the cart');
      const item = state.cart.items[index];
      if (args.quantity > item.quantity) throw new HttpError(409, 'INVALID_QUANTITY', 'Cannot remove more items than the cart contains');
      if (args.quantity === item.quantity) state.cart.items.splice(index, 1);
      else item.quantity -= args.quantity;
      state.cart.total_minor = cartTotal(state.cart);
      state.cart.revision += 1;
      return `Removed ${args.quantity} × ${item.name} from the cart`;
    }

    if (action === 'checkout.place') {
      validateExactKeys(args, ['shipping_address']);
      if (typeof args.shipping_address !== 'string' || args.shipping_address.trim().length < 5 || args.shipping_address.length > 300) {
        throw new HttpError(400, 'INVALID_ARGUMENT', 'shipping_address must contain 5 to 300 characters');
      }
      if (!state.cart.items.length) throw new HttpError(409, 'EMPTY_CART', 'Cannot checkout an empty cart');
      for (const item of state.cart.items) {
        const product = productById(state, item.product_id);
        if (product.availability.stock < item.quantity) throw new HttpError(409, 'INSUFFICIENT_STOCK', `${product.name} no longer has enough stock`);
      }
      for (const item of state.cart.items) {
        const product = productById(state, item.product_id);
        product.availability.stock -= item.quantity;
        product.revision += 1;
      }
      const total = state.cart.total_minor;
      state.orders.push({
        id: orderId,
        revision: 1,
        status: 'placed',
        currency: state.cart.currency,
        total_minor: total,
        items: clone(state.cart.items),
        shipping_address: args.shipping_address.trim()
      });
      state.cart.items = [];
      state.cart.total_minor = 0;
      state.cart.revision += 1;
      return `Placed order ${orderId} for USD ${(total / 100).toFixed(2)}`;
    }

    throw new HttpError(404, 'ACTION_NOT_FOUND', `Unknown action: ${action}`);
  }
}
