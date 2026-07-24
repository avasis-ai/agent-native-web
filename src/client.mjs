import { createHash, randomUUID } from 'node:crypto';
import { decodeInspectionMark } from './media.mjs';

export class AgentProtocolError extends Error {
  constructor(status, code, message, details, requestId) {
    super(message);
    this.name = 'AgentProtocolError';
    this.status = status;
    this.code = code;
    this.details = details;
    this.requestId = requestId;
  }
}

export class UnsupportedAgentSiteError extends Error {
  constructor(origin) {
    super(`${origin} does not expose an agent-native capability manifest; no browser fallback was attempted`);
    this.name = 'UnsupportedAgentSiteError';
    this.code = 'UNSUPPORTED_AGENT_SITE';
  }
}

function trimSlash(value) {
  return value.replace(/\/+$/, '');
}

export class AgentWebClient {
  constructor({ baseUrl, token, fetchImpl = fetch, runId = randomUUID() }) {
    this.baseUrl = trimSlash(baseUrl);
    this.token = token;
    this.fetch = fetchImpl;
    this.runId = runId;
    this.manifest = null;
  }

  async #request(pathOrUrl, { method = 'GET', body, headers = {}, auth = true, accept = 'application/json' } = {}) {
    const url = pathOrUrl.startsWith('http://') || pathOrUrl.startsWith('https://') ? pathOrUrl : `${this.baseUrl}${pathOrUrl}`;
    const finalHeaders = { accept, 'x-agent-run-id': this.runId, ...headers };
    if (auth && this.token) finalHeaders.authorization = `Bearer ${this.token}`;
    if (body !== undefined) finalHeaders['content-type'] = 'application/json';
    const response = await this.fetch(url, { method, headers: finalHeaders, ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
    if (!response.ok) {
      let envelope;
      try { envelope = await response.json(); } catch { envelope = {}; }
      throw new AgentProtocolError(response.status, envelope.error?.code ?? 'HTTP_ERROR', envelope.error?.message ?? `HTTP ${response.status}`, envelope.error?.details, response.headers.get('x-request-id'));
    }
    return response;
  }

  async discover() {
    let response;
    try {
      response = await this.#request('/agent/manifest.json', { auth: false });
    } catch (error) {
      if (error instanceof AgentProtocolError && error.status === 404) throw new UnsupportedAgentSiteError(this.baseUrl);
      throw error;
    }
    const manifest = await response.json();
    if (manifest.protocol !== 'agent-resource-web') throw new UnsupportedAgentSiteError(this.baseUrl);
    this.manifest = manifest;
    return manifest;
  }

  async capabilities() {
    return (await this.#request('/api/agent/v1/capabilities', { auth: false })).json();
  }

  async query(filter = {}, { limit = 20 } = {}) {
    const response = await this.#request('/api/agent/v1/entities', {
      method: 'QUERY',
      body: { operation: 'products.search', filter, limit }
    });
    return response.json();
  }

  async queryPost(filter = {}, { limit = 20 } = {}) {
    return (await this.#request('/api/agent/v1/query', { method: 'POST', body: { operation: 'products.search', filter, limit } })).json();
  }

  async products(query = '') {
    return (await this.#request(`/api/agent/v1/products?query=${encodeURIComponent(query)}`)).json();
  }

  async product(id) {
    return (await this.#request(`/api/agent/v1/products/${encodeURIComponent(id)}`)).json();
  }

  async state(scope = 'all') {
    return (await this.#request(`/api/agent/v1/state?scope=${encodeURIComponent(scope)}`)).json();
  }

  async actions() {
    return (await this.#request('/api/agent/v1/actions')).json();
  }

  async preview(action, args) {
    return (await this.#request(`/api/agent/v1/actions/${encodeURIComponent(action)}/preview`, { method: 'POST', body: { arguments: args } })).json();
  }

  async commit(previewId, { idempotencyKey = randomUUID(), confirmation = false } = {}) {
    return (await this.#request('/api/agent/v1/commits', {
      method: 'POST',
      headers: { 'idempotency-key': idempotencyKey },
      body: { preview_id: previewId, ...(confirmation ? { confirmation: true } : {}) }
    })).json();
  }

  async receipt(id) {
    return (await this.#request(`/api/agent/v1/receipts/${encodeURIComponent(id)}`)).json();
  }

  async mediaDescriptor(id) {
    return (await this.#request(`/api/agent/v1/media/${encodeURIComponent(id)}`, { auth: false })).json();
  }

  async mediaData(id) {
    return (await this.#request(`/api/agent/v1/media/${encodeURIComponent(id)}/data`, { auth: false })).json();
  }

  async mediaBytes(id, { region = null, verify = true } = {}) {
    const descriptor = await this.mediaDescriptor(id);
    const url = region
      ? descriptor.regions?.find((candidate) => candidate.id === region)?.content_url
      : descriptor.source?.url;
    if (!url) throw new AgentProtocolError(409, 'UNSUPPORTED_REPRESENTATION', `Media ${id} has no requested pixel representation`);
    const response = await this.#request(url, { auth: false, accept: 'image/*' });
    const bytes = Buffer.from(await response.arrayBuffer());
    const sha256 = createHash('sha256').update(bytes).digest('hex');
    if (verify && !region && descriptor.source.sha256 !== sha256) {
      throw new AgentProtocolError(502, 'MEDIA_INTEGRITY_ERROR', 'Downloaded media does not match its descriptor hash');
    }
    return { bytes, mimeType: response.headers.get('content-type'), sha256, source: response.headers.get('x-media-source'), descriptor };
  }

  async readInspectionMark(id) {
    const media = await this.mediaBytes(id, { region: 'inspection-mark' });
    return { value: decodeInspectionMark(media.bytes), sha256: media.sha256, source: media.source, region: 'inspection-mark' };
  }

  async eventsSince(sequence = 0) {
    const response = await this.#request(`/api/agent/v1/events?since=${sequence}&once=true`, { accept: 'text/event-stream' });
    const text = await response.text();
    const events = [];
    let current = {};
    for (const line of text.split(/\r?\n/)) {
      if (!line) {
        if (current.event === 'patch' && current.data) events.push(JSON.parse(current.data));
        current = {};
      } else if (line.startsWith('event:')) current.event = line.slice(6).trim();
      else if (line.startsWith('data:')) current.data = `${current.data ?? ''}${line.slice(5).trim()}`;
      else if (line.startsWith('id:')) current.id = line.slice(3).trim();
    }
    return events;
  }

  async trace() {
    return (await this.#request('/api/agent/v1/trace')).json();
  }

  async nlwebAsk(text) {
    return (await this.#request('/ask', { method: 'POST', auth: false, body: { query: { text }, meta: { version: '0.55' } } })).json();
  }

  async automatePurchase({ query, quantity = 1, checkout = false, shippingAddress, approve = async () => false } = {}) {
    const transcript = [];
    const manifest = await this.discover();
    transcript.push({ step: 'discover', protocol: manifest.protocol, version: manifest.protocol_version });
    const capabilities = await this.capabilities();
    transcript.push({ step: 'capabilities', browser_required: capabilities.browser_required, ui_snapshots: capabilities.ui_snapshots });
    const search = await this.query({ text: query, in_stock: true }, { limit: 5 });
    if (!search.items.length) throw new AgentProtocolError(404, 'NO_RESULTS', `No in-stock product matched ${query}`);
    const selected = search.items[0];
    transcript.push({ step: 'select', product_id: selected.id, name: selected.name });
    const image = await this.readInspectionMark(selected.media[0]);
    transcript.push({ step: 'read-direct-image-region', media_id: selected.media[0], inspection_mark: image.value, sha256: image.sha256, source: image.source });
    const baseline = await this.state('cart');
    transcript.push({ step: 'state-baseline', sequence: baseline.sequence, cart_revision: baseline.state.revision });
    const addPreview = await this.preview('cart.add', { product_id: selected.id, quantity });
    transcript.push({ step: 'preview-cart-add', preview_id: addPreview.preview_id, effect: addPreview.effect.summary });
    const addReceipt = await this.commit(addPreview.preview_id, { idempotencyKey: `${this.runId}:cart-add` });
    transcript.push({ step: 'commit-cart-add', receipt_id: addReceipt.receipt_id, sequence: addReceipt.sequence });
    const deltas = await this.eventsSince(baseline.sequence);
    transcript.push({ step: 'state-deltas', count: deltas.length, through_sequence: deltas.at(-1)?.sequence ?? baseline.sequence });
    let checkoutReceipt = null;
    if (checkout) {
      if (!shippingAddress) throw new AgentProtocolError(400, 'SHIPPING_ADDRESS_REQUIRED', 'shippingAddress is required for checkout');
      const checkoutPreview = await this.preview('checkout.place', { shipping_address: shippingAddress });
      transcript.push({ step: 'preview-checkout', preview_id: checkoutPreview.preview_id, effect: checkoutPreview.effect.summary, risk: checkoutPreview.risk });
      const approved = await approve(checkoutPreview);
      if (!approved) throw new AgentProtocolError(409, 'USER_APPROVAL_REQUIRED', 'Checkout preview was not approved');
      checkoutReceipt = await this.commit(checkoutPreview.preview_id, { idempotencyKey: `${this.runId}:checkout`, confirmation: true });
      transcript.push({ step: 'commit-checkout', receipt_id: checkoutReceipt.receipt_id, sequence: checkoutReceipt.sequence });
    }
    return { selected, inspection_mark: image.value, add_receipt: addReceipt, checkout_receipt: checkoutReceipt, transcript };
  }
}
