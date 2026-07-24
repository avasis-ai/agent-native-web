#!/usr/bin/env node
import { fileURLToPath } from 'node:url';
import { resolve } from 'node:path';
import { AgentProtocolError, AgentWebClient } from './client.mjs';

const INPUTS = {
  search: {
    type: 'object', additionalProperties: false,
    properties: { text: { type: 'string' }, colour: { type: 'string' }, max_price_minor: { type: 'integer', minimum: 0 }, in_stock: { type: 'boolean' }, limit: { type: 'integer', minimum: 1, maximum: 100 } }
  },
  state: { type: 'object', additionalProperties: false, properties: { scope: { type: 'string', enum: ['all', 'catalog', 'cart', 'orders'] } } },
  product: { type: 'object', additionalProperties: false, required: ['product_id'], properties: { product_id: { type: 'string' } } },
  media: { type: 'object', additionalProperties: false, required: ['media_id'], properties: { media_id: { type: 'string' }, region: { type: 'string' } } },
  add: { type: 'object', additionalProperties: false, required: ['product_id', 'quantity'], properties: { product_id: { type: 'string' }, quantity: { type: 'integer', minimum: 1, maximum: 10 } } },
  remove: { type: 'object', additionalProperties: false, required: ['product_id', 'quantity'], properties: { product_id: { type: 'string' }, quantity: { type: 'integer', minimum: 1, maximum: 10 } } },
  checkout: { type: 'object', additionalProperties: false, required: ['shipping_address'], properties: { shipping_address: { type: 'string', minLength: 5, maxLength: 300 } } },
  commit: { type: 'object', additionalProperties: false, required: ['preview_id', 'idempotency_key'], properties: { preview_id: { type: 'string' }, idempotency_key: { type: 'string', minLength: 8, maxLength: 200 }, confirmation: { type: 'boolean' } } },
  receipt: { type: 'object', additionalProperties: false, required: ['receipt_id'], properties: { receipt_id: { type: 'string' } } },
  events: { type: 'object', additionalProperties: false, properties: { since: { type: 'integer', minimum: 0 } } }
};

const TOOLS = [
  { name: 'agent.discover', description: 'Discover this cooperating site without loading its HTML interface.', inputSchema: { type: 'object', additionalProperties: false }, annotations: { readOnlyHint: true, openWorldHint: true } },
  { name: 'agent.products.search', description: 'Run a typed product query against authoritative domain data.', inputSchema: INPUTS.search, annotations: { readOnlyHint: true, openWorldHint: false } },
  { name: 'agent.product.get', description: 'Read one product by stable domain ID.', inputSchema: INPUTS.product, annotations: { readOnlyHint: true, openWorldHint: false } },
  { name: 'agent.state.get', description: 'Read a scoped semantic state baseline with a sequence cursor.', inputSchema: INPUTS.state, annotations: { readOnlyHint: true, openWorldHint: false } },
  { name: 'agent.state.changes', description: 'Read resumable JSON Patch state changes after a sequence.', inputSchema: INPUTS.events, annotations: { readOnlyHint: true, openWorldHint: false } },
  { name: 'agent.media.describe', description: 'Read source metadata, hashes, regions, context, and provenance for media.', inputSchema: INPUTS.media, annotations: { readOnlyHint: true, openWorldHint: false } },
  { name: 'agent.media.read', description: 'Read original image bytes or a source region directly. This never returns a webpage screenshot.', inputSchema: INPUTS.media, annotations: { readOnlyHint: true, openWorldHint: false } },
  { name: 'agent.media.data', description: 'Read chart data/specification or a canvas/map scene graph instead of pixels.', inputSchema: INPUTS.media, annotations: { readOnlyHint: true, openWorldHint: false } },
  { name: 'cart.add.preview', description: 'Preview adding a product. Preview has no durable side effect.', inputSchema: INPUTS.add, annotations: { readOnlyHint: true, idempotentHint: true, openWorldHint: false } },
  { name: 'cart.remove.preview', description: 'Preview removing a product. Preview has no durable side effect.', inputSchema: INPUTS.remove, annotations: { readOnlyHint: true, idempotentHint: true, openWorldHint: false } },
  { name: 'checkout.place.preview', description: 'Preview a consequential checkout and disclose the exact effect. Requires later approval and commit.', inputSchema: INPUTS.checkout, annotations: { readOnlyHint: true, idempotentHint: true, openWorldHint: false } },
  { name: 'agent.action.commit', description: 'Commit an exact preview with a retry-safe idempotency key. High-risk previews require confirmation.', inputSchema: INPUTS.commit, annotations: { readOnlyHint: false, idempotentHint: true, destructiveHint: false, openWorldHint: false } },
  { name: 'agent.receipt.get', description: 'Read an immutable mutation receipt.', inputSchema: INPUTS.receipt, annotations: { readOnlyHint: true, openWorldHint: false } }
];

function textResult(value) {
  return { content: [{ type: 'text', text: JSON.stringify(value) }], structuredContent: value };
}

export class McpBridge {
  constructor(client) {
    this.client = client;
  }

  async tool(name, args = {}) {
    if (name === 'agent.discover') return textResult(await this.client.discover());
    if (name === 'agent.products.search') {
      const { limit = 20, ...filter } = args;
      return textResult(await this.client.query(filter, { limit }));
    }
    if (name === 'agent.product.get') return textResult(await this.client.product(args.product_id));
    if (name === 'agent.state.get') return textResult(await this.client.state(args.scope ?? 'all'));
    if (name === 'agent.state.changes') return textResult({ events: await this.client.eventsSince(args.since ?? 0) });
    if (name === 'agent.media.describe') return textResult(await this.client.mediaDescriptor(args.media_id));
    if (name === 'agent.media.data') return textResult(await this.client.mediaData(args.media_id));
    if (name === 'agent.media.read') {
      const media = await this.client.mediaBytes(args.media_id, { region: args.region ?? null });
      return {
        content: [{ type: 'image', data: media.bytes.toString('base64'), mimeType: media.mimeType?.split(';')[0] ?? 'image/png' }],
        structuredContent: { media_id: args.media_id, region: args.region ?? null, byte_size: media.bytes.length, sha256: media.sha256, source: media.source }
      };
    }
    if (name === 'cart.add.preview') return textResult(await this.client.preview('cart.add', args));
    if (name === 'cart.remove.preview') return textResult(await this.client.preview('cart.remove', args));
    if (name === 'checkout.place.preview') return textResult(await this.client.preview('checkout.place', args));
    if (name === 'agent.action.commit') return textResult(await this.client.commit(args.preview_id, { idempotencyKey: args.idempotency_key, confirmation: args.confirmation === true }));
    if (name === 'agent.receipt.get') return textResult(await this.client.receipt(args.receipt_id));
    throw new AgentProtocolError(404, 'MCP_TOOL_NOT_FOUND', `Unknown MCP tool: ${name}`);
  }

  async resources() {
    const search = await this.client.query({}, { limit: 100 });
    const ids = new Set(['media:inventory:chart', 'media:warehouse:scene']);
    for (const product of search.items) for (const id of product.media) ids.add(id);
    return [...ids].map((id) => ({ uri: `agentweb://media/${encodeURIComponent(id)}`, name: id, mimeType: id.endsWith(':hero') ? 'image/png' : 'application/json' }));
  }

  async resourceRead(uri) {
    const url = new URL(uri);
    if (url.protocol !== 'agentweb:' || url.hostname !== 'media') throw new AgentProtocolError(400, 'INVALID_RESOURCE_URI', 'Only agentweb://media resources are supported');
    const id = decodeURIComponent(url.pathname.replace(/^\//, ''));
    const descriptor = await this.client.mediaDescriptor(id);
    if (descriptor.kind === 'image') {
      const media = await this.client.mediaBytes(id);
      return { contents: [{ uri, mimeType: 'image/png', blob: media.bytes.toString('base64') }] };
    }
    const data = await this.client.mediaData(id);
    return { contents: [{ uri, mimeType: 'application/json', text: JSON.stringify(data) }] };
  }

  async handle(message) {
    if (message.jsonrpc !== '2.0') throw new Error('Expected JSON-RPC 2.0');
    if (message.method === 'notifications/initialized') return null;
    if (message.method === 'ping') return { jsonrpc: '2.0', id: message.id, result: {} };
    if (message.method === 'initialize') {
      return {
        jsonrpc: '2.0', id: message.id,
        result: {
          protocolVersion: '2025-11-25',
          capabilities: { tools: { listChanged: false }, resources: { subscribe: false, listChanged: false } },
          serverInfo: { name: 'agent-native-web-reference', version: '0.1.0' },
          instructions: 'Use typed resources/actions directly. No browser, DOM, accessibility snapshot, renderer, or webpage screenshot is available.'
        }
      };
    }
    if (message.method === 'tools/list') return { jsonrpc: '2.0', id: message.id, result: { tools: TOOLS } };
    if (message.method === 'tools/call') {
      try {
        const result = await this.tool(message.params?.name, message.params?.arguments ?? {});
        return { jsonrpc: '2.0', id: message.id, result };
      } catch (error) {
        const payload = { error: { code: error.code ?? 'TOOL_ERROR', message: error.message, status: error.status, details: error.details } };
        return { jsonrpc: '2.0', id: message.id, result: { content: [{ type: 'text', text: JSON.stringify(payload) }], structuredContent: payload, isError: true } };
      }
    }
    if (message.method === 'resources/list') return { jsonrpc: '2.0', id: message.id, result: { resources: await this.resources() } };
    if (message.method === 'resources/read') return { jsonrpc: '2.0', id: message.id, result: await this.resourceRead(message.params?.uri) };
    return { jsonrpc: '2.0', id: message.id, error: { code: -32601, message: `Method not found: ${message.method}` } };
  }
}

async function runStdio() {
  const client = new AgentWebClient({
    baseUrl: process.env.AGENT_BASE_URL ?? 'http://127.0.0.1:4317',
    token: process.env.AGENT_TOKEN ?? 'agent-demo-token'
  });
  const bridge = new McpBridge(client);
  let pending = '';
  process.stdin.setEncoding('utf8');
  for await (const chunk of process.stdin) {
    pending += chunk;
    let newline;
    while ((newline = pending.indexOf('\n')) >= 0) {
      const line = pending.slice(0, newline).trim();
      pending = pending.slice(newline + 1);
      if (!line) continue;
      let response;
      try {
        const message = JSON.parse(line);
        response = await bridge.handle(message);
      } catch (error) {
        response = { jsonrpc: '2.0', id: null, error: { code: -32700, message: error.message } };
      }
      if (response) process.stdout.write(`${JSON.stringify(response)}\n`);
    }
  }
}

const isMain = process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url));
if (isMain) await runStdio();

export { TOOLS as mcpTools };
