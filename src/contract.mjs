export const PROTOCOL_VERSION = '0.1';
export const AGENT_MEDIA_TYPE = 'application/agent+json';

export const actionDefinitions = {
  'cart.add': {
    name: 'cart.add',
    title: 'Add a product to the cart',
    description: 'Adds a bounded quantity of an available product to the current cart.',
    risk: 'low',
    requires_confirmation: false,
    input_schema: {
      type: 'object',
      additionalProperties: false,
      required: ['product_id', 'quantity'],
      properties: {
        product_id: { type: 'string' },
        quantity: { type: 'integer', minimum: 1, maximum: 10 }
      }
    }
  },
  'cart.remove': {
    name: 'cart.remove',
    title: 'Remove a product from the cart',
    description: 'Removes the requested quantity from the current cart.',
    risk: 'low',
    requires_confirmation: false,
    input_schema: {
      type: 'object',
      additionalProperties: false,
      required: ['product_id', 'quantity'],
      properties: {
        product_id: { type: 'string' },
        quantity: { type: 'integer', minimum: 1, maximum: 10 }
      }
    }
  },
  'checkout.place': {
    name: 'checkout.place',
    title: 'Place the order',
    description: 'Purchases the current cart and decrements inventory.',
    risk: 'high',
    requires_confirmation: true,
    input_schema: {
      type: 'object',
      additionalProperties: false,
      required: ['shipping_address'],
      properties: {
        shipping_address: { type: 'string', minLength: 5, maxLength: 300 }
      }
    }
  }
};

export function discoveryDocument(origin) {
  return {
    protocol: 'agent-resource-web',
    protocol_version: PROTOCOL_VERSION,
    status: 'experimental',
    canonical_contract: `${origin}/openapi.json`,
    representations: [
      { media_type: 'text/html', purpose: 'human' },
      { media_type: 'text/markdown', purpose: 'agent-readable' },
      { media_type: 'application/ld+json', purpose: 'linked-data' },
      { media_type: AGENT_MEDIA_TYPE, purpose: 'agent-operable', experimental: true }
    ],
    endpoints: {
      capabilities: `${origin}/api/agent/v1/capabilities`,
      query: `${origin}/api/agent/v1/query`,
      state: `${origin}/api/agent/v1/state`,
      events: `${origin}/api/agent/v1/events`,
      actions: `${origin}/api/agent/v1/actions`,
      commits: `${origin}/api/agent/v1/commits`,
      nlweb_ask: `${origin}/ask`,
      mcp: { transport: 'stdio', command: 'agentweb-mcp' }
    },
    adapters: {
      mcp: { protocol_version: '2025-11-25', transport: 'stdio' },
      nlweb: { version: '0.55', ask: `${origin}/ask`, await: `${origin}/await` }
    },
    authentication: {
      type: 'http',
      scheme: 'bearer',
      token_environment_variable: 'AGENT_TOKEN'
    },
    state_model: {
      baseline: 'JSON document with a monotonically increasing sequence',
      changes: 'RFC 6902 JSON Patch over Server-Sent Events',
      resumable: true
    },
    transaction_model: ['preview', 'optional-confirmation', 'idempotent-commit', 'receipt'],
    media_model: {
      direct_bytes: true,
      region_selectors: ['FragmentSelector'],
      screenshots_required: false,
      render_fallback: false
    }
  };
}

export function openApiDocument(origin) {
  const actionNames = Object.keys(actionDefinitions);
  return {
    openapi: '3.1.0',
    info: {
      title: 'Agent Native Web Reference API',
      version: PROTOCOL_VERSION,
      description: 'A browserless API over the same domain model as the human website.'
    },
    servers: [{ url: origin }],
    security: [{ bearerAuth: [] }],
    paths: {
      '/api/agent/v1/capabilities': { get: { operationId: 'capabilitiesGet', security: [], responses: { 200: { description: 'Capabilities' } } } },
      '/api/agent/v1/entities': { 'x-http-query': { operationId: 'entitiesQuery', requestBody: { required: true }, responses: { 200: { description: 'Typed query result' } } } },
      '/api/agent/v1/query': { post: { operationId: 'queryRunCompatibility', description: 'Compatibility binding for the same safe QUERY engine.', responses: { 200: { description: 'Typed query result' } } } },
      '/api/agent/v1/products': { get: { operationId: 'productsList', responses: { 200: { description: 'Product collection' } } } },
      '/api/agent/v1/products/{productId}': { get: { operationId: 'productGet', parameters: [{ name: 'productId', in: 'path', required: true, schema: { type: 'string' } }], responses: { 200: { description: 'Product entity' } } } },
      '/api/agent/v1/state': { get: { operationId: 'stateGet', responses: { 200: { description: 'State baseline' } } } },
      '/api/agent/v1/events': { get: { operationId: 'eventsSubscribe', responses: { 200: { description: 'SSE state delta stream' } } } },
      '/api/agent/v1/actions': { get: { operationId: 'actionsList', responses: { 200: { description: 'Available actions' } } } },
      '/api/agent/v1/actions/{action}/preview': {
        post: {
          operationId: 'actionPreview',
          parameters: [{ name: 'action', in: 'path', required: true, schema: { type: 'string', enum: actionNames } }],
          responses: { 201: { description: 'Immutable action preview' }, 409: { description: 'State conflict' } }
        }
      },
      '/api/agent/v1/commits': { post: { operationId: 'actionCommit', responses: { 201: { description: 'Commit receipt' }, 409: { description: 'Stale preview or idempotency conflict' } } } },
      '/api/agent/v1/receipts/{receiptId}': { get: { operationId: 'receiptGet', parameters: [{ name: 'receiptId', in: 'path', required: true, schema: { type: 'string' } }], responses: { 200: { description: 'Immutable receipt' } } } },
      '/api/agent/v1/media/{mediaId}': { get: { operationId: 'mediaDescribe', security: [], responses: { 200: { description: 'Media descriptor' } } } },
      '/api/agent/v1/media/{mediaId}/content': { get: { operationId: 'mediaContentGet', security: [], responses: { 200: { description: 'Original media bytes or source region' } } } },
      '/api/agent/v1/media/{mediaId}/data': { get: { operationId: 'mediaDataGet', security: [], responses: { 200: { description: 'Chart data/specification or scene graph' } } } },
      '/ask': { post: { operationId: 'nlwebAsk', security: [], responses: { 200: { description: 'NLWeb 0.55 response' } } } },
      '/await': { post: { operationId: 'nlwebAwait', security: [], responses: { 200: { description: 'NLWeb 0.55 response' } } } }
    },
    components: {
      securitySchemes: { bearerAuth: { type: 'http', scheme: 'bearer' } },
      schemas: {
        ActionDefinition: { type: 'object', required: ['name', 'description', 'risk', 'input_schema'] },
        StateEvent: {
          type: 'object',
          required: ['sequence', 'type', 'patch', 'occurred_at'],
          properties: {
            sequence: { type: 'integer', minimum: 1 },
            type: { type: 'string' },
            patch: { type: 'array', items: { type: 'object' } },
            occurred_at: { type: 'string', format: 'date-time' }
          }
        }
      }
    }
  };
}
