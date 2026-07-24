#!/usr/bin/env node
import { createHash, randomUUID } from 'node:crypto';
import { createServer } from 'node:http';
import { fileURLToPath } from 'node:url';
import { resolve } from 'node:path';
import { AGENT_MEDIA_TYPE, PROTOCOL_VERSION, actionDefinitions, discoveryDocument, openApiDocument } from './contract.mjs';
import { MediaRegistry } from './media.mjs';
import { AgentStore } from './store.mjs';
import { HttpError, bearerPrincipal, errorEnvelope, escapeHtml, readJson, requestOrigin, sendJson, sendText } from './util.mjs';

const SECURITY_HEADERS = {
  'x-content-type-options': 'nosniff',
  'x-frame-options': 'DENY',
  'referrer-policy': 'no-referrer',
  'permissions-policy': 'camera=(), microphone=(), geolocation=()'
};

function exactKeys(value, allowed, label = 'body') {
  for (const key of Object.keys(value)) {
    if (!allowed.includes(key)) throw new HttpError(400, 'INVALID_ARGUMENT', `Unknown ${label} field: ${key}`);
  }
}

function productResource(product, origin) {
  return {
    '@context': ['https://schema.org', `${origin}/contexts/agent-resource-v0.1.jsonld`],
    '@type': 'Product',
    '@id': `${origin}/products/${encodeURIComponent(product.id)}`,
    id: product.id,
    version: `product-v${product.revision}`,
    name: product.name,
    description: product.description,
    offers: {
      '@type': 'Offer',
      priceCurrency: product.price.currency,
      price: (product.price.minor / 100).toFixed(2),
      availability: product.availability.stock > 0 ? 'https://schema.org/InStock' : 'https://schema.org/OutOfStock',
      inventoryLevel: product.availability.stock
    },
    attributes: product.attributes,
    media: product.media.map((id) => ({ id, href: `${origin}/api/agent/v1/media/${encodeURIComponent(id)}` })),
    actions: [{
      id: 'cart.add',
      version: '1',
      href: `${origin}/api/agent/v1/actions/cart.add/preview`,
      method: 'POST',
      input_schema: actionDefinitions['cart.add'].input_schema
    }],
    links: { human: `${origin}/products/${encodeURIComponent(product.id)}` },
    trust_boundary: { descriptive_fields: 'untrusted_publisher_data', action_descriptors: 'server_contract' }
  };
}

function markdownProduct(product, origin) {
  return `# ${product.name}\n\n${product.description}\n\n- Price: ${product.price.currency} ${(product.price.minor / 100).toFixed(2)}\n- Stock: ${product.availability.stock}\n- Colour: ${product.attributes.colour}\n- Agent representation: ${origin}/products/${encodeURIComponent(product.id)}\n`;
}

function htmlDocument(store, origin, selected = null) {
  const products = selected ? [selected] : store.listProducts();
  const cards = products.map((product) => `
    <article>
      <img src="/api/agent/v1/media/${encodeURIComponent(product.media[0])}/content" alt="${escapeHtml(product.name)}" width="300" height="200">
      <div>
        <p class="eyebrow">${escapeHtml(product.attributes.capacity_litres)} litres · ${escapeHtml(product.attributes.colour)}</p>
        <h2><a href="/products/${encodeURIComponent(product.id)}">${escapeHtml(product.name)}</a></h2>
        <p>${escapeHtml(product.description)}</p>
        <p class="price">${product.price.currency} ${(product.price.minor / 100).toFixed(2)}</p>
        <p>${product.availability.stock} in stock</p>
        <button data-product="${escapeHtml(product.id)}">Add through typed action</button>
      </div>
    </article>`).join('');
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Northstar Supply — human interface</title>
  <style>
    :root{font:16px/1.5 ui-sans-serif,system-ui;color:#182132;background:#f4f1ea}body{margin:0}header,main{max-width:980px;margin:auto;padding:2rem}header{display:flex;justify-content:space-between;align-items:center}h1{font-size:1.1rem;letter-spacing:.12em;text-transform:uppercase}header p{color:#586174}article{display:grid;grid-template-columns:300px 1fr;gap:2rem;background:#fff;border:1px solid #d8d4ca;padding:1.25rem;margin:1rem 0;box-shadow:0 8px 25px #34302a0d}img{object-fit:cover;width:100%;height:auto}.eyebrow{font-size:.78rem;text-transform:uppercase;letter-spacing:.1em;color:#647084}.price{font:600 1.5rem ui-monospace,monospace}button{background:#17243d;color:#fff;border:0;padding:.7rem 1rem;cursor:pointer}aside{background:#fff4cf;border:1px solid #e6cd72;padding:1rem;margin-bottom:2rem}code{font-family:ui-monospace,monospace}@media(max-width:700px){article{grid-template-columns:1fr}}
  </style>
</head>
<body>
  <header><h1>Northstar Supply</h1><p>One domain model, two interfaces.</p></header>
  <main>
    <aside><strong>Agent-native demo.</strong> Humans see this HTML. Agents discover <a href="/agent/manifest.json">the capability manifest</a> and never load this page. The button below calls the same preview/commit domain operation for demonstration. Enter the local demo token when prompted.</aside>
    ${cards}
    <pre id="result" aria-live="polite"></pre>
  </main>
  <script>
  for (const button of document.querySelectorAll('button[data-product]')) button.addEventListener('click', async () => {
    const token = prompt('Local demo bearer token', 'agent-demo-token');
    if (!token) return;
    const headers = {'authorization': 'Bearer ' + token, 'content-type': 'application/json'};
    const previewResponse = await fetch('/api/agent/v1/actions/cart.add/preview', {method:'POST', headers, body:JSON.stringify({arguments:{product_id:button.dataset.product,quantity:1}})});
    const preview = await previewResponse.json();
    if (!previewResponse.ok) return document.querySelector('#result').textContent = JSON.stringify(preview,null,2);
    const commitResponse = await fetch('/api/agent/v1/commits', {method:'POST', headers:{...headers,'idempotency-key':crypto.randomUUID()},body:JSON.stringify({preview_id:preview.preview_id})});
    document.querySelector('#result').textContent = JSON.stringify(await commitResponse.json(),null,2);
  });
  </script>
</body></html>`;
}

function representation(request, response, store, origin, product = null) {
  const accept = request.headers.accept ?? 'text/html';
  const products = product ? [product] : store.listProducts();
  const commonHeaders = {
    ...SECURITY_HEADERS,
    vary: 'Accept',
    link: `<${origin}/agent/manifest.json>; rel="https://agent-web.dev/rels/agent-manifest"; type="application/json", <${origin}/openapi.json>; rel="service-desc"; type="application/json"`
  };
  if (accept.includes(AGENT_MEDIA_TYPE) || accept.includes('application/ld+json')) {
    const body = product ? productResource(product, origin) : {
      '@context': `${origin}/contexts/agent-resource-v0.1.jsonld`,
      '@type': 'Collection',
      id: 'collection:products',
      items: products.map((item) => productResource(item, origin))
    };
    return sendJson(response, 200, body, { ...commonHeaders, 'content-type': `${accept.includes('application/ld+json') ? 'application/ld+json' : AGENT_MEDIA_TYPE}; charset=utf-8` });
  }
  if (accept.includes('text/markdown')) {
    const body = products.map((item) => markdownProduct(item, origin)).join('\n---\n\n');
    return sendText(response, 200, body, 'text/markdown; charset=utf-8', commonHeaders);
  }
  return sendText(response, 200, htmlDocument(store, origin, product), 'text/html; charset=utf-8', {
    ...commonHeaders,
    'content-security-policy': "default-src 'self'; img-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'"
  });
}

function searchNatural(store, text) {
  const ignored = new Set(['a', 'an', 'the', 'find', 'show', 'me', 'with', 'for', 'please', 'product', 'products', 'something']);
  const tokens = String(text).toLocaleLowerCase().split(/[^a-z0-9]+/).filter((token) => token.length > 1 && !ignored.has(token));
  const products = store.listProducts();
  if (!tokens.length) return products;
  return products.filter((product) => {
    const haystack = [product.name, product.description, ...Object.values(product.attributes)].join(' ').toLocaleLowerCase();
    return tokens.some((token) => haystack.includes(token));
  });
}

function executeQuery(store, body) {
  exactKeys(body, ['operation', 'filter', 'limit', 'select']);
  if (body.operation !== 'products.search') throw new HttpError(400, 'UNSUPPORTED_QUERY', 'Only products.search is supported by this reference domain');
  if (body.filter !== undefined && (!body.filter || typeof body.filter !== 'object' || Array.isArray(body.filter))) {
    throw new HttpError(400, 'INVALID_ARGUMENT', 'filter must be an object');
  }
  const filter = body.filter ?? {};
  exactKeys(filter, ['text', 'colour', 'max_price_minor', 'in_stock'], 'filter');
  let products = store.listProducts(typeof filter.text === 'string' ? filter.text : '');
  if (filter.colour !== undefined) products = products.filter((product) => product.attributes.colour === filter.colour);
  if (filter.max_price_minor !== undefined) {
    if (!Number.isInteger(filter.max_price_minor) || filter.max_price_minor < 0) throw new HttpError(400, 'INVALID_ARGUMENT', 'max_price_minor must be a non-negative integer');
    products = products.filter((product) => product.price.minor <= filter.max_price_minor);
  }
  if (filter.in_stock === true) products = products.filter((product) => product.availability.stock > 0);
  const limit = body.limit ?? 20;
  if (!Number.isInteger(limit) || limit < 1 || limit > 100) throw new HttpError(400, 'INVALID_ARGUMENT', 'limit must be an integer from 1 to 100');
  return { query_version: '1', items: products.slice(0, limit), count: Math.min(products.length, limit), total: products.length };
}

function sseWrite(response, event) {
  response.write(`id: ${event.sequence}\nevent: patch\ndata: ${JSON.stringify(event)}\n\n`);
}

export function createAgentServer({ port = 0, host = '127.0.0.1', token = 'agent-demo-token', dataFile = null, logger = console } = {}) {
  const store = new AgentStore({ dataFile });
  const media = new MediaRegistry(store);
  const metrics = {
    started_at: new Date().toISOString(),
    requests_total: 0,
    human_html_requests: 0,
    agent_requests: 0,
    media_requests: 0,
    render_requests: 0,
    screenshot_requests: 0,
    errors_total: 0,
    recent_requests: []
  };
  let address;

  const server = createServer(async (request, response) => {
    const requestId = request.headers['x-request-id']?.toString().slice(0, 100) || randomUUID();
    const started = performance.now();
    response.setHeader('x-request-id', requestId);
    for (const [key, value] of Object.entries(SECURITY_HEADERS)) response.setHeader(key, value);
    metrics.requests_total += 1;
    try {
      const url = new URL(request.url, requestOrigin(request));
      const origin = requestOrigin(request);
      const method = request.method ?? 'GET';
      const path = url.pathname;
      if (path.startsWith('/api/agent/')) metrics.agent_requests += 1;
      if (path.includes('/media/')) metrics.media_requests += 1;
      if ((request.headers.accept ?? '').includes('text/html') || (!request.headers.accept && (path === '/' || path.startsWith('/products')))) metrics.human_html_requests += 1;

      if (method === 'GET' && (path === '/healthz' || path === '/readyz')) {
        return sendJson(response, 200, { status: 'ok', protocol_version: PROTOCOL_VERSION, sequence: store.state.sequence });
      }
      if (method === 'GET' && (path === '/agent/manifest.json' || path === '/.well-known/agent.json')) {
        return sendJson(response, 200, discoveryDocument(origin), { 'cache-control': 'public, max-age=300' });
      }
      if (method === 'GET' && path === '/openapi.json') return sendJson(response, 200, openApiDocument(origin), { 'cache-control': 'public, max-age=300' });
      if (method === 'GET' && path === '/contexts/agent-resource-v0.1.jsonld') {
        return sendJson(response, 200, { '@context': { id: '@id', type: '@type', version: 'https://schema.org/version', media: 'https://schema.org/associatedMedia', actions: 'https://schema.org/potentialAction' } });
      }

      if ((method === 'GET' || method === 'HEAD') && (path === '/' || path === '/products')) {
        if (method === 'HEAD') {
          response.writeHead(200, { allow: 'GET, HEAD, OPTIONS, QUERY', 'accept-query': 'application/json' });
          return response.end();
        }
        return representation(request, response, store, origin);
      }
      const humanProductMatch = path.match(/^\/products\/([^/]+)$/);
      if ((method === 'GET' || method === 'HEAD') && humanProductMatch) {
        const product = store.product(decodeURIComponent(humanProductMatch[1]));
        if (method === 'HEAD') {
          response.writeHead(200, { etag: `"product-${product.revision}"`, vary: 'Accept' });
          return response.end();
        }
        return representation(request, response, store, origin, product);
      }

      if (method === 'GET' && path === '/api/agent/v1/capabilities') {
        return sendJson(response, 200, {
          protocol: 'agent-resource-web',
          version: PROTOCOL_VERSION,
          browser_required: false,
          ui_snapshots: false,
          capabilities: ['structured-query', 'direct-media', 'media-regions', 'chart-data', 'scene-graph', 'state-baseline', 'sse-json-patch', 'preview-commit', 'idempotency', 'receipts'],
          unsupported: ['arbitrary-legacy-html', 'visual-layout-inspection', 'canvas-without-scene-data'],
          actions: store.actionList()
        });
      }

      const mediaDescriptorMatch = path.match(/^\/api\/agent\/v1\/media\/([^/]+)$/);
      if (method === 'GET' && mediaDescriptorMatch) {
        return sendJson(response, 200, media.descriptor(decodeURIComponent(mediaDescriptorMatch[1]), origin), { 'cache-control': 'public, max-age=60' });
      }
      const mediaDataMatch = path.match(/^\/api\/agent\/v1\/media\/([^/]+)\/data$/);
      if (method === 'GET' && mediaDataMatch) {
        return sendJson(response, 200, media.data(decodeURIComponent(mediaDataMatch[1])), { 'cache-control': 'public, max-age=30' });
      }
      const mediaContentMatch = path.match(/^\/api\/agent\/v1\/media\/([^/]+)\/content$/);
      if ((method === 'GET' || method === 'HEAD') && mediaContentMatch) {
        const id = decodeURIComponent(mediaContentMatch[1]);
        const region = url.searchParams.get('region');
        const bytes = media.imageBytes(id, region);
        const digestBytes = createHash('sha256').update(bytes).digest();
        const etag = `"sha256-${digestBytes.toString('hex')}"`;
        const headers = {
          'content-type': 'image/png',
          'content-length': bytes.length,
          'content-digest': `sha-256=:${digestBytes.toString('base64')}:`,
          etag,
          'cache-control': 'public, max-age=31536000, immutable',
          'accept-ranges': 'bytes',
          'x-media-source': region ? 'source-region' : 'original-asset'
        };
        if (request.headers['if-none-match'] === etag) {
          response.writeHead(304, headers);
          return response.end();
        }
        if (method === 'HEAD') {
          response.writeHead(200, headers);
          return response.end();
        }
        const range = request.headers.range;
        if (typeof range === 'string') {
          const match = range.match(/^bytes=(\d*)-(\d*)$/);
          if (!match) throw new HttpError(416, 'INVALID_RANGE', 'Only one byte range is supported');
          const start = match[1] ? Number(match[1]) : 0;
          const end = match[2] ? Number(match[2]) : bytes.length - 1;
          if (!Number.isInteger(start) || !Number.isInteger(end) || start < 0 || end < start || end >= bytes.length) throw new HttpError(416, 'INVALID_RANGE', 'The requested byte range is not satisfiable');
          const slice = bytes.subarray(start, end + 1);
          response.writeHead(206, { ...headers, 'content-length': slice.length, 'content-range': `bytes ${start}-${end}/${bytes.length}` });
          return response.end(slice);
        }
        response.writeHead(200, headers);
        return response.end(bytes);
      }

      if (path.startsWith('/api/agent/v1/')) {
        const principal = bearerPrincipal(request, token);
        const runId = typeof request.headers['x-agent-run-id'] === 'string' ? request.headers['x-agent-run-id'].slice(0, 100) : null;

        if ((method === 'POST' && path === '/api/agent/v1/query') || (method === 'QUERY' && path === '/api/agent/v1/entities')) {
          return sendJson(response, 200, executeQuery(store, await readJson(request)), { 'cache-control': 'no-store', 'accept-query': 'application/json' });
        }
        if (method === 'GET' && path === '/api/agent/v1/products') {
          return sendJson(response, 200, { items: store.listProducts(url.searchParams.get('query') ?? ''), sequence: store.state.sequence });
        }
        const productMatch = path.match(/^\/api\/agent\/v1\/products\/([^/]+)$/);
        if (method === 'GET' && productMatch) return sendJson(response, 200, store.product(decodeURIComponent(productMatch[1])));
        if (method === 'GET' && path === '/api/agent/v1/state') return sendJson(response, 200, store.snapshot(url.searchParams.get('scope') ?? 'all'));
        if (method === 'GET' && path === '/api/agent/v1/actions') return sendJson(response, 200, { actions: store.actionList(), sequence: store.state.sequence });

        const previewMatch = path.match(/^\/api\/agent\/v1\/actions\/([^/]+)\/preview$/);
        if (method === 'POST' && previewMatch) {
          const body = await readJson(request);
          exactKeys(body, ['arguments']);
          return sendJson(response, 201, store.preview(decodeURIComponent(previewMatch[1]), body.arguments, principal, { runId, requestId }), { 'cache-control': 'no-store' });
        }
        if (method === 'POST' && path === '/api/agent/v1/commits') {
          const body = await readJson(request);
          exactKeys(body, ['preview_id', 'confirmation']);
          if (typeof body.preview_id !== 'string') throw new HttpError(400, 'INVALID_ARGUMENT', 'preview_id must be a string');
          const receipt = store.commit({
            previewId: body.preview_id,
            idempotencyKey: request.headers['idempotency-key'],
            confirmation: body.confirmation,
            principal,
            runId,
            requestId
          });
          return sendJson(response, receipt.replayed ? 200 : 201, receipt, { 'cache-control': 'no-store', location: `${origin}/api/agent/v1/receipts/${encodeURIComponent(receipt.receipt_id)}` });
        }
        const receiptMatch = path.match(/^\/api\/agent\/v1\/receipts\/([^/]+)$/);
        if (method === 'GET' && receiptMatch) return sendJson(response, 200, store.receipt(decodeURIComponent(receiptMatch[1])), { 'cache-control': 'no-store' });

        if (method === 'GET' && path === '/api/agent/v1/events') {
          const sinceValue = url.searchParams.get('since') ?? request.headers['last-event-id'] ?? '0';
          const since = Number(sinceValue);
          if (!Number.isInteger(since) || since < 0) throw new HttpError(400, 'INVALID_SEQUENCE', 'since must be a non-negative integer');
          const existing = store.eventsSince(since);
          response.writeHead(200, {
            'content-type': 'text/event-stream; charset=utf-8',
            'cache-control': 'no-store',
            connection: 'keep-alive',
            'x-accel-buffering': 'no'
          });
          response.write(`retry: 2000\nevent: ready\ndata: ${JSON.stringify({ current_sequence: store.state.sequence })}\n\n`);
          for (const event of existing) sseWrite(response, event);
          if (url.searchParams.get('once') === 'true') return response.end();
          const listener = (event) => sseWrite(response, event);
          store.on('event', listener);
          const heartbeat = setInterval(() => response.write(': heartbeat\n\n'), 15_000);
          const cleanup = () => { clearInterval(heartbeat); store.off('event', listener); };
          request.on('close', cleanup);
          response.on('close', cleanup);
          return;
        }
        if (method === 'GET' && path === '/api/agent/v1/trace') return sendJson(response, 200, { ...metrics, recent_requests: [...metrics.recent_requests] });
        if (path === '/api/agent/v1/render' || path === '/api/agent/v1/screenshot') {
          if (path.endsWith('/render')) metrics.render_requests += 1;
          else metrics.screenshot_requests += 1;
          throw new HttpError(501, 'UNSUPPORTED_CAPABILITY', 'This server has no renderer or screenshot fallback');
        }
      }

      if (method === 'POST' && path === '/ask') {
        const body = await readJson(request);
        const text = body.query?.text;
        if (typeof text !== 'string') throw new HttpError(400, 'INVALID_QUERY', 'query.text is required');
        const results = searchNatural(store, text).map((product) => ({
          '@context': 'https://schema.org',
          '@type': 'Product',
          identifier: product.id,
          name: product.name,
          description: product.description,
          image: `${origin}/api/agent/v1/media/${encodeURIComponent(product.media[0])}/content`,
          offers: { '@type': 'Offer', price: (product.price.minor / 100).toFixed(2), priceCurrency: product.price.currency },
          grounding: { source: `${origin}/products/${encodeURIComponent(product.id)}` },
          actions: [{
            '@type': 'AddToCartAction',
            name: 'cart.add.preview',
            description: 'Preview adding this product to the cart',
            protocol: 'HTTP',
            method: 'POST',
            endpoint: `${origin}/api/agent/v1/actions/cart.add/preview`,
            params: { arguments: { product_id: product.id, quantity: 1 } }
          }]
        }));
        return sendJson(response, 200, { _meta: { response_type: 'answer', response_format: 'conversational_search', version: '0.55' }, results });
      }
      if (method === 'POST' && path === '/await') {
        return sendJson(response, 200, { _meta: { response_type: 'failure', version: '0.55' }, error: { code: 'UNSUPPORTED_MODE', message: 'This synchronous reference implementation returned no promise' } });
      }

      throw new HttpError(404, 'NOT_FOUND', `No route for ${method} ${path}`);
    } catch (error) {
      metrics.errors_total += 1;
      const envelope = errorEnvelope(error, requestId);
      if (!(error instanceof HttpError)) logger.error?.(error);
      if (!response.headersSent) sendJson(response, envelope.status, envelope.body, { ...SECURITY_HEADERS, 'cache-control': 'no-store' });
      else response.end();
    } finally {
      const url = request.url?.split('?')[0] ?? '/';
      metrics.recent_requests.push({ method: request.method, path: url, status: response.statusCode, duration_ms: Number((performance.now() - started).toFixed(2)), request_id: requestId });
      if (metrics.recent_requests.length > 500) metrics.recent_requests.shift();
    }
  });

  return {
    server,
    store,
    media,
    metrics,
    async start() {
      await new Promise((resolvePromise, reject) => {
        server.once('error', reject);
        server.listen(port, host, () => { server.off('error', reject); resolvePromise(); });
      });
      address = server.address();
      return `http://${address.address === '::' ? '127.0.0.1' : address.address}:${address.port}`;
    },
    async stop() {
      if (!server.listening) return;
      await new Promise((resolvePromise, reject) => server.close((error) => error ? reject(error) : resolvePromise()));
    },
    get url() {
      if (!address) return null;
      return `http://${address.address === '::' ? '127.0.0.1' : address.address}:${address.port}`;
    }
  };
}

const isMain = process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url));
if (isMain) {
  const port = Number(process.env.PORT ?? 4317);
  const dataFile = process.env.AGENT_DATA_FILE === ':memory:' ? null : resolve(process.env.AGENT_DATA_FILE ?? 'data/state.json');
  const app = createAgentServer({ port, host: process.env.HOST ?? '127.0.0.1', token: process.env.AGENT_TOKEN ?? 'agent-demo-token', dataFile });
  const url = await app.start();
  console.log(`Agent-native web reference listening at ${url}`);
  console.log(`Manifest: ${url}/agent/manifest.json`);
  console.log('This process contains no browser, renderer, DOM, or screenshot runtime.');
  const shutdown = async () => { await app.stop(); process.exit(0); };
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
}
