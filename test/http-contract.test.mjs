import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { AgentWebClient } from '../src/client.mjs';
import { withFixture } from './helpers.mjs';

test('discovers capabilities and negotiates semantic representations', async (t) => {
  const { baseUrl, client } = await withFixture(t);
  const manifest = await client.discover();
  assert.equal(manifest.protocol, 'agent-resource-web');
  assert.equal(manifest.media_model.screenshots_required, false);

  const capabilities = await client.capabilities();
  assert.equal(capabilities.browser_required, false);
  assert.equal(capabilities.ui_snapshots, false);

  const agentResponse = await fetch(`${baseUrl}/products/product%3Atrailpack-blue`, { headers: { accept: 'application/agent+json' } });
  assert.match(agentResponse.headers.get('content-type'), /application\/agent\+json/);
  const agentProduct = await agentResponse.json();
  assert.equal(agentProduct.id, 'product:trailpack-blue');
  assert.equal(agentProduct.actions[0].id, 'cart.add');

  const markdownResponse = await fetch(`${baseUrl}/products/product%3Atrailpack-blue`, { headers: { accept: 'text/markdown' } });
  assert.match(markdownResponse.headers.get('content-type'), /text\/markdown/);
  assert.match(await markdownResponse.text(), /Trailpack 28L/);
});

test('runs safe HTTP QUERY and POST compatibility query against the same engine', async (t) => {
  const { client } = await withFixture(t);
  const result = await client.query({ colour: 'blue', in_stock: true, max_price_minor: 15000 });
  assert.equal(result.items.length, 1);
  assert.equal(result.items[0].id, 'product:trailpack-blue');
  const fallback = await client.queryPost({ colour: 'blue' });
  assert.deepEqual(fallback.items, result.items);
});

test('requires authentication for private state and rejects unknown query fields', async (t) => {
  const { baseUrl, client } = await withFixture(t);
  const unauthenticated = await fetch(`${baseUrl}/api/agent/v1/state`);
  assert.equal(unauthenticated.status, 401);
  assert.equal((await unauthenticated.json()).error.code, 'AUTH_REQUIRED');
  await assert.rejects(() => client.query({ arbitrary_sql: 'DROP TABLE products' }), (error) => error.code === 'INVALID_ARGUMENT');
});

test('reads original raster bytes and pixel-only region without a webpage screenshot', async (t) => {
  const { client } = await withFixture(t);
  const id = 'media:trailpack-blue:hero';
  const descriptor = await client.mediaDescriptor(id);
  assert.equal(descriptor.kind, 'image');
  assert.equal(descriptor.derived_assertions.length, 0);
  assert.ok(!JSON.stringify(descriptor).includes('NOVA731'), 'descriptor must not leak the pixel-only value');

  const original = await client.mediaBytes(id);
  assert.equal(original.source, 'original-asset');
  assert.equal(original.sha256, descriptor.source.sha256);
  assert.equal(original.sha256, createHash('sha256').update(original.bytes).digest('hex'));

  const region = descriptor.regions.find((candidate) => candidate.id === 'inspection-mark');
  assert.match(region.sha256, /^[0-9a-f]{64}$/);
  const mark = await client.readInspectionMark(id);
  assert.equal(mark.value, 'NOVA731');
  assert.equal(mark.source, 'source-region');
  assert.equal(mark.sha256, region.sha256);
});

test('rejects tampered source-region bytes even when response digest headers are unchanged', async (t) => {
  const { baseUrl } = await withFixture(t);
  const client = new AgentWebClient({
    baseUrl,
    token: 'test-token-123',
    runId: 'tampered-region-test',
    fetchImpl: async (url, options) => {
      const response = await fetch(url, options);
      if (new URL(url).searchParams.get('region') !== 'inspection-mark') return response;
      const bytes = Buffer.from(await response.arrayBuffer());
      bytes[bytes.length - 1] ^= 0xff;
      return new Response(bytes, {
        status: response.status,
        statusText: response.statusText,
        headers: response.headers
      });
    }
  });

  await assert.rejects(
    () => client.mediaBytes('media:trailpack-blue:hero', { region: 'inspection-mark' }),
    (error) => error.code === 'MEDIA_INTEGRITY_ERROR'
  );
});

test('direct media cannot turn a contract descriptor into a cross-origin fetch or redirect', async () => {
  const baseUrl = 'https://contract.example';
  let offOriginFetches = 0;
  const crossOriginClient = new AgentWebClient({
    baseUrl,
    fetchImpl: async (url) => {
      if (new URL(url).origin !== baseUrl) offOriginFetches += 1;
      return new Response(JSON.stringify({
        source: {
          url: 'http://169.254.169.254/latest/meta-data',
          sha256: '0'.repeat(64)
        }
      }), { status: 200, headers: { 'content-type': 'application/json' } });
    }
  });
  await assert.rejects(
    () => crossOriginClient.mediaBytes('media:untrusted'),
    (error) => error.code === 'MEDIA_ORIGIN_POLICY_VIOLATION'
  );
  assert.equal(offOriginFetches, 0);

  const calls = [];
  const redirectClient = new AgentWebClient({
    baseUrl,
    fetchImpl: async (url, options) => {
      calls.push({ url, redirect: options.redirect });
      if (new URL(url).pathname.includes('/api/agent/v1/media/')) {
        return new Response(JSON.stringify({
          source: {
            url: `${baseUrl}/media/source.png`,
            sha256: '0'.repeat(64)
          }
        }), { status: 200, headers: { 'content-type': 'application/json' } });
      }
      return new Response(null, {
        status: 302,
        headers: { location: 'http://169.254.169.254/latest/meta-data' }
      });
    }
  });
  await assert.rejects(
    () => redirectClient.mediaBytes('media:redirect'),
    (error) => error.code === 'MEDIA_ORIGIN_POLICY_VIOLATION'
  );
  assert.equal(calls.length, 2);
  assert.equal(calls[1].redirect, 'manual');
});

test('represents charts as data/spec and canvas-like maps as a scene graph', async (t) => {
  const { client } = await withFixture(t);
  const chart = await client.mediaData('media:inventory:chart');
  assert.equal(chart.kind, 'chart-data');
  assert.equal(chart.specification.mark, 'bar');
  assert.equal(chart.data.length, 2);
  const scene = await client.mediaData('media:warehouse:scene');
  assert.equal(scene.kind, 'scene-graph');
  assert.ok(scene.nodes.some((node) => node.id === 'rack:backpacks'));
});

test('preview has no durable effect; commit emits a compact resumable delta and receipt', async (t) => {
  const { client } = await withFixture(t);
  const before = await client.state('cart');
  const preview = await client.preview('cart.add', { product_id: 'product:trailpack-blue', quantity: 2 });
  assert.equal(preview.effect.summary.startsWith('Added 2'), true);
  assert.deepEqual((await client.state('cart')).state, before.state, 'preview must not mutate state');

  const receipt = await client.commit(preview.preview_id, { idempotencyKey: 'add-blue-test-0001' });
  assert.equal(receipt.status, 'committed');
  assert.equal(receipt.sequence, before.sequence + 1);
  assert.ok(receipt.preview_digest);
  const events = await client.eventsSince(before.sequence);
  assert.equal(events.length, 1);
  assert.equal(events[0].sequence, receipt.sequence);
  assert.ok(events[0].patch.every((operation) => operation.path.startsWith('/cart/')), 'unchanged catalog and orders must not be retransmitted');
  const cart = await client.state('cart');
  assert.equal(cart.state.items['product:trailpack-blue'].quantity, 2);
});

test('idempotent retry returns the original receipt and conflicting key reuse fails', async (t) => {
  const { client } = await withFixture(t);
  const preview = await client.preview('cart.add', { product_id: 'product:trailpack-orange', quantity: 1 });
  const key = 'retry-safe-key-0001';
  const first = await client.commit(preview.preview_id, { idempotencyKey: key });
  const replay = await client.commit(preview.preview_id, { idempotencyKey: key });
  assert.equal(replay.receipt_id, first.receipt_id);
  assert.equal(replay.replayed, true);
  const other = await client.preview('cart.add', { product_id: 'product:trailpack-blue', quantity: 1 });
  await assert.rejects(() => client.commit(other.preview_id, { idempotencyKey: key }), (error) => error.code === 'IDEMPOTENCY_CONFLICT');
  assert.equal((await client.eventsSince(0)).length, 1, 'retry must not duplicate the mutation');
});

test('stale concurrent previews are rejected before mutation', async (t) => {
  const { client } = await withFixture(t);
  const first = await client.preview('cart.add', { product_id: 'product:trailpack-blue', quantity: 1 });
  const stale = await client.preview('cart.add', { product_id: 'product:trailpack-orange', quantity: 1 });
  await client.commit(first.preview_id, { idempotencyKey: 'concurrency-first-0001' });
  await assert.rejects(() => client.commit(stale.preview_id, { idempotencyKey: 'concurrency-stale-0002' }), (error) => error.code === 'STALE_PREVIEW');
  const cart = await client.state('cart');
  assert.deepEqual(Object.keys(cart.state.items), ['product:trailpack-blue']);
});

test('consequential checkout requires explicit confirmation and revalidates inventory', async (t) => {
  const { client } = await withFixture(t);
  const add = await client.preview('cart.add', { product_id: 'product:trailpack-blue', quantity: 1 });
  await client.commit(add.preview_id, { idempotencyKey: 'checkout-add-0001' });
  const checkout = await client.preview('checkout.place', { shipping_address: '42 Test Avenue' });
  assert.equal(checkout.risk, 'high');
  assert.equal(checkout.requires_confirmation, true);
  await assert.rejects(() => client.commit(checkout.preview_id, { idempotencyKey: 'checkout-order-0001' }), (error) => error.code === 'CONFIRMATION_REQUIRED');
  const receipt = await client.commit(checkout.preview_id, { idempotencyKey: 'checkout-order-0001', confirmation: true });
  assert.equal(receipt.action, 'checkout.place');
  const state = await client.state('all');
  assert.equal(Object.keys(state.state.cart.items).length, 0);
  assert.equal(state.state.orders.order.length, 1);
  assert.equal(state.state.catalog.entities['product:trailpack-blue'].availability.stock, 6);
});

test('NLWeb adapter returns Schema.org results with preview actions', async (t) => {
  const { client } = await withFixture(t);
  const answer = await client.nlwebAsk('find a blue waterproof backpack');
  assert.equal(answer._meta.version, '0.55');
  assert.equal(answer.results.length, 1);
  assert.equal(answer.results[0]['@type'], 'Product');
  assert.match(answer.results[0].actions[0].endpoint, /\/preview$/);
});

test('renderer and screenshot capabilities fail explicitly instead of falling back', async (t) => {
  const { baseUrl } = await withFixture(t);
  for (const capability of ['render', 'screenshot']) {
    const response = await fetch(`${baseUrl}/api/agent/v1/${capability}`, { headers: { authorization: 'Bearer test-token-123' } });
    assert.equal(response.status, 501);
    assert.equal((await response.json()).error.code, 'UNSUPPORTED_CAPABILITY');
  }
});
