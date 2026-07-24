import test from 'node:test';
import assert from 'node:assert/strict';
import { withFixture } from './helpers.mjs';

test('live SSE subscriber receives the contiguous patch caused by a commit', async (t) => {
  const { baseUrl, client } = await withFixture(t);
  const controller = new AbortController();
  t.after(() => controller.abort());
  const response = await fetch(`${baseUrl}/api/agent/v1/events?since=0`, {
    headers: { authorization: 'Bearer test-token-123', accept: 'text/event-stream' },
    signal: controller.signal
  });
  assert.equal(response.status, 200);
  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buffer = '';
  const eventPromise = (async () => {
    while (true) {
      const { done, value } = await reader.read();
      if (done) throw new Error('SSE ended before a patch arrived');
      buffer += decoder.decode(value, { stream: true });
      const blocks = buffer.split('\n\n');
      buffer = blocks.pop();
      for (const block of blocks) {
        if (!block.includes('event: patch')) continue;
        const data = block.split('\n').find((line) => line.startsWith('data: '));
        return JSON.parse(data.slice(6));
      }
    }
  })();

  const preview = await client.preview('cart.add', { product_id: 'product:trailpack-blue', quantity: 1 });
  const receipt = await client.commit(preview.preview_id, { idempotencyKey: 'live-sse-commit-0001' });
  const event = await eventPromise;
  assert.equal(event.base_sequence, 0);
  assert.equal(event.sequence, 1);
  assert.equal(event.caused_by_receipt, receipt.receipt_id);
  assert.ok(event.patch.every((operation) => operation.path.startsWith('/cart/')));
  controller.abort();
});

test('simultaneous idempotent retries create one mutation and one receipt', async (t) => {
  const { client } = await withFixture(t);
  const preview = await client.preview('cart.add', { product_id: 'product:trailpack-orange', quantity: 1 });
  const attempts = await Promise.all(Array.from({ length: 20 }, () => client.commit(preview.preview_id, { idempotencyKey: 'retry-storm-key-0001' })));
  assert.equal(new Set(attempts.map((receipt) => receipt.receipt_id)).size, 1);
  assert.equal((await client.eventsSince(0)).length, 1);
  const state = await client.state('cart');
  assert.equal(state.state.items['product:trailpack-orange'].quantity, 1);
});
