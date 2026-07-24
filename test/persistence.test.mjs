import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fixture } from './helpers.mjs';

test('state, receipts, events, and idempotency survive server restart', async (t) => {
  const directory = await mkdtemp(join(tmpdir(), 'agent-native-web-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const dataFile = join(directory, 'state.json');
  const first = await fixture({ dataFile });
  const preview = await first.client.preview('cart.add', { product_id: 'product:trailpack-blue', quantity: 1 });
  const key = 'persistent-idempotency-0001';
  const receipt = await first.client.commit(preview.preview_id, { idempotencyKey: key });
  await first.stop();

  const persisted = JSON.parse(await readFile(dataFile, 'utf8'));
  assert.equal(persisted.state.cart.items[0].quantity, 1);
  assert.equal(persisted.receipts[0].receipt_id, receipt.receipt_id);

  const second = await fixture({ dataFile });
  t.after(() => second.stop());
  assert.equal((await second.client.state('cart')).state.items['product:trailpack-blue'].quantity, 1);
  const replay = await second.client.commit(preview.preview_id, { idempotencyKey: key });
  assert.equal(replay.receipt_id, receipt.receipt_id);
  assert.equal(replay.replayed, true);
  assert.equal((await second.client.eventsSince(0)).length, 1);
});
