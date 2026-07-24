import test from 'node:test';
import assert from 'node:assert/strict';
import { AgentStore } from '../src/store.mjs';

const principal = { subject: 'user', client_id: 'agent', scopes: ['cart:write'] };

test('expired preview cannot commit and creates no event', () => {
  let now = Date.parse('2026-07-25T00:00:00Z');
  const store = new AgentStore({ clock: () => now });
  const preview = store.preview('cart.add', { product_id: 'product:trailpack-blue', quantity: 1 }, principal);
  now += 5 * 60 * 1000;
  assert.throws(
    () => store.commit({ previewId: preview.preview_id, idempotencyKey: 'expired-preview-key', principal }),
    (error) => error.code === 'PREVIEW_EXPIRED'
  );
  assert.equal(store.state.sequence, 0);
  assert.equal(store.state.cart.items.length, 0);
});

test('preview is bound to the authenticated principal', () => {
  const store = new AgentStore();
  const preview = store.preview('cart.add', { product_id: 'product:trailpack-blue', quantity: 1 }, principal);
  assert.throws(
    () => store.commit({ previewId: preview.preview_id, idempotencyKey: 'wrong-principal-key', principal: { subject: 'attacker', client_id: 'agent', scopes: ['cart:write'] } }),
    (error) => error.code === 'PREVIEW_PRINCIPAL_MISMATCH'
  );
  assert.equal(store.state.sequence, 0);
});
