import test from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { withFixture } from './helpers.mjs';

const exec = promisify(execFile);
const project = resolve(dirname(fileURLToPath(import.meta.url)), '..');

test('CLI completes an image-dependent purchase without HTML, render, or screenshot requests', async (t) => {
  const { baseUrl, client } = await withFixture(t);
  const { stdout, stderr } = await exec(process.execPath, [
    'src/cli.mjs', 'automate', 'buy',
    '--query', 'blue', '--quantity', '1', '--checkout', '--address', '7 Agent Lane', '--yes',
    '--base-url', baseUrl, '--token', 'test-token-123', '--run-id', 'cli-e2e-run'
  ], { cwd: project, env: { ...process.env }, timeout: 20_000 });
  assert.equal(stderr, '');
  const result = JSON.parse(stdout);
  assert.equal(result.inspection_mark, 'NOVA731');
  assert.equal(result.add_receipt.action, 'cart.add');
  assert.equal(result.checkout_receipt.action, 'checkout.place');
  assert.ok(result.transcript.some((step) => step.step === 'state-deltas'));
  const trace = await client.trace();
  assert.equal(trace.human_html_requests, 0);
  assert.equal(trace.render_requests, 0);
  assert.equal(trace.screenshot_requests, 0);
  assert.ok(trace.recent_requests.every((request) => request.path !== '/' && !request.path.startsWith('/products')));
  const state = await client.state('all');
  assert.equal(state.state.orders.order.length, 1);
});

test('CLI refuses high-risk checkout without explicit approval', async (t) => {
  const { baseUrl } = await withFixture(t);
  await assert.rejects(
    () => exec(process.execPath, [
      'src/cli.mjs', 'automate', 'buy', '--query', 'orange', '--checkout', '--address', '7 Agent Lane',
      '--base-url', baseUrl, '--token', 'test-token-123', '--run-id', 'cli-no-approval'
    ], { cwd: project, timeout: 20_000 }),
    (error) => error.code === 5 && /USER_APPROVAL_REQUIRED/.test(error.stderr)
  );
});
