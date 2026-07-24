import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { withFixture } from './helpers.mjs';

const project = resolve(dirname(fileURLToPath(import.meta.url)), '..');

test('real MCP stdio process initializes, lists tools, and returns direct image content', async (t) => {
  const { baseUrl } = await withFixture(t);
  const child = spawn(process.execPath, ['src/mcp.mjs'], {
    cwd: project,
    env: { ...process.env, AGENT_BASE_URL: baseUrl, AGENT_TOKEN: 'test-token-123' },
    stdio: ['pipe', 'pipe', 'pipe']
  });
  t.after(() => { if (!child.killed) child.kill(); });
  const messages = [
    { jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-11-25', capabilities: {}, clientInfo: { name: 'test', version: '1' } } },
    { jsonrpc: '2.0', method: 'notifications/initialized' },
    { jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} },
    { jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'agent.media.read', arguments: { media_id: 'media:trailpack-blue:hero', region: 'inspection-mark' } } }
  ];
  child.stdin.end(`${messages.map((message) => JSON.stringify(message)).join('\n')}\n`);
  let stdout = '';
  let stderr = '';
  child.stdout.setEncoding('utf8').on('data', (chunk) => { stdout += chunk; });
  child.stderr.setEncoding('utf8').on('data', (chunk) => { stderr += chunk; });
  const exitCode = await new Promise((resolvePromise, reject) => {
    child.once('error', reject);
    child.once('close', resolvePromise);
  });
  assert.equal(exitCode, 0, stderr);
  assert.equal(stderr, '');
  const responses = stdout.trim().split('\n').map(JSON.parse);
  assert.equal(responses.length, 3);
  assert.equal(responses[0].result.protocolVersion, '2025-11-25');
  assert.ok(responses[1].result.tools.some((tool) => tool.name === 'agent.action.commit'));
  assert.equal(responses[2].result.content[0].type, 'image');
  assert.equal(responses[2].result.structuredContent.source, 'source-region');
});
