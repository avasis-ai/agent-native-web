import test from 'node:test';
import assert from 'node:assert/strict';
import { McpBridge } from '../src/mcp.mjs';
import { withFixture } from './helpers.mjs';

test('MCP maps discovery, direct image bytes, actions, and receipts to the same domain core', async (t) => {
  const { client } = await withFixture(t);
  const bridge = new McpBridge(client);
  const initialized = await bridge.handle({ jsonrpc: '2.0', id: 1, method: 'initialize', params: {} });
  assert.equal(initialized.result.protocolVersion, '2025-11-25');
  const tools = await bridge.handle({ jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} });
  assert.ok(tools.result.tools.some((tool) => tool.name === 'agent.media.read'));

  const image = await bridge.tool('agent.media.read', { media_id: 'media:trailpack-blue:hero', region: 'inspection-mark' });
  assert.equal(image.content[0].type, 'image');
  assert.equal(image.structuredContent.source, 'source-region');
  assert.ok(Buffer.from(image.content[0].data, 'base64').length > 100);

  const preview = await bridge.tool('cart.add.preview', { product_id: 'product:trailpack-orange', quantity: 1 });
  const commit = await bridge.tool('agent.action.commit', {
    preview_id: preview.structuredContent.preview_id,
    idempotency_key: 'mcp-commit-key-0001'
  });
  assert.equal(commit.structuredContent.action, 'cart.add');
  const receipt = await bridge.tool('agent.receipt.get', { receipt_id: commit.structuredContent.receipt_id });
  assert.equal(receipt.structuredContent.receipt_id, commit.structuredContent.receipt_id);
});

test('MCP resources expose original binary media and semantic visual data', async (t) => {
  const { client } = await withFixture(t);
  const bridge = new McpBridge(client);
  const resources = await bridge.resources();
  assert.ok(resources.some((resource) => resource.name === 'media:inventory:chart'));
  const image = await bridge.resourceRead('agentweb://media/media%3Atrailpack-blue%3Ahero');
  assert.equal(image.contents[0].mimeType, 'image/png');
  assert.ok(image.contents[0].blob.length > 100);
  const chart = await bridge.resourceRead('agentweb://media/media%3Ainventory%3Achart');
  assert.equal(JSON.parse(chart.contents[0].text).kind, 'chart-data');
});
