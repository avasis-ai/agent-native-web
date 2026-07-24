import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { AgentWebClient, UnsupportedAgentSiteError } from '../src/client.mjs';

test('HTML-only legacy site is rejected without fetching its human page', async (t) => {
  const paths = [];
  const server = createServer((request, response) => {
    paths.push(request.url);
    if (request.url === '/') {
      response.writeHead(200, { 'content-type': 'text/html' });
      response.end('<h1>Legacy UI canary</h1>');
    } else {
      response.writeHead(404, { 'content-type': 'application/json' });
      response.end(JSON.stringify({ error: { code: 'NOT_FOUND', message: 'missing' } }));
    }
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const address = server.address();
  const client = new AgentWebClient({ baseUrl: `http://127.0.0.1:${address.port}`, token: 'unused' });
  await assert.rejects(() => client.discover(), UnsupportedAgentSiteError);
  assert.deepEqual(paths, ['/agent/manifest.json']);
});
