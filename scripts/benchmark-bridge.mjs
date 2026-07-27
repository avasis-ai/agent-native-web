import { performance } from 'node:perf_hooks';
import { createServer } from 'node:http';
import { once } from 'node:events';

import { HttpBridgeClient } from '../src/http-bridge/client.mjs';
import { compileForms } from '../src/http-bridge/form-compiler.mjs';
import { parseHtmlSource } from '../src/http-bridge/html-source.mjs';

const samples = Number(process.argv[2] ?? 200);
if (!Number.isInteger(samples) || samples < 10 || samples > 10_000) {
  throw new Error('Sample count must be an integer between 10 and 10000');
}

const html = `<!doctype html><html><body>
  <script src="/analytics.js"></script>
  <form id="search" action="/search">
    <input type="hidden" name="csrf" value="benchmark-token">
    <label>Query <input name="q" type="search" maxlength="120"></label>
    <label>Colour <select name="colour"><option value="">Any</option><option value="blue">Blue</option></select></label>
    <label><input type="checkbox" name="stock" value="yes"> In stock</label>
    <button name="intent" value="search">Search</button>
  </form>
</body></html>`;

function percentile(values, quantile) {
  const sorted = [...values].sort((left, right) => left - right);
  return sorted[Math.min(sorted.length - 1, Math.floor(sorted.length * quantile))];
}

function summary(values) {
  return {
    samples: values.length,
    p50_ms: Number(percentile(values, 0.5).toFixed(3)),
    p95_ms: Number(percentile(values, 0.95).toFixed(3)),
    max_ms: Number(Math.max(...values).toFixed(3))
  };
}

const cpu = [];
for (let index = 0; index < samples; index += 1) {
  const start = performance.now();
  compileForms(parseHtmlSource({
    body: html,
    url: 'https://benchmark.invalid/form',
    contentType: 'text/html; charset=utf-8'
  }));
  cpu.push(performance.now() - start);
}

const server = createServer((_request, response) => {
  response.setHeader('content-type', 'text/html; charset=utf-8');
  response.end(html);
});
server.listen(0, '127.0.0.1');
await once(server, 'listening');
const origin = `http://127.0.0.1:${server.address().port}`;
const client = new HttpBridgeClient({
  sessionOptions: { allowedOrigins: [origin], allowPrivateNetworks: true },
  maxRecords: Math.min(samples + 10, 10_000)
});
const inspect = [];
try {
  for (let index = 0; index < samples; index += 1) {
    const start = performance.now();
    await client.inspect(`${origin}/form`);
    inspect.push(performance.now() - start);
  }
} finally {
  await client.clearSession();
  await new Promise((resolve) => server.close(resolve));
}

process.stdout.write(`${JSON.stringify({
  workload: 'static HTML form inference; no model, browser, DOM runtime, screenshots, or external network',
  node: process.version,
  html_bytes: Buffer.byteLength(html),
  parse_and_compile: summary(cpu),
  local_http_inspect: summary(inspect),
  comparison_note: 'These are local bridge overhead measurements, not a controlled Playwright comparison.'
}, null, 2)}\n`);
