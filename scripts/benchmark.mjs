import { createAgentServer } from '../src/server.mjs';
import { AgentWebClient } from '../src/client.mjs';

const samples = Number(process.argv[2] ?? 100);
const app = createAgentServer({ port: 0, token: 'benchmark-token', dataFile: null, logger: { error() {} } });
const baseUrl = await app.start();
const client = new AgentWebClient({ baseUrl, token: 'benchmark-token', runId: 'benchmark' });

function percentile(values, p) {
  const sorted = [...values].sort((a, b) => a - b);
  return sorted[Math.min(sorted.length - 1, Math.floor(sorted.length * p))];
}

async function measure(name, operation) {
  const timings = [];
  await operation();
  for (let index = 0; index < samples; index += 1) {
    const start = performance.now();
    await operation();
    timings.push(performance.now() - start);
  }
  return {
    operation: name,
    samples,
    p50_ms: Number(percentile(timings, 0.5).toFixed(3)),
    p95_ms: Number(percentile(timings, 0.95).toFixed(3)),
    p99_ms: Number(percentile(timings, 0.99).toFixed(3)),
    min_ms: Number(Math.min(...timings).toFixed(3)),
    max_ms: Number(Math.max(...timings).toFixed(3))
  };
}

try {
  const results = [];
  results.push(await measure('typed product query', () => client.query({ colour: 'blue', in_stock: true })));
  results.push(await measure('scoped state baseline', () => client.state('cart')));
  results.push(await measure('direct image region', () => client.mediaBytes('media:trailpack-blue:hero', { region: 'inspection-mark' })));
  process.stdout.write(`${JSON.stringify({ environment: { node: process.version, platform: process.platform, architecture: process.arch }, results }, null, 2)}\n`);
} finally {
  await app.stop();
}
