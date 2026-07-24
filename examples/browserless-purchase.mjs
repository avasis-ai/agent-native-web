import { createAgentServer } from '../src/server.mjs';
import { AgentWebClient } from '../src/client.mjs';

let app = null;
let baseUrl = process.env.AGENT_BASE_URL;
if (!baseUrl) {
  app = createAgentServer({ port: 0, token: 'demo-run-token', dataFile: null });
  baseUrl = await app.start();
}

try {
  const client = new AgentWebClient({
    baseUrl,
    token: process.env.AGENT_TOKEN ?? 'demo-run-token',
    runId: `browserless-demo-${Date.now()}`
  });
  const result = await client.automatePurchase({
    query: 'blue waterproof',
    quantity: 1,
    checkout: true,
    shippingAddress: '18 Direct Agent Way',
    approve: async (preview) => {
      process.stderr.write(`Approved disclosed effect: ${preview.effect.summary}\n`);
      return true;
    }
  });
  const trace = await client.trace();
  const proof = {
    result,
    no_browser_path: {
      human_html_requests: trace.human_html_requests,
      render_requests: trace.render_requests,
      screenshot_requests: trace.screenshot_requests,
      requested_paths: trace.recent_requests.map(({ method, path }) => ({ method, path }))
    }
  };
  if (trace.human_html_requests || trace.render_requests || trace.screenshot_requests) throw new Error('The browserless invariant was violated');
  process.stdout.write(`${JSON.stringify(proof, null, 2)}\n`);
} finally {
  if (app) await app.stop();
}
