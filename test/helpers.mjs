import { createAgentServer } from '../src/server.mjs';
import { AgentWebClient } from '../src/client.mjs';

export async function fixture(options = {}) {
  const app = createAgentServer({ port: 0, token: 'test-token-123', logger: { error() {} }, ...options });
  const baseUrl = await app.start();
  const client = new AgentWebClient({ baseUrl, token: 'test-token-123', runId: `test-run-${Date.now()}` });
  return { app, baseUrl, client, stop: () => app.stop() };
}

export async function withFixture(test, options = {}) {
  const value = await fixture(options);
  test.after(() => value.stop());
  return value;
}
