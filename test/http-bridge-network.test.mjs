import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { once } from 'node:events';

import { BRIDGE_REFUSAL_CODES } from '../src/http-bridge/errors.mjs';
import { createHttpSession } from '../src/http-bridge/http-session.mjs';
import { createUrlPolicy } from '../src/http-bridge/url-policy.mjs';

const TEST_HOSTNAME = 'bridge.test';
const LOOPBACK_LOOKUP = async () => [{ address: '127.0.0.1', family: 4 }];

function rejectsWithCode(code) {
  return (error) => {
    assert.equal(error?.code, code);
    return true;
  };
}

async function startServer(handler, hostname = TEST_HOSTNAME) {
  const server = http.createServer(handler);
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  return {
    server,
    origin: `http://${hostname}:${server.address().port}`
  };
}

async function stopServer(server) {
  server.closeAllConnections();
  if (!server.listening) return;
  await new Promise((resolve, reject) => {
    server.close((error) => error ? reject(error) : resolve());
  });
}

function localSession(origins, options = {}) {
  return createHttpSession({
    allowedOrigins: origins,
    allowPrivateNetworks: true,
    lookup: LOOPBACK_LOOKUP,
    ...options
  });
}

test('URL policy rejects insecure and SSRF-prone targets by default', async () => {
  const policy = createUrlPolicy();

  assert.throws(
    () => policy.validate('http://example.com/path'),
    rejectsWithCode(BRIDGE_REFUSAL_CODES.TLS_REQUIRED)
  );
  assert.throws(
    () => policy.validate('https://user:secret@example.com/path'),
    rejectsWithCode(BRIDGE_REFUSAL_CODES.SSRF_TARGET_BLOCKED)
  );
  assert.throws(
    () => policy.validate('https://example.com:8443/path'),
    rejectsWithCode(BRIDGE_REFUSAL_CODES.SSRF_TARGET_BLOCKED)
  );
  await assert.rejects(
    policy.resolve('https://127.0.0.1/private'),
    rejectsWithCode(BRIDGE_REFUSAL_CODES.SSRF_TARGET_BLOCKED)
  );
  await assert.rejects(
    createUrlPolicy({
      lookup: async () => [
        { address: '93.184.216.34', family: 4 },
        { address: '169.254.169.254', family: 4 }
      ]
    }).resolve('https://mixed-answer.example/path'),
    rejectsWithCode(BRIDGE_REFUSAL_CODES.SSRF_TARGET_BLOCKED)
  );
  await assert.rejects(
    createUrlPolicy({ allowedOrigins: ['https://[::ffff:127.0.0.1]'] }).resolve('https://[::ffff:127.0.0.1]/'),
    rejectsWithCode(BRIDGE_REFUSAL_CODES.SSRF_TARGET_BLOCKED)
  );
  await assert.rejects(
    createUrlPolicy({ allowPrivateNetworks: true }).resolve('https://127.0.0.1/private'),
    rejectsWithCode(BRIDGE_REFUSAL_CODES.SSRF_TARGET_BLOCKED)
  );
});

test('an explicit local test origin persists cookies without exposing Set-Cookie', async (t) => {
  const fixture = await startServer((request, response) => {
    if (request.url === '/seed') {
      response.setHeader('set-cookie', 'sid=private-session; Path=/; HttpOnly; SameSite=Strict');
      response.end('seeded');
      return;
    }
    response.end(request.headers.cookie ?? 'missing');
  });
  t.after(() => stopServer(fixture.server));

  const session = localSession([fixture.origin]);
  const seeded = await session.request(`${fixture.origin}/seed`);
  assert.equal(seeded.status, 200);
  assert.equal(seeded.cookieStats.accepted, 1);
  assert.equal(seeded.headers.get('set-cookie'), null);
  assert.deepEqual(seeded.headers.getSetCookie(), []);

  const echoed = await session.request(`${fixture.origin}/echo`);
  assert.equal(await echoed.text(), 'sid=private-session');
});

test('credential binding is rechecked atomically before the first network send', async (t) => {
  let commitRequests = 0;
  const fixture = await startServer((request, response) => {
    if (request.url === '/seed') {
      response.setHeader('set-cookie', 'sid=approved-account; Path=/; HttpOnly; SameSite=Lax');
      response.end('seeded');
      return;
    }
    if (request.url === '/commit') commitRequests += 1;
    response.end('unexpected');
  });
  t.after(() => stopServer(fixture.server));
  const session = localSession([fixture.origin]);
  await session.request(`${fixture.origin}/seed`);
  const target = `${fixture.origin}/commit`;
  const context = {
    method: 'POST',
    siteForCookies: `${fixture.origin}/form`,
    topLevelNavigation: true
  };
  const approved = await session.credentialBinding(target, context);
  await session.cookieJar.setCookie('sid=different-account; Path=/; HttpOnly; SameSite=Lax', target);

  await assert.rejects(
    session.request(target, {
      ...context,
      body: 'value=1',
      expectedCredentialBinding: approved.binding_digest
    }),
    rejectsWithCode(BRIDGE_REFUSAL_CODES.CREDENTIAL_BINDING_MISMATCH)
  );
  assert.equal(commitRequests, 0);
});

test('redirects are bounded and strip credentials when the origin changes', async (t) => {
  let capturedHeaders;
  let crossOriginPostBodies = 0;
  const target = await startServer((request, response) => {
    if (request.method === 'POST') crossOriginPostBodies += 1;
    capturedHeaders = request.headers;
    response.setHeader('content-type', 'application/json');
    response.end(JSON.stringify({ reached: true }));
  });
  t.after(() => stopServer(target.server));

  let redirectRequests = 0;
  const source = await startServer((request, response) => {
    if (request.url === '/seed') {
      response.setHeader('set-cookie', 'sid=must-not-cross-ports; Path=/; HttpOnly');
      response.end('seeded');
      return;
    }
    if (request.url === '/cross-origin') {
      response.statusCode = 302;
      response.setHeader('location', `${target.origin}/capture`);
      response.end();
      return;
    }
    if (request.url === '/cross-origin-post') {
      response.statusCode = 307;
      response.setHeader('location', `${target.origin}/must-not-receive-body`);
      response.end();
      return;
    }
    if (request.url.startsWith('/redirect/')) {
      redirectRequests += 1;
      const index = Number(request.url.slice('/redirect/'.length));
      response.statusCode = 302;
      response.setHeader('location', `/redirect/${index + 1}`);
      response.end();
      return;
    }
    response.statusCode = 404;
    response.end();
  });
  t.after(() => stopServer(source.server));

  const session = localSession([source.origin, target.origin]);
  await session.request(`${source.origin}/seed`);
  const result = await session.request(`${source.origin}/cross-origin`, {
    headers: {
      authorization: 'Bearer must-not-cross',
      'x-api-key': 'api-key-must-not-cross',
      'x-csrf-token': 'csrf-must-not-cross',
      origin: source.origin,
      referer: `${source.origin}/form`
    }
  });
  assert.deepEqual(await result.json(), { reached: true });
  assert.equal(capturedHeaders.authorization, undefined);
  assert.equal(capturedHeaders['x-api-key'], undefined);
  assert.equal(capturedHeaders['x-csrf-token'], undefined);
  assert.equal(capturedHeaders.cookie, undefined);
  assert.equal(capturedHeaders.origin, undefined);
  assert.equal(capturedHeaders.referer, undefined);

  const nonSafeRedirect = await session.request(`${source.origin}/cross-origin-post`, {
    method: 'POST',
    body: 'password=must-not-cross'
  });
  assert.equal(nonSafeRedirect.status, 307);
  assert.equal(nonSafeRedirect.redirected, false);
  assert.equal(crossOriginPostBodies, 0);

  await assert.rejects(
    session.request(`${source.origin}/redirect/0`),
    rejectsWithCode(BRIDGE_REFUSAL_CODES.REDIRECT_POLICY_VIOLATION)
  );
  assert.equal(redirectRequests, 6, 'five redirects means at most six total HTTP attempts');
});

test('cross-origin redirect chains keep cookie credentials suppressed on later hops', async (t) => {
  const cookies = [];
  const target = await startServer((request, response) => {
    if (request.url === '/seed') {
      response.setHeader('set-cookie', 'target_session=must-stay-private; Path=/; HttpOnly; SameSite=Lax');
      response.end('seeded');
      return;
    }
    cookies.push(request.headers.cookie ?? null);
    if (request.url === '/hop1') {
      response.statusCode = 302;
      response.setHeader('location', '/hop2');
      response.end();
      return;
    }
    response.end('done');
  }, 'target.test');
  t.after(() => stopServer(target.server));
  const source = await startServer((_request, response) => {
    response.statusCode = 302;
    response.setHeader('location', `${target.origin}/hop1`);
    response.end();
  });
  t.after(() => stopServer(source.server));
  const session = localSession([source.origin, target.origin]);
  await session.request(`${target.origin}/seed`);

  const result = await session.request(`${source.origin}/chain`);
  assert.equal(await result.text(), 'done');
  assert.deepEqual(cookies, [null, null]);
});

test('a later-hop policy failure preserves evidence that an earlier response was received', async (t) => {
  const blockedOrigin = 'http://next.test:4444';
  const source = await startServer((_request, response) => {
    response.statusCode = 302;
    response.setHeader('location', `${blockedOrigin}/next`);
    response.end();
  });
  t.after(() => stopServer(source.server));
  const session = createHttpSession({
    allowedOrigins: [source.origin, blockedOrigin],
    allowPrivateNetworks: true,
    lookup: async (hostname) => {
      if (hostname === TEST_HOSTNAME) return [{ address: '127.0.0.1', family: 4 }];
      throw new Error('simulated later-hop DNS failure');
    }
  });

  await assert.rejects(session.request(`${source.origin}/start`), (error) => {
    assert.equal(error.code, BRIDGE_REFUSAL_CODES.REDIRECT_POLICY_VIOLATION);
    assert.equal(error.dispatchState, 'response_received');
    return true;
  });
});

test('an approved non-safe request is never replayed through a same-origin redirect', async (t) => {
  const attempts = [];
  const bodies = [];
  const fixture = await startServer(async (request, response) => {
    attempts.push(`${request.method} ${request.url}`);
    const chunks = [];
    for await (const chunk of request) chunks.push(chunk);
    bodies.push(Buffer.concat(chunks).toString('utf8'));
    if (request.url === '/approved') {
      response.statusCode = 307;
      response.setHeader('location', '/unapproved');
      response.end('redirect not followed');
      return;
    }
    response.end('must not be reached');
  });
  t.after(() => stopServer(fixture.server));
  const session = localSession([fixture.origin]);

  const result = await session.request(`${fixture.origin}/approved`, {
    method: 'POST',
    body: 'secret=approved-once'
  });
  assert.equal(result.status, 307);
  assert.equal(result.redirected, false);
  assert.deepEqual(attempts, ['POST /approved']);
  assert.deepEqual(bodies, ['secret=approved-once']);
});

test('streamed responses are stopped at the configured byte cap', async (t) => {
  let requests = 0;
  const fixture = await startServer((_request, response) => {
    requests += 1;
    response.write('x'.repeat(12));
    response.end('y'.repeat(12));
  });
  t.after(() => stopServer(fixture.server));

  const session = localSession([fixture.origin], { maxResponseBytes: 16 });
  await assert.rejects(
    session.request(`${fixture.origin}/oversized`),
    rejectsWithCode(BRIDGE_REFUSAL_CODES.BODY_LIMIT_EXCEEDED)
  );
  const requestBounded = localSession([fixture.origin], { maxRequestBytes: 4 });
  await assert.rejects(
    requestBounded.request(`${fixture.origin}/too-large`, { method: 'POST', body: '12345' }),
    rejectsWithCode(BRIDGE_REFUSAL_CODES.BODY_LIMIT_EXCEEDED)
  );
  const urlBounded = localSession([fixture.origin], { maxRequestBytes: 128 });
  await assert.rejects(
    urlBounded.request(`${fixture.origin}/too-long?query=${'x'.repeat(256)}`),
    rejectsWithCode(BRIDGE_REFUSAL_CODES.BODY_LIMIT_EXCEEDED)
  );
  assert.equal(requests, 1, 'oversized request is refused before dispatch');
});

test('POST socket loss and timeout are ambiguous and are never retried', async (t) => {
  const attempts = { drop: 0, timeout: 0 };
  const fixture = await startServer((request, _response) => {
    if (request.url === '/drop' || request.url.startsWith('/share/')) {
      attempts.drop += 1;
      request.socket.destroy();
      return;
    }
    if (request.url === '/timeout') {
      attempts.timeout += 1;
      request.resume();
    }
  });
  t.after(() => stopServer(fixture.server));

  const dropSession = localSession([fixture.origin], {
    requestTimeoutMs: 1_000,
    connectTimeoutMs: 250
  });
  await assert.rejects(
    dropSession.request(`${fixture.origin}/drop`, { method: 'POST', body: 'commit=1' }),
    (error) => {
      assert.equal(error.code, BRIDGE_REFUSAL_CODES.COMMIT_OUTCOME_UNKNOWN);
      assert.equal(error.requiredAction?.kind, 'verify_outcome_before_retry');
      return true;
    }
  );
  assert.equal(attempts.drop, 1);

  await assert.rejects(
    dropSession.request(`${fixture.origin}/share/short-token?code=secret`, { method: 'POST', body: 'commit=private' }),
    (error) => {
      const serialized = JSON.stringify(error.toProblem());
      assert.equal(error.code, BRIDGE_REFUSAL_CODES.COMMIT_OUTCOME_UNKNOWN);
      assert.equal(serialized.includes('short-token'), false);
      assert.equal(serialized.includes('secret'), false);
      assert.match(error.requiredAction.target, /~redacted/);
      return true;
    }
  );
  assert.equal(attempts.drop, 2);

  const timeoutSession = localSession([fixture.origin], {
    requestTimeoutMs: 120,
    connectTimeoutMs: 60
  });
  await assert.rejects(
    timeoutSession.request(`${fixture.origin}/timeout`, { method: 'POST', body: 'commit=2' }),
    rejectsWithCode(BRIDGE_REFUSAL_CODES.COMMIT_OUTCOME_UNKNOWN)
  );
  assert.equal(attempts.timeout, 1);
});
