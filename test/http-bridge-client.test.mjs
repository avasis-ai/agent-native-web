import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { once } from 'node:events';

import { HttpBridgeClient } from '../src/http-bridge/client.mjs';
import { BridgeError } from '../src/http-bridge/errors.mjs';
import { createHttpSession } from '../src/http-bridge/http-session.mjs';

async function body(request) {
  const chunks = [];
  for await (const chunk of request) chunks.push(chunk);
  return Buffer.concat(chunks).toString('utf8');
}

async function bridgeFixture(t, handler) {
  const server = createServer(handler);
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const address = server.address();
  const baseUrl = `http://127.0.0.1:${address.port}`;
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const client = new HttpBridgeClient({
    sessionOptions: {
      allowedOrigins: [baseUrl],
      allowPrivateNetworks: true,
      requestTimeoutMs: 2_000
    }
  });
  t.after(() => client.clearSession());
  return { client, baseUrl };
}

function fieldsFor(contract, operation) {
  return Object.fromEntries(operation.fields.map((field) => [field.wire_name, field.field_id]));
}

test('public path-derived fingerprints are keyed while operation IDs stay cross-process stable', async (t) => {
  const server = createServer((_request, response) => {
    response.setHeader('content-type', 'text/html');
    response.end('<form id="login" method="post"><input name="identity"><button>Continue</button></form>');
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const baseUrl = `http://127.0.0.1:${server.address().port}`;
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const options = { allowedOrigins: [baseUrl], allowPrivateNetworks: true };
  const first = new HttpBridgeClient({ digestKey: Buffer.alloc(32, 1), sessionOptions: options });
  const second = new HttpBridgeClient({ digestKey: Buffer.alloc(32, 2), sessionOptions: options });
  t.after(() => Promise.all([first.clearSession(), second.clearSession()]));

  const url = `${baseUrl}/r/7xQ`;
  const firstContract = await first.inspect(url);
  const secondContract = await second.inspect(url);
  assert.equal(firstContract.operations[0].operation_id, secondContract.operations[0].operation_id);
  assert.equal(firstContract.operations[0].fields[0].field_id, secondContract.operations[0].fields[0].field_id);
  assert.match(firstContract.fingerprints.compiled_contract, /^hmac-sha256:/);
  assert.notEqual(firstContract.fingerprints.compiled_contract, secondContract.fingerprints.compiled_contract);
  assert.equal(JSON.stringify(firstContract).includes('/r/7xQ'), false);

  const firstField = firstContract.operations[0].fields[0].field_id;
  const firstPreview = await first.prepare({
    contractId: firstContract.contract_id,
    actionId: firstContract.operations[0].operation_id,
    input: { [firstField]: 'alice' }
  });
  assert.match(firstPreview.bindings.form_fingerprint_digest, /^hmac-sha256:/);
});

test('fills a static login form through HTTP, persists cookies, and never overclaims success', async (t) => {
  const state = { get: 0, post: 0, submitted: null, loginCookie: null, origin: null };
  const { client, baseUrl } = await bridgeFixture(t, async (request, response) => {
    if (request.url === '/login' && request.method === 'GET') {
      state.get += 1;
      response.setHeader('content-type', 'text/html; charset=utf-8; private=GET-METADATA-SECRET');
      response.setHeader('set-cookie', 'visit=seen; Path=/; HttpOnly; SameSite=Lax');
      response.end(`<!doctype html><p>render nonce ${Date.now()}</p>
        <form id="login" action="/session" method="post">
          <input type="hidden" name="csrf" value="stable-csrf">
          <label>Email <input name="email" type="email" required></label>
          <label>Password <input name="password" type="password" required minlength="8"></label>
          <button name="intent" value="login">Sign in</button>
        </form>`);
      return;
    }
    if (request.url === '/session' && request.method === 'POST') {
      state.post += 1;
      state.loginCookie = request.headers.cookie;
      state.origin = request.headers.origin;
      state.submitted = new URLSearchParams(await body(request));
      response.statusCode = 303;
      response.statusMessage = 'POST-REASON-SECRET';
      response.setHeader('location', '/account');
      response.setHeader('set-cookie', 'session=opaque; Path=/; HttpOnly; SameSite=Lax');
      response.setHeader('content-type', 'application/x-private-result; token=POST-METADATA-SECRET');
      response.end();
      return;
    }
    if (request.url === '/account') {
      response.setHeader('content-type', 'text/html; charset=utf-8');
      response.end('<h1>Account</h1>');
      return;
    }
    response.statusCode = 404;
    response.end('missing');
  });

  const contract = await client.inspect(`${baseUrl}/login`);
  assert.equal(contract.rail, 'standard_html');
  assert.equal(contract.automation_ceiling, 'approved_dispatch');
  assert.equal(contract.assurance.semantic_effect, 'unknown');
  assert.equal(contract.assurance.auth_subject, 'unknown');
  assert.equal(JSON.stringify(contract).includes('GET-METADATA-SECRET'), false);
  const operation = contract.operations.find((candidate) => candidate.executable);
  const fields = fieldsFor(contract, operation);
  const preview = await client.prepare({
    contractId: contract.contract_id,
    actionId: operation.operation_id,
    input: {
      [fields.email]: 'agent@example.com',
      [fields.password]: 'correct horse battery staple'
    }
  });
  const serialized = JSON.stringify(preview);
  assert.equal(preview.kind, 'request_preview');
  assert.equal(preview.effect.status, 'not_claimed');
  assert.equal(preview.bindings.transport_profile, 'undici-fetch-v8; browser-navigation-headers-not-emulated');
  assert.equal(preview.request.headers['user-agent'], 'agent-native-web-http-bridge/0.1');
  assert.equal(serialized.includes('correct horse'), false);
  assert.equal(serialized.includes('stable-csrf'), false);

  await assert.rejects(
    () => client.dispatch(preview.preview_id),
    (error) => error instanceof BridgeError && error.code === 'APPROVAL_REQUIRED'
  );
  await assert.rejects(
    () => client.dispatch(preview.preview_id, { approvalDigest: 'sha256:not-the-preview' }),
    (error) => error instanceof BridgeError && error.code === 'APPROVAL_BINDING_MISMATCH'
  );
  await assert.rejects(
    () => client.dispatch(preview.preview_id, { approvalDigest: preview.preview_digest }),
    (error) => error instanceof BridgeError && error.code === 'COMMIT_NOT_AUTOMATABLE'
  );

  const dispatchOptions = {
    approvalDigest: preview.preview_digest,
    allowUnverifiedWrite: true
  };
  const [receipt, concurrentReplay] = await Promise.all([
    client.dispatch(preview.preview_id, dispatchOptions),
    client.dispatch(preview.preview_id, dispatchOptions)
  ]);
  assert.equal(receipt.kind, 'attempt_receipt');
  assert.equal(receipt.dispatch, 'response_received');
  assert.equal(receipt.outcome, 'unverified');
  assert.equal(JSON.stringify(receipt).includes('POST-REASON-SECRET'), false);
  assert.equal(JSON.stringify(receipt).includes('POST-METADATA-SECRET'), false);
  assert.equal(receipt.response.status_text, undefined);
  assert.equal(receipt.response.content_type, 'other');
  assert.match(receipt.response.content_type_metadata_digest, /^hmac-sha256:/);
  assert.match(receipt.authority_limit, /not an unverified remote business effect/);
  assert.equal(state.get, 2, 'commit re-fetches and recompiles the form');
  assert.equal(state.post, 1);
  assert.match(state.loginCookie, /visit=seen/);
  assert.equal(state.origin, baseUrl);
  assert.equal(state.submitted.get('csrf'), 'stable-csrf');
  assert.equal(state.submitted.get('email'), 'agent@example.com');
  assert.equal(state.submitted.get('password'), 'correct horse battery staple');
  assert.equal(state.submitted.get('intent'), 'login');
  assert.equal(concurrentReplay.receipt_id, receipt.receipt_id);

  const replay = await client.dispatch(preview.preview_id, dispatchOptions);
  assert.equal(replay.receipt_id, receipt.receipt_id);
  assert.equal(state.post, 1, 'a consumed preview is not dispatched twice');
});

test('hidden-field drift invalidates approval before a POST is sent', async (t) => {
  const state = { token: 0, post: 0 };
  const { client, baseUrl } = await bridgeFixture(t, async (request, response) => {
    if (request.method === 'GET') {
      state.token += 1;
      response.setHeader('content-type', 'text/html');
      response.end(`<form id="change" method="post" action="/change">
        <input type="hidden" name="csrf" value="token-${state.token}">
        <input name="value" required><button>Save</button></form>`);
      return;
    }
    state.post += 1;
    response.end('unexpected');
  });
  const contract = await client.inspect(`${baseUrl}/edit`);
  const operation = contract.operations[0];
  const value = operation.fields.find((field) => field.wire_name === 'value');
  const preview = await client.prepare({
    contractId: contract.contract_id,
    actionId: operation.operation_id,
    input: { [value.field_id]: 'new value' }
  });
  await assert.rejects(
    () => client.dispatch(preview.preview_id, {
      approvalDigest: preview.preview_digest,
      allowUnverifiedWrite: true
    }),
    (error) => error instanceof BridgeError && error.code === 'PREVIEW_STALE'
  );
  assert.equal(state.post, 0);
});

test('session or account cookie drift invalidates approval before a POST is sent', async (t) => {
  const state = { reads: 0, post: 0 };
  const { client, baseUrl } = await bridgeFixture(t, (request, response) => {
    if (request.method === 'GET') {
      state.reads += 1;
      response.setHeader('content-type', 'text/html');
      response.setHeader('set-cookie', `sid=${state.reads === 1 ? 'account-a' : 'account-b'}; Path=/; HttpOnly; SameSite=Lax`);
      response.end('<form id="change" method="post" action="/change"><input name="value" required><button>Save</button></form>');
      return;
    }
    state.post += 1;
    response.end('unexpected');
  });
  const contract = await client.inspect(`${baseUrl}/edit`);
  const operation = contract.operations[0];
  const value = operation.fields.find((candidate) => candidate.wire_name === 'value');
  const preview = await client.prepare({
    contractId: contract.contract_id,
    actionId: operation.operation_id,
    input: { [value.field_id]: 'new value' }
  });

  await assert.rejects(
    () => client.dispatch(preview.preview_id, {
      approvalDigest: preview.preview_digest,
      allowUnverifiedWrite: true
    }),
    (error) => error instanceof BridgeError && error.code === 'CREDENTIAL_BINDING_MISMATCH'
  );
  assert.equal(state.reads, 2);
  assert.equal(state.post, 0);
});

test('approval expiry during the freshness fetch prevents the POST', async (t) => {
  let currentTime = Date.parse('2026-07-26T00:00:00.000Z');
  const state = { reads: 0, post: 0 };
  const server = createServer((request, response) => {
    if (request.method === 'GET') {
      state.reads += 1;
      if (state.reads === 2) currentTime += 5_000;
      response.setHeader('content-type', 'text/html');
      response.end('<form method="post" action="/save"><input name="value"><button>Save</button></form>');
      return;
    }
    state.post += 1;
    response.end('unexpected');
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const baseUrl = `http://127.0.0.1:${server.address().port}`;
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const client = new HttpBridgeClient({
    now: () => new Date(currentTime),
    previewTtlMs: 1_000,
    sessionOptions: { allowedOrigins: [baseUrl], allowPrivateNetworks: true }
  });
  t.after(() => client.clearSession());
  const contract = await client.inspect(`${baseUrl}/form`);
  const operation = contract.operations[0];
  const value = operation.fields.find((item) => item.wire_name === 'value');
  const preview = await client.prepare({
    contractId: contract.contract_id,
    actionId: operation.operation_id,
    input: { [value.field_id]: 'approved' }
  });

  await assert.rejects(
    () => client.dispatch(preview.preview_id, {
      approvalDigest: preview.preview_digest,
      allowUnverifiedWrite: true
    }),
    (error) => error instanceof BridgeError && error.code === 'PREVIEW_STALE'
  );
  assert.equal(state.reads, 2);
  assert.equal(state.post, 0);
});

test('visible semantic label drift invalidates approval before a POST is sent', async (t) => {
  const state = { reads: 0, post: 0 };
  const { client, baseUrl } = await bridgeFixture(t, (request, response) => {
    if (request.method === 'GET') {
      state.reads += 1;
      const label = state.reads === 1 ? 'Enable notifications' : 'Delete account';
      response.setHeader('content-type', 'text/html');
      response.end(`<form method="post" action="/apply"><p>${label}</p><input name="confirm" required><button>Apply</button></form>`);
      return;
    }
    state.post += 1;
    response.end('unexpected');
  });
  const contract = await client.inspect(`${baseUrl}/settings`);
  const operation = contract.operations[0];
  const confirm = operation.fields.find((candidate) => candidate.wire_name === 'confirm');
  const preview = await client.prepare({
    contractId: contract.contract_id,
    actionId: operation.operation_id,
    input: { [confirm.field_id]: 'yes' }
  });
  await assert.rejects(
    () => client.dispatch(preview.preview_id, {
      approvalDigest: preview.preview_digest,
      allowUnverifiedWrite: true
    }),
    (error) => error instanceof BridgeError && error.code === 'PREVIEW_STALE'
  );
  assert.equal(state.post, 0);
});

test('option label and optgroup semantics are freshness-bound', async (t) => {
  const state = { reads: 0, post: 0 };
  const { client, baseUrl } = await bridgeFixture(t, (request, response) => {
    if (request.method === 'GET') {
      state.reads += 1;
      const optionLabel = state.reads === 1 ? 'Keep account' : 'Delete account';
      response.setHeader('content-type', 'text/html');
      response.end(`<form method="post" action="/apply">
        <select name="decision"><optgroup label="Account action">
          <option value="confirmed" label="${optionLabel}">Unchanged fallback text</option>
        </optgroup></select><button>Apply</button></form>`);
      return;
    }
    state.post += 1;
    response.end('unexpected');
  });
  const contract = await client.inspect(`${baseUrl}/settings`);
  const operation = contract.operations[0];
  const decision = operation.fields.find((candidate) => candidate.wire_name === 'decision');
  assert.equal(decision.options[0].label, 'Keep account');
  assert.equal(decision.options[0].group_label, 'Account action');
  const preview = await client.prepare({
    contractId: contract.contract_id,
    actionId: operation.operation_id,
    input: { [decision.field_id]: decision.options[0].option_id }
  });
  await assert.rejects(
    () => client.dispatch(preview.preview_id, {
      approvalDigest: preview.preview_digest,
      allowUnverifiedWrite: true
    }),
    (error) => error instanceof BridgeError && error.code === 'PREVIEW_STALE'
  );
  assert.equal(state.post, 0);
});

test('external aria-labelledby drift invalidates the selected submitter before dispatch', async (t) => {
  const state = { reads: 0, post: 0 };
  const { client, baseUrl } = await bridgeFixture(t, (request, response) => {
    if (request.method === 'GET') {
      state.reads += 1;
      const actionName = state.reads === 1 ? 'Keep account' : 'Delete account';
      response.setHeader('content-type', 'text/html');
      response.end(`<span id="action-name">${actionName}</span>
        <form method="post" action="/apply"><input name="confirm" required>
          <button aria-labelledby="action-name">Unchanged button text</button></form>`);
      return;
    }
    state.post += 1;
    response.end('unexpected');
  });
  const contract = await client.inspect(`${baseUrl}/settings`);
  const operation = contract.operations[0];
  assert.equal(operation.label, 'Keep account');
  const confirm = operation.fields[0];
  const preview = await client.prepare({
    contractId: contract.contract_id,
    actionId: operation.operation_id,
    input: { [confirm.field_id]: 'yes' }
  });
  await assert.rejects(
    () => client.dispatch(preview.preview_id, {
      approvalDigest: preview.preview_digest,
      allowUnverifiedWrite: true
    }),
    (error) => error instanceof BridgeError && error.code === 'PREVIEW_STALE'
  );
  assert.equal(state.post, 0);
});

test('semantic suffix drift beyond the public text bound invalidates approval', async (t) => {
  const state = { reads: 0, post: 0 };
  const prefix = 'a'.repeat(100_100);
  const { client, baseUrl } = await bridgeFixture(t, (request, response) => {
    if (request.method === 'GET') {
      state.reads += 1;
      response.setHeader('content-type', 'text/html');
      response.end(`<form method="post" action="/apply"><p>${prefix}${state.reads === 1 ? 'A' : 'B'}</p>
        <input name="confirm" required><button>Apply</button></form>`);
      return;
    }
    state.post += 1;
    response.end('unexpected');
  });
  const contract = await client.inspect(`${baseUrl}/settings`);
  const operation = contract.operations[0];
  const confirm = operation.fields[0];
  const preview = await client.prepare({
    contractId: contract.contract_id,
    actionId: operation.operation_id,
    input: { [confirm.field_id]: 'yes' }
  });
  await assert.rejects(
    () => client.dispatch(preview.preview_id, {
      approvalDigest: preview.preview_digest,
      allowUnverifiedWrite: true
    }),
    (error) => error instanceof BridgeError && error.code === 'PREVIEW_STALE'
  );
  assert.equal(state.post, 0);
});

test('HTML semantic and validity mutations cannot preserve an approved write', async (t) => {
  const cases = {
    hidden: [
      '<form method="post" action="/apply"><input name="value"><button><span>Save draft</span><span hidden>Delete account</span></button></form>',
      '<form method="post" action="/apply"><input name="value"><button><span hidden>Save draft</span><span>Delete account</span></button></form>'
    ],
    alt: [
      '<form method="post" action="/apply"><input name="value"><button>Apply <img alt="safe shield"></button></form>',
      '<form method="post" action="/apply"><input name="value"><button>Apply <img alt="destructive warning"></button></form>'
    ],
    unnamed: [
      '<form method="post" action="/apply"><input name="value"><button>Apply</button></form>',
      '<form method="post" action="/apply"><input type="password" required><input name="value"><button>Apply</button></form>'
    ],
    command: [
      '<form method="post" action="/apply"><input name="value"><button>Apply</button></form>',
      '<form method="post" action="/apply"><input name="value"><button commandfor="dialog" command="show-modal">Apply</button></form>'
    ],
    disabled: [
      '<form method="post" action="/apply"><input name="value"></form>',
      '<form method="post" action="/apply"><input name="value"><input type="submit" disabled></form>'
    ],
    wrap: [
      '<form method="post" action="/apply"><textarea name="value" wrap="soft" cols="5"></textarea><button>Apply</button></form>',
      '<form method="post" action="/apply"><textarea name="value" wrap="hard" cols="5"></textarea><button>Apply</button></form>'
    ]
  };
  const reads = Object.fromEntries(Object.keys(cases).map((name) => [name, 0]));
  let posts = 0;
  const { client, baseUrl } = await bridgeFixture(t, (request, response) => {
    if (request.method === 'GET') {
      const name = request.url.slice(1);
      const pair = cases[name];
      reads[name] += 1;
      response.setHeader('content-type', 'text/html');
      response.end(pair[Math.min(reads[name] - 1, 1)]);
      return;
    }
    posts += 1;
    response.end('unexpected');
  });

  for (const name of Object.keys(cases)) {
    const contract = await client.inspect(`${baseUrl}/${name}`);
    const operation = contract.operations.find((candidate) => candidate.executable);
    assert.ok(operation, `${name} must begin with an executable operation`);
    const value = operation.fields.find((candidate) => candidate.wire_name === 'value');
    const preview = await client.prepare({
      contractId: contract.contract_id,
      actionId: operation.operation_id,
      input: { [value.field_id]: 'approved' }
    });
    await assert.rejects(
      () => client.dispatch(preview.preview_id, {
        approvalDigest: preview.preview_digest,
        allowUnverifiedWrite: true
      }),
      (error) => error instanceof BridgeError && error.code === 'PREVIEW_STALE',
      `${name} drift must invalidate approval`
    );
  }
  assert.equal(posts, 0);
});

test('enumerated method whitespace drift cannot preserve an approved POST', async (t) => {
  const state = { reads: 0, post: 0 };
  const { client, baseUrl } = await bridgeFixture(t, (request, response) => {
    if (request.method === 'GET') {
      state.reads += 1;
      response.setHeader('content-type', 'text/html');
      response.end(`<form method="${state.reads === 1 ? 'post' : ' post '}" action="/apply">
        <input name="value"><button>Apply</button></form>`);
      return;
    }
    state.post += 1;
    response.end('unexpected');
  });
  const contract = await client.inspect(`${baseUrl}/settings`);
  const operation = contract.operations[0];
  const value = operation.fields[0];
  const preview = await client.prepare({
    contractId: contract.contract_id,
    actionId: operation.operation_id,
    input: { [value.field_id]: 'approved' }
  });
  await assert.rejects(
    () => client.dispatch(preview.preview_id, {
      approvalDigest: preview.preview_digest,
      allowUnverifiedWrite: true
    }),
    (error) => error instanceof BridgeError && error.code === 'PREVIEW_STALE'
  );
  assert.equal(state.post, 0);
});

test('new auth interaction evidence during freshness checking stops dispatch', async (t) => {
  const state = { reads: 0, post: 0 };
  const { client, baseUrl } = await bridgeFixture(t, (request, response) => {
    if (request.method === 'GET') {
      state.reads += 1;
      response.setHeader('content-type', 'text/html');
      response.end(`<form id="login" method="post" action="/session">
        <input name="email" required>
        ${state.reads > 1 ? '<div class="g-recaptcha" data-sitekey="public-site-key"></div>' : ''}
        <button>Continue</button></form>`);
      return;
    }
    state.post += 1;
    response.end('unexpected');
  });
  const contract = await client.inspect(`${baseUrl}/login`);
  const operation = contract.operations[0];
  const email = operation.fields[0];
  const preview = await client.prepare({
    contractId: contract.contract_id,
    actionId: operation.operation_id,
    input: { [email.field_id]: 'agent@example.com' }
  });
  await assert.rejects(
    () => client.dispatch(preview.preview_id, {
      approvalDigest: preview.preview_digest,
      allowUnverifiedWrite: true
    }),
    (error) => error instanceof BridgeError && error.code === 'AUTH_CAPTCHA_REQUIRED'
  );
  assert.equal(state.post, 0);
});

test('GET form dispatch refuses a cross-origin redirect before the foreign request', async (t) => {
  let foreignHits = 0;
  const foreign = createServer((_request, response) => {
    foreignHits += 1;
    response.end('must not be reached');
  });
  foreign.listen(0, '127.0.0.1');
  await once(foreign, 'listening');
  const foreignOrigin = `http://127.0.0.1:${foreign.address().port}`;
  t.after(() => new Promise((resolve) => foreign.close(resolve)));

  const source = createServer((request, response) => {
    if (request.url === '/form') {
      response.setHeader('content-type', 'text/html');
      response.end('<form action="/go"><input name="value"><button>Go</button></form>');
      return;
    }
    response.statusCode = 302;
    response.setHeader('location', `${foreignOrigin}/landing`);
    response.end();
  });
  source.listen(0, '127.0.0.1');
  await once(source, 'listening');
  const sourceOrigin = `http://127.0.0.1:${source.address().port}`;
  t.after(() => new Promise((resolve) => source.close(resolve)));
  const client = new HttpBridgeClient({
    sessionOptions: {
      allowedOrigins: [sourceOrigin, foreignOrigin],
      allowPrivateNetworks: true
    }
  });
  t.after(() => client.clearSession());

  const contract = await client.inspect(`${sourceOrigin}/form`);
  const operation = contract.operations[0];
  const value = operation.fields[0];
  const preview = await client.prepare({
    contractId: contract.contract_id,
    actionId: operation.operation_id,
    input: { [value.field_id]: 'approved' }
  });
  await assert.rejects(
    () => client.dispatch(preview.preview_id, {
      approvalDigest: preview.preview_digest,
      allowUnverifiedWrite: true
    }),
    (error) => {
      assert.equal(error.code, 'REDIRECT_POLICY_VIOLATION');
      assert.equal(error.attemptReceipt.dispatch, 'response_received');
      assert.equal(error.attemptReceipt.response.status, 302);
      return true;
    }
  );
  assert.equal(foreignHits, 0);
});

test('does not infer HTML from a response with no HTML content type', async (t) => {
  const { client, baseUrl } = await bridgeFixture(t, (_request, response) => {
    response.removeHeader('content-type');
    response.end('<form method="post"><input name="value"><button>Save</button></form>');
  });
  const contract = await client.inspect(`${baseUrl}/opaque`);
  assert.equal(contract.rail, 'unsupported');
  assert.equal(contract.operations.length, 0);
  assert.ok(contract.refusals.some((problem) => problem.code === 'FORM_NOT_FOUND'));
  assert.ok(contract.evidence.some((item) => item.content_type === null));
});

test('script-bearing forms remain preparable but are explicitly lower assurance', async (t) => {
  const { client, baseUrl } = await bridgeFixture(t, (_request, response) => {
    response.setHeader('content-type', 'text/html');
    response.end('<script src="/bundle.js"></script><form action="/find"><input name="q"><button>Find</button></form>');
  });
  const contract = await client.inspect(`${baseUrl}/search`);
  assert.equal(contract.assurance.input_completeness, 'heuristic');
  assert.equal(contract.operations[0].assurance.input_completeness, 'heuristic');
  assert.ok(contract.operations[0].findings.some((item) => item.code === 'PAGE_SCRIPT_NOT_EXECUTED'));
});

test('a CAPTCHA widget is a typed handoff, not a guessed or bypassed field', async (t) => {
  const { client, baseUrl } = await bridgeFixture(t, (_request, response) => {
    response.setHeader('content-type', 'text/html');
    response.end(`<form id="search" action="/find"><input name="q"><button>Find</button></form>
      <form id="login" action="/login" method="post">
      <input name="email" required>
      <div class="cf-turnstile" data-sitekey="public-site-key"></div>
      <button>Continue</button></form>`);
  });
  const contract = await client.inspect(`${baseUrl}/login`);
  const search = contract.operations.find((item) => item.fields.some((field) => field.wire_name === 'q'));
  const query = search.fields.find((item) => item.wire_name === 'q');
  const safePreview = await client.prepare({
    contractId: contract.contract_id,
    actionId: search.operation_id,
    input: { [query.field_id]: 'docs' }
  });
  assert.equal(safePreview.kind, 'request_preview', 'CAPTCHA on another form does not poison this operation');

  const login = contract.operations.find((item) => item.fields.some((field) => field.wire_name === 'email'));
  const email = login.fields.find((item) => item.wire_name === 'email');
  await assert.rejects(
    () => client.prepare({
      contractId: contract.contract_id,
      actionId: login.operation_id,
      input: { [email.field_id]: 'agent@example.com' }
    }),
    (error) => error instanceof BridgeError && error.code === 'AUTH_CAPTCHA_REQUIRED'
  );
});

test('a custom session failure after request invocation can never produce a not-sent POST receipt', async (t) => {
  let posts = 0;
  const server = createServer((request, response) => {
    if (request.method === 'GET') {
      response.setHeader('content-type', 'text/html; charset=utf-8');
      response.end('<form method="post" action="/save"><input name="value" required><button>Save</button></form>');
      return;
    }
    posts += 1;
    request.resume();
    response.setHeader('content-type', 'text/plain');
    response.end('accepted');
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const origin = `http://127.0.0.1:${server.address().port}`;
  t.after(() => new Promise((resolve) => server.close(resolve)));

  const underlying = createHttpSession({
    allowedOrigins: [origin],
    allowPrivateNetworks: true
  });
  const session = {
    cookieJar: underlying.cookieJar,
    credentialBinding: underlying.credentialBinding.bind(underlying),
    async request(url, options) {
      const response = await underlying.request(url, options);
      if (options.method === 'POST') throw new Error('custom response materializer failed after upstream completion');
      return response;
    }
  };
  const client = new HttpBridgeClient({ session });
  t.after(() => client.clearSession());

  const contract = await client.inspect(`${origin}/form`);
  const operation = contract.operations[0];
  const value = operation.fields[0];
  const preview = await client.prepare({
    contractId: contract.contract_id,
    actionId: operation.operation_id,
    input: { [value.field_id]: 'approved' }
  });
  await assert.rejects(
    () => client.dispatch(preview.preview_id, {
      approvalDigest: preview.preview_digest,
      allowUnverifiedWrite: true
    }),
    (error) => {
      assert.equal(error.code, 'COMMIT_OUTCOME_UNKNOWN');
      assert.equal(error.attemptReceipt.dispatch, 'transport_ambiguous');
      assert.equal(error.attemptReceipt.outcome, 'unknown');
      return true;
    }
  );
  assert.equal(posts, 1);
  assert.equal(client.getAttemptReceipt(preview.preview_id).dispatch, 'transport_ambiguous');
});

test('a backward wall-clock adjustment after POST cannot erase response evidence', async (t) => {
  let posts = 0;
  let postCompleted = false;
  const futureStart = Date.now() + 86_400_000;
  const server = createServer((request, response) => {
    if (request.method === 'GET') {
      response.setHeader('content-type', 'text/html; charset=utf-8');
      response.end('<form method="post" action="/save"><input name="value" required><button>Save</button></form>');
      return;
    }
    posts += 1;
    request.resume();
    postCompleted = true;
    response.setHeader('content-type', 'text/plain; charset=utf-8');
    response.end('accepted');
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const origin = `http://127.0.0.1:${server.address().port}`;
  t.after(() => new Promise((resolve) => server.close(resolve)));

  const client = new HttpBridgeClient({
    now: () => new Date(postCompleted ? futureStart - 3_600_000 : futureStart),
    sessionOptions: {
      allowedOrigins: [origin],
      allowPrivateNetworks: true
    }
  });
  t.after(() => client.clearSession());

  const contract = await client.inspect(`${origin}/form`);
  const operation = contract.operations[0];
  const value = operation.fields[0];
  const preview = await client.prepare({
    contractId: contract.contract_id,
    actionId: operation.operation_id,
    input: { [value.field_id]: 'approved' }
  });
  const receipt = await client.dispatch(preview.preview_id, {
    approvalDigest: preview.preview_digest,
    allowUnverifiedWrite: true
  });

  assert.equal(posts, 1);
  assert.equal(receipt.dispatch, 'response_received');
  assert.equal(receipt.outcome, 'unverified');
  assert.equal(receipt.observed_at, receipt.started_at);
  assert.deepEqual(client.getAttemptReceipt(preview.preview_id), receipt);
});
