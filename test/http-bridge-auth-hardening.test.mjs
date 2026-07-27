import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { once } from 'node:events';

import { HttpBridgeClient } from '../src/http-bridge/client.mjs';
import { BridgeError } from '../src/http-bridge/errors.mjs';

async function bridgeFixture(t, html) {
  let dispatches = 0;
  const server = createServer((request, response) => {
    if (request.method === 'GET' && request.url === '/login') {
      response.setHeader('content-type', 'text/html; charset=utf-8');
      response.end(html);
      return;
    }
    dispatches += 1;
    response.end('unexpected dispatch');
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const address = server.address();
  const baseUrl = `http://127.0.0.1:${address.port}`;
  const client = new HttpBridgeClient({
    sessionOptions: {
      allowedOrigins: [baseUrl],
      allowPrivateNetworks: true,
      requestTimeoutMs: 2_000
    }
  });
  t.after(() => client.clearSession());
  t.after(() => new Promise((resolve) => server.close(resolve)));
  return { client, baseUrl, dispatchCount: () => dispatches };
}

function inputFor(operation, values) {
  return Object.fromEntries(operation.fields
    .filter((field) => Object.hasOwn(values, field.wire_name))
    .map((field) => [field.field_id, values[field.wire_name]]));
}

test('a passkey-only form cannot be prepared or dispatched', async (t) => {
  const { client, baseUrl, dispatchCount } = await bridgeFixture(t, `
    <form id="passkey-login" method="post" action="/session">
      <input name="username" autocomplete="username webauthn" required>
      <button>Sign in</button>
    </form>`);
  const contract = await client.inspect(`${baseUrl}/login`);
  const operation = contract.operations[0];

  await assert.rejects(
    () => client.prepare({
      contractId: contract.contract_id,
      actionId: operation.operation_id,
      input: inputFor(operation, { username: 'agent@example.com' })
    }),
    (error) => error instanceof BridgeError && error.code === 'AUTH_PASSKEY_REQUIRED'
  );
  assert.equal(dispatchCount(), 0, 'no request reaches the form action without a preview');
});

test('a passkey control in the first legend of a disabled fieldset remains active', async (t) => {
  const { client, baseUrl, dispatchCount } = await bridgeFixture(t, `
    <form id="passkey-login" method="post" action="/session">
      <fieldset disabled>
        <legend><input name="credential" autocomplete="webauthn" required></legend>
        <input name="disabled-value">
      </fieldset>
      <button>Continue</button>
    </form>`);
  const contract = await client.inspect(`${baseUrl}/login`);
  const operation = contract.operations[0];
  const credential = operation.fields.find((field) => field.wire_name === 'credential');
  assert.ok(credential, 'the first-legend control is a successful form control');
  assert.equal(operation.fields.some((field) => field.wire_name === 'disabled-value'), false);

  await assert.rejects(
    () => client.prepare({
      contractId: contract.contract_id,
      actionId: operation.operation_id,
      input: { [credential.field_id]: 'opaque-credential' }
    }),
    (error) => error instanceof BridgeError && error.code === 'AUTH_PASSKEY_REQUIRED'
  );
  assert.equal(dispatchCount(), 0);
});

test('a WebAuthn-capable form with a password fallback remains preparable', async (t) => {
  const { client, baseUrl, dispatchCount } = await bridgeFixture(t, `
    <form id="password-login" method="post" action="/session">
      <input name="username" autocomplete="username webauthn" required>
      <input name="password" type="password" autocomplete="current-password" required>
      <button>Sign in</button>
    </form>`);
  const contract = await client.inspect(`${baseUrl}/login`);
  const operation = contract.operations[0];
  const preview = await client.prepare({
    contractId: contract.contract_id,
    actionId: operation.operation_id,
    input: inputFor(operation, {
      username: 'agent@example.com',
      password: 'correct horse battery staple'
    })
  });

  assert.equal(preview.kind, 'request_preview');
  assert.equal(contract.refusals.some((item) => item.code === 'AUTH_PASSKEY_REQUIRED'), false);
  assert.equal(dispatchCount(), 0);
});

test('a directly detected OAuth authorization form is refused', async (t) => {
  const hiddenResponseType = 'code HIDDEN-RESPONSE-TYPE-CAPABILITY-7xQ';
  const { client, baseUrl, dispatchCount } = await bridgeFixture(t, `
    <form id="oauth" method="post" action="/consent">
      <input type="hidden" name="client_id" value="agent">
      <input type="hidden" name="response_type" value="${hiddenResponseType}">
      <input name="scope" value="profile">
      <button>Authorize</button>
    </form>`);
  const contract = await client.inspect(`${baseUrl}/login`);
  const operation = contract.operations[0];
  assert.equal(JSON.stringify(contract).includes(hiddenResponseType), false);

  await assert.rejects(
    () => client.prepare({
      contractId: contract.contract_id,
      actionId: operation.operation_id,
      input: inputFor(operation, { scope: 'profile' })
    }),
    (error) => error instanceof BridgeError && error.code === 'AUTH_EXTERNAL_USER_AGENT_REQUIRED'
  );
  assert.equal(dispatchCount(), 0);
});

test('OAuth handoff follows the selected submitter without poisoning an ordinary sibling action', async (t) => {
  const { client, baseUrl, dispatchCount } = await bridgeFixture(t, `
    <form id="mixed" method="post" action="/ordinary">
      <input type="hidden" name="client_id" value="demo-client">
      <button name="intent" value="save">Save normally</button>
      <button name="response_type" value="code" formaction="/oauth/authorize">Authorize access</button>
    </form>`);
  const contract = await client.inspect(`${baseUrl}/login`);
  const ordinary = contract.operations.find((operation) => operation.label === 'Save normally');
  const oauth = contract.operations.find((operation) => operation.label === 'Authorize access');

  const preview = await client.prepare({
    contractId: contract.contract_id,
    actionId: ordinary.operation_id,
    input: {}
  });
  assert.equal(preview.kind, 'request_preview');
  await assert.rejects(
    () => client.prepare({
      contractId: contract.contract_id,
      actionId: oauth.operation_id,
      input: {}
    }),
    (error) => error instanceof BridgeError && error.code === 'AUTH_EXTERNAL_USER_AGENT_REQUIRED'
  );
  assert.equal(dispatchCount(), 0);
});
