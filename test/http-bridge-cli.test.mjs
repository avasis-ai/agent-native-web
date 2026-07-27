import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { once } from 'node:events';
import { spawn } from 'node:child_process';
import { access, copyFile, mkdir, mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { canonicalSha256 } from '../src/http-bridge/profile.mjs';

const project = resolve(dirname(fileURLToPath(import.meta.url)), '..');

function runCli(args, input = '', env = {}) {
  return new Promise((resolveRun, reject) => {
    const child = spawn(process.execPath, ['src/cli.mjs', ...args], {
      cwd: project,
      env: { ...process.env, ...env },
      stdio: ['pipe', 'pipe', 'pipe']
    });
    const stdout = [];
    const stderr = [];
    child.stdout.on('data', (chunk) => stdout.push(chunk));
    child.stderr.on('data', (chunk) => stderr.push(chunk));
    child.on('error', reject);
    child.on('close', (code) => resolveRun({
      code,
      stdout: Buffer.concat(stdout).toString('utf8'),
      stderr: Buffer.concat(stderr).toString('utf8')
    }));
    child.stdin.end(input);
  });
}

test('CLI keeps the compatibility bridge separate from the native bearer token and splits session state from one-shot approval', async (t) => {
  const observed = { authorization: [], posts: 0, submitted: null, cookie: null };
  const server = createServer(async (request, response) => {
    observed.authorization.push(request.headers.authorization);
    if (request.method === 'GET' && request.url === '/form') {
      response.setHeader('content-type', 'text/html; charset=utf-8');
      response.setHeader('set-cookie', 'sid=approved-account; Path=/; HttpOnly; SameSite=Lax');
      response.end('<form id="note" action="/save" method="post"><input type="hidden" name="csrf" value="fixed"><input name="note" required><button>Save</button></form>');
      return;
    }
    if (request.method === 'POST' && request.url === '/save') {
      observed.posts += 1;
      observed.cookie = request.headers.cookie;
      const chunks = [];
      for await (const chunk of request) chunks.push(chunk);
      observed.submitted = new URLSearchParams(Buffer.concat(chunks).toString('utf8'));
      response.statusCode = 303;
      response.setHeader('location', '/done');
      response.end();
      return;
    }
    if (request.url === '/done') {
      response.setHeader('content-type', 'text/html');
      response.end('<p>done</p>');
      return;
    }
    response.statusCode = 404;
    response.end('missing');
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  t.after(() => new Promise((resolveClose) => server.close(resolveClose)));
  const url = `http://127.0.0.1:${server.address().port}/form`;
  const common = ['--allow-private-network'];
  const env = { AGENT_TOKEN: 'native-token-must-never-leak' };
  const temporary = await mkdtemp(join(tmpdir(), 'agentweb-cli-'));
  const sessionPath = join(temporary, 'bridge-session.json');
  const approvalPath = join(temporary, 'bridge-approval.json');
  t.after(() => rm(temporary, { recursive: true, force: true }));

  const falsePrivateOptIn = await runCli(['bridge', 'inspect', url, '--allow-private-network=false'], '', env);
  assert.equal(falsePrivateOptIn.code, 2);
  assert.match(falsePrivateOptIn.stderr, /presence-only flag/);
  assert.equal(observed.authorization.length, 0, 'an explicit false value is rejected before any fetch');

  const inspected = await runCli(['bridge', 'inspect', url, ...common], '', env);
  assert.equal(inspected.code, 0, inspected.stderr);
  const contract = JSON.parse(inspected.stdout);
  const operation = contract.operations[0];
  const note = operation.fields.find((field) => field.wire_name === 'note');
  const input = JSON.stringify({ [note.field_id]: 'hello from an agent' });

  const malformedSecret = 'super-secret-bridge-password';
  const malformed = await runCli([
    'bridge', 'prepare', url,
    '--action', operation.operation_id,
    '--input', '-',
    ...common
  ], `{"password":${malformedSecret}}`, env);
  assert.equal(malformed.code, 2);
  assert.equal(malformed.stderr.includes(malformedSecret), false);
  assert.equal(JSON.parse(malformed.stderr).error.code, 'INVALID_BRIDGE_DATA');

  const secretUnknownField = 'callback/STDIN-SECRET';
  const invalidField = await runCli([
    'bridge', 'prepare', url,
    '--action', operation.operation_id,
    '--input', '-',
    ...common
  ], JSON.stringify({ [secretUnknownField]: 'not-for-output' }), env);
  assert.equal(invalidField.code, 2);
  assert.equal(invalidField.stderr.includes(secretUnknownField), false);
  assert.equal(invalidField.stderr.includes('not-for-output'), false);

  const prepared = await runCli([
    'bridge', 'prepare', url,
    '--action', operation.operation_id,
    '--input', '-',
    '--session-file', sessionPath,
    '--approval-file', approvalPath,
    ...common
  ], input, env);
  assert.equal(prepared.code, 0, prepared.stderr);
  const preparedValue = JSON.parse(prepared.stdout);
  assert.equal(preparedValue.preview.effect.status, 'not_claimed');
  assert.equal(preparedValue.session_state.contains_credentials, true);
  assert.equal(preparedValue.approval_capsule.one_shot, true);
  assert.equal((await stat(sessionPath)).mode & 0o077, 0);
  assert.equal((await stat(approvalPath)).mode & 0o077, 0);
  assert.equal(prepared.stdout.includes('approved-account'), false);
  assert.equal(prepared.stdout.includes('digest_key_base64'), false);
  const storedSession = await readFile(sessionPath, 'utf8');
  assert.equal(storedSession.includes('approval_binding_digest'), false);
  assert.equal(storedSession.includes('digest_key_base64'), false);

  const falseAcknowledgement = await runCli([
    'bridge', 'submit', url,
    '--action', operation.operation_id,
    '--input', '-',
    '--session-file', sessionPath,
    '--approval-file', approvalPath,
    '--approval-binding-digest', preparedValue.preview.approval_binding_digest,
    '--allow-unverified-write=false',
    ...common
  ], input, env);
  assert.equal(falseAcknowledgement.code, 2);
  assert.match(falseAcknowledgement.stderr, /presence-only flag/);
  assert.equal(observed.posts, 0);
  await access(sessionPath);
  await access(approvalPath);

  const submitted = await runCli([
    'bridge', 'submit', url,
    '--action', operation.operation_id,
    '--input', '-',
    '--session-file', sessionPath,
    '--approval-file', approvalPath,
    '--approval-binding-digest', preparedValue.preview.approval_binding_digest,
    '--allow-unverified-write',
    ...common
  ], input, env);
  assert.equal(submitted.code, 0, submitted.stderr);
  const result = JSON.parse(submitted.stdout);
  assert.equal(result.receipt.dispatch, 'response_received');
  assert.equal(result.receipt.outcome, 'unverified');
  assert.equal(observed.posts, 1);
  assert.equal(observed.submitted.get('csrf'), 'fixed');
  assert.equal(observed.submitted.get('note'), 'hello from an agent');
  assert.match(observed.cookie, /sid=approved-account/);
  assert.ok(observed.authorization.every((value) => value === undefined));
  await access(sessionPath);
  await assert.rejects(access(approvalPath));
  assert.ok(result.session_state.generation > preparedValue.session_state.generation);
});

test('CLI rejects semantic form drift even when the wire field names are unchanged', async (t) => {
  const observed = { label: 'Enable feature', posts: 0 };
  const server = createServer((request, response) => {
    if (request.method === 'GET') {
      response.setHeader('content-type', 'text/html; charset=utf-8');
      response.end(`<form id="setting" action="/save" method="post"><label>${observed.label}<input name="value" required></label><button>Apply</button></form>`);
      return;
    }
    observed.posts += 1;
    response.end('unexpected');
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  t.after(() => new Promise((resolveClose) => server.close(resolveClose)));
  const temporary = await mkdtemp(join(tmpdir(), 'agentweb-cli-drift-'));
  const sessionPath = join(temporary, 'bridge-session.json');
  const approvalPath = join(temporary, 'bridge-approval.json');
  t.after(() => rm(temporary, { recursive: true, force: true }));
  const url = `http://127.0.0.1:${server.address().port}/form`;
  const common = ['--allow-private-network'];

  const inspected = await runCli(['bridge', 'inspect', url, ...common]);
  assert.equal(inspected.code, 0, inspected.stderr);
  const operation = JSON.parse(inspected.stdout).operations[0];
  const value = operation.fields.find((candidate) => candidate.wire_name === 'value');
  const input = JSON.stringify({ [value.field_id]: 'yes' });
  const prepared = await runCli([
    'bridge', 'prepare', url, '--action', operation.operation_id, '--input', '-',
    '--session-file', sessionPath, '--approval-file', approvalPath, ...common
  ], input);
  assert.equal(prepared.code, 0, prepared.stderr);
  const preview = JSON.parse(prepared.stdout).preview;

  observed.label = 'Delete account';
  const submitted = await runCli([
    'bridge', 'submit', url, '--action', operation.operation_id, '--input', '-',
    '--session-file', sessionPath,
    '--approval-file', approvalPath,
    '--approval-binding-digest', preview.approval_binding_digest,
    '--allow-unverified-write', ...common
  ], input);
  assert.equal(submitted.code, 5, submitted.stderr);
  assert.equal(JSON.parse(submitted.stderr).error.code, 'APPROVAL_BINDING_MISMATCH');
  assert.equal(observed.posts, 0);
  await access(sessionPath);
  await access(approvalPath);
});

test('CLI persists login response cookies for later authenticated forms and rejects copied approval replay', async (t) => {
  const observed = { loginPosts: 0, privateGets: 0, privatePosts: 0, privateCookies: [] };
  const server = createServer(async (request, response) => {
    if (request.method === 'GET' && request.url === '/login') {
      response.setHeader('content-type', 'text/html; charset=utf-8');
      response.end('<form id="login" action="/session" method="post"><input name="username" required><input name="password" type="password" required><button>Sign in</button></form>');
      return;
    }
    if (request.method === 'POST' && request.url === '/session') {
      observed.loginPosts += 1;
      request.resume();
      response.statusCode = 303;
      response.setHeader('set-cookie', 'session=logged-in; Path=/; HttpOnly; SameSite=Lax');
      response.setHeader('location', '/private');
      response.end();
      return;
    }
    if (request.method === 'GET' && request.url === '/private') {
      observed.privateGets += 1;
      observed.privateCookies.push(request.headers.cookie ?? '');
      if (!request.headers.cookie?.includes('session=logged-in')) {
        response.statusCode = 401;
        response.end('login required');
        return;
      }
      response.setHeader('content-type', 'text/html; charset=utf-8');
      response.end('<form id="private" action="/private/save" method="post"><input name="note" required><button>Save private note</button></form>');
      return;
    }
    if (request.method === 'POST' && request.url === '/private/save') {
      observed.privatePosts += 1;
      observed.privateCookies.push(request.headers.cookie ?? '');
      request.resume();
      response.end('saved');
      return;
    }
    response.statusCode = 404;
    response.end('missing');
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  t.after(() => new Promise((resolveClose) => server.close(resolveClose)));

  const origin = `http://127.0.0.1:${server.address().port}`;
  const common = ['--allow-private-network'];
  const temporary = await mkdtemp(join(tmpdir(), 'agentweb-cli-auth-'));
  const sessionPath = join(temporary, 'session.json');
  const approvalPath = join(temporary, 'approval.json');
  const copiedApprovalPath = join(temporary, 'copied-approval.json');
  t.after(() => rm(temporary, { recursive: true, force: true }));

  const loginInspection = await runCli(['bridge', 'inspect', `${origin}/login`, ...common]);
  assert.equal(loginInspection.code, 0, loginInspection.stderr);
  const loginOperation = JSON.parse(loginInspection.stdout).operations[0];
  const loginInput = Object.fromEntries(loginOperation.fields.map((candidate) => [
    candidate.field_id,
    candidate.wire_name === 'password' ? 'correct horse battery staple' : 'alice'
  ]));
  const loginPrepared = await runCli([
    'bridge', 'prepare', `${origin}/login`, '--action', loginOperation.operation_id,
    '--input', '-', '--session-file', sessionPath, '--approval-file', approvalPath, ...common
  ], JSON.stringify(loginInput));
  assert.equal(loginPrepared.code, 0, loginPrepared.stderr);
  const loginPreview = JSON.parse(loginPrepared.stdout).preview;
  await copyFile(approvalPath, copiedApprovalPath);

  const loginSubmitted = await runCli([
    'bridge', 'submit', `${origin}/login`, '--action', loginOperation.operation_id,
    '--input', '-', '--session-file', sessionPath, '--approval-file', approvalPath,
    '--approval-binding-digest', loginPreview.approval_binding_digest,
    '--allow-unverified-write', ...common
  ], JSON.stringify(loginInput));
  assert.equal(loginSubmitted.code, 0, loginSubmitted.stderr);
  assert.equal(JSON.parse(loginSubmitted.stdout).receipt.outcome, 'unverified');
  assert.equal(observed.loginPosts, 1);
  await access(sessionPath);
  await assert.rejects(access(approvalPath));

  const replay = await runCli([
    'bridge', 'submit', `${origin}/login`, '--action', loginOperation.operation_id,
    '--input', '-', '--session-file', sessionPath, '--approval-file', copiedApprovalPath,
    '--approval-binding-digest', loginPreview.approval_binding_digest,
    '--allow-unverified-write', ...common
  ], JSON.stringify(loginInput));
  assert.equal(replay.code, 5, replay.stderr);
  assert.equal(JSON.parse(replay.stderr).error.code, 'BRIDGE_SESSION_CONFLICT');
  assert.equal(observed.loginPosts, 1);

  const privateInspection = await runCli([
    'bridge', 'inspect', `${origin}/private`, '--session-file', sessionPath, ...common
  ]);
  assert.equal(privateInspection.code, 0, privateInspection.stderr);
  const privateOperation = JSON.parse(privateInspection.stdout).operations[0];
  assert.ok(privateOperation);
  const note = privateOperation.fields.find((candidate) => candidate.wire_name === 'note');
  const privateInput = { [note.field_id]: 'authenticated continuation works' };

  const privatePrepared = await runCli([
    'bridge', 'prepare', `${origin}/private`, '--action', privateOperation.operation_id,
    '--input', '-', '--session-file', sessionPath, '--approval-file', approvalPath, ...common
  ], JSON.stringify(privateInput));
  assert.equal(privatePrepared.code, 0, privatePrepared.stderr);
  const privatePreview = JSON.parse(privatePrepared.stdout).preview;
  const privateSubmitted = await runCli([
    'bridge', 'submit', `${origin}/private`, '--action', privateOperation.operation_id,
    '--input', '-', '--session-file', sessionPath, '--approval-file', approvalPath,
    '--approval-binding-digest', privatePreview.approval_binding_digest,
    '--allow-unverified-write', ...common
  ], JSON.stringify(privateInput));
  assert.equal(privateSubmitted.code, 0, privateSubmitted.stderr);
  assert.equal(observed.privatePosts, 1);
  assert.ok(observed.privateCookies.every((value) => value.includes('session=logged-in')));
  assert.equal(privateInspection.stdout.includes('logged-in'), false);
  assert.equal(privateSubmitted.stdout.includes('logged-in'), false);
});

test('CLI preserves verifiable ambiguous-outcome evidence when lock cleanup also fails', async (t) => {
  let sessionPath;
  let posts = 0;
  const server = createServer(async (request, response) => {
    if (request.method === 'GET' && request.url === '/form') {
      response.setHeader('content-type', 'text/html; charset=utf-8');
      response.end('<form action="/share/LEAKME-CAPABILITY?code=QUERY-LEAKME" method="post"><input name="value"><button>Send</button></form>');
      return;
    }
    if (request.method === 'POST' && request.url.startsWith('/share/')) {
      posts += 1;
      request.resume();
      const lockPath = `${sessionPath}.lock`;
      await rm(lockPath, { recursive: true, force: true });
      await mkdir(lockPath, { mode: 0o700 });
      await writeFile(join(lockPath, 'owner-replacement.json'), '{}\n', { mode: 0o600 });
      request.socket.destroy();
      return;
    }
    response.statusCode = 404;
    response.end('missing');
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  t.after(() => new Promise((resolveClose) => server.close(resolveClose)));

  const temporary = await mkdtemp(join(tmpdir(), 'agentweb-cli-ambiguous-'));
  sessionPath = join(temporary, 'session.json');
  const approvalPath = join(temporary, 'approval.json');
  t.after(() => rm(temporary, { recursive: true, force: true }));
  const url = `http://127.0.0.1:${server.address().port}/form`;
  const common = ['--allow-private-network'];

  const inspected = await runCli(['bridge', 'inspect', url, ...common]);
  assert.equal(inspected.code, 0, inspected.stderr);
  const operation = JSON.parse(inspected.stdout).operations[0];
  const value = operation.fields.find((candidate) => candidate.wire_name === 'value');
  const input = JSON.stringify({ [value.field_id]: 'approved' });
  const prepared = await runCli([
    'bridge', 'prepare', url, '--action', operation.operation_id, '--input', '-',
    '--session-file', sessionPath, '--approval-file', approvalPath, ...common
  ], input);
  assert.equal(prepared.code, 0, prepared.stderr);
  const preview = JSON.parse(prepared.stdout).preview;

  const submitted = await runCli([
    'bridge', 'submit', url, '--action', operation.operation_id, '--input', '-',
    '--session-file', sessionPath, '--approval-file', approvalPath,
    '--approval-binding-digest', preview.approval_binding_digest,
    '--allow-unverified-write', ...common
  ], input);
  assert.equal(submitted.code, 2);
  const problem = JSON.parse(submitted.stderr);
  assert.equal(problem.error.code, 'COMMIT_OUTCOME_UNKNOWN');
  assert.equal(problem.error.required_action.retry_request, false);
  assert.equal(problem.error.required_action.cleanup_warning.code, 'BRIDGE_SESSION_PERSISTENCE_FAILED');
  assert.equal(problem.attempt_receipt.outcome, 'unknown');
  const { receipt_digest: receiptDigest, ...receiptBody } = problem.attempt_receipt;
  assert.equal(canonicalSha256(receiptBody), receiptDigest);
  assert.equal(
    problem.attempt_receipt.$schema,
    'https://raw.githubusercontent.com/avasis-ai/agent-native-web/main/schemas/http-form-bridge/attempt-receipt-0.1-draft.json'
  );
  assert.equal(submitted.stderr.includes('LEAKME-CAPABILITY'), false);
  assert.equal(submitted.stderr.includes('QUERY-LEAKME'), false);
  assert.equal(posts, 1);
  await access(`${sessionPath}.lock`);
});

test('CLI refuses a cross-origin form navigation before persisting foreign-origin cookies', async (t) => {
  const observed = { entryGets: 0, targetGets: 0, targetPosts: 0 };
  const target = createServer((request, response) => {
    if (request.method === 'GET') {
      observed.targetGets += 1;
      response.setHeader('set-cookie', 'foreign=credential; Path=/; HttpOnly; SameSite=Lax');
      response.setHeader('content-type', 'text/html; charset=utf-8');
      response.end('<form method="post" action="/save"><input name="value"><button>Save</button></form>');
      return;
    }
    observed.targetPosts += 1;
    response.end('unexpected');
  });
  target.listen(0, '127.0.0.1');
  await once(target, 'listening');
  t.after(() => new Promise((resolveClose) => target.close(resolveClose)));
  const targetOrigin = `http://127.0.0.1:${target.address().port}`;

  const entry = createServer((_request, response) => {
    observed.entryGets += 1;
    response.statusCode = 302;
    response.setHeader('location', `${targetOrigin}/form`);
    response.end();
  });
  entry.listen(0, '127.0.0.1');
  await once(entry, 'listening');
  t.after(() => new Promise((resolveClose) => entry.close(resolveClose)));
  const entryOrigin = `http://127.0.0.1:${entry.address().port}`;

  const temporary = await mkdtemp(join(tmpdir(), 'agentweb-cli-cross-origin-'));
  const sessionPath = join(temporary, 'session.json');
  t.after(() => rm(temporary, { recursive: true, force: true }));
  const inspected = await runCli([
    'bridge', 'inspect', `${entryOrigin}/start`,
    '--session-file', sessionPath,
    '--allow-origin', `${entryOrigin},${targetOrigin}`,
    '--allow-private-network'
  ]);
  assert.equal(inspected.code, 2, inspected.stderr);
  assert.equal(JSON.parse(inspected.stderr).error.code, 'REDIRECT_POLICY_VIOLATION');
  assert.equal(observed.entryGets, 1);
  assert.equal(observed.targetGets, 0);
  assert.equal(observed.targetPosts, 0);
  await assert.rejects(access(sessionPath));
});

test('CLI preserves a successful-response receipt when only lock cleanup fails', async (t) => {
  let sessionPath;
  let posts = 0;
  const server = createServer(async (request, response) => {
    if (request.method === 'GET') {
      response.setHeader('content-type', 'text/html; charset=utf-8');
      response.end('<form method="post" action="/save"><input name="value"><button>Save</button></form>');
      return;
    }
    posts += 1;
    request.resume();
    const lockPath = `${sessionPath}.lock`;
    await rm(lockPath, { recursive: true, force: true });
    await mkdir(lockPath, { mode: 0o700 });
    await writeFile(join(lockPath, 'owner-replacement.json'), '{}\n', { mode: 0o600 });
    response.setHeader('content-type', 'text/plain');
    response.end('saved');
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  t.after(() => new Promise((resolveClose) => server.close(resolveClose)));

  const temporary = await mkdtemp(join(tmpdir(), 'agentweb-cli-cleanup-receipt-'));
  sessionPath = join(temporary, 'session.json');
  const approvalPath = join(temporary, 'approval.json');
  t.after(() => rm(temporary, { recursive: true, force: true }));
  const url = `http://127.0.0.1:${server.address().port}/form`;
  const common = ['--allow-private-network'];
  const inspected = await runCli(['bridge', 'inspect', url, ...common]);
  assert.equal(inspected.code, 0, inspected.stderr);
  const operation = JSON.parse(inspected.stdout).operations[0];
  const value = operation.fields[0];
  const input = JSON.stringify({ [value.field_id]: 'approved' });
  const prepared = await runCli([
    'bridge', 'prepare', url, '--action', operation.operation_id, '--input', '-',
    '--session-file', sessionPath, '--approval-file', approvalPath, ...common
  ], input);
  assert.equal(prepared.code, 0, prepared.stderr);
  const preview = JSON.parse(prepared.stdout).preview;

  const submitted = await runCli([
    'bridge', 'submit', url, '--action', operation.operation_id, '--input', '-',
    '--session-file', sessionPath, '--approval-file', approvalPath,
    '--approval-binding-digest', preview.approval_binding_digest,
    '--allow-unverified-write', ...common
  ], input);
  assert.equal(submitted.code, 2);
  const problem = JSON.parse(submitted.stderr);
  assert.equal(problem.error.code, 'BRIDGE_SESSION_PERSISTENCE_FAILED');
  assert.equal(problem.attempt_receipt.dispatch, 'response_received');
  assert.equal(problem.attempt_receipt.outcome, 'unverified');
  const { receipt_digest: receiptDigest, ...receiptBody } = problem.attempt_receipt;
  assert.equal(canonicalSha256(receiptBody), receiptDigest);
  assert.equal(posts, 1);
  await access(`${sessionPath}.lock`);
});
