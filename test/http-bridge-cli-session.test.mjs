import test from 'node:test';
import assert from 'node:assert/strict';
import { access, mkdtemp, rm, stat, symlink } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  acquireBridgeSessionLock,
  loadBridgeSession,
  persistBridgeSession
} from '../src/http-bridge/cli-session-store.mjs';
import { BridgeError } from '../src/http-bridge/errors.mjs';

test('private bridge session state is exact-origin, owner-only, and rejects symlinks', async (t) => {
  const directory = await mkdtemp(join(tmpdir(), 'agentweb-session-store-'));
  const sessionPath = join(directory, 'session.json');
  t.after(() => rm(directory, { recursive: true, force: true }));

  let session = await loadBridgeSession(sessionPath, 'https://one.example/login', { allowCreate: true });
  await session.cookieJar.setCookie('sid=private; Path=/; Secure; HttpOnly', 'https://one.example/login');
  session = await persistBridgeSession(sessionPath, session, session.cookieJar);
  assert.equal((await stat(sessionPath)).mode & 0o077, 0);

  const restored = await loadBridgeSession(sessionPath, 'https://one.example/account');
  assert.match(await restored.cookieJar.getCookieString('https://one.example/account'), /sid=private/);
  await assert.rejects(
    loadBridgeSession(sessionPath, 'https://two.example/account'),
    (error) => error instanceof BridgeError && error.code === 'CREDENTIAL_BINDING_MISMATCH'
  );

  const linkPath = join(directory, 'session-link.json');
  await symlink(sessionPath, linkPath);
  await assert.rejects(
    loadBridgeSession(linkPath, 'https://one.example/account'),
    (error) => error instanceof BridgeError && error.code === 'INVALID_BRIDGE_DATA'
  );
});

test('session lock serializes commands without deleting another process lock', async (t) => {
  const directory = await mkdtemp(join(tmpdir(), 'agentweb-session-lock-'));
  const sessionPath = join(directory, 'session.json');
  const lockPath = `${sessionPath}.lock`;
  t.after(() => rm(directory, { recursive: true, force: true }));

  const releaseFirst = await acquireBridgeSessionLock(sessionPath);
  await assert.rejects(
    acquireBridgeSessionLock(sessionPath),
    (error) => error instanceof BridgeError && error.code === 'BRIDGE_SESSION_CONFLICT'
  );
  await access(lockPath);
  await rm(lockPath, { recursive: true });
  const releaseSecond = await acquireBridgeSessionLock(sessionPath);
  await assert.rejects(
    releaseFirst(),
    (error) => error instanceof BridgeError && error.code === 'BRIDGE_SESSION_PERSISTENCE_FAILED'
  );
  await access(lockPath); // A replacement owner lock must survive first-owner cleanup.
  await releaseSecond();
  await assert.rejects(access(lockPath));
});
