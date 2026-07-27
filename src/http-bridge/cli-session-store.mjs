import { constants } from 'node:fs';
import {
  link,
  mkdir,
  open,
  rename,
  rmdir,
  unlink
} from 'node:fs/promises';
import { basename, dirname, join } from 'node:path';
import { randomBytes, randomUUID } from 'node:crypto';
import { CookieJar } from 'tough-cookie';
import { BRIDGE_REFUSAL_CODES, BridgeError } from './errors.mjs';

const SESSION_VERSION = 2;
const APPROVAL_VERSION = 1;
const MAX_PRIVATE_FILE_BYTES = 1024 * 1024;
const SESSION_TTL_MS = 8 * 60 * 60 * 1000;
const APPROVAL_TTL_LIMIT_MS = 60_000;
const PRIVATE_MODE_MASK = 0o077;

function storeError(code, detail, { cause, requiredAction } = {}) {
  return new BridgeError(code, {
    detail,
    stage: 'cli_session',
    cause,
    requiredAction
  });
}

function validatePath(path, label) {
  if (typeof path !== 'string' || path.length === 0 || path.includes('\0')) {
    throw storeError(BRIDGE_REFUSAL_CODES.INVALID_BRIDGE_DATA, `${label} requires a filesystem path.`);
  }
  return path;
}

function serialize(value, label) {
  let data;
  try {
    data = `${JSON.stringify(value)}\n`;
  } catch (cause) {
    throw storeError(BRIDGE_REFUSAL_CODES.INVALID_BRIDGE_DATA, `${label} is not serializable.`, { cause });
  }
  if (Buffer.byteLength(data) > MAX_PRIVATE_FILE_BYTES) {
    throw storeError(BRIDGE_REFUSAL_CODES.INVALID_BRIDGE_DATA, `${label} exceeds its size limit.`);
  }
  return data;
}

async function syncDirectory(path) {
  let handle;
  try {
    handle = await open(dirname(path), constants.O_RDONLY);
    await handle.sync();
  } catch (cause) {
    if (!['EINVAL', 'EBADF', 'ENOTSUP'].includes(cause?.code)) throw cause;
  } finally {
    await handle?.close();
  }
}

async function readPrivateJson(path, label) {
  validatePath(path, label);
  let handle;
  try {
    handle = await open(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
    const metadata = await handle.stat();
    if (!metadata.isFile()) throw new Error('not a regular file');
    if ((metadata.mode & PRIVATE_MODE_MASK) !== 0) throw new Error('permissions are broader than 0600');
    if (typeof process.getuid === 'function' && metadata.uid !== process.getuid()) throw new Error('owner mismatch');
    if (metadata.size < 2 || metadata.size > MAX_PRIVATE_FILE_BYTES) throw new Error('file size is invalid');
    return JSON.parse(await handle.readFile('utf8'));
  } catch (cause) {
    throw storeError(
      BRIDGE_REFUSAL_CODES.INVALID_BRIDGE_DATA,
      `${label} must be a regular, owner-only file created by agentweb.`,
      { cause }
    );
  } finally {
    await handle?.close();
  }
}

async function pathExists(path) {
  let handle;
  try {
    handle = await open(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
    return true;
  } catch (cause) {
    if (cause?.code === 'ENOENT') return false;
    throw cause;
  } finally {
    await handle?.close();
  }
}

async function writeNewPrivateJson(path, value, label) {
  validatePath(path, label);
  const data = serialize(value, label);
  const temporary = join(dirname(path), `.${basename(path)}.${randomUUID()}.tmp`);
  let handle;
  try {
    handle = await open(temporary, 'wx', 0o600);
    await handle.writeFile(data, 'utf8');
    await handle.sync();
    await handle.close();
    handle = null;
    await link(temporary, path);
    await unlink(temporary);
    await syncDirectory(path);
  } catch (cause) {
    await handle?.close().catch(() => {});
    await unlink(temporary).catch(() => {});
    throw storeError(
      BRIDGE_REFUSAL_CODES.BRIDGE_SESSION_PERSISTENCE_FAILED,
      `${label} could not be created at a new path on the private local filesystem.`,
      { cause }
    );
  }
}

async function replacePrivateJson(path, value, label) {
  const data = serialize(value, label);
  const temporary = join(dirname(path), `.${basename(path)}.${randomUUID()}.tmp`);
  let handle;
  try {
    handle = await open(temporary, 'wx', 0o600);
    await handle.writeFile(data, 'utf8');
    await handle.sync();
    await handle.close();
    handle = null;
    await rename(temporary, path);
    await syncDirectory(path);
  } catch (cause) {
    await handle?.close().catch(() => {});
    await unlink(temporary).catch(() => {});
    throw storeError(
      BRIDGE_REFUSAL_CODES.BRIDGE_SESSION_PERSISTENCE_FAILED,
      `${label} could not be atomically updated.`,
      { cause }
    );
  }
}

function exactOrigin(value, label) {
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    throw storeError(BRIDGE_REFUSAL_CODES.INVALID_BRIDGE_DATA, `${label} has an invalid origin.`);
  }
  if (parsed.origin !== value || parsed.username || parsed.password) {
    throw storeError(BRIDGE_REFUSAL_CODES.INVALID_BRIDGE_DATA, `${label} must contain one exact origin.`);
  }
  return parsed.origin;
}

function validInstant(value, label) {
  const timestamp = Date.parse(value);
  if (!Number.isFinite(timestamp)) {
    throw storeError(BRIDGE_REFUSAL_CODES.INVALID_BRIDGE_DATA, `${label} has an invalid timestamp.`);
  }
  return timestamp;
}

function validateSessionRecord(record, expectedOrigin) {
  if (!record || record.version !== SESSION_VERSION || record.kind !== 'bridge_session'
      || !/^[a-f0-9]{32}$/.test(record.session_id ?? '')
      || !Number.isSafeInteger(record.generation) || record.generation < 0
      || typeof record.created_at !== 'string' || typeof record.updated_at !== 'string'
      || typeof record.expires_at !== 'string'
      || !record.cookie_jar || typeof record.cookie_jar !== 'object') {
    throw storeError(BRIDGE_REFUSAL_CODES.INVALID_BRIDGE_DATA, 'The bridge session file has an invalid schema.');
  }
  const origin = exactOrigin(record.origin, 'The bridge session file');
  if (origin !== expectedOrigin) {
    throw storeError(
      BRIDGE_REFUSAL_CODES.CREDENTIAL_BINDING_MISMATCH,
      'The bridge session is bound to a different exact origin.'
    );
  }
  validInstant(record.created_at, 'The bridge session file');
  validInstant(record.updated_at, 'The bridge session file');
  const expiresAt = validInstant(record.expires_at, 'The bridge session file');
  if (expiresAt <= Date.now()) {
    throw storeError(BRIDGE_REFUSAL_CODES.AUTH_SESSION_EXPIRED, 'The bridge session file expired; authenticate again.');
  }
  if (expiresAt - Date.now() > SESSION_TTL_MS + 60_000) {
    throw storeError(BRIDGE_REFUSAL_CODES.INVALID_BRIDGE_DATA, 'The bridge session expiry exceeds the safety window.');
  }
  let cookieJar;
  try {
    cookieJar = CookieJar.deserializeSync(record.cookie_jar);
  } catch (cause) {
    throw storeError(BRIDGE_REFUSAL_CODES.INVALID_BRIDGE_DATA, 'The bridge session contains an invalid cookie jar.', { cause });
  }
  return { record, cookieJar, existed: true };
}

function newSession(origin) {
  const now = new Date();
  const cookieJar = new CookieJar();
  return {
    record: {
      version: SESSION_VERSION,
      kind: 'bridge_session',
      session_id: randomBytes(16).toString('hex'),
      generation: 0,
      origin,
      created_at: now.toISOString(),
      updated_at: now.toISOString(),
      expires_at: new Date(now.getTime() + SESSION_TTL_MS).toISOString(),
      cookie_jar: cookieJar.serializeSync()
    },
    cookieJar,
    existed: false
  };
}

export async function loadBridgeSession(path, origin, { allowCreate = false } = {}) {
  validatePath(path, '--session-file');
  const expectedOrigin = new URL(origin).origin;
  try {
    return validateSessionRecord(await readPrivateJson(path, 'The bridge session file'), expectedOrigin);
  } catch (error) {
    if (allowCreate && error?.cause?.code === 'ENOENT') return newSession(expectedOrigin);
    throw error;
  }
}

export async function persistBridgeSession(path, current, cookieJar) {
  if (!current?.record || !(cookieJar instanceof CookieJar)) {
    throw storeError(BRIDGE_REFUSAL_CODES.INVALID_BRIDGE_DATA, 'Bridge session persistence received invalid state.');
  }
  if (current.existed) {
    const disk = await readPrivateJson(path, 'The bridge session file');
    if (disk.session_id !== current.record.session_id || disk.generation !== current.record.generation) {
      throw storeError(
        BRIDGE_REFUSAL_CODES.BRIDGE_SESSION_CONFLICT,
        'The bridge session changed in another process; no write authority was consumed.'
      );
    }
  } else if (await pathExists(path)) {
    throw storeError(BRIDGE_REFUSAL_CODES.BRIDGE_SESSION_CONFLICT, 'The bridge session path was created by another process.');
  }
  const now = new Date();
  const record = {
    ...current.record,
    generation: current.record.generation + 1,
    updated_at: now.toISOString(),
    expires_at: new Date(now.getTime() + SESSION_TTL_MS).toISOString(),
    cookie_jar: cookieJar.serializeSync()
  };
  if (current.existed) await replacePrivateJson(path, record, 'The bridge session file');
  else await writeNewPrivateJson(path, record, 'The bridge session file');
  return { record, cookieJar, existed: true };
}

function approvalKey(record) {
  if (!/^[A-Za-z0-9+/]{43}=$/.test(record.digest_key_base64 ?? '')) {
    throw storeError(BRIDGE_REFUSAL_CODES.INVALID_BRIDGE_DATA, 'The bridge approval file has an invalid private key encoding.');
  }
  const key = Buffer.from(record.digest_key_base64, 'base64');
  if (key.byteLength !== 32) {
    throw storeError(BRIDGE_REFUSAL_CODES.INVALID_BRIDGE_DATA, 'The bridge approval file has an invalid private key.');
  }
  return key;
}

export async function readBridgeApproval(path) {
  const record = await readPrivateJson(path, 'The one-shot bridge approval file');
  if (!record || record.version !== APPROVAL_VERSION || record.kind !== 'bridge_approval'
      || !/^[a-f0-9]{32}$/.test(record.approval_id ?? '')
      || !/^[a-f0-9]{32}$/.test(record.session_id ?? '')
      || !Number.isSafeInteger(record.session_generation) || record.session_generation < 1
      || typeof record.url !== 'string' || typeof record.action_id !== 'string'
      || typeof record.approval_binding_digest !== 'string' || typeof record.expires_at !== 'string') {
    throw storeError(BRIDGE_REFUSAL_CODES.INVALID_BRIDGE_DATA, 'The bridge approval file has an invalid schema.');
  }
  const expiresAt = validInstant(record.expires_at, 'The bridge approval file');
  if (expiresAt <= Date.now()) {
    throw storeError(BRIDGE_REFUSAL_CODES.PREVIEW_STALE, 'The one-shot bridge approval expired; prepare and approve a new request.');
  }
  if (expiresAt - Date.now() > APPROVAL_TTL_LIMIT_MS) {
    throw storeError(BRIDGE_REFUSAL_CODES.INVALID_BRIDGE_DATA, 'The bridge approval expiry exceeds the safety window.');
  }
  return { record, digestKey: approvalKey(record) };
}

export async function writeBridgeApproval(path, {
  session,
  url,
  actionId,
  approvalBindingDigest,
  expiresAt,
  digestKey
}) {
  const record = {
    version: APPROVAL_VERSION,
    kind: 'bridge_approval',
    approval_id: randomBytes(16).toString('hex'),
    session_id: session.record.session_id,
    session_generation: session.record.generation,
    url: new URL(url).href,
    action_id: actionId,
    approval_binding_digest: approvalBindingDigest,
    expires_at: new Date(expiresAt).toISOString(),
    digest_key_base64: Buffer.from(digestKey).toString('base64')
  };
  await writeNewPrivateJson(path, record, 'The one-shot bridge approval file');
  return record;
}

export async function consumeBridgeApproval(path) {
  try {
    await unlink(path);
    await syncDirectory(path);
  } catch (cause) {
    throw storeError(
      BRIDGE_REFUSAL_CODES.BRIDGE_SESSION_PERSISTENCE_FAILED,
      'The one-shot bridge approval could not be consumed; no request was sent.',
      { cause }
    );
  }
}

export async function acquireBridgeSessionLock(path) {
  validatePath(path, '--session-file');
  const lockPath = `${path}.lock`;
  const lockId = randomBytes(16).toString('hex');
  const ownerPath = join(lockPath, `owner-${lockId}.json`);
  let handle;
  let directoryCreated = false;
  try {
    await mkdir(lockPath, { mode: 0o700 });
    directoryCreated = true;
    handle = await open(ownerPath, 'wx', 0o600);
    await handle.writeFile(`${JSON.stringify({ lock_id: lockId, pid: process.pid, created_at: new Date().toISOString() })}\n`, 'utf8');
    await handle.sync();
    await handle.close();
    handle = null;
    await syncDirectory(ownerPath);
  } catch (cause) {
    await handle?.close().catch(() => {});
    if (directoryCreated) {
      await unlink(ownerPath).catch(() => {});
      await rmdir(lockPath).catch(() => {});
    }
    throw storeError(
      BRIDGE_REFUSAL_CODES.BRIDGE_SESSION_CONFLICT,
      'The bridge session is already in use by another process. A stale lock directory must be removed only after confirming no command is active.',
      { cause }
    );
  }
  let released = false;
  return async () => {
    if (released) return;
    released = true;
    try {
      // The unguessable owner entry prevents this process from deleting a
      // replacement lock created after its own directory was removed.
      await unlink(ownerPath);
      await rmdir(lockPath);
      await syncDirectory(lockPath);
    } catch (cause) {
      throw storeError(BRIDGE_REFUSAL_CODES.BRIDGE_SESSION_PERSISTENCE_FAILED, 'The bridge session lock could not be released.', { cause });
    }
  };
}

export function assertApprovalMatchesSession(approval, session, url, actionId) {
  if (approval.record.session_id !== session.record.session_id
      || approval.record.session_generation !== session.record.generation
      || new URL(approval.record.url).href !== new URL(url).href
      || approval.record.action_id !== actionId) {
    throw storeError(
      BRIDGE_REFUSAL_CODES.BRIDGE_SESSION_CONFLICT,
      'The one-shot approval does not match the live session generation, URL, or form action.'
    );
  }
}
