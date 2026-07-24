import { createHash, randomUUID, timingSafeEqual } from 'node:crypto';
import { isDeepStrictEqual } from 'node:util';

export class HttpError extends Error {
  constructor(status, code, message, details = undefined) {
    super(message);
    this.name = 'HttpError';
    this.status = status;
    this.code = code;
    this.details = details;
  }
}

export function jsonDigest(value) {
  return createHash('sha256').update(stableJson(value)).digest('hex');
}

export function stableJson(value) {
  if (Array.isArray(value)) return `[${value.map(stableJson).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableJson(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

export function newId(prefix) {
  return `${prefix}_${randomUUID().replaceAll('-', '')}`;
}

export function clone(value) {
  return structuredClone(value);
}

export function assertObject(value, label = 'body') {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new HttpError(400, 'INVALID_ARGUMENT', `${label} must be a JSON object`);
  }
  return value;
}

export function integer(value, label, { min = Number.MIN_SAFE_INTEGER, max = Number.MAX_SAFE_INTEGER } = {}) {
  if (!Number.isInteger(value) || value < min || value > max) {
    throw new HttpError(400, 'INVALID_ARGUMENT', `${label} must be an integer between ${min} and ${max}`);
  }
  return value;
}

export async function readJson(request, maxBytes = 64 * 1024) {
  const chunks = [];
  let size = 0;
  for await (const chunk of request) {
    size += chunk.length;
    if (size > maxBytes) throw new HttpError(413, 'BODY_TOO_LARGE', `Request body exceeds ${maxBytes} bytes`);
    chunks.push(chunk);
  }
  const raw = Buffer.concat(chunks).toString('utf8');
  if (!raw) return {};
  try {
    return assertObject(JSON.parse(raw));
  } catch (error) {
    if (error instanceof HttpError) throw error;
    throw new HttpError(400, 'INVALID_JSON', 'Request body is not valid JSON');
  }
}

export function sendJson(response, status, value, extraHeaders = {}) {
  const body = JSON.stringify(value, null, 2);
  response.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'content-length': Buffer.byteLength(body),
    ...extraHeaders
  });
  response.end(body);
}

export function sendText(response, status, body, contentType = 'text/plain; charset=utf-8', extraHeaders = {}) {
  response.writeHead(status, {
    'content-type': contentType,
    'content-length': Buffer.byteLength(body),
    ...extraHeaders
  });
  response.end(body);
}

export function requestOrigin(request) {
  const forwardedProto = request.headers['x-forwarded-proto'];
  const proto = typeof forwardedProto === 'string' ? forwardedProto.split(',')[0].trim() : 'http';
  const host = request.headers.host ?? '127.0.0.1';
  return `${proto}://${host}`;
}

export function bearerPrincipal(request, configuredToken) {
  const header = request.headers.authorization;
  if (typeof header !== 'string' || !header.startsWith('Bearer ')) {
    throw new HttpError(401, 'AUTH_REQUIRED', 'A bearer token is required');
  }
  const supplied = Buffer.from(header.slice(7));
  const expected = Buffer.from(configuredToken);
  if (supplied.length !== expected.length || !timingSafeEqual(supplied, expected)) {
    throw new HttpError(401, 'INVALID_TOKEN', 'The bearer token is invalid');
  }
  return {
    subject: 'demo-user',
    client_id: 'demo-agent-client',
    scopes: ['catalog:read', 'cart:write', 'checkout:preview', 'checkout:commit']
  };
}

export function escapeHtml(value) {
  return String(value)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#039;');
}

function pointerToken(value) {
  return String(value).replaceAll('~', '~0').replaceAll('/', '~1');
}

export function jsonPatch(before, after, path = '') {
  if (Object.is(before, after) || isDeepStrictEqual(before, after)) return [];
  if (Array.isArray(before) || Array.isArray(after)) {
    return [{ op: before === undefined ? 'add' : after === undefined ? 'remove' : 'replace', path: path || '/', ...(after === undefined ? {} : { value: clone(after) }) }];
  }
  if (before && after && typeof before === 'object' && typeof after === 'object') {
    const patches = [];
    const keys = new Set([...Object.keys(before), ...Object.keys(after)]);
    for (const key of [...keys].sort()) {
      const childPath = `${path}/${pointerToken(key)}`;
      if (!(key in after)) patches.push({ op: 'remove', path: childPath });
      else if (!(key in before)) patches.push({ op: 'add', path: childPath, value: clone(after[key]) });
      else patches.push(...jsonPatch(before[key], after[key], childPath));
    }
    return patches;
  }
  return [{ op: before === undefined ? 'add' : after === undefined ? 'remove' : 'replace', path: path || '/', ...(after === undefined ? {} : { value: clone(after) }) }];
}

export function errorEnvelope(error, requestId) {
  if (error instanceof HttpError) {
    return {
      status: error.status,
      body: { error: { code: error.code, message: error.message, ...(error.details === undefined ? {} : { details: error.details }) }, request_id: requestId }
    };
  }
  return {
    status: 500,
    body: { error: { code: 'INTERNAL_ERROR', message: 'The server could not complete the request' }, request_id: requestId }
  };
}
