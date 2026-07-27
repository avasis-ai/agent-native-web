import { createHash } from 'node:crypto';
import { Agent, Headers, fetch, interceptors } from 'undici';
import { CookieJar, getPublicSuffix } from 'tough-cookie';

import {
  BRIDGE_REFUSAL_CODES,
  BRIDGE_RETRY,
  BridgeError
} from './errors.mjs';
import { UrlPolicy, createUrlPolicy, redactUrl } from './url-policy.mjs';

const DEFAULT_MAX_REDIRECTS = 5;
const DEFAULT_MAX_REQUEST_BYTES = 64 * 1024;
const DEFAULT_MAX_RESPONSE_BYTES = 2 * 1024 * 1024;
const DEFAULT_REQUEST_TIMEOUT_MS = 30_000;
const DEFAULT_CONNECT_TIMEOUT_MS = 5_000;
const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);
const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);
const FORBIDDEN_METHODS = new Set(['CONNECT', 'TRACE']);
const SAME_SITE_CONTEXTS = new Set(['strict', 'lax', 'none']);
const CROSS_ORIGIN_ALLOWED_HEADERS = new Set(['accept', 'accept-language']);
const CALLER_FORBIDDEN_HEADERS = new Set([
  'connection',
  'content-length',
  'cookie',
  'forwarded',
  'host',
  'keep-alive',
  'proxy-authorization',
  'proxy-connection',
  'te',
  'trailer',
  'transfer-encoding',
  'upgrade',
  'x-forwarded-for',
  'x-forwarded-host',
  'x-forwarded-proto',
  'x-original-url',
  'x-rewrite-url'
]);

function invalid(detail, cause) {
  return new BridgeError(BRIDGE_REFUSAL_CODES.INVALID_BRIDGE_DATA, {
    detail,
    stage: 'network',
    cause
  });
}

function positiveInteger(value, label, { maximum = Number.MAX_SAFE_INTEGER } = {}) {
  if (!Number.isInteger(value) || value < 1 || value > maximum) {
    throw new TypeError(`${label} must be an integer between 1 and ${maximum}`);
  }
  return value;
}

function normalizeMethod(value) {
  const method = String(value ?? 'GET').toUpperCase();
  if (!/^[!#$%&'*+.^_`|~0-9A-Z-]+$/.test(method) || FORBIDDEN_METHODS.has(method)) {
    throw invalid(`Unsupported HTTP method: ${method}`);
  }
  return method;
}

function normalizeHeaders(value) {
  let headers;
  try {
    headers = new Headers(value);
  } catch (cause) {
    throw invalid('Request headers are invalid.', cause);
  }
  for (const name of CALLER_FORBIDDEN_HEADERS) {
    if (headers.has(name)) {
      throw invalid(`The HTTP bridge manages the ${name} header and does not accept it from callers.`);
    }
  }
  return headers;
}

function normalizeBody(body, method) {
  if (body === undefined || body === null) return null;
  if (method === 'GET' || method === 'HEAD') {
    throw invalid(`${method} requests cannot have a body.`);
  }
  if (typeof body === 'string') return body;
  if (body instanceof URLSearchParams) return new URLSearchParams(body);
  if (body instanceof ArrayBuffer) return new Uint8Array(body.slice(0));
  if (ArrayBuffer.isView(body)) {
    return new Uint8Array(body.buffer.slice(body.byteOffset, body.byteOffset + body.byteLength));
  }
  if (typeof Blob !== 'undefined' && body instanceof Blob) return body;
  if (typeof FormData !== 'undefined' && body instanceof FormData) {
    throw invalid('Generic FormData bodies are not accepted because their encoded size cannot be bounded before dispatch.');
  }
  throw invalid('Request bodies must be replayable strings, bytes, URLSearchParams, or Blob.');
}

function bodyByteLength(body) {
  if (body === null) return 0;
  if (typeof body === 'string') return Buffer.byteLength(body);
  if (body instanceof URLSearchParams) return Buffer.byteLength(body.toString());
  if (body instanceof Uint8Array) return body.byteLength;
  if (typeof Blob !== 'undefined' && body instanceof Blob) return body.size;
  throw invalid('The request body size could not be determined safely.');
}

function approximateRequestBytes(url, method, headers, body) {
  let total = Buffer.byteLength(`${method} ${url.pathname}${url.search} HTTP/1.1\r\n`);
  for (const [name, value] of headers) total += Buffer.byteLength(`${name}: ${value}\r\n`);
  return total + 2 + bodyByteLength(body);
}

function findBridgeError(error) {
  let current = error;
  for (let depth = 0; current && depth < 8; depth += 1) {
    if (current instanceof BridgeError) return current;
    current = current.cause;
  }
  return null;
}

function annotateDispatch(error, state, response) {
  if (error && typeof error === 'object' && Object.isExtensible(error)) {
    error.dispatchState = state;
    if (response) error.upstreamStatus = response.status;
  }
  return error;
}

function preDispatchFailure(error, timedOut) {
  const nested = findBridgeError(error);
  if (nested) return nested;
  const timeout = timedOut || error?.name === 'TimeoutError';
  return new BridgeError(BRIDGE_REFUSAL_CODES.BRIDGE_INTERNAL_ERROR, {
    title: timeout ? 'Upstream request timed out' : 'Upstream request failed',
    status: timeout ? 504 : 502,
    detail: timeout
      ? 'The request timed out before it was dispatched.'
      : 'The request could not be dispatched to the upstream origin.',
    stage: 'network',
    retryable: BRIDGE_RETRY.SAFE,
    cause: error
  });
}

function dispatchedFailure(error, { method, url, timedOut }) {
  const nested = findBridgeError(error);
  if (nested) return nested;
  if (!SAFE_METHODS.has(method)) {
    return new BridgeError(BRIDGE_REFUSAL_CODES.COMMIT_OUTCOME_UNKNOWN, {
      detail: `Transport failed after ${method} dispatch; the remote outcome is unknown and the request must not be retried blindly.`,
      stage: 'outcome',
      requiredAction: {
        kind: 'verify_outcome_before_retry',
        method,
        target: redactUrl(url)
      },
      cause: error
    });
  }
  const timeout = timedOut || error?.name === 'TimeoutError';
  return new BridgeError(BRIDGE_REFUSAL_CODES.BRIDGE_INTERNAL_ERROR, {
    title: timeout ? 'Upstream request timed out' : 'Upstream transport failed',
    status: timeout ? 504 : 502,
    detail: timeout
      ? 'The upstream request exceeded its time limit.'
      : 'The upstream connection failed.',
    stage: 'network',
    retryable: BRIDGE_RETRY.SAFE,
    cause: error
  });
}

function redirectViolation(error) {
  if (error instanceof BridgeError && error.code === BRIDGE_REFUSAL_CODES.REDIRECT_POLICY_VIOLATION) {
    return error;
  }
  return new BridgeError(BRIDGE_REFUSAL_CODES.REDIRECT_POLICY_VIOLATION, {
    detail: 'A redirect target failed the bridge URL or network policy.',
    stage: 'network',
    cause: error
  });
}

function transitionRedirect(status, method, body, headers) {
  const rewriteToGet = status === 303
    ? method !== 'HEAD'
    : (status === 301 || status === 302) && method === 'POST';
  if (!rewriteToGet) return { method, body, headers };

  const nextHeaders = new Headers(headers);
  for (const name of ['content-encoding', 'content-language', 'content-location', 'content-type']) {
    nextHeaders.delete(name);
  }
  return { method: 'GET', body: null, headers: nextHeaders };
}

function schemefulSite(value) {
  const url = value instanceof URL ? value : new URL(value);
  const hostname = url.hostname.startsWith('[') ? url.hostname.slice(1, -1) : url.hostname;
  let registrable;
  try {
    registrable = getPublicSuffix(hostname, {
      allowSpecialUseDomain: true,
      ignoreError: true
    });
  } catch {
    registrable = undefined;
  }
  return `${url.protocol}//${registrable ?? hostname}`;
}

function cookieContext(target, siteForCookies, initialMethodSafe, explicitContext) {
  if (explicitContext) return explicitContext;
  if (schemefulSite(target) === schemefulSite(siteForCookies)) return 'strict';
  return initialMethodSafe ? 'lax' : 'none';
}

function getSetCookieLines(headers) {
  if (typeof headers.getSetCookie === 'function') return headers.getSetCookie();
  return [];
}

async function storeResponseCookies(jar, response, url, sameSiteContext) {
  let accepted = 0;
  let rejected = 0;
  for (const line of getSetCookieLines(response.headers)) {
    try {
      const cookie = await jar.setCookie(line, url.href, {
        sameSiteContext,
        http: true,
        ignoreError: false
      });
      if (cookie) accepted += 1;
      else rejected += 1;
    } catch {
      // Browser behavior is to ignore malformed or policy-invalid Set-Cookie
      // fields. Tough Cookie's strict prefix checks ensure they are not stored.
      rejected += 1;
    }
  }
  return { accepted, rejected };
}

async function cookieHeader(jar, url, sameSiteContext) {
  try {
    return await jar.getCookieString(url.href, {
      sameSiteContext,
      http: true,
      expire: true
    });
  } catch (cause) {
    throw new BridgeError(BRIDGE_REFUSAL_CODES.BRIDGE_INTERNAL_ERROR, {
      detail: 'The cookie store could not prepare the request.',
      stage: 'network',
      cause
    });
  }
}

function credentialBindingRecord(url, sameSiteContext, cookies) {
  const core = {
    kind: 'cookie_header_binding',
    target_origin: url.origin,
    target_path: url.pathname,
    same_site_context: sameSiteContext,
    cookie_header_present: cookies.length > 0,
    cookie_header_digest: `sha256:${createHash('sha256').update(cookies).digest('hex')}`
  };
  return Object.freeze({
    ...core,
    binding_digest: `sha256:${createHash('sha256').update(JSON.stringify(core)).digest('hex')}`
  });
}

function cookieSite(value, fallback) {
  let siteUrl;
  try {
    siteUrl = value === undefined ? new URL(fallback.href) : new URL(value);
  } catch (cause) {
    throw invalid('siteForCookies must be an absolute URL.', cause);
  }
  if (!['http:', 'https:'].includes(siteUrl.protocol) || siteUrl.username || siteUrl.password) {
    throw invalid('siteForCookies must be an HTTP(S) URL without userinfo.');
  }
  return siteUrl;
}

async function cancelBody(response) {
  try {
    await response.body?.cancel();
  } catch {
    // Cancellation is best-effort; the request-scoped dispatcher is destroyed
    // in the surrounding finally block.
  }
}

async function readBoundedBody(response, maximumBytes) {
  const declared = response.headers.get('content-length');
  if (/^\d+$/.test(declared ?? '') && BigInt(declared) > BigInt(maximumBytes)) {
    await cancelBody(response);
    throw new BridgeError(BRIDGE_REFUSAL_CODES.BODY_LIMIT_EXCEEDED, {
      detail: `The upstream response exceeds the ${maximumBytes}-byte limit.`,
      stage: 'network'
    });
  }
  if (!response.body) return new Uint8Array();

  const reader = response.body.getReader();
  const chunks = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maximumBytes) {
        await reader.cancel();
        throw new BridgeError(BRIDGE_REFUSAL_CODES.BODY_LIMIT_EXCEEDED, {
          detail: `The upstream response exceeds the ${maximumBytes}-byte limit.`,
          stage: 'network'
        });
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }

  const body = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return body;
}

function publicHeaderEntries(headers) {
  const entries = [];
  for (const [name, value] of headers) {
    if (name.toLowerCase() !== 'set-cookie') entries.push(Object.freeze([name, value]));
  }
  return Object.freeze(entries);
}

function createPinnedDispatcher(resolution, {
  connectTimeoutMs,
  headersTimeoutMs,
  bodyTimeoutMs,
  pinTtlMs
}) {
  const agent = new Agent({
    connectTimeout: connectTimeoutMs,
    headersTimeout: headersTimeoutMs,
    bodyTimeout: bodyTimeoutMs,
    connections: 1,
    pipelining: 1,
    maxCachedSessions: 0,
    connect: { rejectUnauthorized: true }
  });

  // IP literals need no lookup. Hostnames use Undici's DNS interceptor, which
  // connects to the pinned IP while preserving the original Host header and
  // TLS SNI servername.
  if (resolution.url.hostname.startsWith('[') || resolution.url.hostname === resolution.hostname) {
    const isLiteral = resolution.url.hostname.startsWith('[')
      || /^\d{1,3}(?:\.\d{1,3}){3}$/.test(resolution.hostname);
    if (isLiteral) return agent;
  }

  const expectedHostname = resolution.hostname.toLowerCase();
  // Select one already-validated answer. Undici's dual-stack DNS mode retries
  // the other address family after connection failures; disabling it is
  // essential because a POST must never be dispatched twice implicitly.
  const selected = resolution.addresses[0];
  const pinned = [{
    address: selected.address,
    family: selected.family,
    ttl: pinTtlMs
  }];
  return agent.compose(interceptors.dns({
    dualStack: false,
    affinity: selected.family,
    maxItems: 1,
    maxTTL: pinTtlMs,
    lookup(origin, _options, callback) {
      if (origin.hostname.toLowerCase() !== expectedHostname) {
        callback(new BridgeError(BRIDGE_REFUSAL_CODES.DNS_REBINDING_DETECTED, {
          detail: 'Undici requested DNS for a hostname other than the validated target.',
          stage: 'network'
        }));
        return;
      }
      callback(null, pinned.map((record) => ({ ...record })));
    }
  }));
}

async function closeDispatcher(dispatcher) {
  if (!dispatcher) return;
  try {
    await dispatcher.close();
  } catch {
    try {
      dispatcher.destroy();
    } catch {
      // Nothing else can safely be done with a request-scoped dispatcher.
    }
  }
}

export class HttpSessionResponse {
  #body;
  #headerEntries;

  constructor({ status, statusText, url, method, headers, body, redirects, cookieStats }) {
    this.status = status;
    this.statusText = statusText;
    this.ok = status >= 200 && status <= 299;
    this.url = url;
    this.method = method;
    this.redirected = redirects.length > 0;
    this.redirects = Object.freeze(redirects.map((item) => Object.freeze({ ...item })));
    this.cookieStats = Object.freeze({ ...cookieStats });
    this.#headerEntries = publicHeaderEntries(headers);
    this.#body = Uint8Array.from(body);
    Object.freeze(this);
  }

  get headers() {
    return new Headers(this.#headerEntries);
  }

  get body() {
    return Uint8Array.from(this.#body);
  }

  async arrayBuffer() {
    const copy = Uint8Array.from(this.#body);
    return copy.buffer;
  }

  async bytes() {
    return Uint8Array.from(this.#body);
  }

  async text() {
    return new TextDecoder().decode(this.#body);
  }

  async json() {
    return JSON.parse(await this.text());
  }
}

export class HttpSession {
  constructor({
    urlPolicy,
    allowedOrigins = [],
    allowedPorts = [],
    allowPrivateNetworks = false,
    lookup,
    cookieJar,
    maxRedirects = DEFAULT_MAX_REDIRECTS,
    maxRequestBytes = DEFAULT_MAX_REQUEST_BYTES,
    maxResponseBytes = DEFAULT_MAX_RESPONSE_BYTES,
    requestTimeoutMs = DEFAULT_REQUEST_TIMEOUT_MS,
    connectTimeoutMs = DEFAULT_CONNECT_TIMEOUT_MS
  } = {}) {
    if (urlPolicy !== undefined
      && !(urlPolicy instanceof UrlPolicy)
      && (typeof urlPolicy?.validate !== 'function' || typeof urlPolicy?.resolve !== 'function')) {
      throw new TypeError('urlPolicy must expose validate() and resolve()');
    }
    if (!Number.isInteger(maxRedirects) || maxRedirects < 0 || maxRedirects > DEFAULT_MAX_REDIRECTS) {
      throw new TypeError(`maxRedirects must be an integer between 0 and ${DEFAULT_MAX_REDIRECTS}`);
    }
    const normalizedMaxRequestBytes = positiveInteger(maxRequestBytes, 'maxRequestBytes');
    const normalizedMaxResponseBytes = positiveInteger(maxResponseBytes, 'maxResponseBytes');
    const normalizedRequestTimeoutMs = positiveInteger(requestTimeoutMs, 'requestTimeoutMs');
    const normalizedConnectTimeoutMs = positiveInteger(connectTimeoutMs, 'connectTimeoutMs');
    const policy = urlPolicy ?? createUrlPolicy({
      allowedOrigins,
      allowedPorts,
      allowPrivateNetworks,
      ...(lookup === undefined ? {} : { lookup })
    });
    const jar = cookieJar ?? new CookieJar(undefined, {
      rejectPublicSuffixes: true,
      looseMode: false,
      prefixSecurity: 'strict',
      allowSpecialUseDomain: allowPrivateNetworks,
      allowSecureOnLocal: false
    });
    if (typeof jar.getCookieString !== 'function' || typeof jar.setCookie !== 'function') {
      throw new TypeError('cookieJar must implement Tough Cookie getCookieString() and setCookie()');
    }
    Object.defineProperties(this, {
      maxRedirects: { value: maxRedirects, enumerable: true },
      maxRequestBytes: { value: normalizedMaxRequestBytes, enumerable: true },
      maxResponseBytes: { value: normalizedMaxResponseBytes, enumerable: true },
      requestTimeoutMs: { value: normalizedRequestTimeoutMs, enumerable: true },
      connectTimeoutMs: { value: normalizedConnectTimeoutMs, enumerable: true },
      urlPolicy: { value: policy, enumerable: true },
      cookieJar: { value: jar, enumerable: true }
    });
    Object.freeze(this);
  }

  async credentialBinding(value, {
    method: methodInput = 'GET',
    sameSiteContext,
    siteForCookies,
    topLevelNavigation = true
  } = {}) {
    const method = normalizeMethod(methodInput);
    if (sameSiteContext !== undefined && !SAME_SITE_CONTEXTS.has(sameSiteContext)) {
      throw invalid('sameSiteContext must be strict, lax, or none.');
    }
    if (typeof topLevelNavigation !== 'boolean') throw invalid('topLevelNavigation must be a boolean.');
    const target = this.urlPolicy.validate(value);
    const siteUrl = cookieSite(siteForCookies, target);
    const initialMethodSafe = topLevelNavigation && (method === 'GET' || method === 'HEAD');
    const context = cookieContext(target, siteUrl, initialMethodSafe, sameSiteContext);
    const cookies = await cookieHeader(this.cookieJar, target, context);
    return credentialBindingRecord(target, context, cookies);
  }

  async request(value, {
    method: methodInput = 'GET',
    headers: headerInput,
    body: bodyInput,
    signal: callerSignal,
    sameSiteContext,
    siteForCookies,
    topLevelNavigation = true,
    allowCrossOriginRedirects = true,
    expectedCredentialBinding,
    notAfter
  } = {}) {
    try {
    const method = normalizeMethod(methodInput);
    if (sameSiteContext !== undefined && !SAME_SITE_CONTEXTS.has(sameSiteContext)) {
      throw invalid('sameSiteContext must be strict, lax, or none.');
    }
    if (typeof topLevelNavigation !== 'boolean') throw invalid('topLevelNavigation must be a boolean.');
    if (typeof allowCrossOriginRedirects !== 'boolean') throw invalid('allowCrossOriginRedirects must be a boolean.');
    if (callerSignal !== undefined && !(callerSignal instanceof AbortSignal)) {
      throw invalid('signal must be an AbortSignal.');
    }
    if (expectedCredentialBinding !== undefined
      && !/^sha256:[0-9a-f]{64}$/.test(expectedCredentialBinding)) {
      throw invalid('expectedCredentialBinding must be a SHA-256 binding digest.');
    }
    if (notAfter !== undefined && (!Number.isFinite(notAfter) || notAfter <= 0)) {
      throw invalid('notAfter must be a positive epoch-millisecond deadline.');
    }
    const assertBeforeDeadline = () => {
      if (notAfter !== undefined && Date.now() >= notAfter) {
        throw new BridgeError(BRIDGE_REFUSAL_CODES.PREVIEW_STALE, {
          detail: 'The approved request expired before network dispatch.',
          stage: 'freshness'
        });
      }
    };
    assertBeforeDeadline();

    let currentUrl = this.urlPolicy.validate(value);
    let currentMethod = method;
    let currentHeaders = normalizeHeaders(headerInput);
    let currentBody = normalizeBody(bodyInput, method);
    const requestBytes = bodyByteLength(currentBody);
    if (requestBytes > this.maxRequestBytes) {
      throw new BridgeError(BRIDGE_REFUSAL_CODES.BODY_LIMIT_EXCEEDED, {
        detail: `The request body exceeds the ${this.maxRequestBytes}-byte limit.`,
        stage: 'network'
      });
    }
    const siteUrl = cookieSite(siteForCookies, currentUrl);

    const initialMethodSafe = topLevelNavigation && (method === 'GET' || method === 'HEAD');
    const redirects = [];
    const cookieStats = { accepted: 0, rejected: 0 };
    let suppressCookiesForHop = false;
    let timedOut = false;
    const deadline = Date.now() + this.requestTimeoutMs;
    const timeoutController = new AbortController();
    const timer = setTimeout(() => {
      timedOut = true;
      timeoutController.abort(new DOMException('HTTP bridge request timed out', 'TimeoutError'));
    }, this.requestTimeoutMs);
    timer.unref?.();
    const signal = callerSignal
      ? AbortSignal.any([callerSignal, timeoutController.signal])
      : timeoutController.signal;

    try {
      while (true) {
        let resolution;
        try {
          resolution = await this.urlPolicy.resolve(currentUrl, { signal });
        } catch (error) {
          const failure = preDispatchFailure(error, timedOut);
          throw redirects.length > 0 && !timedOut ? redirectViolation(failure) : failure;
        }

        const context = cookieContext(currentUrl, siteUrl, initialMethodSafe, sameSiteContext);
        const hopHeaders = new Headers(currentHeaders);
        const cookies = suppressCookiesForHop
          ? ''
          : await cookieHeader(this.cookieJar, currentUrl, context);
        if (cookies) hopHeaders.set('cookie', cookies);
        if (redirects.length === 0 && expectedCredentialBinding !== undefined) {
          const actualBinding = credentialBindingRecord(currentUrl, context, cookies);
          if (actualBinding.binding_digest !== expectedCredentialBinding) {
            throw new BridgeError(BRIDGE_REFUSAL_CODES.CREDENTIAL_BINDING_MISMATCH, {
              detail: 'The session cookies changed after approval; the request was not dispatched.',
              stage: 'auth'
            });
          }
        }
        if (approximateRequestBytes(currentUrl, currentMethod, hopHeaders, currentBody) > this.maxRequestBytes) {
          throw new BridgeError(BRIDGE_REFUSAL_CODES.BODY_LIMIT_EXCEEDED, {
            title: 'Request size limit exceeded',
            detail: `The complete upstream request exceeds the ${this.maxRequestBytes}-byte limit.`,
            stage: 'network'
          });
        }
        assertBeforeDeadline();

        const remainingMs = Math.max(1, deadline - Date.now());
        let dispatcher = createPinnedDispatcher(resolution, {
          connectTimeoutMs: Math.min(this.connectTimeoutMs, remainingMs),
          headersTimeoutMs: remainingMs,
          bodyTimeoutMs: remainingMs,
          pinTtlMs: remainingMs
        });
        let dispatched = false;
        let response;
        try {
          assertBeforeDeadline();
          dispatched = true;
          response = await fetch(currentUrl, {
            method: currentMethod,
            headers: hopHeaders,
            body: currentBody,
            redirect: 'manual',
            dispatcher,
            signal
          });

          const stored = await storeResponseCookies(this.cookieJar, response, currentUrl, context);
          cookieStats.accepted += stored.accepted;
          cookieStats.rejected += stored.rejected;

          const location = response.headers.get('location');
          if (REDIRECT_STATUSES.has(response.status) && location !== null) {
            // An approved non-safe request authorizes exactly one upstream
            // target. Never replay or rewrite it through a redirect, even on
            // the same origin. The caller receives the 3xx observation and
            // can prepare a separate request if another step is intended.
            if (!SAFE_METHODS.has(currentMethod)) {
              const body = await readBoundedBody(response, this.maxResponseBytes);
              return new HttpSessionResponse({
                status: response.status,
                statusText: response.statusText,
                url: currentUrl.href,
                method: currentMethod,
                headers: response.headers,
                body,
                redirects,
                cookieStats
              });
            }
            if (redirects.length >= this.maxRedirects) {
              await cancelBody(response);
              throw new BridgeError(BRIDGE_REFUSAL_CODES.REDIRECT_POLICY_VIOLATION, {
                detail: `The upstream response exceeded the ${this.maxRedirects}-redirect limit.`,
                stage: 'network'
              });
            }

            let nextUrl;
            try {
              nextUrl = new URL(location, currentUrl);
              this.urlPolicy.validate(nextUrl);
            } catch (error) {
              await cancelBody(response);
              throw redirectViolation(error);
            }

            const previousMethod = currentMethod;
            const transition = transitionRedirect(response.status, currentMethod, currentBody, currentHeaders);
            const crossOrigin = nextUrl.origin !== currentUrl.origin;
            if (crossOrigin && !allowCrossOriginRedirects) {
              await cancelBody(response);
              throw new BridgeError(BRIDGE_REFUSAL_CODES.REDIRECT_POLICY_VIOLATION, {
                detail: 'The form bridge does not follow a navigation to a different origin.',
                stage: 'network'
              });
            }
            if (crossOrigin && transition.body !== null) {
              await cancelBody(response);
              throw new BridgeError(BRIDGE_REFUSAL_CODES.CROSS_ORIGIN_CREDENTIAL_BLOCKED, {
                detail: 'A cross-origin redirect attempted to replay a request body; explicit adapter policy is required.',
                stage: 'network'
              });
            }
            currentMethod = transition.method;
            currentBody = transition.body;
            currentHeaders = transition.headers;
            if (crossOrigin) {
              for (const name of [...currentHeaders.keys()]) {
                if (!CROSS_ORIGIN_ALLOWED_HEADERS.has(name.toLowerCase())) currentHeaders.delete(name);
              }
            }
            // Once a redirect chain leaves the approved origin, no cookie-jar
            // credentials are attached to any later unapproved hop.
            suppressCookiesForHop ||= crossOrigin;
            redirects.push({
              status: response.status,
              from: currentUrl.href,
              to: nextUrl.href,
              method: previousMethod,
              nextMethod: currentMethod,
              crossOrigin
            });
            await cancelBody(response);
            currentUrl = nextUrl;
            continue;
          }

          const body = await readBoundedBody(response, this.maxResponseBytes);
          return new HttpSessionResponse({
            status: response.status,
            statusText: response.statusText,
            url: currentUrl.href,
            method: currentMethod,
            headers: response.headers,
            body,
            redirects,
            cookieStats
          });
        } catch (error) {
          const nested = findBridgeError(error);
          if (nested) throw annotateDispatch(nested, response ? 'response_received' : dispatched ? 'sent' : 'not_sent', response);
          if (!dispatched) throw annotateDispatch(preDispatchFailure(error, timedOut), 'not_sent');
          throw annotateDispatch(dispatchedFailure(error, {
            method: currentMethod,
            url: currentUrl,
            timedOut
          }), response ? 'response_received' : 'sent', response);
        } finally {
          await closeDispatcher(dispatcher);
          dispatcher = null;
        }
      }
    } catch (error) {
      if (error?.dispatchState || redirects.length === 0) throw error;
      // A prior hop returned a response. Failure while preparing a later hop
      // must not erase that dispatch evidence.
      throw annotateDispatch(error, 'response_received');
    } finally {
      clearTimeout(timer);
    }
    } catch (error) {
      if (error?.dispatchState) throw error;
      throw annotateDispatch(error, 'not_sent');
    }
  }
}

export function createHttpSession(options) {
  return new HttpSession(options);
}
