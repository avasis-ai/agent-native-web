import { lookup as systemLookup } from 'node:dns/promises';
import ipaddr from 'ipaddr.js';

import { BRIDGE_REFUSAL_CODES, BridgeError } from './errors.mjs';

const DEFAULT_HTTPS_PORT = 443;
const PRIVATE_NETWORK_RANGES = Object.freeze({
  ipv4: new Set(['private', 'loopback']),
  ipv6: new Set(['uniqueLocal', 'loopback'])
});

function refusal(code, detail, cause) {
  return new BridgeError(code, { detail, stage: 'network', cause });
}

function hostnameWithoutBrackets(hostname) {
  return hostname.startsWith('[') && hostname.endsWith(']')
    ? hostname.slice(1, -1)
    : hostname;
}

function normalizeOrigin(value) {
  let url;
  try {
    url = new URL(value);
  } catch (cause) {
    throw new TypeError('allowedOrigins entries must be absolute HTTP(S) origins', { cause });
  }
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password) {
    throw new TypeError('allowedOrigins entries must be absolute HTTP(S) origins without userinfo');
  }
  if (url.pathname !== '/' || url.search || url.hash) {
    throw new TypeError('allowedOrigins entries must not contain a path, query, or fragment');
  }
  return url.origin;
}

function normalizeAllowedPorts(values) {
  if (!Array.isArray(values) && !(values instanceof Set)) {
    throw new TypeError('allowedPorts must be an array or Set of TCP port numbers');
  }
  const ports = new Set();
  for (const value of values) {
    const port = typeof value === 'string' && /^\d+$/.test(value) ? Number(value) : value;
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      throw new TypeError(`Invalid allowed TCP port: ${String(value)}`);
    }
    ports.add(port);
  }
  return ports;
}

function familyNumber(value, parsedAddress) {
  const inferred = parsedAddress.kind() === 'ipv4' ? 4 : 6;
  if (value === undefined || value === null || value === 0) return inferred;
  const normalized = Number(value);
  if (normalized !== inferred) {
    throw refusal(
      BRIDGE_REFUSAL_CODES.SSRF_TARGET_BLOCKED,
      'DNS returned an address whose family metadata does not match the address.'
    );
  }
  return inferred;
}

function raceWithSignal(promise, signal) {
  if (!signal) return promise;
  signal.throwIfAborted();
  return new Promise((resolve, reject) => {
    const onAbort = () => reject(signal.reason);
    signal.addEventListener('abort', onAbort, { once: true });
    promise.then(
      (value) => {
        signal.removeEventListener('abort', onAbort);
        resolve(value);
      },
      (error) => {
        signal.removeEventListener('abort', onAbort);
        reject(error);
      }
    );
  });
}

/**
 * Classify an address without performing DNS. Only ordinary global unicast is
 * allowed by default. Link-local (including cloud metadata), carrier-grade
 * NAT, IPv4-mapped IPv6, multicast, and transition/reserved ranges remain
 * blocked even when private test networks are enabled.
 */
export function classifyAddress(value) {
  const raw = hostnameWithoutBrackets(String(value));
  if (!ipaddr.isValid(raw)) {
    throw refusal(BRIDGE_REFUSAL_CODES.SSRF_TARGET_BLOCKED, 'The target resolved to an invalid IP address.');
  }
  const parsed = ipaddr.parse(raw);
  const family = parsed.kind();
  const range = parsed.range();
  return Object.freeze({
    address: parsed.toNormalizedString(),
    family: family === 'ipv4' ? 4 : 6,
    range,
    public: range === 'unicast',
    privateNetwork: PRIVATE_NETWORK_RANGES[family].has(range)
  });
}

/** Remove all untrusted path/query/credential material before a URL enters an error. */
export function redactUrl(value) {
  try {
    const url = value instanceof URL ? new URL(value.href) : new URL(value);
    url.username = '';
    url.password = '';
    url.hash = '';
    url.pathname = url.pathname.split('/').map((segment) => segment ? '~redacted' : segment).join('/');
    if (url.search) url.search = '?redacted';
    return url.href;
  } catch {
    return '<invalid-url>';
  }
}

export class UrlPolicy {
  #allowedOrigins;
  #allowedPorts;
  #allowPrivateNetworks;
  #lookup;

  constructor({
    allowedOrigins = [],
    allowedPorts = [],
    allowPrivateNetworks = false,
    lookup = systemLookup
  } = {}) {
    if (!Array.isArray(allowedOrigins) && !(allowedOrigins instanceof Set)) {
      throw new TypeError('allowedOrigins must be an array or Set of exact origins');
    }
    if (typeof allowPrivateNetworks !== 'boolean') {
      throw new TypeError('allowPrivateNetworks must be a boolean');
    }
    if (typeof lookup !== 'function') throw new TypeError('lookup must be a function');

    this.#allowedOrigins = new Set([...allowedOrigins].map(normalizeOrigin));
    this.#allowedPorts = normalizeAllowedPorts(allowedPorts);
    this.#allowPrivateNetworks = allowPrivateNetworks;
    this.#lookup = lookup;
    Object.freeze(this);
  }

  get allowedOrigins() {
    return Object.freeze([...this.#allowedOrigins]);
  }

  get allowedPorts() {
    return Object.freeze([...this.#allowedPorts]);
  }

  get allowPrivateNetworks() {
    return this.#allowPrivateNetworks;
  }

  /**
   * Validate URL-level policy before DNS. An exact allowedOrigins entry is an
   * explicit opt-in to that origin's scheme and port (useful for local tests),
   * but private addresses still require allowPrivateNetworks.
   */
  validate(value) {
    let url;
    try {
      url = value instanceof URL ? new URL(value.href) : new URL(value);
    } catch (cause) {
      throw refusal(BRIDGE_REFUSAL_CODES.INVALID_BRIDGE_DATA, 'The request URL must be absolute.', cause);
    }

    if (url.username || url.password) {
      throw refusal(BRIDGE_REFUSAL_CODES.SSRF_TARGET_BLOCKED, 'URL userinfo is not allowed.');
    }
    if (!['http:', 'https:'].includes(url.protocol)) {
      throw refusal(BRIDGE_REFUSAL_CODES.SSRF_TARGET_BLOCKED, 'Only HTTP(S) targets can be requested.');
    }

    url.hash = '';
    const explicitlyAllowed = this.#allowedOrigins.has(url.origin);
    if (this.#allowedOrigins.size > 0 && !explicitlyAllowed) {
      throw refusal(BRIDGE_REFUSAL_CODES.SSRF_TARGET_BLOCKED, 'The target origin is not in allowedOrigins.');
    }
    if (url.protocol !== 'https:' && !explicitlyAllowed) {
      throw refusal(BRIDGE_REFUSAL_CODES.TLS_REQUIRED, 'HTTPS is required unless an exact HTTP test origin is allowed.');
    }

    const effectivePort = Number(url.port || (url.protocol === 'https:' ? DEFAULT_HTTPS_PORT : 80));
    const standardHttpsPort = url.protocol === 'https:' && effectivePort === DEFAULT_HTTPS_PORT;
    if (!standardHttpsPort && !explicitlyAllowed && !this.#allowedPorts.has(effectivePort)) {
      throw refusal(BRIDGE_REFUSAL_CODES.SSRF_TARGET_BLOCKED, 'The target uses a blocked TCP port.');
    }
    return url;
  }

  assertAddressAllowed(value, { origin } = {}) {
    const classification = classifyAddress(value);
    if (classification.public) return classification;
    if (this.#allowPrivateNetworks
      && classification.privateNetwork
      && typeof origin === 'string'
      && this.#allowedOrigins.has(origin)) return classification;
    throw refusal(
      BRIDGE_REFUSAL_CODES.SSRF_TARGET_BLOCKED,
      `The target resolved to a blocked ${classification.range} address.`
    );
  }

  /**
   * Validate every DNS answer and return immutable records suitable for a
   * request-scoped Undici DNS interceptor. Reusing these exact records pins the
   * subsequent socket connection and closes the DNS-rebinding gap.
   */
  async resolve(value, { signal } = {}) {
    const url = this.validate(value);
    const hostname = hostnameWithoutBrackets(url.hostname);
    if (ipaddr.isValid(hostname)) {
      const checked = this.assertAddressAllowed(hostname, { origin: url.origin });
      return Object.freeze({
        url,
        hostname,
        addresses: Object.freeze([Object.freeze({ address: checked.address, family: checked.family, ttl: 1 })])
      });
    }

    let answers;
    try {
      answers = await raceWithSignal(
        Promise.resolve(this.#lookup(hostname, { all: true, order: 'verbatim' })),
        signal
      );
    } catch (cause) {
      if (signal?.aborted) throw signal.reason;
      throw refusal(BRIDGE_REFUSAL_CODES.SSRF_TARGET_BLOCKED, 'The target hostname could not be safely resolved.', cause);
    }
    if (!Array.isArray(answers)) answers = answers ? [answers] : [];
    if (answers.length === 0) {
      throw refusal(BRIDGE_REFUSAL_CODES.SSRF_TARGET_BLOCKED, 'The target hostname returned no usable addresses.');
    }

    const unique = new Map();
    for (const answer of answers) {
      const rawAddress = typeof answer === 'string' ? answer : answer?.address;
      const checked = this.assertAddressAllowed(rawAddress, { origin: url.origin });
      const family = familyNumber(typeof answer === 'string' ? undefined : answer.family, ipaddr.parse(checked.address));
      unique.set(`${family}:${checked.address}`, Object.freeze({ address: checked.address, family, ttl: 1 }));
    }
    return Object.freeze({
      url,
      hostname,
      addresses: Object.freeze([...unique.values()])
    });
  }
}

export function createUrlPolicy(options) {
  return new UrlPolicy(options);
}
