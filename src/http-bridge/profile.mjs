import { createHash, createHmac, randomBytes, randomUUID } from 'node:crypto';
import { createAssuranceVector } from './assurance.mjs';
import { BRIDGE_REFUSAL_CODES, BridgeError, isBridgeRefusalCode } from './errors.mjs';
import { HTTP_BRIDGE_SCHEMAS } from './uris.mjs';

export { HTTP_BRIDGE_SCHEMAS } from './uris.mjs';

export const HTTP_BRIDGE_PROTOCOL = 'http-form-bridge';
export const HTTP_BRIDGE_PROTOCOL_VERSION = '0.1-draft';
export const HTTP_BRIDGE_PROFILE = 'agent-wire-contract';
export const HTTP_BRIDGE_PROFILE_VERSION = '0.1-draft';

export const CONTRACT_RAILS = Object.freeze([
  'standard_html',
  'verified_adapter',
  'unsupported'
]);

export const AUTOMATION_CEILINGS = Object.freeze([
  'inspect',
  'read',
  'prepare',
  'approved_dispatch',
  'approved_commit',
  'autonomous_commit'
]);

export const DISPATCH_STATES = Object.freeze([
  'not_sent',
  'sent',
  'response_received',
  'transport_ambiguous'
]);

export const OUTCOME_STATES = Object.freeze([
  'unverified',
  'pending_verified',
  'succeeded_verified',
  'failed_verified',
  'partial_verified',
  'mismatch',
  'unknown'
]);

const VERIFIED_OUTCOMES = new Set([
  'pending_verified',
  'succeeded_verified',
  'failed_verified',
  'partial_verified',
  'mismatch'
]);
const RAIL_SET = new Set(CONTRACT_RAILS);
const CEILING_SET = new Set(AUTOMATION_CEILINGS);
const DISPATCH_SET = new Set(DISPATCH_STATES);
const OUTCOME_SET = new Set(OUTCOME_STATES);
const VALUE_KEYS = new Set(['value', 'default_value', 'raw_value', 'wire_value', 'content', 'ref']);
const ALWAYS_SECRET_KEYS = new Set([
  'authorization',
  'cookie',
  'set_cookie',
  'password',
  'secret',
  'token',
  'access_token',
  'refresh_token',
  'id_token',
  'api_key',
  'apikey',
  'client_secret',
  'credential',
  'csrf_token',
  'otp',
  'magic_link',
  'vault_ref',
  'raw_body',
  'body_bytes',
  'request_body',
  'response_body',
  'html',
  'source_fingerprint',
  'form_fingerprint',
  'form_instance_fingerprint',
  'action_fingerprint',
  'query_parameter_names'
]);
const SENSITIVE_ROLE = /(?:^|[_-])(hidden|csrf|password|passwd|token|cookie|authorization|otp|magic[_-]?link|secret)(?:$|[_-])/i;
const URL_VALUE_KEYS = new Set([
  'url', 'requested_url', 'final_url', 'action_url', 'action', 'location',
  'target', 'endpoint', 'uri', 'href',
  // Redirect records use from/to. Treat both as URLs so OAuth codes, search
  // values, and other query material cannot enter public evidence or receipts.
  'from', 'to'
]);
const URL_PATH_KEYS = new Set(['path', 'pathname']);

function invalid(detail, stage = 'profile') {
  return new BridgeError(BRIDGE_REFUSAL_CODES.INVALID_BRIDGE_DATA, { detail, stage });
}

function isPlainObject(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function assertPlainObject(value, label) {
  if (!isPlainObject(value)) throw invalid(`${label} must be a plain object`);
  return value;
}

function requiredString(value, label) {
  if (typeof value !== 'string' || value.length === 0) throw invalid(`${label} must be a non-empty string`);
  return value;
}

function requiredDigest(value, label, algorithm) {
  requiredString(value, label);
  const prefix = algorithm === 'hmac-sha256' ? 'hmac-sha256' : 'sha256';
  if (!new RegExp(`^${prefix}:[0-9a-f]{64}$`).test(value)) {
    throw invalid(`${label} must be a ${prefix} digest`);
  }
  return value;
}

function stringList(value, label) {
  if (value === undefined) return [];
  if (!Array.isArray(value) || value.some((item) => typeof item !== 'string' || item.length === 0)) {
    throw invalid(`${label} must be an array of non-empty strings`);
  }
  return [...new Set(value)];
}

function isoInstant(value, label, fallback = undefined) {
  const selected = value ?? fallback;
  if (selected === undefined) return undefined;
  const date = selected instanceof Date ? selected : new Date(selected);
  if (!Number.isFinite(date.getTime())) throw invalid(`${label} must be a valid date-time`);
  return date.toISOString();
}

function canonicalUrl(value, label) {
  requiredString(value, label);
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    throw invalid(`${label} must be an absolute URL`);
  }
  if (parsed.username || parsed.password) throw invalid(`${label} must not contain URL userinfo`);
  parsed.hash = '';
  return parsed.href;
}

/**
 * Canonical JSON for bridge fingerprints. It accepts JSON data only, sorts
 * object keys, rejects cycles/non-finite numbers, and does not silently drop
 * undefined values. This is deliberately narrower than JSON.stringify.
 */
export function canonicalJson(value) {
  const active = new Set();
  const encode = (current, path) => {
    if (current === null) return 'null';
    if (typeof current === 'string' || typeof current === 'boolean') return JSON.stringify(current);
    if (typeof current === 'number') {
      if (!Number.isFinite(current)) throw invalid(`Non-finite number at ${path}`);
      return JSON.stringify(Object.is(current, -0) ? 0 : current);
    }
    if (typeof current === 'undefined') throw invalid(`Undefined value at ${path}`);
    if (typeof current !== 'object') throw invalid(`Non-JSON value at ${path}`);
    if (ArrayBuffer.isView(current)) throw invalid(`Binary value at ${path} must be digested before canonicalization`);
    if (active.has(current)) throw invalid(`Cyclic value at ${path}`);
    active.add(current);
    let encoded;
    if (Array.isArray(current)) {
      encoded = `[${current.map((item, index) => encode(item, `${path}/${index}`)).join(',')}]`;
    } else {
      if (!isPlainObject(current)) throw invalid(`Non-plain object at ${path}`);
      encoded = `{${Object.keys(current).sort().map((key) => {
        const child = current[key];
        if (child === undefined) throw invalid(`Undefined value at ${path}/${key}`);
        return `${JSON.stringify(key)}:${encode(child, `${path}/${key}`)}`;
      }).join(',')}}`;
    }
    active.delete(current);
    return encoded;
  };
  return encode(value, '$');
}

export function canonicalSha256(value) {
  return `sha256:${createHash('sha256').update(canonicalJson(value)).digest('hex')}`;
}

function digestKeyBytes(value) {
  if (!(value instanceof Uint8Array) || value.byteLength < 32) {
    throw invalid('digestKey must contain at least 32 private random bytes');
  }
  return Buffer.from(value);
}

export function canonicalHmacSha256(value, digestKey) {
  return `hmac-sha256:${createHmac('sha256', digestKeyBytes(digestKey)).update(canonicalJson(value)).digest('hex')}`;
}

export function bytesSha256(value) {
  if (!(value instanceof Uint8Array)) throw invalid('bytesSha256 requires a Uint8Array');
  return `sha256:${createHash('sha256').update(value).digest('hex')}`;
}

export function bytesHmacSha256(value, digestKey) {
  if (!(value instanceof Uint8Array)) throw invalid('bytesHmacSha256 requires a Uint8Array');
  return `hmac-sha256:${createHmac('sha256', digestKeyBytes(digestKey)).update(value).digest('hex')}`;
}

function digestable(value, path = '$') {
  if (value instanceof Uint8Array) return { byte_length: value.byteLength, bytes_digest: bytesSha256(value) };
  if (Array.isArray(value)) return value.map((item, index) => digestable(item, `${path}/${index}`));
  if (isPlainObject(value)) {
    const result = {};
    for (const [key, child] of Object.entries(value)) {
      if (child === undefined) throw invalid(`Undefined value at ${path}/${key}`);
      result[key] = digestable(child, `${path}/${key}`);
    }
    return result;
  }
  if (value instanceof Date) return value.toISOString();
  return value;
}

function normalizedKey(key) {
  return key.toLocaleLowerCase('en-US').replaceAll('-', '_');
}

function isSecretBearingKey(key) {
  if (ALWAYS_SECRET_KEYS.has(key)) return true;
  if (key.includes('csrf') || key.includes('xsrf') || key.includes('password') || key.includes('passwd')) return true;
  return /(?:^|_)(authorization|cookie|token|otp|secret|api_?key|credential|magic_link|samlrequest|samlresponse|assertion|signature|state|nonce|code_verifier|code_challenge)(?:$|_)/i.test(key);
}

function redactUrlPath(value, digestKey) {
  const segments = String(value).split('/');
  return segments.map((segment) => {
    if (segment === '') return segment;
    let decoded = segment;
    try {
      decoded = decodeURIComponent(segment);
    } catch {
      // Malformed escapes are still considered opaque below.
    }
    // There is no sound generic classifier for a public route segment versus
    // a bearer capability. A short reset code such as `/r/7xQ` is just as
    // credential-bearing as a long JWT-shaped value. Digest every non-empty
    // segment so public evidence has no false-negative privacy heuristic.
    return `~${canonicalHmacSha256(decoded, digestKey).replace(':', '-')}`;
  }).join('/');
}

function redactUrl(value, digestKey) {
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    return `~${canonicalHmacSha256(String(value), digestKey).replace(':', '-')}`;
  }
  parsed.username = '';
  parsed.password = '';
  // URL queries routinely contain search text, email addresses, OAuth state,
  // and other user material. Preserve names and multiplicity, never values.
  const queryEntries = [...parsed.searchParams.entries()];
  parsed.search = '';
  for (const [name, queryValue] of queryEntries) {
    parsed.searchParams.append(
      `~${canonicalHmacSha256(name, digestKey).replace(':', '-')}`,
      canonicalHmacSha256(queryValue, digestKey)
    );
  }
  parsed.pathname = redactUrlPath(parsed.pathname, digestKey);
  parsed.hash = '';
  return parsed.href;
}

function isSensitiveRecord(value, inherited) {
  if (inherited) return true;
  if (!isPlainObject(value)) return false;
  if (value.sensitive === true || value.secret === true || value.hidden === true) return true;
  const indicators = [
    value.type,
    value.control_type,
    value.input_type,
    value.role,
    value.kind,
    value.name,
    value.binding?.kind
  ].filter((item) => typeof item === 'string');
  return indicators.some((item) => SENSITIVE_ROLE.test(item));
}

/**
 * Produces a public view. Hidden controls, CSRF material, credentials, raw
 * bodies, cookies, and vault references are represented only by keyed HMACs.
 * The executor may retain the raw values in its private request vault; this
 * function never returns them or a digest suitable for offline guessing.
 */
export function redactForPublicContract(value, inheritedSensitive = false, digestKey = randomBytes(32)) {
  const keyBytes = digestKeyBytes(digestKey);
  if (value instanceof Uint8Array) return Object.freeze({ byte_length: value.byteLength, bytes_digest: bytesHmacSha256(value, keyBytes) });
  if (Array.isArray(value)) return value.map((item) => redactForPublicContract(item, inheritedSensitive, keyBytes));
  if (!isPlainObject(value)) {
    if (value instanceof Date) return value.toISOString();
    if (typeof value === 'string') {
      if (/^https?:\/\//i.test(value)) return redactUrl(value, keyBytes);
      if (value.startsWith('/')) return redactUrlPath(value, keyBytes);
    }
    return value;
  }
  const sensitive = isSensitiveRecord(value, inheritedSensitive);
  const result = {};
  for (const [fieldKey, child] of Object.entries(value)) {
    if (child === undefined) continue;
    const normalized = normalizedKey(fieldKey);
    const secretBearing = isSecretBearingKey(normalized);
    if (normalized.endsWith('_digest') && !secretBearing && !(sensitive && normalized === 'binding_digest')) {
      result[fieldKey] = child;
      continue;
    }
    const mustDigest = secretBearing
      || normalized === 'body'
      || (sensitive && (VALUE_KEYS.has(normalized) || normalized.endsWith('_digest')));
    if (mustDigest) {
      result[`${fieldKey}_digest`] = child instanceof Uint8Array
        ? bytesHmacSha256(child, keyBytes)
        : canonicalHmacSha256(digestable(child), keyBytes);
      continue;
    }
    if ((URL_VALUE_KEYS.has(normalized) || normalized.endsWith('_url')) && typeof child === 'string') {
      result[fieldKey] = redactUrl(child, keyBytes);
      continue;
    }
    if (URL_PATH_KEYS.has(normalized) && typeof child === 'string') {
      result[fieldKey] = redactUrlPath(child, keyBytes);
      continue;
    }
    result[fieldKey] = redactForPublicContract(child, sensitive, keyBytes);
  }
  return result;
}

function deepFreeze(value, seen = new WeakSet()) {
  if (!value || typeof value !== 'object' || seen.has(value)) return value;
  seen.add(value);
  for (const child of Object.values(value)) deepFreeze(child, seen);
  return Object.freeze(value);
}

function attachDigest(value, field = 'digest') {
  return deepFreeze({ ...value, [field]: canonicalSha256(value) });
}

export function createPublicEvidence(input, digestKey = randomBytes(32)) {
  const key = digestKeyBytes(digestKey);
  assertPlainObject(input, 'evidence');
  if (input.id !== undefined) requiredString(input.id, 'evidence.id');
  const publicEvidence = redactForPublicContract(input, false, key);
  const seed = { ...publicEvidence };
  delete seed.id;
  delete seed.digest;
  const digest = canonicalSha256(seed);
  return deepFreeze({
    ...publicEvidence,
    $schema: HTTP_BRIDGE_SCHEMAS.evidence,
    id: input.id ?? `evidence_${digest.slice(7, 23)}`,
    digest
  });
}

function normalizeRefusal(value, digestKey) {
  if (value instanceof BridgeError) return redactForPublicContract(value.toProblem(), false, digestKey);
  if (typeof value === 'string') {
    if (!isBridgeRefusalCode(value)) throw invalid(`Unknown refusal code: ${value}`);
    return redactForPublicContract(new BridgeError(value).toProblem(), false, digestKey);
  }
  assertPlainObject(value, 'refusal');
  if (!isBridgeRefusalCode(value.code)) throw invalid(`Unknown refusal code: ${value.code}`);
  return redactForPublicContract(value, false, digestKey);
}

export function createInferredContract({
  contractId,
  rail = 'standard_html',
  automationCeiling = 'inspect',
  target,
  assurance = {},
  observedAt = new Date(),
  validUntil,
  session,
  fingerprints = {},
  evidence = [],
  operations = [],
  refusals = [],
  digestKey = randomBytes(32)
}) {
  const key = digestKeyBytes(digestKey);
  if (contractId !== undefined) requiredString(contractId, 'contractId');
  if (!RAIL_SET.has(rail)) throw invalid(`Unknown bridge rail: ${rail}`);
  if (!CEILING_SET.has(automationCeiling)) throw invalid(`Unknown automation ceiling: ${automationCeiling}`);
  if (rail === 'standard_html' && ['approved_commit', 'autonomous_commit'].includes(automationCeiling)) {
    throw invalid('standard_html contracts can authorize an approved dispatch, never a semantic commit');
  }
  if (rail === 'unsupported' && automationCeiling !== 'inspect') {
    throw invalid('unsupported contracts have an inspect-only automation ceiling');
  }
  assertPlainObject(target, 'target');
  const requestedUrl = canonicalUrl(target.requested_url, 'target.requested_url');
  const finalUrl = canonicalUrl(target.final_url ?? requestedUrl, 'target.final_url');
  const canonicalOrigin = target.canonical_origin ?? new URL(finalUrl).origin;
  if (new URL(canonicalOrigin).origin !== canonicalOrigin) throw invalid('target.canonical_origin must be an origin without path, query, or fragment');
  if (!Array.isArray(evidence) || !Array.isArray(operations) || !Array.isArray(refusals)) {
    throw invalid('evidence, operations, and refusals must be arrays');
  }
  assertPlainObject(fingerprints, 'fingerprints');

  const publicEvidence = evidence.map((item) => createPublicEvidence(item, key));
  const publicOperations = operations.map((operation, index) => {
    assertPlainObject(operation, `operations[${index}]`);
    return redactForPublicContract(operation, false, key);
  });
  const observedInstant = isoInstant(observedAt, 'observedAt');
  const validUntilInstant = validUntil === undefined ? undefined : isoInstant(validUntil, 'validUntil');
  if (validUntilInstant !== undefined && Date.parse(validUntilInstant) <= Date.parse(observedInstant)) {
    throw invalid('validUntil must be later than observedAt');
  }
  const body = {
    $schema: HTTP_BRIDGE_SCHEMAS.inferredContract,
    protocol: HTTP_BRIDGE_PROTOCOL,
    protocol_version: HTTP_BRIDGE_PROTOCOL_VERSION,
    profile: HTTP_BRIDGE_PROFILE,
    profile_version: HTTP_BRIDGE_PROFILE_VERSION,
    kind: 'inferred_contract',
    rail,
    automation_ceiling: automationCeiling,
    target: redactForPublicContract({ ...target, requested_url: requestedUrl, final_url: finalUrl, canonical_origin: canonicalOrigin }, false, key),
    observed_at: observedInstant,
    ...(validUntilInstant === undefined ? {} : { valid_until: validUntilInstant }),
    ...(session === undefined ? {} : { session: redactForPublicContract(assertPlainObject(session, 'session'), false, key) }),
    fingerprints: redactForPublicContract(fingerprints, false, key),
    assurance: createAssuranceVector(assurance),
    evidence: publicEvidence,
    operations: publicOperations,
    refusals: refusals.map((item) => normalizeRefusal(item, key))
  };
  const identityDigest = canonicalSha256({
    target: body.target,
    rail,
    fingerprints: body.fingerprints,
    operation_ids: publicOperations.map((operation) => operation.operation_id ?? null)
  });
  return attachDigest({
    ...body,
    contract_id: contractId ?? `contract_${identityDigest.slice(7, 31)}`
  }, 'contract_digest');
}

export function createRequestPreview({
  previewId = `preview_${randomUUID().replaceAll('-', '')}`,
  contractId,
  operationId,
  request,
  assurance = {},
  evidenceRefs = [],
  bindings = {},
  risk = 'unknown',
  requiresApproval = true,
  createdAt = new Date(),
  expiresAt,
  digestKey = randomBytes(32)
}) {
  const key = digestKeyBytes(digestKey);
  requiredString(previewId, 'previewId');
  requiredString(contractId, 'contractId');
  requiredString(operationId, 'operationId');
  requiredString(risk, 'risk');
  if (typeof requiresApproval !== 'boolean') throw invalid('requiresApproval must be a boolean');
  assertPlainObject(request, 'request');
  assertPlainObject(bindings, 'bindings');
  const method = requiredString(request.method, 'request.method').toUpperCase();
  const url = canonicalUrl(request.url, 'request.url');
  const created = isoInstant(createdAt, 'createdAt');
  const expires = isoInstant(expiresAt, 'expiresAt', new Date(Date.parse(created) + 60_000));
  if (Date.parse(expires) <= Date.parse(created)) throw invalid('expiresAt must be later than createdAt');
  const requestPlan = digestable({ ...request, method, url });
  const requestDigest = canonicalHmacSha256(requestPlan, key);
  const publicRequest = redactForPublicContract({ ...request, method, url }, false, key);
  const publicBindings = redactForPublicContract(bindings, false, key);
  const assuranceVector = createAssuranceVector(assurance);
  const approvalBindingDigest = canonicalHmacSha256({
    protocol: HTTP_BRIDGE_PROTOCOL,
    protocol_version: HTTP_BRIDGE_PROTOCOL_VERSION,
    operation_id: operationId,
    request_digest: requestDigest,
    bindings: publicBindings,
    assurance: assuranceVector,
    risk
  }, key);
  const body = {
    $schema: HTTP_BRIDGE_SCHEMAS.requestPreview,
    protocol: HTTP_BRIDGE_PROTOCOL,
    protocol_version: HTTP_BRIDGE_PROTOCOL_VERSION,
    kind: 'request_preview',
    preview_type: 'request_preview',
    preview_id: previewId,
    contract_id: contractId,
    operation_id: operationId,
    risk,
    request: publicRequest,
    request_digest: requestDigest,
    approval_binding_digest: approvalBindingDigest,
    effect: {
      status: 'not_claimed',
      reason: 'An inferred request preview does not predict the remote business effect.'
    },
    assurance: assuranceVector,
    evidence_refs: stringList(evidenceRefs, 'evidenceRefs'),
    bindings: publicBindings,
    approval: {
      required: requiresApproval === true,
      binds_to: 'preview_digest',
      portable_binds_to: 'approval_binding_digest'
    },
    created_at: created,
    expires_at: expires
  };
  return attachDigest(body, 'preview_digest');
}

function publicResponse(response, digestKey) {
  if (response === undefined) return undefined;
  assertPlainObject(response, 'response');
  return redactForPublicContract(response, false, digestKey);
}

function publicError(error, digestKey) {
  if (error === undefined) return undefined;
  if (error instanceof BridgeError) return redactForPublicContract(error.toProblem(), false, digestKey);
  return {
    title: 'Upstream transport error',
    detail: 'An unclassified transport error occurred; its raw message was withheld because it may contain request data.',
    ...(typeof error?.name === 'string' && /^[A-Za-z][A-Za-z0-9_.-]{0,79}$/.test(error.name)
      ? { error_type: error.name }
      : {})
  };
}

export function createAttemptReceipt({
  receiptId = `attempt_${randomUUID().replaceAll('-', '')}`,
  preview,
  previewId,
  previewDigest,
  requestDigest,
  dispatch = 'not_sent',
  outcome = 'unverified',
  response,
  verification,
  siteReceipt,
  error,
  evidenceRefs = [],
  startedAt = new Date(),
  observedAt = new Date(),
  digestKey = randomBytes(32)
}) {
  const key = digestKeyBytes(digestKey);
  requiredString(receiptId, 'receiptId');
  if (!DISPATCH_SET.has(dispatch)) throw invalid(`Unknown dispatch state: ${dispatch}`, 'receipt');
  if (!OUTCOME_SET.has(outcome)) throw invalid(`Unknown outcome state: ${outcome}`, 'receipt');
  if (dispatch === 'not_sent' && outcome !== 'unverified') {
    throw invalid('A request that was not sent cannot have a remote outcome', 'receipt');
  }
  if (dispatch === 'response_received' && response === undefined) {
    throw invalid('response_received requires response evidence', 'receipt');
  }
  if (dispatch === 'transport_ambiguous' && outcome === 'unverified') {
    throw invalid('An ambiguous dispatch must report outcome unknown or an independently verified outcome', 'receipt');
  }
  if (VERIFIED_OUTCOMES.has(outcome)) {
    const verificationRefs = verification?.evidence_refs ?? verification?.evidenceRefs;
    if (siteReceipt === undefined && (!Array.isArray(verificationRefs) || verificationRefs.length === 0)) {
      throw invalid(`${outcome} requires a site receipt or verification evidence`, 'receipt');
    }
  }

  const previewObject = isPlainObject(preview) ? preview : undefined;
  const finalPreviewId = previewId ?? previewObject?.preview_id;
  const finalPreviewDigest = previewDigest ?? previewObject?.preview_digest;
  const finalRequestDigest = requestDigest ?? previewObject?.request_digest;
  requiredString(finalPreviewId, 'previewId');
  requiredDigest(finalPreviewDigest, 'previewDigest', 'sha256');
  requiredDigest(finalRequestDigest, 'requestDigest', 'hmac-sha256');

  const body = {
    $schema: HTTP_BRIDGE_SCHEMAS.attemptReceipt,
    protocol: HTTP_BRIDGE_PROTOCOL,
    protocol_version: HTTP_BRIDGE_PROTOCOL_VERSION,
    kind: 'attempt_receipt',
    receipt_id: receiptId,
    authority: 'bridge_local_observation',
    authority_limit: 'This receipt proves the local dispatch record and observations, not an unverified remote business effect.',
    preview_id: finalPreviewId,
    preview_digest: finalPreviewDigest,
    request_digest: finalRequestDigest,
    dispatch,
    outcome,
    ...(response === undefined ? {} : { response: publicResponse(response, key) }),
    ...(verification === undefined ? {} : { verification: redactForPublicContract(assertPlainObject(verification, 'verification'), false, key) }),
    ...(siteReceipt === undefined ? {} : { site_receipt: redactForPublicContract(siteReceipt, false, key) }),
    ...(error === undefined ? {} : { error: publicError(error, key) }),
    evidence_refs: stringList(evidenceRefs, 'evidenceRefs'),
    started_at: isoInstant(startedAt, 'startedAt'),
    observed_at: isoInstant(observedAt, 'observedAt')
  };
  if (Date.parse(body.observed_at) < Date.parse(body.started_at)) throw invalid('observedAt cannot precede startedAt', 'receipt');
  return attachDigest(body, 'receipt_digest');
}
