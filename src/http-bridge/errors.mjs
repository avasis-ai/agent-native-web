import {
  HTTP_BRIDGE_PROBLEM_REGISTRY,
  HTTP_BRIDGE_SCHEMAS,
  httpBridgeProblemType
} from './uris.mjs';

export const BRIDGE_RETRY = Object.freeze({
  NEVER: 'never',
  SAFE: 'safe',
  AFTER_REFRESH: 'after_refresh',
  AFTER_USER_ACTION: 'after_user_action',
  AFTER_ADAPTER_INSTALL: 'after_adapter_install'
});

export const BRIDGE_REFUSAL_CODES = Object.freeze({
  NATIVE_CONTRACT_INVALID: 'NATIVE_CONTRACT_INVALID',
  CONTRACT_DOWNGRADE_DETECTED: 'CONTRACT_DOWNGRADE_DETECTED',
  CONTRACT_AMBIGUOUS: 'CONTRACT_AMBIGUOUS',
  CONTRACT_DRIFTED: 'CONTRACT_DRIFTED',
  EVIDENCE_STALE: 'EVIDENCE_STALE',
  FORM_NOT_FOUND: 'FORM_NOT_FOUND',
  FORM_SUBMITTER_AMBIGUOUS: 'FORM_SUBMITTER_AMBIGUOUS',
  FORM_SEMANTICS_UNSUPPORTED: 'FORM_SEMANTICS_UNSUPPORTED',
  FORM_SCRIPT_DEPENDENT: 'FORM_SCRIPT_DEPENDENT',
  SEMANTIC_EFFECT_UNKNOWN: 'SEMANTIC_EFFECT_UNKNOWN',
  EFFECT_PREVIEW_UNAVAILABLE: 'EFFECT_PREVIEW_UNAVAILABLE',
  AUTH_METADATA_INVALID: 'AUTH_METADATA_INVALID',
  AUTH_EXTERNAL_USER_AGENT_REQUIRED: 'AUTH_EXTERNAL_USER_AGENT_REQUIRED',
  AUTH_CREDENTIAL_REQUIRED: 'AUTH_CREDENTIAL_REQUIRED',
  AUTH_OTP_REQUIRED: 'AUTH_OTP_REQUIRED',
  AUTH_MAGIC_LINK_REQUIRED: 'AUTH_MAGIC_LINK_REQUIRED',
  AUTH_PASSKEY_REQUIRED: 'AUTH_PASSKEY_REQUIRED',
  AUTH_CAPTCHA_REQUIRED: 'AUTH_CAPTCHA_REQUIRED',
  AUTH_STEP_UP_REQUIRED: 'AUTH_STEP_UP_REQUIRED',
  AUTH_SESSION_UNVERIFIED: 'AUTH_SESSION_UNVERIFIED',
  AUTH_SESSION_EXPIRED: 'AUTH_SESSION_EXPIRED',
  AUTH_SUBJECT_CHANGED: 'AUTH_SUBJECT_CHANGED',
  TLS_REQUIRED: 'TLS_REQUIRED',
  SSRF_TARGET_BLOCKED: 'SSRF_TARGET_BLOCKED',
  DNS_REBINDING_DETECTED: 'DNS_REBINDING_DETECTED',
  REDIRECT_POLICY_VIOLATION: 'REDIRECT_POLICY_VIOLATION',
  CROSS_ORIGIN_CREDENTIAL_BLOCKED: 'CROSS_ORIGIN_CREDENTIAL_BLOCKED',
  CREDENTIAL_BINDING_MISMATCH: 'CREDENTIAL_BINDING_MISMATCH',
  BODY_LIMIT_EXCEEDED: 'BODY_LIMIT_EXCEEDED',
  PREVIEW_STALE: 'PREVIEW_STALE',
  APPROVAL_REQUIRED: 'APPROVAL_REQUIRED',
  APPROVAL_BINDING_MISMATCH: 'APPROVAL_BINDING_MISMATCH',
  IDEMPOTENCY_UNAVAILABLE: 'IDEMPOTENCY_UNAVAILABLE',
  COMMIT_NOT_AUTOMATABLE: 'COMMIT_NOT_AUTOMATABLE',
  COMMIT_OUTCOME_UNKNOWN: 'COMMIT_OUTCOME_UNKNOWN',
  OUTCOME_VERIFICATION_UNAVAILABLE: 'OUTCOME_VERIFICATION_UNAVAILABLE',
  OUTCOME_MISMATCH: 'OUTCOME_MISMATCH',
  SERVER_VALIDATION_REJECTED: 'SERVER_VALIDATION_REJECTED',
  RATE_LIMITED: 'RATE_LIMITED',
  BRIDGE_SESSION_CONFLICT: 'BRIDGE_SESSION_CONFLICT',
  BRIDGE_SESSION_PERSISTENCE_FAILED: 'BRIDGE_SESSION_PERSISTENCE_FAILED',
  INVALID_BRIDGE_DATA: 'INVALID_BRIDGE_DATA',
  BRIDGE_INTERNAL_ERROR: 'BRIDGE_INTERNAL_ERROR'
});

const DEFINITIONS = Object.freeze({
  NATIVE_CONTRACT_INVALID: [422, 'Native contract is invalid', 'discovery', BRIDGE_RETRY.NEVER],
  CONTRACT_DOWNGRADE_DETECTED: [409, 'Contract downgrade detected', 'discovery', BRIDGE_RETRY.AFTER_USER_ACTION],
  CONTRACT_AMBIGUOUS: [409, 'Contract evidence is ambiguous', 'inference', BRIDGE_RETRY.AFTER_USER_ACTION],
  CONTRACT_DRIFTED: [409, 'Contract structure changed', 'freshness', BRIDGE_RETRY.AFTER_REFRESH],
  EVIDENCE_STALE: [409, 'Evidence is stale', 'freshness', BRIDGE_RETRY.AFTER_REFRESH],
  FORM_NOT_FOUND: [404, 'No supported form was found', 'inference', BRIDGE_RETRY.NEVER],
  FORM_SUBMITTER_AMBIGUOUS: [409, 'Form submitter is ambiguous', 'inference', BRIDGE_RETRY.AFTER_USER_ACTION],
  FORM_SEMANTICS_UNSUPPORTED: [422, 'Form semantics are unsupported', 'inference', BRIDGE_RETRY.AFTER_ADAPTER_INSTALL],
  FORM_SCRIPT_DEPENDENT: [422, 'Form submission depends on script execution', 'inference', BRIDGE_RETRY.AFTER_ADAPTER_INSTALL],
  SEMANTIC_EFFECT_UNKNOWN: [422, 'Operation effect is unknown', 'policy', BRIDGE_RETRY.AFTER_ADAPTER_INSTALL],
  EFFECT_PREVIEW_UNAVAILABLE: [422, 'Effect preview is unavailable', 'preview', BRIDGE_RETRY.NEVER],
  AUTH_METADATA_INVALID: [422, 'Authentication metadata is invalid', 'auth', BRIDGE_RETRY.NEVER],
  AUTH_EXTERNAL_USER_AGENT_REQUIRED: [409, 'External user authorization is required', 'auth', BRIDGE_RETRY.AFTER_USER_ACTION],
  AUTH_CREDENTIAL_REQUIRED: [401, 'A credential is required', 'auth', BRIDGE_RETRY.AFTER_USER_ACTION],
  AUTH_OTP_REQUIRED: [409, 'A one-time password is required', 'auth', BRIDGE_RETRY.AFTER_USER_ACTION],
  AUTH_MAGIC_LINK_REQUIRED: [409, 'A magic-link interaction is required', 'auth', BRIDGE_RETRY.AFTER_USER_ACTION],
  AUTH_PASSKEY_REQUIRED: [409, 'A passkey or authenticator interaction is required', 'auth', BRIDGE_RETRY.AFTER_USER_ACTION],
  AUTH_CAPTCHA_REQUIRED: [409, 'A CAPTCHA interaction is required', 'auth', BRIDGE_RETRY.NEVER],
  AUTH_STEP_UP_REQUIRED: [409, 'Step-up authorization is required', 'auth', BRIDGE_RETRY.AFTER_USER_ACTION],
  AUTH_SESSION_UNVERIFIED: [401, 'Authentication session is not verified', 'auth', BRIDGE_RETRY.AFTER_USER_ACTION],
  AUTH_SESSION_EXPIRED: [401, 'Authentication session expired', 'auth', BRIDGE_RETRY.AFTER_USER_ACTION],
  AUTH_SUBJECT_CHANGED: [409, 'Authenticated subject changed', 'auth', BRIDGE_RETRY.AFTER_USER_ACTION],
  TLS_REQUIRED: [403, 'TLS is required', 'network', BRIDGE_RETRY.NEVER],
  SSRF_TARGET_BLOCKED: [403, 'Network target is blocked', 'network', BRIDGE_RETRY.NEVER],
  DNS_REBINDING_DETECTED: [403, 'DNS rebinding was detected', 'network', BRIDGE_RETRY.NEVER],
  REDIRECT_POLICY_VIOLATION: [403, 'Redirect violates bridge policy', 'network', BRIDGE_RETRY.NEVER],
  CROSS_ORIGIN_CREDENTIAL_BLOCKED: [403, 'Cross-origin credential forwarding is blocked', 'network', BRIDGE_RETRY.NEVER],
  CREDENTIAL_BINDING_MISMATCH: [403, 'Credential binding does not match the request origin', 'auth', BRIDGE_RETRY.NEVER],
  BODY_LIMIT_EXCEEDED: [413, 'Response or request body limit exceeded', 'network', BRIDGE_RETRY.NEVER],
  PREVIEW_STALE: [409, 'Request preview is stale', 'commit', BRIDGE_RETRY.AFTER_REFRESH],
  APPROVAL_REQUIRED: [428, 'Explicit approval is required', 'commit', BRIDGE_RETRY.AFTER_USER_ACTION],
  APPROVAL_BINDING_MISMATCH: [409, 'Approval does not match this request preview', 'commit', BRIDGE_RETRY.AFTER_USER_ACTION],
  IDEMPOTENCY_UNAVAILABLE: [409, 'Upstream idempotency is not established', 'commit', BRIDGE_RETRY.NEVER],
  COMMIT_NOT_AUTOMATABLE: [422, 'Operation is not eligible for automated commit', 'commit', BRIDGE_RETRY.NEVER],
  COMMIT_OUTCOME_UNKNOWN: [409, 'Remote operation outcome is unknown', 'outcome', BRIDGE_RETRY.NEVER],
  OUTCOME_VERIFICATION_UNAVAILABLE: [422, 'Outcome cannot be verified', 'outcome', BRIDGE_RETRY.NEVER],
  OUTCOME_MISMATCH: [409, 'Observed outcome does not match the expected postcondition', 'outcome', BRIDGE_RETRY.NEVER],
  SERVER_VALIDATION_REJECTED: [422, 'Upstream server rejected the submitted values', 'outcome', BRIDGE_RETRY.AFTER_USER_ACTION],
  RATE_LIMITED: [429, 'Operation is rate limited', 'network', BRIDGE_RETRY.AFTER_REFRESH],
  BRIDGE_SESSION_CONFLICT: [409, 'Bridge session is in use or has changed', 'cli_session', BRIDGE_RETRY.AFTER_REFRESH],
  BRIDGE_SESSION_PERSISTENCE_FAILED: [500, 'Bridge session could not be persisted safely', 'cli_session', BRIDGE_RETRY.NEVER],
  INVALID_BRIDGE_DATA: [400, 'Bridge data is invalid', 'bridge', BRIDGE_RETRY.NEVER],
  BRIDGE_INTERNAL_ERROR: [500, 'Bridge could not complete the operation', 'bridge', BRIDGE_RETRY.NEVER]
});

const CODE_SET = new Set(Object.values(BRIDGE_REFUSAL_CODES));
const RETRY_SET = new Set(Object.values(BRIDGE_RETRY));
const SCHEMA_URI_SET = new Set(Object.values(HTTP_BRIDGE_SCHEMAS));
const PROBLEM_TYPE_SET = new Set([...CODE_SET].map(httpBridgeProblemType));

function redactProblemPath(pathname) {
  return String(pathname).split('/').map((segment) => segment ? '~redacted' : segment).join('/');
}

function redactProblemLocation(value) {
  try {
    const parsed = new URL(value);
    parsed.username = '';
    parsed.password = '';
    parsed.pathname = redactProblemPath(parsed.pathname);
    parsed.search = parsed.search ? '?redacted' : '';
    parsed.hash = '';
    return parsed.href;
  } catch {
    return String(value).startsWith('/') ? redactProblemPath(value) : '<redacted-location>';
  }
}

function sanitizeProblemText(value) {
  return String(value)
    .replace(/https?:\/\/[^\s<>"']+/gi, (candidate) => redactProblemLocation(candidate))
    .replace(/(^|\s)(\/[A-Za-z0-9._~!$&()*+,;=:@%/-]+)/g, (_match, prefix, path) => `${prefix}${redactProblemPath(path)}`);
}

function isSensitiveProblemKey(key) {
  return /(?:^|_)(?:authorization|bearer|cookie|set_cookie|password|passwd|token|access_token|refresh_token|id_token|otp|secret|client_secret|api_?key|apikey|credentials?|csrf|xsrf|magic_?link|magiclink|assertion|signature|state|nonce|code_verifier|code_challenge|vault_ref|raw_body|request_body|response_body)(?:$|_)/i.test(key);
}

function sanitizeProblemValue(value, key = '', inheritedSensitive = false) {
  const keySensitive = inheritedSensitive || isSensitiveProblemKey(key);
  if (Array.isArray(value)) return value.map((item) => sanitizeProblemValue(item, key, keySensitive));
  if (value && typeof value === 'object') {
    // A plain digest is not provenance. Receipt-shaped arbitrary data is never
    // trusted inside required_action; the CLI carries factory output in a
    // separate, internal-symbol-gated top-level field instead.
    if (value.kind === 'attempt_receipt') {
      return { kind: 'untrusted_attempt_receipt', detail: 'Receipt-shaped required-action data was withheld.' };
    }
    const recordSensitive = keySensitive || ['kind', 'type', 'role'].some((indicator) => (
      typeof value[indicator] === 'string' && isSensitiveProblemKey(value[indicator].toLowerCase().replaceAll('-', '_'))
    ));
    return Object.fromEntries(Object.entries(value).map(([childKey, child]) => {
      const normalizedChildKey = childKey.toLowerCase().replaceAll('-', '_');
      return [childKey, sanitizeProblemValue(child, normalizedChildKey, recordSensitive)];
    }));
  }
  if (typeof value !== 'string') return value;
  if (keySensitive) return '<redacted>';
  if (key === '$schema' && SCHEMA_URI_SET.has(value)) return value;
  if (key === 'type' && PROBLEM_TYPE_SET.has(value)
      && value.startsWith(`${HTTP_BRIDGE_PROBLEM_REGISTRY}?problem=`)) return value;
  if (/(?:^|_)(?:url|uri|href|target|location|endpoint|path|pathname)(?:$|_)/i.test(key)) {
    return /^https?:\/\//i.test(value) || value.startsWith('/')
      ? redactProblemLocation(value)
      : '<redacted-location>';
  }
  if (/^https?:\/\//i.test(value) || value.startsWith('/')) return redactProblemLocation(value);
  return value;
}

function stringList(value, label) {
  if (value === undefined) return [];
  if (!Array.isArray(value) || value.some((item) => typeof item !== 'string' || item.length === 0)) {
    throw new TypeError(`${label} must be an array of non-empty strings`);
  }
  return [...new Set(value)];
}

export function isBridgeRefusalCode(value) {
  return CODE_SET.has(value);
}

export class BridgeError extends Error {
  constructor(code, {
    detail,
    message,
    title,
    status,
    stage,
    retryable,
    evidenceRefs,
    requiredAction,
    cause
  } = {}) {
    if (!isBridgeRefusalCode(code)) throw new TypeError(`Unknown HTTP bridge refusal code: ${code}`);
    const definition = DEFINITIONS[code];
    const finalTitle = title ?? definition[1];
    const finalDetail = detail ?? message ?? finalTitle;
    super(finalDetail, cause === undefined ? undefined : { cause });
    this.name = 'BridgeError';
    this.code = code;
    this.status = status ?? definition[0];
    this.title = finalTitle;
    this.stage = stage ?? definition[2];
    this.retryable = retryable ?? definition[3];
    this.evidenceRefs = stringList(evidenceRefs, 'evidenceRefs');
    this.requiredAction = requiredAction;
    if (!Number.isInteger(this.status) || this.status < 400 || this.status > 599) {
      throw new TypeError('BridgeError status must be an HTTP error status');
    }
    if (!RETRY_SET.has(this.retryable)) throw new TypeError(`Unknown retry policy: ${this.retryable}`);
  }

  toProblem({ instance, requestId } = {}) {
    return {
      type: httpBridgeProblemType(this.code),
      title: sanitizeProblemText(this.title),
      status: this.status,
      detail: sanitizeProblemText(this.message),
      code: this.code,
      stage: this.stage,
      retryable: this.retryable,
      ...(this.evidenceRefs.length ? { evidence_refs: [...this.evidenceRefs] } : {}),
      ...(this.requiredAction === undefined ? {} : { required_action: sanitizeProblemValue(this.requiredAction) }),
      ...(instance === undefined ? {} : { instance: sanitizeProblemValue(instance) }),
      ...(requestId === undefined ? {} : { request_id: requestId })
    };
  }
}

export function asBridgeError(error, fallback = {}) {
  if (error instanceof BridgeError) return error;
  return new BridgeError(BRIDGE_REFUSAL_CODES.BRIDGE_INTERNAL_ERROR, {
    detail: fallback.detail,
    status: fallback.status,
    stage: fallback.stage,
    evidenceRefs: fallback.evidenceRefs,
    cause: error
  });
}

export function bridgeProblem(error, options) {
  const bridgeError = asBridgeError(error);
  return { status: bridgeError.status, body: bridgeError.toProblem(options) };
}
