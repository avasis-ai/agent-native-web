import { randomBytes } from 'node:crypto';
import { detectOAuthAuthorizationRequest, discoverAuthSignals } from './auth-discovery.mjs';
import { ASSURANCE_LEVELS, createAssuranceVector } from './assurance.mjs';
import { BRIDGE_REFUSAL_CODES, BridgeError } from './errors.mjs';
import { buildFormSubmission, compileForms } from './form-compiler.mjs';
import { parseHtmlSource } from './html-source.mjs';
import { HttpSession, createHttpSession } from './http-session.mjs';
import {
  bytesHmacSha256,
  canonicalHmacSha256,
  canonicalSha256,
  createAttemptReceipt,
  createInferredContract,
  createRequestPreview
} from './profile.mjs';

const HTML_ACCEPT = 'text/html,application/xhtml+xml;q=0.9,*/*;q=0.1';
const APPLICATION_TRANSPORT_PROFILE = 'undici-fetch-v8; browser-navigation-headers-not-emulated';
const BRIDGE_USER_AGENT = 'agent-native-web-http-bridge/0.1';
const PUBLIC_MEDIA_TYPES = new Set([
  'text/html',
  'application/xhtml+xml',
  'application/json',
  'application/problem+json',
  'text/plain',
  'application/octet-stream',
  'application/x-www-form-urlencoded',
  'image/png',
  'image/jpeg',
  'image/webp',
  'image/gif'
]);

function asDate(now) {
  const value = typeof now === 'function' ? now() : new Date();
  const date = value instanceof Date ? new Date(value) : new Date(value);
  if (!Number.isFinite(date.getTime())) throw new TypeError('now() must return a valid date or timestamp');
  return date;
}

function receiptObservedAt(now, startedAt) {
  try {
    const observed = asDate(now);
    return observed.getTime() < startedAt.getTime() ? new Date(startedAt) : observed;
  } catch {
    // Dispatch evidence must survive a faulty or adjusted wall clock. The
    // receipt records a zero-duration observation rather than disappearing.
    return new Date(startedAt);
  }
}

function positiveInteger(value, label) {
  if (!Number.isInteger(value) || value < 1) throw new TypeError(`${label} must be a positive integer`);
  return value;
}

function mediaType(headers) {
  return headers.get('content-type') ?? 'application/octet-stream';
}

function publicContentType(headers, digestKey) {
  const raw = headers.get('content-type');
  if (raw === null) return { content_type: null };
  const essence = raw.split(';', 1)[0].trim().toLowerCase();
  const safeEssence = PUBLIC_MEDIA_TYPES.has(essence) ? essence : 'other';
  const charsetMatch = raw.match(/(?:^|;)\s*charset\s*=\s*(?:"([^"]+)"|'([^']+)'|([^;\s]+))/i);
  const charset = (charsetMatch?.[1] ?? charsetMatch?.[2] ?? charsetMatch?.[3] ?? '').trim().toLowerCase();
  const safeCharset = ['utf-8', 'utf8', 'us-ascii', 'ascii'].includes(charset)
    ? charset === 'utf8' ? 'utf-8' : charset === 'ascii' ? 'us-ascii' : charset
    : null;
  return {
    content_type: safeEssence,
    ...(safeCharset ? { content_charset: safeCharset } : {}),
    ...((safeEssence === 'other' || raw.includes(';'))
      ? { content_type_metadata_digest: canonicalHmacSha256(raw, digestKey) }
      : {})
  };
}

function findingRefusals(compiled, auth) {
  const blockers = compiled.findings.filter((item) => item.blocking);
  const result = [];
  if (!compiled.contract.forms.length) {
    result.push(new BridgeError(BRIDGE_REFUSAL_CODES.FORM_NOT_FOUND, {
      detail: 'No supported static HTML form was found in this response.',
      stage: 'inference'
    }));
  }
  if (blockers.some((item) => /SCRIPT/.test(item.code))) {
    result.push(new BridgeError(BRIDGE_REFUSAL_CODES.FORM_SCRIPT_DEPENDENT, {
      detail: 'At least one candidate form depends on script behavior that the inert bridge cannot reproduce.',
      stage: 'inference'
    }));
  }
  if (blockers.length && !compiled.contract.actions.some((action) => action.executable)) {
    result.push(new BridgeError(BRIDGE_REFUSAL_CODES.FORM_SEMANTICS_UNSUPPORTED, {
      detail: 'The discovered forms use semantics outside the conservative standard-HTML subset.',
      stage: 'inference'
    }));
  }
  const interactionCodes = new Set(auth.required_interactions.map((item) => item.code));
  for (const code of interactionCodes) {
    if (Object.values(BRIDGE_REFUSAL_CODES).includes(code)) {
      result.push(new BridgeError(code, {
        detail: 'Static authentication evidence requires an interaction the HTTP bridge does not perform automatically.',
        stage: 'auth',
        requiredAction: auth.required_interactions.find((item) => item.code === code)
      }));
    }
  }
  return result;
}

function operationRecords(compiled) {
  const forms = new Map(compiled.contract.forms.map((form) => [form.form_id, form]));
  return compiled.contract.actions.map((action) => {
    const form = forms.get(action.form_id);
    return {
      operation_id: action.action_id,
      kind: 'html_form_submission_candidate',
      label: action.label,
      method: action.method,
      enctype: action.enctype,
      target: action.target,
      input_schema: action.input_schema,
      fields: form?.fields ?? [],
      submitter: action.submitter,
      validation_bypassed: action.validation_bypassed,
      executable: action.executable,
      derivation: action.derivation,
      assurance: action.assurance,
      findings: action.findings
    };
  });
}

const HARD_AUTH_INTERACTIONS = new Set([
  BRIDGE_REFUSAL_CODES.AUTH_CAPTCHA_REQUIRED,
  BRIDGE_REFUSAL_CODES.AUTH_PASSKEY_REQUIRED,
  BRIDGE_REFUSAL_CODES.AUTH_EXTERNAL_USER_AGENT_REQUIRED
]);

function hardInteractionForOperation(auth, form, action) {
  if (!form || !action) return null;
  return auth.required_interactions.find((item) => {
    if (!HARD_AUTH_INTERACTIONS.has(item.code)) return false;
    const formMatches = item.form_context?.start_offset !== null && item.form_context?.start_offset !== undefined
      ? item.form_context.start_offset === form.source?.start_offset
      : Boolean(item.form_context?.html_id && item.form_context.html_id === form.html_id);
    if (!formMatches) return false;
    if (!item.submitter_context) return true;
    return item.submitter_context.start_offset !== null
      && item.submitter_context.start_offset !== undefined
      && item.submitter_context.start_offset === action.submitter?.source?.start_offset;
  }) ?? null;
}

function oauthInteractionForSubmission(submission) {
  const candidate = detectOAuthAuthorizationRequest(
    submission.url,
    submission.method === 'POST' ? submission.private_entries : []
  );
  if (!candidate) return null;
  return Object.freeze({
    code: BRIDGE_REFUSAL_CODES.AUTH_EXTERNAL_USER_AGENT_REQUIRED,
    kind: 'open_authorization_url',
    blocking: true,
    authorization_target: {
      origin: candidate.authorization_origin,
      path: candidate.authorization_path
    }
  });
}

function authenticationHandoff(interaction) {
  return new BridgeError(interaction.code, {
    detail: 'This form action requires an authentication interaction that the HTTP bridge will not emulate.',
    stage: 'auth',
    requiredAction: interaction
  });
}

function overallInputAssurance(compiled) {
  const executable = compiled.contract.actions.filter((action) => action.executable);
  if (!executable.length) return ASSURANCE_LEVELS.CONFLICTED;
  if (executable.some((action) => action.assurance.input_completeness === ASSURANCE_LEVELS.HEURISTIC)) {
    return ASSURANCE_LEVELS.HEURISTIC;
  }
  return ASSURANCE_LEVELS.DIRECT;
}

function responseEvidence(response, digestKey) {
  return {
    kind: 'http_response',
    source: 'hardened_http_session',
    url: response.url,
    method: response.method,
    status: response.status,
    ...publicContentType(response.headers, digestKey),
    byte_length: response.body.byteLength,
    body_digest: bytesHmacSha256(response.body, digestKey),
    redirects: response.redirects,
    cookie_updates: response.cookieStats
  };
}

function parseEvidence(source, compiled, auth, digestKey) {
  return {
    kind: 'static_html_inference',
    source: 'parse5_inert_tree',
    source_url: source.source_url,
    source_fingerprint: canonicalHmacSha256(source.source_fingerprint, digestKey),
    encoding: source.encoding,
    parse_error_count: source.parse_errors.length,
    form_count: compiled.contract.forms.length,
    executable_action_count: compiled.contract.actions.filter((action) => action.executable).length,
    finding_codes: [...new Set(compiled.findings.map((item) => item.code))].sort(),
    auth: {
      authenticated: auth.authenticated,
      signals: auth.signals,
      interaction_candidates: auth.interaction_candidates,
      required_interactions: auth.required_interactions,
      caveat: auth.caveat
    }
  };
}

function responseSummary(response, digestKey) {
  return {
    status: response.status,
    final_url: response.url,
    method: response.method,
    redirected: response.redirected,
    redirect_count: response.redirects.length,
    ...publicContentType(response.headers, digestKey),
    byte_length: response.body.byteLength,
    body_digest: bytesHmacSha256(response.body, digestKey),
    cookie_updates: response.cookieStats
  };
}

function requestDigest(request, digestKey) {
  const url = new URL(request.url);
  url.hash = '';
  return canonicalHmacSha256({
    ...request,
    method: request.method.toUpperCase(),
    url: url.href
  }, digestKey);
}

function validateCredentialBinding(binding, requestUrl) {
  const target = new URL(requestUrl);
  if (!binding || typeof binding !== 'object'
    || binding.kind !== 'cookie_header_binding'
    || binding.target_origin !== target.origin
    || binding.target_path !== target.pathname
    || !['strict', 'lax', 'none'].includes(binding.same_site_context)
    || typeof binding.cookie_header_present !== 'boolean'
    || !/^sha256:[0-9a-f]{64}$/.test(binding.cookie_header_digest ?? '')
    || !/^sha256:[0-9a-f]{64}$/.test(binding.binding_digest ?? '')) {
    throw new BridgeError(BRIDGE_REFUSAL_CODES.BRIDGE_INTERNAL_ERROR, {
      detail: 'The HTTP session returned an invalid credential binding.',
      stage: 'auth'
    });
  }
  return Object.freeze({
    kind: binding.kind,
    target_origin: binding.target_origin,
    target_path: binding.target_path,
    same_site_context: binding.same_site_context,
    cookie_header_present: binding.cookie_header_present,
    cookie_header_digest: binding.cookie_header_digest,
    binding_digest: binding.binding_digest
  });
}

async function bindSessionCredentials(session, request, sourceUrl) {
  const binding = await session.credentialBinding(request.url, {
    method: request.method,
    siteForCookies: sourceUrl,
    topLevelNavigation: true
  });
  return validateCredentialBinding(binding, request.url);
}

function privateRequest(submission, sourceUrl) {
  const target = new URL(submission.url);
  target.hash = '';
  const headers = {
    accept: '*/*',
    'user-agent': BRIDGE_USER_AGENT,
    ...submission.headers,
    ...(submission.method === 'POST' ? { origin: new URL(sourceUrl).origin } : {})
  };
  return {
    method: submission.method,
    url: target.href,
    headers,
    ...(submission.body === null ? {} : { body: submission.body })
  };
}

function publicBindings(contractRecord, submission) {
  const action = contractRecord.compiled.execution_binding.actions[submission.action_id];
  const form = contractRecord.compiled.execution_binding.forms[action.form_id];
  return {
    source_url: contractRecord.finalUrl,
    form_id: form.form_id,
    form_fingerprint: form.fingerprint,
    form_instance_fingerprint: form.instance_fingerprint,
    action_fingerprint: action.fingerprint,
    transport_profile: APPLICATION_TRANSPORT_PROFILE,
    ordered_entry_names: submission.private_entries.map(([name]) => name),
    ordered_entry_count: submission.private_entries.length
  };
}

function previewAssurance(contract) {
  return createAssuranceVector({
    ...contract.assurance,
    freshness: ASSURANCE_LEVELS.DIRECT,
    semantic_effect: ASSURANCE_LEVELS.UNKNOWN,
    retry_safety: ASSURANCE_LEVELS.UNKNOWN,
    outcome_verifiability: ASSURANCE_LEVELS.UNKNOWN
  });
}

export class HttpBridgeClient {
  #contracts = new Map();
  #previews = new Map();
  #digestKey;

  constructor({
    session,
    sessionOptions,
    contractTtlMs = 60_000,
    previewTtlMs = 30_000,
    maxRecords = 100,
    now = () => new Date(),
    digestKey = randomBytes(32)
  } = {}) {
    if (session !== undefined && !(session instanceof HttpSession)
      && (typeof session?.request !== 'function' || typeof session?.credentialBinding !== 'function')) {
      throw new TypeError('session must expose request() and credentialBinding()');
    }
    if (typeof now !== 'function') throw new TypeError('now must be a function');
    if (!(digestKey instanceof Uint8Array) || digestKey.byteLength < 32) {
      throw new TypeError('digestKey must contain at least 32 private random bytes');
    }
    this.session = session ?? createHttpSession(sessionOptions);
    this.contractTtlMs = positiveInteger(contractTtlMs, 'contractTtlMs');
    this.previewTtlMs = positiveInteger(previewTtlMs, 'previewTtlMs');
    this.maxRecords = positiveInteger(maxRecords, 'maxRecords');
    this.now = now;
    this.#digestKey = Buffer.from(digestKey);
  }

  #prune() {
    const time = asDate(this.now).getTime();
    for (const [id, record] of this.#contracts) {
      if (record.expiresAt <= time) this.#contracts.delete(id);
    }
    for (const [id, record] of this.#previews) {
      if (record.expiresAt <= time && !record.receipt && !record.inFlight) {
        record.input = null;
        this.#previews.delete(id);
      }
    }
    while (this.#contracts.size > this.maxRecords) this.#contracts.delete(this.#contracts.keys().next().value);
    while (this.#previews.size > this.maxRecords) {
      const id = [...this.#previews].find(([, record]) => !record.inFlight)?.[0];
      if (id === undefined) break;
      const record = this.#previews.get(id);
      if (record) record.input = null;
      this.#previews.delete(id);
    }
  }

  async #load(url) {
    const response = await this.session.request(url, {
      method: 'GET',
      headers: { accept: HTML_ACCEPT },
      siteForCookies: url,
      topLevelNavigation: true,
      allowCrossOriginRedirects: false
    });
    const requestedOrigin = new URL(url).origin;
    if (new URL(response.url).origin !== requestedOrigin
        || response.redirects.some((redirect) => redirect.crossOrigin)) {
      throw new BridgeError(BRIDGE_REFUSAL_CODES.REDIRECT_POLICY_VIOLATION, {
        detail: 'The form bridge refuses cross-origin navigation; inspect the destination as a separate exact-origin session.',
        stage: 'network'
      });
    }
    const source = parseHtmlSource({
      body: response.body,
      url: response.url,
      contentType: mediaType(response.headers)
    });
    const compiled = compileForms(source, {
      contentSecurityPolicy: response.headers.get('content-security-policy')
    });
    const auth = source.document
      ? discoverAuthSignals(source)
      : { authenticated: 'unverified', signals: [], interaction_candidates: [], required_interactions: [], caveat: 'No inert HTML document was available.' };
    return { response, source, compiled, auth };
  }

  async inspect(url) {
    this.#prune();
    const requestedUrl = new URL(url).href;
    const loaded = await this.#load(requestedUrl);
    const { response, source, compiled, auth } = loaded;
    const observedAt = asDate(this.now);
    const validUntil = new Date(observedAt.getTime() + this.contractTtlMs);
    const executable = compiled.contract.actions.some((action) => action.executable);
    const https = new URL(response.url).protocol === 'https:';
    const assurance = createAssuranceVector({
      origin_authenticity: ASSURANCE_LEVELS.DIRECT,
      transport: https ? ASSURANCE_LEVELS.VERIFIED : ASSURANCE_LEVELS.CONFLICTED,
      input_completeness: overallInputAssurance(compiled),
      semantic_effect: ASSURANCE_LEVELS.UNKNOWN,
      auth_subject: ASSURANCE_LEVELS.UNKNOWN,
      freshness: ASSURANCE_LEVELS.DIRECT,
      retry_safety: ASSURANCE_LEVELS.UNKNOWN,
      outcome_verifiability: ASSURANCE_LEVELS.UNKNOWN
    });
    const contract = createInferredContract({
      rail: executable ? 'standard_html' : 'unsupported',
      automationCeiling: executable ? 'approved_dispatch' : 'inspect',
      target: {
        requested_url: requestedUrl,
        final_url: response.url,
        canonical_origin: new URL(response.url).origin,
        status: response.status,
        ...publicContentType(response.headers, this.#digestKey)
      },
      assurance,
      observedAt,
      validUntil,
      session: {
        cookie_updates: response.cookieStats,
        authenticated_subject: 'unverified'
      },
      fingerprints: {
        source_document: canonicalHmacSha256(source.source_fingerprint, this.#digestKey),
        compiled_contract: canonicalHmacSha256(
          compiled.contract.contract_fingerprint ?? {
            state: 'unavailable',
            finding_codes: [...new Set(compiled.findings.map((item) => item.code))].sort()
          },
          this.#digestKey
        )
      },
      evidence: [responseEvidence(response, this.#digestKey), parseEvidence(source, compiled, auth, this.#digestKey)],
      operations: operationRecords(compiled),
      refusals: findingRefusals(compiled, auth),
      digestKey: this.#digestKey
    });

    this.#contracts.set(contract.contract_id, {
      contract,
      compiled,
      auth,
      requestedUrl,
      finalUrl: response.url,
      expiresAt: validUntil.getTime()
    });
    this.#prune();
    return contract;
  }

  async prepare({ contractId, actionId, input = {} } = {}) {
    this.#prune();
    const record = this.#contracts.get(contractId);
    if (!record) {
      throw new BridgeError(BRIDGE_REFUSAL_CODES.EVIDENCE_STALE, {
        detail: 'The inferred contract is missing or expired; inspect the page again.',
        stage: 'preview'
      });
    }
    const selectedAction = record.compiled.execution_binding.actions[actionId];
    const selectedPublicAction = record.compiled.contract.actions.find((item) => item.action_id === actionId);
    const selectedForm = selectedAction
      ? record.compiled.contract.forms.find((item) => item.form_id === selectedAction.form_id)
      : null;
    const hardInteraction = hardInteractionForOperation(record.auth, selectedForm, selectedPublicAction);
    if (hardInteraction) {
      throw authenticationHandoff(hardInteraction);
    }
    const submission = buildFormSubmission(record.compiled.execution_binding, actionId, input);
    const oauthInteraction = oauthInteractionForSubmission(submission);
    if (oauthInteraction) throw authenticationHandoff(oauthInteraction);
    const request = privateRequest(submission, record.finalUrl);
    const credentialBinding = await bindSessionCredentials(this.session, request, record.finalUrl);
    if (this.#contracts.get(contractId) !== record || record.expiresAt <= asDate(this.now).getTime()) {
      throw new BridgeError(BRIDGE_REFUSAL_CODES.EVIDENCE_STALE, {
        detail: 'The inferred contract expired while session credentials were being bound; inspect the page again.',
        stage: 'preview'
      });
    }
    const boundRequest = { ...request, credential_binding: credentialBinding };
    const createdAt = asDate(this.now);
    const expiresAt = new Date(createdAt.getTime() + this.previewTtlMs);
    const preview = createRequestPreview({
      contractId,
      operationId: actionId,
      request: boundRequest,
      assurance: previewAssurance(record.contract),
      evidenceRefs: record.contract.evidence.map((item) => item.id),
      bindings: publicBindings(record, submission),
      risk: 'unknown',
      requiresApproval: true,
      createdAt,
      expiresAt,
      digestKey: this.#digestKey
    });
    this.#previews.set(preview.preview_id, {
      preview,
      contractId,
      actionId,
      input: structuredClone(input),
      requestDigest: requestDigest(boundRequest, this.#digestKey),
      credentialBindingDigest: credentialBinding.binding_digest,
      sourceUrl: record.finalUrl,
      bindings: publicBindings(record, submission),
      expiresAt: expiresAt.getTime(),
      receipt: null,
      inFlight: null
    });
    this.#prune();
    return preview;
  }

  async dispatch(previewId, {
    approvalDigest,
    allowUnverifiedWrite = false,
    approvalExpiresAt,
    beforeDispatch
  } = {}) {
    this.#prune();
    const record = this.#previews.get(previewId);
    if (!record) {
      throw new BridgeError(BRIDGE_REFUSAL_CODES.PREVIEW_STALE, {
        detail: 'The request preview is missing or expired.',
        stage: 'dispatch'
      });
    }
    if (record.receipt) return record.receipt;
    let approvalDeadline = record.expiresAt;
    if (approvalExpiresAt !== undefined) {
      const portableDeadline = new Date(approvalExpiresAt).getTime();
      if (!Number.isFinite(portableDeadline)) {
        throw new BridgeError(BRIDGE_REFUSAL_CODES.INVALID_BRIDGE_DATA, {
          detail: 'approvalExpiresAt must be a valid date-time.',
          stage: 'dispatch'
        });
      }
      approvalDeadline = Math.min(approvalDeadline, portableDeadline);
    }
    const assertApprovalFresh = () => {
      if (this.#previews.get(previewId) !== record || approvalDeadline <= asDate(this.now).getTime()) {
        throw new BridgeError(BRIDGE_REFUSAL_CODES.PREVIEW_STALE, {
          detail: 'The request approval expired before the approved dispatch began.',
          stage: 'freshness'
        });
      }
    };
    assertApprovalFresh();
    const { preview_digest: attachedPreviewDigest, ...previewBody } = record.preview;
    if (canonicalSha256(previewBody) !== attachedPreviewDigest) {
      throw new BridgeError(BRIDGE_REFUSAL_CODES.APPROVAL_BINDING_MISMATCH, {
        detail: 'The stored request preview was modified after issuance.',
        stage: 'dispatch'
      });
    }
    if (!approvalDigest) {
      throw new BridgeError(BRIDGE_REFUSAL_CODES.APPROVAL_REQUIRED, {
        detail: 'Every inferred form submission requires approval of its exact preview digest.',
        stage: 'dispatch',
        requiredAction: { kind: 'approve_preview_digest', preview_digest: record.preview.preview_digest }
      });
    }
    if (approvalDigest !== record.preview.preview_digest) {
      throw new BridgeError(BRIDGE_REFUSAL_CODES.APPROVAL_BINDING_MISMATCH, {
        detail: 'The supplied approval digest does not match this request preview.',
        stage: 'dispatch'
      });
    }
    if (allowUnverifiedWrite !== true) {
      throw new BridgeError(BRIDGE_REFUSAL_CODES.COMMIT_NOT_AUTOMATABLE, {
        detail: 'Generic HTML cannot establish the business effect or outcome verifier. Set allowUnverifiedWrite only after accepting that limitation.',
        stage: 'dispatch',
        requiredAction: { kind: 'acknowledge_unverified_remote_effect' }
      });
    }
    if (beforeDispatch !== undefined && typeof beforeDispatch !== 'function') {
      throw new BridgeError(BRIDGE_REFUSAL_CODES.INVALID_BRIDGE_DATA, {
        detail: 'beforeDispatch must be an async function when supplied.',
        stage: 'dispatch'
      });
    }

    if (record.inFlight) return record.inFlight;
    const run = (async () => {

    const startedAt = asDate(this.now);
    let fresh;
    try {
      fresh = await this.#load(record.sourceUrl);
    } catch (error) {
      throw new BridgeError(BRIDGE_REFUSAL_CODES.PREVIEW_STALE, {
        detail: 'The source form could not be re-fetched before dispatch.',
        stage: 'freshness',
        cause: error
      });
    }
    const oldAction = this.#contracts.get(record.contractId)?.compiled.execution_binding.actions[record.actionId];
    const freshAction = fresh.compiled.execution_binding.actions[record.actionId];
    const oldForm = oldAction && this.#contracts.get(record.contractId)?.compiled.execution_binding.forms[oldAction.form_id];
    const freshForm = freshAction && fresh.compiled.execution_binding.forms[freshAction.form_id];
    const freshPublicAction = fresh.compiled.contract.actions.find((item) => item.action_id === record.actionId);
    const freshPublicForm = freshAction
      ? fresh.compiled.contract.forms.find((item) => item.form_id === freshAction.form_id)
      : null;
    const freshHardInteraction = hardInteractionForOperation(fresh.auth, freshPublicForm, freshPublicAction);
    if (freshHardInteraction) throw authenticationHandoff(freshHardInteraction);
    if (!oldAction || !freshAction || !oldForm || !freshForm
      || oldAction.fingerprint !== freshAction.fingerprint
      || oldForm.fingerprint !== freshForm.fingerprint
      || oldForm.instance_fingerprint !== freshForm.instance_fingerprint) {
      throw new BridgeError(BRIDGE_REFUSAL_CODES.PREVIEW_STALE, {
        detail: 'The form structure, submitter, or managed hidden values changed after preview; inspect and approve a new request.',
        stage: 'freshness'
      });
    }

    const freshSubmission = buildFormSubmission(fresh.compiled.execution_binding, record.actionId, record.input);
    const freshOAuthInteraction = oauthInteractionForSubmission(freshSubmission);
    if (freshOAuthInteraction) throw authenticationHandoff(freshOAuthInteraction);
    const request = privateRequest(freshSubmission, record.sourceUrl);
    const credentialBinding = await bindSessionCredentials(this.session, request, record.sourceUrl);
    if (credentialBinding.binding_digest !== record.credentialBindingDigest) {
      throw new BridgeError(BRIDGE_REFUSAL_CODES.CREDENTIAL_BINDING_MISMATCH, {
        detail: 'The session cookies changed after preview; inspect and approve the request again.',
        stage: 'auth'
      });
    }
    const boundRequest = { ...request, credential_binding: credentialBinding };
    if (requestDigest(boundRequest, this.#digestKey) !== record.requestDigest || record.requestDigest !== record.preview.request_digest) {
      throw new BridgeError(BRIDGE_REFUSAL_CODES.APPROVAL_BINDING_MISMATCH, {
        detail: 'The recompiled wire request no longer matches the approved request digest.',
        stage: 'freshness'
      });
    }
    assertApprovalFresh();

    // Cross-process callers can durably spend a one-shot grant here, after
    // every safe freshness and credential check but before any approved send.
    if (beforeDispatch) {
      await beforeDispatch(Object.freeze({
        preview_id: record.preview.preview_id,
        preview_digest: record.preview.preview_digest,
        request_digest: record.preview.request_digest
      }));
      assertApprovalFresh();
    }

    // Consume before dispatch. This local gate prevents a healthy bridge from
    // sending one preview twice; it is not a claim of upstream idempotency.
    record.input = null;
    let receipt;
    let requestInvoked = false;
    let sessionReturned = false;
    let sessionResponse;
    try {
      requestInvoked = true;
      sessionResponse = await this.session.request(request.url, {
        method: request.method,
        headers: request.headers,
        ...(request.body === undefined ? {} : { body: request.body }),
        siteForCookies: record.sourceUrl,
        topLevelNavigation: true,
        allowCrossOriginRedirects: false,
        expectedCredentialBinding: credentialBinding.binding_digest,
        notAfter: approvalDeadline
      });
      sessionReturned = true;
      receipt = createAttemptReceipt({
        preview: record.preview,
        dispatch: 'response_received',
        outcome: 'unverified',
        response: responseSummary(sessionResponse, this.#digestKey),
        evidenceRefs: record.preview.evidence_refs,
        startedAt,
        observedAt: receiptObservedAt(this.now, startedAt),
        digestKey: this.#digestKey
      });
      record.receipt = receipt;
      return receipt;
    } catch (error) {
      const dispatch = sessionReturned || error?.dispatchState === 'response_received'
        ? 'response_received'
        : error?.dispatchState === 'not_sent'
          ? 'not_sent'
          : requestInvoked
          ? 'transport_ambiguous'
          : 'not_sent';
      const outcome = dispatch === 'transport_ambiguous' ? 'unknown' : 'unverified';
      const response = dispatch === 'response_received'
        ? {
            ...(Number.isInteger(sessionResponse?.status ?? error?.upstreamStatus)
              ? { status: sessionResponse?.status ?? error.upstreamStatus }
              : {}),
            body_unavailable: true
          }
        : undefined;
      const publicError = error instanceof BridgeError
        ? error
        : new BridgeError(
            dispatch === 'transport_ambiguous'
              ? BRIDGE_REFUSAL_CODES.COMMIT_OUTCOME_UNKNOWN
              : BRIDGE_REFUSAL_CODES.BRIDGE_INTERNAL_ERROR,
            {
              detail: dispatch === 'transport_ambiguous'
                ? 'A custom HTTP session failed after request invocation; dispatch cannot be disproved, so the remote outcome is unknown.'
                : dispatch === 'response_received'
                  ? 'The custom HTTP session returned a response that could not be materialized safely.'
                  : 'The custom HTTP session failed before dispatch.',
              stage: dispatch === 'transport_ambiguous' ? 'outcome' : 'network',
              cause: error
            }
          );
      receipt = createAttemptReceipt({
        preview: record.preview,
        dispatch,
        outcome,
        response,
        error: publicError,
        evidenceRefs: record.preview.evidence_refs,
        startedAt,
        observedAt: receiptObservedAt(this.now, startedAt),
        digestKey: this.#digestKey
      });
      record.receipt = receipt;
      if (publicError && typeof publicError === 'object' && Object.isExtensible(publicError)) {
        publicError.attemptReceipt = receipt;
      }
      throw publicError;
    }
    })();
    record.inFlight = run;
    try {
      return await run;
    } finally {
      record.inFlight = null;
    }
  }

  getAttemptReceipt(previewId) {
    return this.#previews.get(previewId)?.receipt ?? null;
  }

  async clearSession() {
    const inFlight = [...this.#previews.values()]
      .map((record) => record.inFlight)
      .filter(Boolean);
    if (inFlight.length) await Promise.allSettled(inFlight);
    for (const record of this.#previews.values()) record.input = null;
    this.#previews.clear();
    this.#contracts.clear();
    if (typeof this.session.cookieJar?.removeAllCookies === 'function') {
      await this.session.cookieJar.removeAllCookies();
    }
  }
}

export function createHttpBridgeClient(options) {
  return new HttpBridgeClient(options);
}
