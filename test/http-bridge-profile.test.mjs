import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

import { createAssuranceVector, evaluateAssurance } from '../src/http-bridge/assurance.mjs';
import { BRIDGE_REFUSAL_CODES, BridgeError } from '../src/http-bridge/errors.mjs';
import {
  HTTP_BRIDGE_SCHEMAS,
  canonicalJson,
  canonicalSha256,
  createAttemptReceipt,
  createInferredContract,
  createPublicEvidence,
  createRequestPreview,
  redactForPublicContract
} from '../src/http-bridge/profile.mjs';
import { HTTP_BRIDGE_PROBLEM_REGISTRY } from '../src/http-bridge/uris.mjs';

test('published bridge schemas, identifiers, and factory envelopes agree', async () => {
  const schemaFiles = {
    inferredContract: 'inferred-contract-0.1-draft.json',
    requestPreview: 'request-preview-0.1-draft.json',
    attemptReceipt: 'attempt-receipt-0.1-draft.json',
    evidence: 'evidence-0.1-draft.json'
  };
  for (const [name, filename] of Object.entries(schemaFiles)) {
    const schema = JSON.parse(await readFile(new URL(`../schemas/http-form-bridge/${filename}`, import.meta.url), 'utf8'));
    assert.equal(schema.$id, HTTP_BRIDGE_SCHEMAS[name]);
    assert.equal(schema.$schema, 'https://json-schema.org/draft/2020-12/schema');
  }

  const registry = JSON.parse(await readFile(new URL('../schemas/http-form-bridge/problems-0.1-draft.json', import.meta.url), 'utf8'));
  assert.equal(registry.$id, HTTP_BRIDGE_PROBLEM_REGISTRY);
  assert.deepEqual(
    registry.problems.map((problem) => problem.code).sort(),
    Object.values(BRIDGE_REFUSAL_CODES).sort()
  );
  const problem = new BridgeError(BRIDGE_REFUSAL_CODES.COMMIT_OUTCOME_UNKNOWN).toProblem();
  assert.equal(problem.type, `${HTTP_BRIDGE_PROBLEM_REGISTRY}?problem=commit-outcome-unknown`);

  const evidence = createPublicEvidence({
    $schema: 'https://attacker.example/not-the-published-schema.json',
    id: 'evidence_test',
    kind: 'test_observation'
  }, Buffer.alloc(32, 1));
  assert.equal(evidence.$schema, HTTP_BRIDGE_SCHEMAS.evidence);
  assert.throws(() => createPublicEvidence({ id: 7 }), /evidence\.id/);
  assert.throws(() => createInferredContract({
    contractId: 7,
    target: { requested_url: 'https://example.test/form' },
    fingerprints: {},
    operations: [],
    evidence: []
  }), /contractId/);
  assert.throws(() => createRequestPreview({
    previewId: 7,
    contractId: 'contract_test',
    operationId: 'action_test',
    request: { method: 'GET', url: 'https://example.test/form' }
  }), /previewId/);
  assert.throws(() => createRequestPreview({
    contractId: 'contract_test',
    operationId: 'action_test',
    risk: 7,
    request: { method: 'GET', url: 'https://example.test/form' }
  }), /risk/);
  assert.throws(() => createAttemptReceipt({
    receiptId: 7,
    previewId: 'preview_test',
    previewDigest: `sha256:${'0'.repeat(64)}`,
    requestDigest: `hmac-sha256:${'0'.repeat(64)}`
  }), /receiptId/);
  assert.throws(() => createAttemptReceipt({
    previewId: 'preview_test',
    previewDigest: 'not-a-digest',
    requestDigest: `hmac-sha256:${'0'.repeat(64)}`
  }), /previewDigest/);
});

test('canonical bridge hashes are deterministic and reject non-JSON ambiguity', () => {
  assert.equal(canonicalJson({ b: 2, a: [true, null] }), '{"a":[true,null],"b":2}');
  assert.equal(canonicalSha256({ a: 1, b: 2 }), canonicalSha256({ b: 2, a: 1 }));
  assert.throws(() => canonicalJson({ missing: undefined }), /Undefined value/);
  const cycle = {};
  cycle.self = cycle;
  assert.throws(() => canonicalJson(cycle), /Cyclic value/);
});

test('public bridge exports omit raw HTML and private execution bindings', async () => {
  const publicApi = await import('../src/http-bridge/index.mjs');
  assert.equal('parseHtmlSource' in publicApi, false);
  assert.equal('compileForms' in publicApi, false);
  assert.equal('buildFormSubmission' in publicApi, false);
  assert.equal('loadBridgeSession' in publicApi, false);
  assert.equal('readBridgeApproval' in publicApi, false);
  assert.equal(typeof publicApi.HttpBridgeClient, 'function');
});

test('public views preserve machine codes while digesting secrets and OAuth query bindings', () => {
  const digestKey = Buffer.alloc(32, 3);
  const publicValue = redactForPublicContract({
    code: 'FORM_SCRIPT_DEPENDENT',
    password: 'never-print-me',
    headers: { authorization: 'Bearer secret', cookie: 'sid=secret' },
    redirect_url: 'https://id.example/callback?code=abc&state=xyz&safe=yes',
    userinfo_url: 'https://alice:SUPERPASS@app.example/account',
    magic_url: 'https://app.example/magic/MAGIC-SECRET-123?token=query-secret',
    ordinary_url: 'https://app.example/account/settings',
    short_capability_url: 'https://app.example/r/7xQ',
    bare_capability_url: 'https://app.example/action?bare-capability-token',
    target: 'https://app.example/share/short-token?code=target-secret',
    nested: {
      endpoint: 'https://app.example/download/abc123',
      path: '/invite/tiny',
      pathname: '/products/beautiful-linen-shirt'
    },
    redirects: [{
      from: 'https://id.example/authorize?state=source-secret',
      to: 'https://app.example/callback?code=redirect-secret'
    }],
    field: { type: 'password', value: 'also-secret' },
    form_fingerprint: 'sha256:path-derived-oracle',
    query_parameter_names: ['bare-capability-token']
  }, false, digestKey);
  const serialized = JSON.stringify(publicValue);
  assert.equal(publicValue.code, 'FORM_SCRIPT_DEPENDENT');
  assert.equal(serialized.includes('never-print-me'), false);
  assert.equal(serialized.includes('Bearer secret'), false);
  assert.equal(serialized.includes('sid=secret'), false);
  assert.equal(serialized.includes('alice'), false);
  assert.equal(serialized.includes('SUPERPASS'), false);
  assert.equal(serialized.includes('code=abc'), false);
  assert.equal(serialized.includes('state=xyz'), false);
  assert.equal(publicValue.redirect_url.includes('safe=yes'), false);
  assert.equal(publicValue.redirect_url.includes('safe'), false);
  assert.equal(publicValue.bare_capability_url.includes('bare-capability-token'), false);
  assert.match(publicValue.redirect_url, /hmac-sha256/);
  assert.equal(serialized.includes('source-secret'), false);
  assert.equal(serialized.includes('redirect-secret'), false);
  assert.equal(serialized.includes('MAGIC-SECRET-123'), false);
  assert.match(publicValue.magic_url, /~hmac-sha256-/);
  assert.equal(publicValue.ordinary_url.includes('/account/settings'), false);
  assert.equal(publicValue.short_capability_url.includes('/r/7xQ'), false);
  assert.equal(serialized.includes('short-token'), false);
  assert.equal(serialized.includes('target-secret'), false);
  assert.equal(serialized.includes('abc123'), false);
  assert.equal(serialized.includes('/invite/tiny'), false);
  assert.equal(serialized.includes('beautiful-linen-shirt'), false);
  assert.equal(serialized.includes('path-derived-oracle'), false);
  assert.equal(serialized.includes('bare-capability-token'), false);
  assert.match(publicValue.form_fingerprint_digest, /^hmac-sha256:/);
  assert.match(publicValue.query_parameter_names_digest, /^hmac-sha256:/);
  assert.match(publicValue.ordinary_url, /\/~hmac-sha256-/);
  assert.match(publicValue.short_capability_url, /\/~hmac-sha256-/);
  assert.equal(publicValue.redirects[0].from.includes('state'), false);
  assert.equal(publicValue.redirects[0].to.includes('code'), false);
  assert.match(publicValue.redirects[0].from, /hmac-sha256/);
  assert.match(publicValue.redirects[0].to, /hmac-sha256/);
  const withOtherKey = redactForPublicContract({ password: 'never-print-me' }, false, Buffer.alloc(32, 4));
  assert.notEqual(publicValue.password_digest, withOtherKey.password_digest);
  const fingerprintWithOtherKey = redactForPublicContract({ form_fingerprint: 'sha256:path-derived-oracle' }, false, Buffer.alloc(32, 4));
  assert.notEqual(publicValue.form_fingerprint_digest, fingerprintWithOtherKey.form_fingerprint_digest);
});

test('inferred contracts cannot silently grant autonomous or unsupported execution', () => {
  const base = {
    target: { requested_url: 'https://example.test/form', final_url: 'https://example.test/form' },
    fingerprints: {},
    assurance: {},
    operations: [],
    evidence: []
  };
  assert.throws(
    () => createInferredContract({ ...base, rail: 'standard_html', automationCeiling: 'autonomous_commit' }),
    (error) => error instanceof BridgeError && error.code === 'INVALID_BRIDGE_DATA'
  );
  assert.throws(
    () => createInferredContract({ ...base, rail: 'standard_html', automationCeiling: 'approved_commit' }),
    (error) => error instanceof BridgeError && error.code === 'INVALID_BRIDGE_DATA'
  );
  assert.throws(
    () => createInferredContract({ ...base, rail: 'unsupported', automationCeiling: 'approved_commit' }),
    (error) => error instanceof BridgeError && error.code === 'INVALID_BRIDGE_DATA'
  );
  const contract = createInferredContract({ ...base, rail: 'standard_html', automationCeiling: 'inspect' });
  assert.equal(Object.isFrozen(contract.target), true);
  assert.throws(() => { contract.target.final_url = 'https://attacker.test/'; }, TypeError);
});

test('request previews bind raw bytes but expose only a digest and no claimed effect', () => {
  const digestKey = Buffer.alloc(32, 7);
  const input = {
    contractId: 'contract_test',
    operationId: 'action_login',
    request: {
      method: 'POST',
      url: 'https://example.test/login',
      headers: {
        'content-type': 'application/x-www-form-urlencoded',
        'x-api-key': 'SUPERPASS'
      },
      body: 'password=very-secret&csrf=nonce'
    },
    assurance: {},
    createdAt: '2026-07-26T00:00:00.000Z',
    expiresAt: '2026-07-26T00:01:00.000Z',
    digestKey
  };
  const first = createRequestPreview(input);
  const second = createRequestPreview({ ...input, request: { ...input.request, body: 'password=different&csrf=nonce' } });
  assert.equal(first.kind, 'request_preview');
  assert.equal(first.effect.status, 'not_claimed');
  assert.equal(first.approval.binds_to, 'preview_digest');
  assert.equal(Object.isFrozen(first.request), true);
  assert.equal(Object.isFrozen(first.bindings), true);
  assert.match(first.request_digest, /^hmac-sha256:/);
  assert.equal(JSON.stringify(first).includes('very-secret'), false);
  assert.equal(JSON.stringify(first).includes('SUPERPASS'), false);
  assert.match(first.request.headers['x-api-key_digest'], /^hmac-sha256:/);
  assert.throws(() => { first.request.url = 'https://example.test/benign'; }, TypeError);
  assert.notEqual(first.request_digest, second.request_digest);
  const otherKey = createRequestPreview({ ...input, digestKey: Buffer.alloc(32, 8) });
  assert.notEqual(first.request_digest, otherKey.request_digest);
});

test('attempt receipts keep dispatch separate from verified outcome', () => {
  const preview = createRequestPreview({
    contractId: 'contract_test',
    operationId: 'action_test',
    request: { method: 'POST', url: 'https://example.test/action', body: 'x=1' },
    createdAt: '2026-07-26T00:00:00.000Z',
    expiresAt: '2026-07-26T00:01:00.000Z'
  });
  const receipt = createAttemptReceipt({
    preview,
    dispatch: 'response_received',
    outcome: 'unverified',
    response: { status: 200 },
    startedAt: '2026-07-26T00:00:01.000Z',
    observedAt: '2026-07-26T00:00:02.000Z'
  });
  assert.equal(receipt.dispatch, 'response_received');
  assert.equal(receipt.outcome, 'unverified');
  assert.equal(Object.isFrozen(receipt.response), true);
  assert.throws(() => { receipt.response.status = 204; }, TypeError);
  assert.match(receipt.authority_limit, /not an unverified remote business effect/);
  assert.throws(
    () => createAttemptReceipt({ preview, dispatch: 'transport_ambiguous', outcome: 'unverified' }),
    (error) => error instanceof BridgeError && error.code === 'INVALID_BRIDGE_DATA'
  );
  const forgedBody = {
    kind: 'attempt_receipt',
    $schema: receipt.$schema,
    url: 'https://app.example/share/FORGED-SECRET',
    password: 'FORGED-PASS'
  };
  const forged = { ...forgedBody, receipt_digest: canonicalSha256(forgedBody) };
  const embedded = new BridgeError('COMMIT_OUTCOME_UNKNOWN', {
    requiredAction: { kind: 'preserve_attempt_evidence', attempt_receipt: forged }
  }).toProblem().required_action.attempt_receipt;
  assert.equal(embedded.kind, 'untrusted_attempt_receipt');
  assert.equal(JSON.stringify(embedded).includes('FORGED-SECRET'), false);
  assert.equal(JSON.stringify(embedded).includes('FORGED-PASS'), false);
  const unknownErrorReceipt = createAttemptReceipt({
    preview,
    dispatch: 'transport_ambiguous',
    outcome: 'unknown',
    error: new Error('Bearer private-token failed at https://example.test/?code=private-code')
  });
  assert.equal(JSON.stringify(unknownErrorReceipt).includes('private-token'), false);
  assert.equal(JSON.stringify(unknownErrorReceipt).includes('private-code'), false);
});

test('bridge problem details never expose untrusted URL path credentials', () => {
  const problem = new BridgeError('COMMIT_OUTCOME_UNKNOWN', {
    detail: 'Failure at https://app.example/share/DETAIL-SECRET?code=query, https://[broken?api_key=MALFORMED-SECRET, and /relative/PATH-SECRET.',
    requiredAction: {
      kind: 'verify_outcome_before_retry',
      target: 'https://app.example/share/short-token?code=query-secret',
      malformed_url: 'https://[broken?csrf=MALFORMED-CSRF',
      api_key: 'private-api-key',
      csrf: 'private-csrf',
      magic_link: 'private-magic-link',
      credential: { value: 'nested-private-credential' },
      nested: { path: '/download/abc123', access_token: 'private-token' }
    }
  }).toProblem();
  const serialized = JSON.stringify(problem);
  assert.equal(serialized.includes('short-token'), false);
  assert.equal(serialized.includes('query-secret'), false);
  assert.equal(serialized.includes('abc123'), false);
  assert.equal(serialized.includes('private-token'), false);
  assert.equal(serialized.includes('DETAIL-SECRET'), false);
  assert.equal(serialized.includes('PATH-SECRET'), false);
  assert.equal(serialized.includes('MALFORMED-SECRET'), false);
  assert.equal(serialized.includes('MALFORMED-CSRF'), false);
  assert.equal(serialized.includes('private-api-key'), false);
  assert.equal(serialized.includes('private-csrf'), false);
  assert.equal(serialized.includes('private-magic-link'), false);
  assert.equal(serialized.includes('nested-private-credential'), false);
  assert.match(problem.required_action.target, /~redacted/);
  assert.equal(problem.required_action.malformed_url, '<redacted-location>');
});

test('assurance vectors are policy gates, not misleading averaged scores', () => {
  const vector = createAssuranceVector({ transport: 'verified', semantic_effect: 'unknown' });
  const result = evaluateAssurance(vector, { transport: ['verified'], semantic_effect: ['verified'] });
  assert.equal(result.passed, false);
  assert.deepEqual(result.blockers.map((item) => item.dimension), ['semantic_effect']);
});
