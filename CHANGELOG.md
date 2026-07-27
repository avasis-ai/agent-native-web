# Changelog

This file records notable project changes. The project follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Community contribution, conduct, and security policies.
- GitHub issue forms, pull request guidance, and continuous integration.
- Explicit HTTP Form Bridge compatibility rail for static legacy forms, with inert parse5 compilation and ordered successful-control encoding.
- Hardened HTTP session with DNS/IP validation, connection pinning, redirect credential stripping, cookie/SameSite handling, and bounded responses.
- Evidence-first assurance vectors, typed refusal problems, redacted request previews, and dispatch/outcome-separated attempt receipts.
- Static authentication signals for credentials, OTP, magic links, OAuth candidates, passkeys, and CAPTCHA, plus conservative authorization-metadata validation.
- `agentweb bridge inspect|prepare|submit`, a local bridge benchmark, and adversarial network/form/client/CLI tests.
- Session-bound approvals with pre-dispatch cookie rechecks, keyed public fingerprints, a reusable exact-origin cookie session, and a generation-bound one-shot approval file.
- Authenticated CLI continuation across login responses, atomic owner-only session persistence, copied-approval replay rejection, and lock-serialized commands.
- All-path/query redaction, path-independent public IDs, credential-header protection, bounded element inference, and refusal of untrusted HTML regular expressions.
- CSP form restrictions, constraint-validation and validation-bypass handling, semantic form drift checks, and typed passkey/OAuth handoffs.
- Checked-in JSON Schemas and a machine-readable problem registry for every public HTTP Form Bridge identifier.
- Region-specific media digests with client-side verification and tamper rejection for direct source-image reads.
- Exact-origin direct-media enforcement with redirects rejected before a contract descriptor can become an arbitrary fetch primitive.
- Full private semantic freshness digests for bounded public labels, ARIA-labelled controls and submitters, fieldset/optgroup context, and long form text.
- Conservative HTML Auto-button and implicit-submission handling, plus typed refusals for unnamed validating controls, hard-wrapped textareas, and named `object` controls.

### Changed

- HTML-only sites are still rejected by the native client, but callers may now opt into the separate lower-assurance bridge instead of using a hidden browser fallback.
- Public-deployment guidance now references OAuth 2.0 security BCP and describes OAuth 2.1 accurately as an Internet-Draft.
- URL form controls now publish and execute the same conservative absolute-URI grammar instead of relying on non-asserting JSON Schema `format` metadata.
- Form inference now preserves full option wire values while bounding only public display text, and rechecks auth-interaction evidence immediately before dispatch.
- Freshness fingerprints now bind semantic element structure, hidden/ARIA state, and image alternatives so presentation-relevant source changes cannot preserve an approved write.

## [0.1.0] - 2026-07-25

### Added

- Agent manifest, OpenAPI contract, content negotiation, and typed entity queries.
- Scoped semantic state with resumable JSON Patch events over SSE.
- Direct original-image and bounded-region access with content hashes.
- Machine-readable chart data and map scene graphs.
- Preview and commit transactions with approval, idempotency, stale-state checks, and durable receipts.
- HTTP, CLI, MCP, and NLWeb interfaces backed by one domain store and policy path.
- Persistent local state, hardened container packaging, integration tests, and a no-browser verifier.
- Explicit refusal of unsupported HTML-only sites without a browser fallback.
