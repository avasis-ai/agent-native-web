# Verification record

Date: 27 July 2026
Environment: Node.js 22.23.1, macOS arm64

## Final acceptance run

Command:

```bash
npm run verify
node examples/browserless-purchase.mjs
node scripts/benchmark.mjs 100
npm run benchmark:bridge -- 100
```

Results:

- 94 tests passed; 0 failed, skipped, or cancelled.
- 20 production source files passed the runtime-pattern scanner.
- 4 direct production npm dependencies: parse5, tough-cookie, ipaddr.js, and undici.
- 0 forbidden package or browser-runtime findings.
- The full automation produced both `cart.add` and `checkout.place` receipts.
- It read `NOVA731`, a value present only in an addressable raster region and absent from its descriptor.
- The source-region bytes matched the region-specific descriptor SHA-256; a one-byte mutation produced `MEDIA_INTEGRITY_ERROR` before decoding.
- Server trace after the complete run: 0 human HTML requests, 0 render requests, 0 screenshot requests.
- The retry-storm test issued 20 concurrent commits with one idempotency key and observed one receipt, one event, and one unit in the cart.
- Persistence verification restarted the server, recovered state/events/receipts, and returned the original receipt on retry.
- A real MCP stdio child process initialized with protocol `2025-11-25`, listed tools, and returned direct image content.
- An HTML-only fixture was refused after only `/agent/manifest.json`; its `/` page was never fetched.
- The explicit bridge compiled ordered duplicate controls, external `form=` controls, labels, constraints, hidden values, choices, disabled fieldsets, and submitter overrides without exposing secrets.
- A browserless login-form run re-fetched the form, sent one URL-encoded POST, retained its session cookies, and returned `outcome: unverified` rather than inferring success from its redirect.
- A changed hidden/CSRF value, full semantic form text, hidden/visible text placement, image alternative, external ARIA name, option/optgroup label, action label, validation mode, or session/account cookie invalidated approval before any POST. A suffix change beyond the public display bound was also rejected.
- The selected Cookie-header binding was checked again inside the HTTP transport immediately before dispatch; a cookie mutation produced `CREDENTIAL_BINDING_MISMATCH` and zero upstream writes.
- CSP `form-action`, response-header `sandbox`, and `base-uri` behavior was reproduced, while email, finite-number, step, `novalidate`, and `formnovalidate` semantics were tested. Unnamed validating controls, hard-wrapped textareas, named objects, command buttons, disabled default submitters, and invalid implicit submission were refused or modeled according to the tested static HTML rules.
- A body that looked like HTML but lacked an HTML content type was not parsed as a form.
- Private/link-local/reserved targets, URL userinfo, insecure/default-disallowed origins, redirect escapes, oversized responses, and cross-origin credential forwarding were rejected.
- Native direct-media reads remained exact-origin: a malicious descriptor could neither fetch a private address nor follow a redirect, and region bytes were verified against their region-specific digest.
- A dropped POST connection produced `COMMIT_OUTCOME_UNKNOWN`, an `unknown` attempt receipt, and one upstream attempt with no automatic retry.
- The CLI compatibility plane accepted sensitive form data only through stdin, never forwarded `AGENT_TOKEN`, rejected structural drift across processes, and separated reusable exact-origin cookie state from generation-bound one-shot approval.
- A login response cookie survived process exit, authenticated a later form inspection and write, while a copied approval failed against the advanced session generation.
- Owner/mode/symlink checks, atomic session replacement, lock serialization, and cleanup-failure handling were exercised; an ambiguous POST kept a verifiable attempt receipt even when lock cleanup also failed.
- All public URL path segments and query names/values, credential headers, and path-derived fingerprints were keyed or removed; public IDs remained stable without including the source path.
- An adversarial HTML `pattern` regular expression was refused without evaluation, and oversized element inference stopped at its configured bound.
- Secret-bearing public fingerprints and application-request bindings used a private keyed HMAC; the same low-entropy secret produced different public digests under different keys.

## Covered behavior

| Requirement | Evidence |
|---|---|
| Agent discovery | Manifest, capabilities, OpenAPI and content-negotiation tests |
| No UI snapshots/headless browser | Zero dependency/source findings plus zero HTML/render/screenshot trace counters |
| Direct media | Original PNG hash, named region hash, pixel-only inspection value |
| Non-image visuals | Chart data/specification and warehouse scene-graph tests |
| Semantic state | Keyed baseline, live SSE patch, cursor replay, base/result sequence |
| Safe actions | Preview purity, principal binding, expiry, stale-state rejection, confirmation |
| Retry safety | Sequential replay, conflicting-key rejection, 20-request retry storm, restart replay |
| Audit | Durable receipts with principal, run/request IDs, digests, policy, revisions and patches |
| Adapter parity | HTTP client, CLI subprocess, in-process MCP and real MCP stdio |
| Compatibility boundary | Typed refusal for render/screenshot and for an HTML-only site |
| Inert form inference | Ordered controls, duplicates, labels, constraints, submitter variants, hidden-value redaction |
| Bridge authentication | Password form + cookie session, selected Cookie-header binding, OTP signals, and direct passkey/CAPTCHA/OAuth handoffs |
| Bridge network safety | SSRF classification, DNS pinning, redirect checks, SameSite cookies, CSP, byte/time limits |
| Bridge writes | Keyed application-request-plan approval, structural/semantic freshness rejection, split CLI session/approval state, one dispatch |
| Honest outcomes | Attempt receipt separates dispatch from unverified/unknown remote outcome |

## Local protocol benchmark

These measure warm, local infrastructure latency without model time. They are not a universal comparison against Playwright or CloakBrowser.

| Operation | Samples | p50 | p95 | p99 |
|---|---:|---:|---:|---:|
| Typed product query | 100 | 1.737 ms | 3.212 ms | 5.645 ms |
| Scoped state baseline | 100 | 1.423 ms | 1.825 ms | 1.935 ms |
| Direct source-image region | 100 | 2.838 ms | 3.334 ms | 3.529 ms |

## Local HTTP bridge benchmark

The bridge benchmark uses a 519-byte representative form. It executes no model and no external network request.

| Operation | Samples | p50 | p95 | max |
|---|---:|---:|---:|---:|
| Inert HTML parse + form compile | 100 | 0.265 ms | 1.007 ms | 5.723 ms |
| Complete local HTTP inspection | 100 | 0.818 ms | 2.087 ms | 21.430 ms |

## Claim boundary

This evidence proves two narrower claims:

1. The included cooperating site can be fully automated through its native agent contract without loading or controlling a browser.
2. The tested standard HTML subset can be compiled and submitted through raw HTTP without a browser, with a bound application-request plan and conservative failure handling.

It does not prove arbitrary JavaScript applications, passkeys, CAPTCHA, visual editors, or high-consequence third-party workflows can be safely automated without a browser or reviewed adapter. It does not prove generic HTML success, authenticated identity, or upstream exactly-once behavior. Those gaps remain explicit rather than hidden behind a confidence score.
