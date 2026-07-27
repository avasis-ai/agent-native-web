# HTTP Form Bridge 0.1 draft

The HTTP Form Bridge is the compatibility rail for sites that do not publish `/agent/manifest.json`. It fetches bytes, parses HTML inertly, compiles standard form controls into a typed request candidate, and can send one explicitly approved request. It starts no browser, executes no JavaScript, builds no rendered DOM, and takes no screenshot.

It is deliberately not presented as a native contract. Static HTML can prove request syntax; it cannot prove business intent, the authenticated subject, or the remote effect.

## The four rails

| Rail | Source of authority | Maximum safe claim |
|---|---|---|
| `native` | Site-owned agent contract and domain service | Effect preview, idempotent commit, verified receipt when implemented by the site |
| `verified_adapter` | Reviewed, versioned adapter with pinned postconditions | Adapter-specific operations and outcome checks |
| `standard_html` | Inert HTML and HTTP observations | Bound application-request plan and local attempt receipt |
| `unsupported` | Insufficient or conflicting evidence | Typed refusal or human/browser handoff |

The native client still returns `UNSUPPORTED_AGENT_SITE` for an HTML-only origin. There is no silent downgrade. A caller must choose the separate bridge API or `agentweb bridge` command.

## What the compiler actually observes

The parser uses [parse5](https://github.com/inikulin/parse5), a WHATWG-oriented inert HTML parser. It does not load scripts, styles, frames, images, or custom-element code.

That omission is a hard evidence boundary. The bridge cannot determine whether CSS makes a control or image visible, whether an image is relevant, or what arbitrary page imagery contains. Direct source-media and bounded-region reading are capabilities of a native contract or reviewed adapter. When the rendered pixels themselves are the evidence—canvas, video, CSS composition, or visual state—a screenshot/browser rail is still required.

The current compiler covers a conservative subset of the [HTML form submission model](https://html.spec.whatwg.org/multipage/form-control-infrastructure.html):

- document-order successful controls, including controls associated with `form=id` outside the form;
- duplicate wire names without collapsing them into a JSON object;
- native labels, `aria-label`, resolvable `aria-labelledby`, fieldset/optgroup context, input types, required/read-only/disabled state, disabled fieldsets, and length/range constraints;
- checkboxes, radio groups, text areas, single and multiple selects;
- hidden and read-only managed values in a private execution binding;
- distinct submitters, including `formaction`, `formmethod`, and `formenctype` overrides;
- `form-action` CSP from response headers and meta elements, response-header `sandbox` only when both `allow-forms` and `allow-same-origin` preserve the emulated semantics, and `base-uri` when resolving a document `<base>`;
- form-level `novalidate` and submitter-level `formnovalidate`, with the bypass recorded on the selected action;
- intrinsic email checks, a published conservative absolute-URI grammar for URL inputs, and numeric min/max/step checks when constraint validation applies, plus rejection of non-finite values for `number` and `range` controls;
- UTF-8 `GET` and `application/x-www-form-urlencoded` `POST` requests.

The compiler refuses file controls, image-coordinate submitters, multipart and `text/plain` bodies, non-UTF-8 forms, `method=dialog`, cross-origin actions or navigations, temporal controls whose sanitization/step rules are not implemented, hard-wrapped textareas, named `object` controls, numeric step offsets that cannot be represented faithfully in JSON Schema, HTML `pattern` constraints, ambiguous non-submitting button actions, and potentially form-associated custom elements. An enabled editable control without a name blocks an action when browser constraint validation applies; `novalidate` or the selected submitter's `formnovalidate` is the explicit bypass. Missing/invalid `button` types follow HTML's Auto rules, including `command`, `commandfor`, and direct `select` children. A disabled default submitter is not replaced by an invented implicit action, and a form with no submit button and multiple fields that block implicit submission is refused. URL fields deliberately accept a conservative ASCII absolute-URI subset: HTTP(S), WS(S), and FTP values require a bounded DNS/IPv4 host and valid port, while raw spaces, malformed percent escapes, Unicode host text, IPv6 literals, and browser-specific URL normalization are refused. The exact grammar is present in the emitted schema and is evaluated by the runtime from the same patterns. `novalidate` and `formnovalidate` relax this check explicitly. An untrusted regular expression is never evaluated on the agent event loop. Page scripts lower `input_completeness` to `heuristic`, even when the static form remains preparable. Inference stops at 50,000 elements, and repeated label resolution is pre-indexed rather than rescanning matching labels for every control. Public labels are capped for bounded output, but their full normalized source, image alternatives, selected semantic attributes, element structure, and the full form text feed private freshness fingerprints; display truncation or a hidden/visible text swap therefore cannot preserve an old approval. Option text used as a wire value is not truncated and follows the HTML ASCII-whitespace fallback when `value` is absent.

Bridge-managed hidden values, submitted credentials, credential headers, URL userinfo, and raw request bodies never enter public bridge objects. Public output contains field IDs, constraints, ordered wire names, and cryptographic fingerprints. The bridge uses keyed HMAC-SHA-256 for fingerprints derived from secrets, every untrusted URL path segment and query name/value, response bodies, and full private requests. Error URLs replace every path segment and all query material with non-secret markers. Public IDs are contract-scoped ordinals rather than hashes of a source path or submitter value. This deterministic policy deliberately avoids guessing whether `/share/7xQ` is a route or a bearer capability. A reader who lacks the private key cannot test low-entropy guesses against public fingerprints. The bridge may use plain SHA-256 for public structural data that contains no secret value. Raw form values and hidden bindings remain in the process-local binding until the preview is consumed or cleared. Visible labels and other selected source text are deliberately exposed as untrusted review data; do not publish bridge output to a broader audience than the source page.

The compiler treats CSP and constraint validation as compatibility limits. A blocked `form-action`, a response-header sandbox lacking either `allow-forms` or `allow-same-origin`, or a cross-origin action makes the action non-executable. If `base-uri` rejects a `<base>`, the compiler resolves relative actions against the document URL. `novalidate` or the chosen submitter's `formnovalidate` disables the browser-style constraint checks for that action; it does not raise assurance or prove that the server will accept the values.

Every editable control is agent-explicit. The caller must supply a value even when HTML declares a default. Use `""` for an intentionally empty text value, `false` for an unchecked box, `[]` for an empty multi-select, and `null` for an optional radio group or single select with no choice. Hidden, disabled, and read-only controls remain bridge-managed. This prevents an invisible page default from becoming an unreviewed action.

## Prepare and dispatch

An inferred write is not a native effect preview:

```text
fetch → inert parse → compile → request_preview → exact approval
      → re-fetch → recompile → freshness check → one dispatch → attempt_receipt
```

`request_preview` binds the application-request plan: method, URL, bridge-declared headers, exact encoded body, selected Cookie header, form instance, submitter, and evidence. Public output replaces sensitive values with keyed HMACs. Before dispatch, the bridge fetches and compiles the form again. A changed structure, submitter, action, accessible-name source, image alternative, hidden/ARIA semantic state, full semantic text, validation mode, managed hidden value, newly detected hard auth interaction, or selected Cookie-header binding returns a typed refusal before dispatch.

This is not a byte-for-byte capture of every header on the socket. The bound transport profile is `undici-fetch-v8; browser-navigation-headers-not-emulated`; the bridge declares its `User-Agent`, `Accept`, content type, and `Origin` where applicable, while Undici still manages transport headers such as `Host`, `Content-Length`, `Connection`, and `Accept-Encoding`. The bridge does not imitate browser navigation headers. Sites that depend on an exact browser fingerprint need a reviewed adapter or browser rail.

Every inferred submission requires both:

1. approval of the exact in-process preview, or the CLI's portable `approval_binding_digest` with its matching one-shot approval file and live session generation; and
2. an explicit `allowUnverifiedWrite` acknowledgement.

The approval covers the method, target URL, headers, encoded body, ordered entry names, form and action fingerprints, labels and semantic form text, validation mode, managed hidden-field instance, assurance state, and risk. It also covers the exact Cookie header selected for the target origin, path, and SameSite context. Before dispatch, the bridge re-fetches the form, rebuilds the request, and compares the selected Cookie-header binding with the approved binding.

The in-process preview is consumed before network dispatch. The local bridge will not send it twice. This local gate does not provide upstream idempotency.

## Receipts without false certainty

An `attempt_receipt` has two independent fields:

- `dispatch`: `not_sent`, `sent`, `response_received`, or `transport_ambiguous`;
- `outcome`: `unverified`, `pending_verified`, `succeeded_verified`, `failed_verified`, `partial_verified`, `mismatch`, or `unknown`.

A status code, redirect, cookie, or success-looking phrase does not by itself prove the business effect. The standard HTML rail therefore returns `outcome: unverified` after a response. If a connection fails after a non-safe request may have left the process, it returns `COMMIT_OUTCOME_UNKNOWN`, never retries automatically, and instructs the caller to verify before retrying.

A future verified adapter may promote an outcome only with a pinned site receipt or explicit postcondition evidence.

## Authentication reality

| Flow | Browserless handling | Claim boundary |
|---|---|---|
| Static username/password form | Compile, fill, submit, retain session cookies | Cookie receipt is not proof of user identity |
| Session cookies | RFC-style cookie jar with SameSite context and public-suffix checks | Held in memory or an exact-origin private CLI session file; cookie values are never printed |
| Standard OTP form | Detect `autocomplete=one-time-code`; accept a user-supplied value | The bridge does not obtain the OTP |
| Magic link | Record a heuristic source-text signal; do not create a blocking interaction candidate | Mailbox retrieval and link trust need an authorized connector/adapter |
| OAuth/OIDC | Syntax-check caller-supplied metadata; directly detected authorization-code markup produces an external-user-agent handoff | No issuer trust, metadata fetch, authorization flow, or token exchange is performed |
| Device authorization | Possible in a future adapter | A person still authorizes on another browser-capable device |
| Passkey/WebAuthn | Direct `autocomplete=webauthn` without a password fallback produces `AUTH_PASSKEY_REQUIRED`; a password fallback remains preparable | Requires an authenticator and browser/platform ceremony |
| CAPTCHA/Turnstile | A directly detected known integration inside the form produces `AUTH_CAPTCHA_REQUIRED` | No bypass or solving path; unknown challenge markup may not be recognized |
| JWT/token response | Verified adapter only | Generic response inspection never harvests bearer tokens |

This follows the security direction of [OAuth 2.0 Security Best Current Practice (RFC 9700)](https://www.rfc-editor.org/rfc/rfc9700.html), [OAuth for native apps (RFC 8252)](https://www.rfc-editor.org/rfc/rfc8252.html), [device authorization (RFC 8628)](https://www.rfc-editor.org/rfc/rfc8628.html), and [WebAuthn](https://www.w3.org/TR/webauthn-3/). OAuth 2.1 remains an Internet-Draft as of this profile; the project does not describe it as a published RFC.

## Network boundary

The HTTP session is hardened for local agent use:

- HTTPS is required unless an exact origin is explicitly allowed for testing;
- URL userinfo, unusual ports, loopback/private/link-local/multicast/reserved addresses, IPv4-mapped IPv6, and cloud-metadata ranges are blocked by default;
- every DNS answer and redirect target is validated;
- the validated address is pinned for the socket while the original hostname remains the Host header and TLS SNI;
- redirect count is bounded and cross-origin authorization/cookie forwarding is suppressed;
- compatibility-form navigation is exact-origin; a cross-origin redirect is refused before fetching the destination, so its cookies cannot enter the CLI session;
- non-safe responses are never followed through redirects automatically; any follow-up GET is a new explicit action;
- response bytes, connect time, and total request time are bounded;
- environment proxy variables are not used;
- non-safe requests have no automatic transport retry.

Private-network access requires an exact origin plus an explicit opt-in. Do not expose the bridge itself as an unauthenticated remote fetch endpoint. See the [OWASP SSRF prevention guidance](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html).

## CLI

Inspect a public HTTPS form:

```bash
node src/cli.mjs bridge inspect https://example.com/login
```

Use the emitted operation and field IDs to prepare. The CLI accepts form values only on stdin. The following shell flow reads one line of JSON without echoing it and reuses the same input for both commands:

```bash
session_dir="$(mktemp -d)"
session_file="$session_dir/bridge-session.json"
approval_file="$session_dir/bridge-approval.json"

IFS= read -r -s form_input
printf '\n'

printf '%s' "$form_input" |
  node src/cli.mjs bridge prepare https://example.com/login \
    --action action_login --input - \
    --session-file "$session_file" \
    --approval-file "$approval_file"
```

Review the URL and supplied input together with the redacted, bound preview metadata, then copy `preview.approval_binding_digest` into the submit command. The public preview intentionally HMACs path/query values and the encoded body; copying its digest is a technical acknowledgement, not proof that a person understood the action. Submit must use the same URL, action, and input:

```bash
approval_binding_digest='hmac-sha256:...'

printf '%s' "$form_input" |
  node src/cli.mjs bridge submit https://example.com/login \
    --action action_login --input - \
    --session-file "$session_file" \
    --approval-file "$approval_file" \
    --approval-binding-digest "$approval_binding_digest" \
    --allow-unverified-write

unset form_input approval_binding_digest
```

The two files carry different authority:

- `--session-file` is reusable, exact-origin credential state. It contains the cookie jar, a random session ID, and a monotonically increasing generation, but no request approval or HMAC key. Safe `inspect` and `prepare` commands can restore it; response cookies from a login POST are atomically saved for a later authenticated form.
- `--approval-file` is short-lived, generation-bound, and one-shot. It contains the URL, action, portable approval binding, expiry, and private HMAC key, but no cookie jar. It is created at a new path and removed immediately before any approved dispatch.

Both files are regular owner-only `0600` files. Reads use `O_NOFOLLOW` plus file-descriptor metadata checks; writes use same-directory temporary files, file sync, atomic link/rename, and directory sync. A per-session lock serializes commands. After all safe freshness checks pass, submit durably advances the session generation before removing the approval. A copied approval therefore fails against the live generation, and either persistence or unlink failure prevents that dispatch. After a response or ambiguous transport failure, the current cookie jar is persisted before process cleanup.

The lock is fail-closed: after a process crash, remove a stale `.lock` directory only after confirming that no bridge command still owns that session. Mode `0600` is access control, not encryption. Same-UID malware, backups, or a rollback of both session and approval files can still copy or restore authority. A production service needs an encrypted credential vault and non-rollback monotonic storage. A persisted cookie still does not prove the authenticated subject.

If an injected custom HTTP session throws after request invocation without an explicit `dispatchState`, the client records `transport_ambiguous` rather than claiming `not_sent`. Custom transports are trusted adapter code; they should report `not_sent`, `sent`, or `response_received` when they can prove that boundary.

After a successful login submit, reuse the surviving session state on the next safe command:

```bash
node src/cli.mjs bridge inspect https://example.com/account \
  --session-file "$session_file"

# Remove private state only after the authenticated workflow is finished.
rm -f "$session_file" "$approval_file"
rmdir "$session_dir"
```

For local test services, add `--allow-private-network`. This flag binds the exact target origin; it is not a wildcard private-network proxy.

CLI exit categories are `0` success, `2` general CLI/bridge failure (including redirect, cross-origin, and size-policy refusals), `3` native-client authentication failure, `4` unsupported native site, `5` approval or concurrency conflict, `6` any bridge `AUTH_*` refusal, and `7` TLS, SSRF-target, or DNS-rebinding refusal. The structured problem `code` remains the precise machine-readable reason.

Programmatic users should keep one `HttpBridgeClient` instance so its preview vault and cookie jar remain in one process:

```js
import { HttpBridgeClient } from './src/http-bridge/index.mjs';

const bridge = new HttpBridgeClient();
const contract = await bridge.inspect('https://example.com/login');
const operation = contract.operations.find((item) => item.executable);
const preview = await bridge.prepare({
  contractId: contract.contract_id,
  actionId: operation.operation_id,
  input: { field_id_from_contract: 'value' }
});
const receipt = await bridge.dispatch(preview.preview_id, {
  approvalDigest: preview.preview_digest,
  allowUnverifiedWrite: true
});
```

## Best use cases

The strongest initial use case is not autonomous shopping. It is user-approved operation of stable server-rendered forms where the request itself is useful evidence: search and filtering, simple sign-in bootstrap, migration inventory, and low-consequence, reversible data entry or administrative work on systems the operator owns or is authorized to use.

The bridge is also useful as a migration tool. It can inventory existing forms and show which ones can become native typed operations, while preserving a hard distinction between inferred syntax and site-owned semantics.

It is a poor fit for JavaScript-only applications, client-side cryptography, passkeys, CAPTCHA, visual editors, canvas interactions, arbitrary file upload, or high-consequence actions without a reviewed adapter and outcome verifier.

## Does this replace headless browsers?

Not completely. It removes browser startup and rendering from the supported standard-form subset, so that subset may be cheaper and more deterministic. The current measurements are local bridge overhead, not a controlled browser comparison. It cannot reconstruct arbitrary JavaScript application state from HTTP bytes without either executing the application or obtaining a cooperating contract.

The bridge protocol, public profile, and checked-in JSON schemas are all versioned `0.1-draft`. Schema and problem-type identifiers resolve to repository resources under `schemas/http-form-bridge/`; they are draft interfaces and may change before a stable release.

Projects such as [CloakBrowser](https://github.com/CloakHQ/cloakbrowser) remain browser runtimes: they modify Chromium/Playwright behavior to improve compatibility or detection resistance. That is useful for the browser rail, but it is the opposite architecture from this bridge. CloakBrowser can serve as a compatibility oracle in controlled testing; it is not a dependency or hidden fallback.

The larger opportunity is a transition: infer conservative request candidates today, add reviewed adapters for important legacy sites, and move durable integrations to native contracts. That can change the default for browser automation without claiming that pixels and browser engines disappear from the entire web.
