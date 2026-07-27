# Security boundary

## Implemented in the reference

- bearer tokens are compared in constant time and mapped server-side to one demo principal;
- protected state, actions, events, traces, and receipts authenticate on every request;
- request bodies are limited to 64 KiB and parsed only as JSON objects;
- query and action fields are allowlisted, with bounded values and no arbitrary evaluation;
- native media is generated/served from an internal registry, so agents cannot supply fetch URLs through the storefront API;
- PNG dimensions and regions are bounded; content types, byte counts, hashes, ETags, and source kind are explicit;
- descriptive fields are marked as untrusted publisher data;
- previews are principal-bound, expire, and become stale after relevant revisions change;
- checkout needs a separate explicit confirmation bit;
- commits require bounded idempotency keys and durable receipts;
- response security headers, restrictive human-page CSP, no permissive CORS, request IDs, and redacted request traces are present;
- container configuration uses a non-root user, read-only root filesystem, no-new-privileges, and no Linux capabilities;
- unknown legacy/render/screenshot capability requests return a typed refusal.

Authorization is checked in the server. MCP tool annotations and natural-language descriptions are hints and never grant authority.

## Implemented in the HTTP bridge

- the bridge is an explicit client-side plane; the native client never silently falls back and never forwards `AGENT_TOKEN`;
- HTTPS is the default, URL userinfo and unusual ports are blocked, and private/loopback access needs an exact-origin test opt-in;
- every literal and DNS answer is classified; private, link-local, metadata, multicast, reserved, transition, and IPv4-mapped IPv6 targets are rejected by default;
- each redirect is revalidated, the validated address is pinned to the socket, and the original hostname is retained for Host and TLS SNI; compatibility-form navigation refuses a cross-origin hop before fetching its destination;
- authorization and cookie forwarding are suppressed across origins; cookie storage applies public-suffix, prefix, secure-context, and SameSite policy;
- response bytes, redirects, connect time, and total request time are bounded;
- HTML parsing is inert: no scripts, subresources, custom-element code, layout, renderer, or screenshot path exists;
- native direct-media URLs must remain on the manifest origin and redirects are rejected; every returned source region is verified against its region-specific digest before decoding;
- the compiler applies its supported `form-action` CSP subset from headers and meta elements, requires both `allow-forms` and `allow-same-origin` in a response-header `sandbox`, and applies `base-uri` before accepting a document `<base>`;
- the compiler records `novalidate` and `formnovalidate`; without a bypass it checks intrinsic email syntax, evaluates URL inputs against the same conservative absolute-URI patterns published in their schema, checks numeric min/max/step constraints, and rejects non-finite numeric values in all modes;
- public fingerprints derived from hidden fields, passwords, cookies, authorization material, URL path segments, query names/values, raw bodies, OAuth state/code bindings, and complete private requests use a private keyed HMAC rather than a guessable plain hash;
- every inferred submission is re-fetched and recompiled; changed form structure, action, submitter, accessible-name source, image alternative, hidden/ARIA semantic state, full semantic text, validation mode, managed hidden-field instance, or newly detected hard auth interaction invalidates approval;
- approval binds the application request method, URL, bridge-declared headers, encoded body, ordered fields, form/action instance, transport profile, assurance state, and session Cookie header for the target origin, path, and SameSite context; Undici-managed socket headers are not claimed as byte-for-byte previewed;
- programmatic clients keep credentials and private form bindings in memory and can clear them;
- the CLI separates an exact-origin reusable `0600` cookie session from a short-lived `0600` one-shot approval containing the private HMAC key; safe descriptor reads use `O_NOFOLLOW`, owner/mode checks, bounded JSON, and a per-session lock directory;
- immediately before dispatch, the CLI atomically advances the durable session generation and consumes the approval; copied approvals fail against the live generation, and response cookies are atomically persisted for later authenticated forms;
- session and approval files are not encrypted or rollback-proof; same-UID compromise, backups, or restoring both files can recover authority, so production needs an encrypted vault and monotonic non-rollback state;
- URL userinfo, every untrusted path segment, query name/value, credential header, and path-derived public fingerprint is removed or protected with a private keyed HMAC; error URLs use non-secret path markers;
- public response metadata omits reason phrases, allowlists normalized media types/charsets, and HMACs untrusted content-type metadata;
- untrusted HTML `pattern` regular expressions are refused instead of evaluated in-process;
- temporal controls, hard-wrapped textareas, named `object` controls, unnamed validating controls, and non-zero numeric step offsets that are not represented faithfully by the draft compiler are refused rather than approximated;
- HTML button Auto behavior and implicit-submission blockers are modeled conservatively; disabled or non-submitting buttons never cause the bridge to invent a submission action;
- inferred requests need exact approval and a separate acknowledgement that the remote effect is unverified;
- one preview is dispatched at most once locally; non-safe transport failures are never automatically retried, and a custom transport error without explicit dispatch evidence is treated as ambiguous after invocation;
- attempt receipts separate dispatch evidence from outcome evidence and never equate HTTP status, redirects, or cookies with business success.

Do not mount `HttpBridgeClient` behind a public unauthenticated “fetch any URL” endpoint. The current design is for a local agent process or a tenant-isolated worker with an egress policy.

## Deliberately not claimed

The local demo token is not OAuth, the JSON file is not a distributed database, and this build is not multi-tenant. It does not claim payment-network integration, cross-service exactly-once delivery, signed receipts, C2PA verification, malware scanning, or an IIIF deployment. The standard HTML bridge does not claim authenticated-subject verification, upstream idempotency, business-effect knowledge, or outcome verification. Those need site authority or a reviewed adapter.

For public use:

1. Use OAuth 2.0 authorization code with PKCE following RFC 9700 for user delegation, RFC 9728 protected-resource metadata, RFC 8707 resource indicators, strict audience validation, short lifetimes, narrow read/preview/commit scopes, and step-up approval. OAuth 2.1 is still an Internet-Draft as of this profile.
2. Keep user subject, agent client, tenant, and run identity separate. Bind every projection, preview, receipt, and idempotency entry to them.
3. Use a transactional database and outbox. Encrypt addresses and other sensitive fields. Apply retention and access policy to receipts and traces.
4. Proxy or tightly allowlist remote media and bridge egress. Block private networks, redirect escapes, unusual schemes, MIME confusion, oversized/decompression-bomb content, active SVG, and external SVG resources.
5. Add per-principal and per-operation distributed limits, quotas, anomaly detection, structured audit export, and secret redaction tests.
6. Run the browserless service in an egress-restricted image that contains no browser binary. Trace process execution and network connections in CI.
7. Treat all publisher text and derived model output as data. Never concatenate it into privileged instructions or use it to bypass typed approval.
