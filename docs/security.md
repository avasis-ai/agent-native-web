# Security boundary

## Implemented in the reference

- bearer tokens are compared in constant time and mapped server-side to one demo principal;
- protected state, actions, events, traces, and receipts authenticate on every request;
- request bodies are limited to 64 KiB and parsed only as JSON objects;
- query and action fields are allowlisted, with bounded values and no arbitrary evaluation;
- media is generated/served from an internal registry, so agents cannot supply fetch URLs or trigger SSRF;
- PNG dimensions and regions are bounded; content types, byte counts, hashes, ETags, and source kind are explicit;
- descriptive fields are marked as untrusted publisher data;
- previews are principal-bound, expire, and become stale after relevant revisions change;
- checkout needs a separate explicit confirmation bit;
- commits require bounded idempotency keys and durable receipts;
- response security headers, restrictive human-page CSP, no permissive CORS, request IDs, and redacted request traces are present;
- container configuration uses a non-root user, read-only root filesystem, no-new-privileges, and no Linux capabilities;
- unknown legacy/render/screenshot capability requests return a typed refusal.

Authorization is checked in the server. MCP tool annotations and natural-language descriptions are hints and never grant authority.

## Deliberately not claimed

The local demo token is not OAuth, the JSON file is not a distributed database, and this build is not multi-tenant. It does not claim payment-network integration, cross-service exactly-once delivery, signed receipts, C2PA verification, malware scanning, or an IIIF deployment. Those need deployment-specific infrastructure.

For public use:

1. Use OAuth 2.1 authorization code with PKCE for user delegation, RFC 9728 protected-resource metadata, RFC 8707 resource indicators, strict audience validation, short lifetimes, narrow read/preview/commit scopes, and step-up approval.
2. Keep user subject, agent client, tenant, and run identity separate. Bind every projection, preview, receipt, and idempotency entry to them.
3. Use a transactional database and outbox. Encrypt addresses and other sensitive fields. Apply retention and access policy to receipts and traces.
4. Proxy or tightly allowlist remote media. Block private networks, redirect escapes, unusual schemes, MIME confusion, oversized/decompression-bomb images, active SVG, and external SVG resources.
5. Add per-principal and per-operation distributed limits, quotas, anomaly detection, structured audit export, and secret redaction tests.
6. Run the browserless service in an egress-restricted image that contains no browser binary. Trace process execution and network connections in CI.
7. Treat all publisher text and derived model output as data. Never concatenate it into privileged instructions or use it to bypass typed approval.
