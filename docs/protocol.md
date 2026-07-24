# Browserless Site Profile 0.1

Status: experimental reference profile, not an Internet standard.

## Invariants

1. Successful agent operations do not depend on a browser, rendered page, DOM, accessibility tree, or webpage screenshot.
2. Stable domain IDs replace selectors and screen coordinates.
3. Site content, annotations, OCR, and media descriptions are untrusted claims, not agent instructions.
4. Original media bytes remain distinguishable from derived assertions.
5. Each state event names its base and resulting sequence. A gap forces a new scoped baseline.
6. Preview produces no durable domain effect.
7. Commit is bound to the authenticated principal, exact preview, arguments, relevant revisions, and expiry.
8. High-risk commits require explicit confirmation.
9. Every mutation requires an idempotency key and returns a receipt.
10. Unsupported visual or legacy behavior fails explicitly; there is no hidden browser fallback.

## Discovery

The canonical manifest is `/agent/manifest.json`. Human resource responses also include an RFC 8288 `Link` header using the unregistered extension relation `https://agent-web.dev/rels/agent-manifest`. `/.well-known/agent.json` is a convenience alias only; this profile does not claim that name is registered.

The manifest states its experimental status, canonical contract, authentication, representations, state model, transaction model, media model, and adapters.

## Representations

Human resource URLs negotiate:

- `text/html` for people;
- `text/markdown` for readable content;
- `application/ld+json` for linked structured data;
- experimental `application/agent+json` for the full operable representation.

Agent representations contain stable IDs, versions, first-party data, linked media, current action descriptors, and links to human resources. `Vary: Accept` prevents cache confusion.

## Query

The primary structured query uses the safe and idempotent HTTP `QUERY` method defined by RFC 10008. `POST /api/agent/v1/query` calls the same engine for compatibility. Filter names and operators are allowlisted. Unknown fields fail; the server never evaluates agent-supplied source code, SQL, JSONPath, shell text, or URLs.

## Semantic state

`GET /api/agent/v1/state?scope=...` returns a baseline and monotonic sequence. Collections use dictionaries keyed by stable entity IDs plus explicit order arrays. `GET /api/agent/v1/events?since=N` returns RFC 6902 JSON Patch events over SSE. Each event carries `base_sequence`, `sequence`, the causing receipt, principal, and timestamp.

The server retains a bounded event log. A cursor older than retained history receives `RESYNC_REQUIRED`; a cursor ahead of the server receives `INVALID_SEQUENCE`. Clients must not guess across either condition.

## Media

An image descriptor links to the original encoded bytes, dimensions, MIME type, byte size, SHA-256 digest, context, named W3C-style fragment regions, provenance claims, and rights. A region request crops the original asset, not a webpage rendering. Content responses include `Content-Digest`, `ETag`, cache policy, byte ranges, and `X-Media-Source`.

Charts expose data and a grammar specification. Canvas/WebGL/map-like media expose a scene graph when the domain owns one. If no source, data, graph, or authorized artifact exists, the correct response is `UNSUPPORTED_REPRESENTATION`.

## Actions and receipts

Action schemas reject unknown fields and bound integer/string values. Availability is state-dependent.

A preview stores the authenticated principal, exact arguments, related entity revisions, expiry, risk, simulated patch, and digest. A commit rechecks the principal, expiry, confirmation, and revisions in the same synchronous critical section as the mutation. It stores state, event, receipt, and idempotency result atomically in the reference persistence file.

The file implementation demonstrates semantics for one process. A distributed deployment needs a database transaction plus outbox and must propagate the idempotency intent to downstream side effects.

## MCP and NLWeb

MCP tools map to the same HTTP contract. Image resources use MCP image/blob content. Authentication is process environment/transport configuration, never a tool parameter.

The `/ask` endpoint follows NLWeb 0.55 response structure for conversational product discovery. NLWeb actions point to preview endpoints. Preview/commit, state patches, media regions, and receipts are profile extensions, not claims about NLWeb itself.
