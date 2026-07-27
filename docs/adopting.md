# Adopt Agent Native Web in an existing site

Agent Native Web adds an agent surface beside your human interface. Both surfaces call the same domain services and policy code.

This guide describes the experimental `0.1` profile implemented by this repository. Treat it as a reference contract, not an adopted web standard.

The repository also includes an HTTP Form Bridge for legacy sites. That bridge is a migration and compatibility tool, not a substitute for this adoption path: inferred HTML cannot publish authoritative effects, retry semantics, authorization scopes, or outcome receipts on behalf of a site.

## 1. Start from domain operations

List the tasks your site owns as domain operations:

- reads such as product search, account state, availability, and order status;
- writes such as cart updates, bookings, messages, and checkout;
- media such as source images, chart datasets, maps, and documents.

Do not translate buttons into tool names. Define stable entities and operations first, then let the human UI and agent adapters call them.

## 2. Publish discovery

Serve a public manifest at `/agent/manifest.json` and link to it from human responses:

```http
Link: </agent/manifest.json>; rel="https://agent-web.dev/rels/agent-manifest"; type="application/json"
```

The manifest should name the contract version, API base, OpenAPI document, authentication scheme, state transport, transaction policy, media support, and optional MCP/NLWeb adapters.

Keep action catalogues and private entity access behind authorization even when the manifest is public.

## 3. Expose stable resources

Give each domain entity a stable ID and revision. Return links instead of asking clients to construct routes.

```json
{
  "id": "product:trailpack-blue",
  "version": "product-v17",
  "type": "Product",
  "media": [
    {"id": "media:trailpack-blue:hero", "href": "/api/agent/v1/media/media%3Atrailpack-blue%3Ahero"}
  ],
  "actions": [
    {"id": "cart.add", "href": "/api/agent/v1/actions/cart.add/preview"}
  ]
}
```

Support JSON-LD when Schema.org or another shared vocabulary describes the entity well. Keep project-specific fields under a versioned context.

## 4. Serve media at the source

Return original bytes with MIME type, dimensions, byte size, hash, ETag, cache policy, rights, and provenance claims. Use W3C-style selectors or IIIF for addressable regions.

Expose the source data behind charts. Expose scene graphs or feature collections for maps and canvas applications. Return `UNSUPPORTED_REPRESENTATION` when your site owns no semantic source or authorized artifact.

Keep publisher descriptions, OCR, and model annotations separate from source bytes. Agents must treat those fields as untrusted claims.

## 5. Stream semantic state

Let the client open one scoped baseline, then send sequenced changes:

```text
event: patch
id: 92
data: {"base_sequence":91,"sequence":92,"patch":[...]}
```

Key collections by stable entity ID so patches do not depend on array positions. Reject cursors ahead of the server. Ask clients to resync when retained history no longer covers their cursor.

## 6. Split writes into preview and commit

Preview should:

- validate a strict versioned schema;
- capture the authenticated principal and relevant entity revisions;
- disclose money, recipients, publication, deletion, or other effects;
- create no durable external effect;
- return an expiry and digest.

Commit should authenticate again, recheck authorization and revisions, require approval for consequential work, and require an idempotency key. Store the mutation, event, receipt, and idempotency result in one transaction or through an outbox.

## 7. Add adapters after the contract works

Generate or implement CLI and MCP adapters from the same typed operations. Keep credentials in transport configuration. Do not accept tokens, tenant IDs, or actor identity as tool arguments.

An NLWeb adapter can provide conversational discovery and point result actions to preview endpoints. Label state, media, and transaction extensions as profile features rather than NLWeb features.

## 8. Prove the boundary

Your conformance suite should run in a container with no browser binary and no public egress. Assert that the agent path made zero requests for human HTML, rendering, DOM or accessibility snapshots, and page screenshots.

Test at least:

- manifest discovery and typed refusal of an HTML-only fixture;
- direct source media and region hashes;
- state replay, gaps, and reconnects;
- preview purity, expiry, principal binding, and stale state;
- concurrent idempotent retries and restart recovery;
- HTTP, CLI, and MCP parity;
- prompt injection inside descriptive data.

Use this repository's `npm run verify` and test directory as a small executable example.

## 9. Use inference to plan migration

Run `node src/cli.mjs bridge inspect https://legacy.example/form` against server-rendered forms you already own. The result inventories field schemas, submitter variants, unsupported mechanics, script participation, and auth-interaction signals. Use that inventory to prioritize native operations:

- migrate frequent or consequential writes first;
- keep stable search/filter forms on the compatibility rail when an unverified request is sufficient;
- add a reviewed adapter only when a legacy service cannot yet expose a native contract;
- never treat a bridge attempt receipt as the site's durable business receipt.
