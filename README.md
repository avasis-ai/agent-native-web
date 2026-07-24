<h1 align="center">Agent Native Web</h1>

<p align="center">
  <strong>Automate the contract, not the screen.</strong><br>
  A runnable reference for websites that agents can discover, read, inspect, and transact with through typed capabilities.
</p>

<p align="center">
  <img src="./assets/hero.svg" alt="Agent Native Web direct automation flow from discovery through receipt" width="100%">
</p>

<p align="center">
  <a href="https://github.com/avasis-ai/agent-native-web/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/avasis-ai/agent-native-web/actions/workflows/ci.yml/badge.svg"></a>
  <img alt="Status: experimental" src="https://img.shields.io/badge/status-experimental-B8FFD8?style=flat-square&labelColor=08110F">
  <img alt="Node.js 22 or newer" src="https://img.shields.io/badge/node-%3E%3D22-75A7FF?style=flat-square&labelColor=08110F">
  <img alt="Zero production dependencies" src="https://img.shields.io/badge/production_dependencies-0-B8FFD8?style=flat-square&labelColor=08110F">
  <a href="./LICENSE"><img alt="MIT license" src="https://img.shields.io/badge/license-MIT-FF8066?style=flat-square&labelColor=08110F"></a>
</p>

Agents use a manifest, stable domain IDs, direct media, sequenced state, and typed actions. The included storefront completes an authenticated purchase without loading its human page, starting a browser, reading a DOM, or taking a screenshot.

> [!IMPORTANT]
> Agent Native Web supports cooperating sites that expose the Agent Resource Web contract. The client rejects HTML-only sites with `UNSUPPORTED_AGENT_SITE`. It does not automate arbitrary existing websites.

## Run the proof

You need Node.js 22 or newer.

```bash
npm ci
npm run verify
npm run demo
```

The demo discovers the site, queries products, reads a bounded source-image region, previews and commits a cart update, consumes its state patch, requests checkout approval, and returns two receipts.

<p align="center">
  <img src="./assets/terminal-demo.svg" alt="Verified browserless purchase run with zero HTML, render, screenshot, and browser dependency counts" width="100%">
</p>

The verification suite checks the server trace after the full run:

```json
{
  "inspection_mark": "NOVA731",
  "receipts": 2,
  "human_html_requests": 0,
  "render_requests": 0,
  "screenshot_requests": 0,
  "production_browser_dependencies": 0
}
```

## Contract-native automation

| Concern | UI-driving automation | Agent Native Web |
|---|---|---|
| Runtime target | Rendered page in a browser engine | Typed site contract |
| Identity | Selectors, text matches, coordinates | Stable domain IDs |
| Reads | DOM, accessibility tree, screenshots | Scoped state and RFC 6902 patches |
| Images | Rendered pixels or OCR | Original bytes and bounded source regions |
| Charts and maps | Recover data from presentation | Data/specification or scene graph |
| Writes | Click, type, wait | Preview, confirm, idempotent commit |
| Evidence | Logs, recordings, screenshots | Receipt and sequenced state event |
| Coverage | Browser-accessible interfaces | Sites that expose the contract |
| Unsupported work | Tool-specific fallback | Typed refusal without a render fallback |

UI automation remains the compatibility path for unmodified sites. Agent Native Web gives sites a direct agent interface when they control the domain service.

## Architecture

Both surfaces call one authoritative domain core. The CLI and MCP server reuse the HTTP client; they do not contain a second mock store or a second policy implementation.

<p align="center">
  <img src="./assets/architecture.svg" alt="Shared domain core serving a human HTML surface and direct agent interfaces with media, state, and safe transaction layers" width="100%">
</p>

The reference implements four connected layers:

- **Resources:** versioned entities, structured queries, negotiated representations, and stable links.
- **Media:** original PNG bytes, named source regions, content hashes, chart data/specification, and a warehouse scene graph.
- **State:** a keyed semantic baseline followed by resumable JSON Patch events over SSE.
- **Actions:** strict schemas, effect previews, approval, stale-state checks, idempotent commits, and persistent receipts.

## Direct media

The blue product descriptor names an `inspection-mark` region without exposing its value. `NOVA731` exists only in the raster pixels. The client requests that 50×50 source region, verifies its hash, and feeds the bytes to the sample decoder.

```bash
node src/cli.mjs media read-mark 'media:trailpack-blue:hero'

node src/cli.mjs media fetch 'media:trailpack-blue:hero' \
  --region inspection-mark \
  --output inspection.png
```

MCP tool `agent.media.read` returns the same original or region bytes as `ImageContent`. A multimodal model can consume those bytes without a page capture. The chart and map endpoints return their source data and scene graph because an agent should not reconstruct known data from pixels.

## Safe writes

Every mutation follows one server-owned path:

```text
strict input → preview → approval when required → idempotent commit → receipt
```

A preview validates arguments, captures relevant revisions, simulates the effect, and expires after five minutes. It creates no durable domain change. Commit authenticates the principal again, checks the captured revisions, requires confirmation for checkout, records one event, and stores a receipt.

Every commit requires `Idempotency-Key`. A retry with the same principal, preview, and key returns the first receipt. Reusing a key for another request returns `IDEMPOTENCY_CONFLICT`. The test suite sends 20 concurrent retries and observes one mutation.

## Interfaces

| Interface | Entry point | Purpose |
|---|---|---|
| Discovery | `GET /agent/manifest.json` | Contract, authentication, capabilities, adapters |
| OpenAPI | `GET /openapi.json` | HTTP operation descriptions |
| Negotiation | `GET /products/:id` | HTML, Markdown, JSON-LD, or experimental agent JSON |
| Query | `QUERY /api/agent/v1/entities` | Safe structured product search |
| State | `GET /api/agent/v1/state?scope=cart` | Keyed baseline and sequence |
| Changes | `GET /api/agent/v1/events?since=N` | SSE JSON Patch stream |
| Media | `GET /api/agent/v1/media/:id` | Source metadata, hashes, regions, provenance |
| Preview | `POST /api/agent/v1/actions/:action/preview` | Validate and disclose effects |
| Commit | `POST /api/agent/v1/commits` | Revalidate and mutate once |
| Receipt | `GET /api/agent/v1/receipts/:id` | Persistent local audit record |
| NLWeb | `POST /ask` | NLWeb 0.55 response-structure adapter |
| MCP | `node src/mcp.mjs` | Tools and binary/JSON resources over stdio |

The Agent Resource Web profile and `application/agent+json` media type remain experimental. The implementation uses existing standards where they fit, including HTTP content negotiation, JSON-LD, RFC 6902 JSON Patch, SSE, MCP, Schema.org, and W3C-style fragment selectors.

## CLI

```bash
node src/cli.mjs discover
node src/cli.mjs query --colour blue --in-stock
node src/cli.mjs state --scope cart
node src/cli.mjs actions
node src/cli.mjs preview cart.add \
  --args '{"product_id":"product:trailpack-blue","quantity":1}'
node src/cli.mjs events --since 0
node src/cli.mjs media data 'media:inventory:chart'
```

The CLI writes success results as JSON. It writes protocol errors as JSON to stderr and uses stable exit codes.

## MCP

Start the HTTP service, then point an MCP client at the stdio adapter:

```json
{
  "command": "node",
  "args": ["/absolute/path/to/agent-native-web/src/mcp.mjs"],
  "env": {
    "AGENT_BASE_URL": "http://127.0.0.1:4317",
    "AGENT_TOKEN": "replace-this-token"
  }
}
```

The adapter implements MCP `2025-11-25` initialization, tools, resource listing, and resource reads. Authentication stays in the transport configuration instead of tool arguments.

## Run the service

```bash
AGENT_TOKEN='replace-this-token' npm start
```

The human storefront runs at `http://127.0.0.1:4317/`. Agents start at `/agent/manifest.json` and do not request `/`.

Docker Compose runs the service as an unprivileged user with a read-only root filesystem:

```bash
AGENT_TOKEN='replace-this-token' docker compose up --build
```

The standalone server writes state, events, receipts, and the idempotency ledger to `data/state.json`. Set `AGENT_DATA_FILE=:memory:` for disposable runs.

## Verification

```bash
npm run verify
npm run benchmark -- 100
```

The final local acceptance run passed 22 tests across HTTP, CLI, MCP stdio, live SSE, persistence, media integrity, approval, stale state, and concurrent retries. The source scanner found zero production browser packages or runtime hooks.

| Local operation | Samples | p50 | p95 |
|---|---:|---:|---:|
| Typed product query | 100 | 1.516 ms | 1.888 ms |
| Scoped state baseline | 100 | 1.494 ms | 1.725 ms |
| Direct source-image region | 100 | 5.674 ms | 7.318 ms |

These numbers measure warm protocol overhead on the development Apple Silicon machine. They exclude model time and do not constitute a controlled comparison with Playwright or CloakBrowser. See [VERIFICATION.md](./VERIFICATION.md) for the evidence record.

## Project status

Version `0.1.0` proves the full contract-native path for the included storefront. Public deployments still need OAuth 2.1, a transactional database and outbox, tenant isolation, encrypted sensitive fields, distributed limits, and signed audit retention.

Planned work:

- extract the protocol profile and conformance suite from the demo domain;
- add adapters for one content site and one authenticated SaaS application;
- publish controlled browser and contract-native benchmark workloads;
- test interoperable IIIF, C2PA, OAuth, and remote MCP deployments.

## Documentation

- [Protocol profile](./docs/protocol.md)
- [Adoption guide](./docs/adopting.md)
- [Security boundary](./docs/security.md)
- [Verification record](./VERIFICATION.md)
- [Contributing guide](./CONTRIBUTING.md)
- [Changelog](./CHANGELOG.md)

## Contributing

Issues and focused pull requests are welcome. Read [CONTRIBUTING.md](./CONTRIBUTING.md) before proposing a protocol change. Security reports should follow [SECURITY.md](./SECURITY.md).

## License

[MIT](./LICENSE)
