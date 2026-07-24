# Verification record

Date: 25 July 2026
Environment: Node.js 22.23.1, macOS arm64

## Final acceptance run

Command:

```bash
npm run verify
node examples/browserless-purchase.mjs
node scripts/benchmark.mjs 100
```

Results:

- 22 tests passed; 0 failed, skipped, or cancelled.
- 8 production source files passed the runtime-pattern scanner.
- 0 production npm dependencies.
- 0 forbidden package or browser-runtime findings.
- The full automation produced both `cart.add` and `checkout.place` receipts.
- It read `NOVA731`, a value present only in an addressable raster region and absent from its descriptor.
- Server trace after the complete run: 0 human HTML requests, 0 render requests, 0 screenshot requests.
- The retry-storm test issued 20 concurrent commits with one idempotency key and observed one receipt, one event, and one unit in the cart.
- Persistence verification restarted the server, recovered state/events/receipts, and returned the original receipt on retry.
- A real MCP stdio child process initialized with protocol `2025-11-25`, listed tools, and returned direct image content.
- An HTML-only fixture was refused after only `/agent/manifest.json`; its `/` page was never fetched.

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

## Local protocol benchmark

These measure warm, local infrastructure latency without model time. They are not a universal comparison against Playwright or CloakBrowser.

| Operation | Samples | p50 | p95 | p99 |
|---|---:|---:|---:|---:|
| Typed product query | 100 | 1.516 ms | 1.888 ms | 3.813 ms |
| Scoped state baseline | 100 | 1.494 ms | 1.725 ms | 2.096 ms |
| Direct source-image region | 100 | 5.674 ms | 7.318 ms | 8.196 ms |

## Claim boundary

This evidence proves the included cooperating site can be fully automated through its agent contract without loading or controlling a browser. It does not prove that an unmodified HTML-only third-party site can be automated without a browser. The implementation refuses that case instead of hiding a fallback.
