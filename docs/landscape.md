# Browser automation landscape

Research snapshot: 27 July 2026. This review uses project repositories, specifications, and vendor documentation. It compares runtime architecture and safety claims, not popularity.

## Result

Static server-rendered forms can run over raw HTTP. JavaScript-only applications still require execution. Among the eleven repositories reviewed at the pinned commits below, none documented all of these properties together:

- automatic HTTP-only discovery of standard HTML forms;
- ordered successful-control encoding, cookies, and CSRF value handling;
- an exact, redacted request preview tied to approval;
- freshness checks before a single non-safe dispatch;
- typed refusals and separate dispatch/outcome evidence.

This was a manual architecture-and-claims review of each pinned repository's code, package manifests, README, documentation, and license—not a security audit, benchmark, or exhaustive search of every project. It cannot establish that no such repository exists. Several projects solve adjacent parts of the problem.

## Projects reviewed

| Project | Runtime | Discovery and interaction model | Relevance |
|---|---|---|---|
| [Playwright](https://github.com/microsoft/playwright/tree/3827650d171cc1b035cbefb7e00bf5948d6809df) | Chromium, Firefox, or WebKit | Browser DOM, roles, locators, input events, and stored browser auth state | Reliable browser executor and compatibility oracle. It does not infer a site contract. |
| [CloakBrowser](https://github.com/CloakHQ/CloakBrowser/tree/093a6646016f7068ff1bcf92a7ec4fd226f694b0) | Patched Chromium through Playwright/Puppeteer-compatible wrappers | Full browser, DOM, JavaScript, profiles, and browser input | A stealth browser rail. The wrappers are MIT-licensed, while CloakHQ's [distributed patches and binary use a proprietary license](https://github.com/CloakHQ/CloakBrowser/blob/093a6646016f7068ff1bcf92a7ec4fd226f694b0/BINARY-LICENSE.md). |
| [Browser Use](https://github.com/browser-use/browser-use/tree/0964ad452a9f3fe249042a5ffb235e5f98519b2e) | Chrome/Chromium over CDP | Browser element state with optional screenshot vision; profiles, secrets, and interactive auth support | Broad browser agent coverage with browser startup and page-state ambiguity. |
| [Stagehand](https://github.com/browserbase/stagehand/tree/2557a797fd685702236d59c1adca02e34fa87f3c) | Local or hosted Chrome over CDP | Semantic browser actions, extraction, form filling, and optional vision | Gives agents a higher-level browser API. It still executes a live browser document. |
| [Skyvern](https://github.com/Skyvern-AI/skyvern/tree/91dcd2a0f9b5d03acb8d74ac21091a95c3767373) | Playwright-compatible browser automation | Selectors, LLM reasoning, computer vision, credentials, and common 2FA handoffs | Strong fallback for visual or JavaScript workflows. It does not remove the browser. |
| [Steel Browser](https://github.com/steel-dev/steel-browser/tree/5880b48c1af107219ff3d904edbb8f6b76bea9b6) | Managed Chrome | CDP, Playwright, Puppeteer, Selenium, scrape, screenshot, and session APIs | Browser infrastructure. Useful as an isolated fallback rail. |
| [Firecrawl](https://github.com/firecrawl/firecrawl/tree/ab033afd95b6e7865cf8d955fec359043389f227) | HTTP scraping plus a Playwright microservice | Extraction can avoid a browser; interactive writes use browser sessions | Strong read/context layer. Interactive actions retain browser semantics. |
| [OpenCLI](https://github.com/jackwener/OpenCLI/tree/5256711a25458e537c5a63d2a6f9c7fd36d0d1eb) | Logged-in Chrome through an extension, local daemon, and CDP | Structured DOM snapshots, network inspection, form actions, and authored site adapters | Closest match to the website-as-CLI experience. Generic mode still depends on Chrome. |
| [AutomatiQ](https://github.com/StoneSteel27/AutomatiQ/tree/8d3a5b91e4217585671b9cfbddc5bea62f5c6b3a) | Chrome and vision during discovery | Records browser traffic and interaction, then generates a standalone automation script | Strong hybrid precedent. Bootstrap still uses a browser, and generated scripts need their own approval and outcome model. |
| [MechanicalSoup](https://github.com/MechanicalSoup/MechanicalSoup/tree/e72a4247909c6f247db3fd3a99a508eb53c2f34b) | Requests plus Beautiful Soup | Cookies, redirects, links, and static HTML form submission without JavaScript | Closest mature HTTP-only form precedent. It does not expose typed assurance, approval binding, or outcome receipts. |
| [WebMCP](https://github.com/webmachinelearning/webmcp/tree/58016782fa379c25bc9584433f29127a9855647b) | Browser-mediated page JavaScript | Cooperating pages register structured tools; a declarative proposal can synthesize form tools | Strong support for an agent-native web, but it requires publisher participation and a live browser context. |

The browser-agent projects differ in element representation. Some use DOM or accessibility snapshots and add screenshots only when needed. That can reduce vision cost, but it still requires a browser engine to execute the page and produce live state. Agent Native Web compiles evidence from the transport layer and refuses any behavior it cannot derive there.

## The useful gap

Project scope excludes a universal Playwright replacement. A layered runtime gives agents the cheapest rail that can support an operation:

1. `native`: use a site-owned contract or OpenAPI operation with authoritative schemas and receipts.
2. `standard_html`: infer a conservative HTTP request from inert HTML, require exact approval, and return an attempt receipt.
3. `verified_adapter`: use reviewed, version-pinned knowledge of a stable site API plus explicit postconditions.
4. `unsupported`: hand the task to a browser or person when JavaScript, visual state, or an authentication ceremony carries required meaning.

This architecture can change the default for form-heavy automation. A browser becomes an explicit compatibility rail instead of the first dependency for every website.

## Auth and forms

Static username/password forms, cookies, hidden CSRF values, and user-supplied OTP fields fit the HTTP rail when the server expresses them through ordinary HTML. A cookie proves that the server set a cookie. It does not prove which person authenticated or whether the intended account action succeeded.

OAuth authorization pages, passkeys, CAPTCHA, client-side cryptography, and JavaScript-only state require an external user agent, authenticator, reviewed adapter, or browser handoff. The bridge reports these boundaries with machine-readable refusal codes instead of imitating the missing ceremony.

## Images without screenshots

Image understanding does not inherently require a page screenshot. A cooperating site can expose original image bytes, named regions, structured chart data, or a scene graph. The reference storefront demonstrates original-byte and bounded-region access through its native media contract.

An HTTP compatibility layer can also discover ordinary image resources from `img`, `picture`, metadata, and linked documents, then fetch the source bytes under the same network policy. HTTP Form Bridge 0.1 does not yet publish a generic image-resource compiler, so the project does not claim that coverage today.

Screenshots remain necessary when the rendered composition is the evidence: canvas output, CSS composites, a particular video frame, visual regression, or layout-dependent meaning. The long-term interface should return source assets first and request a screenshot only for those cases.

## Standards around the gap

- [OpenAPI 3.2](https://spec.openapis.org/oas/v3.2.0.html) is the strongest cooperating-site HTTP contract. It describes operations and security schemes but does not infer hidden HTML forms or prove effects.
- [MCP 2025-11-25](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization) can expose the resulting tools and authorization flow. It does not define how a legacy site operation should be inferred.
- [llms.txt](https://github.com/AnswerDotAI/llms-txt) helps with content navigation. It has no transaction or authentication model.
- [NLWeb](https://github.com/nlweb-ai/NLWeb) offers a cooperative natural-language query layer over structured site content. It does not cover arbitrary authenticated writes.

## Defensible use cases

The first users should target stable, server-rendered systems they own or have permission to operate: search/filter forms, migration inventory, simple sign-in bootstrap, and low-consequence, reversible administrative or data-entry work. A second use case is migration analysis: compile existing forms, expose uncertainty, and show maintainers where a native contract or reviewed adapter would remove risk.

Autonomous shopping, banking, healthcare, and account recovery need site-owned semantics and verified outcomes. Generic HTML provides too little authority for those operations.
