# Contributing

Thanks for helping improve Agent Native Web. Contributions can cover implementation, protocol design, tests, documentation, and examples.

## Before you start

- Search existing issues and pull requests before opening a new one.
- Use an issue to discuss changes that alter the protocol, security model, or public interfaces.
- Report vulnerabilities through the private process in [SECURITY.md](SECURITY.md). Do not disclose them in an issue.
- Follow our [Code of Conduct](CODE_OF_CONDUCT.md).

## Development setup

You need Node.js 22 or newer. From your checkout:

```bash
nvm use
npm ci
npm run verify
npm run demo
```

The project has no production npm dependencies. Please explain any proposal that adds one and include its license and security implications.

## Design constraints

Keep these properties intact:

- Agent execution uses typed contracts and direct media. Production code must not launch or control a browser, capture a screenshot, or read DOM and accessibility snapshots.
- HTML-only sites return `UNSUPPORTED_AGENT_SITE`; clients must not hide a browser fallback.
- HTTP, CLI, MCP, and NLWeb adapters use the same domain store, policy checks, and receipt path.
- Mutations use preview and commit, bind authentication to the transport, require idempotency, and reject stale state.
- Public errors and protocol responses stay machine-readable and stable.
- Original image bytes and bounded source regions count as media. A composed webpage capture does not.

## Make a change

1. Create a focused branch from the default branch.
2. Add tests that fail without your change.
3. Update protocol or security documentation when behavior changes.
4. Run `npm run verify` and `npm run demo`.
5. Open a pull request with the problem, approach, and verification evidence.

Keep unrelated refactors out of the same pull request. Avoid committing tokens, state files, generated coverage, or local environment files.

## Protocol changes

A protocol proposal should describe:

- the agent task and cooperating-site capability it supports;
- request and response shapes, versioning, and failure behavior;
- authentication, authorization, replay, privacy, and prompt-injection risks;
- compatibility across HTTP, CLI, MCP, and NLWeb where applicable;
- tests that prove browserless execution and safe failure on unsupported sites.

Label project-specific extensions as experimental. Do not present an extension as part of MCP, NLWeb, Schema.org, or a W3C standard unless the cited specification defines it.

## Tests

Run the full gate before requesting review:

```bash
npm run verify
```

The verifier scans production code and dependencies for browser-control paths, then runs the integration suite. Add a regression test for each bug fix. Keep tests deterministic and independent of public network services.

## License

By submitting a contribution, you agree that the project may distribute it under the [MIT License](LICENSE).
