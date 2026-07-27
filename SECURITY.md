# Security Policy

## Supported versions

Maintainers provide security fixes for the default branch and the most recent release.

| Version | Supported |
|---|---|
| Default branch | Yes |
| Latest release | Yes |
| Older releases | No |

This project remains pre-1.0. A security fix may include a compatible protocol clarification or a documented breaking change when compatibility would preserve the vulnerability.

## Report a vulnerability

Do not open a public issue or discussion.

Use GitHub Private Vulnerability Reporting:

1. Open the repository's **Security** tab.
2. Select **Report a vulnerability**.
3. Submit the advisory form with reproduction details.

If private reporting is unavailable, contact the repository owner through their GitHub profile and ask for a private reporting channel. Do not include vulnerability details in that first message.

Include the affected version or commit, impact, prerequisites, a minimal reproduction, and any suggested mitigation. Remove real credentials and personal data from logs.

Maintainers aim to acknowledge a report within three business days and provide an initial assessment within seven business days. Complex reports may require more time. The maintainer will coordinate disclosure and credit with the reporter.

## Security-sensitive areas

Reports are useful when they cover:

- authentication, authorization, tenant or principal isolation;
- preview and commit binding, stale-state checks, idempotency, or receipt integrity;
- path traversal, unsafe file persistence, request smuggling, or denial of service;
- state stream disclosure or event replay across principals;
- media integrity, region bounds, content-type confusion, or untrusted metadata;
- HTTP bridge SSRF/DNS rebinding, redirect credential leakage, cookie isolation, secret redaction, form/approval binding, or ambiguous retry behavior;
- MCP framing, tool argument validation, or prompt-injection boundaries;
- container isolation and vulnerable dependencies.

Security research must use test data and systems you own or have permission to test. The project does not run a bug bounty unless the repository states otherwise.

## Secrets

The token in examples is a local development placeholder. Deployers must replace it and should follow the production boundary documented in the README and [docs/security.md](docs/security.md).
