# Security Policy

## Supported Versions

| Version | Supported |
| ------- | --------- |
| 0.4.x   | Yes       |
| < 0.4   | No        |

## Reporting a Vulnerability

Report vulnerabilities privately using GitHub Security Advisories:

1. Open: https://github.com/debu-sinha/agentsec/security/advisories/new
2. Include clear reproduction steps, impact, and affected versions.
3. Share proof-of-concept details privately only.

Do not open public GitHub issues for undisclosed vulnerabilities.

## Response Targets

- Acknowledgment: within 48 hours
- Triage/initial severity decision: within 5 business days
- Mitigation or fix plan for confirmed issues: within 30 days

For severe actively exploited issues, we prioritize emergency response outside normal cadence.

## Scope

In scope:

- `agentsec-ai` package source in `src/agentsec/`
- CLI behavior and report generation
- Built-in scanners and hardening profiles
- Release artifacts and workflow security

Out of scope:

- Third-party packages and external repositories scanned by agentsec
- Vulnerabilities already public without a reproducible new impact case

## Disclosure Policy

We follow coordinated disclosure. After a fix is available, advisories are published with affected versions and remediation guidance.
