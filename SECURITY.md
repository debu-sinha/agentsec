# Security Policy

## Supported Versions

| Version | Supported | Security Fixes |
| ------- | --------- | -------------- |
| 0.4.x   | Yes       | Yes            |
| < 0.4   | No        | No             |

Only the latest patch release in each supported minor line receives security fixes.

## Reporting a Vulnerability

Report vulnerabilities privately through GitHub Security Advisories:

- Submit: https://github.com/debu-sinha/agentsec/security/advisories/new
- Include: affected version, impact, reproduction steps, and proof-of-concept
- Do not include real secrets or production credentials in reports

Do not open public GitHub issues for undisclosed vulnerabilities.

## Response Targets

- Acknowledgment: within 48 hours
- Triage and initial severity: within 5 business days
- Fix or mitigation plan for confirmed issues: within 30 days
- Critical actively exploited issues: expedited response outside normal cadence

## Scope

In scope:

- `src/agentsec/` package code
- CLI behavior, output handling, and reporting
- Built-in scanners, hardening profiles, and gate logic
- Official release artifacts and GitHub workflows in this repository

Out of scope:

- Third-party packages or repositories scanned by agentsec
- Vulnerabilities already publicly disclosed without new reproducible impact
- Misuse of intentionally insecure demo fixtures

## Coordinated Disclosure

We follow coordinated disclosure:

1. Vulnerability is received privately and triaged
2. Fix is developed and released
3. Advisory is published with affected versions and remediation guidance

When possible, we credit reporters in the advisory after disclosure.

## Security Update Distribution

Security fixes are communicated through:

- GitHub Security Advisories
- GitHub releases/changelogs
- Tagged patch releases on the default branch

## Hardening Guidance

Users should run `agentsec scan` regularly, apply relevant hardening profiles, and rotate any exposed credentials immediately.
