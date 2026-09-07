# FlorianBruniaux/claude-code-ultimate-guide

![Grade](https://img.shields.io/badge/Grade-F-red?style=for-the-badge) ![Score](https://img.shields.io/badge/Score-30%2F100-red?style=for-the-badge)

**Repository:** [FlorianBruniaux/claude-code-ultimate-guide](https://github.com/FlorianBruniaux/claude-code-ultimate-guide)
**Stars:** 5,909
**Last scan:** 2026-09-07

## Severity Summary

| Severity | Count |
|----------|------:|
| 🔴 Critical | **1** |
| 🟠 High | **1** |
| 🟡 Medium | **12** |
| 🟢 Low | **12** |
| 🔵 Info | **1** |
| **Total** | **27** |

## Findings

| # | Severity | Category | Title | Remediation |
|--:|:--------:|----------|-------|-------------|
| 1 | 🔵 Info | Outdated Version | Could not determine agent version | Ensure agent is updated to latest version |
| 2 | 🟠 High | Exposed Credentials | Hook reads sensitive data: dangerous-actions-blocker | Remove sensitive data access from hooks |
| 3 | 🔴 Critical | Insecure Config | Hook modifies security settings: dangerous-actions-blocker | Remove security config modifications from hooks |
| 4 | 🟡 Medium | Exposed Token | Secret Keyword found in 08-mcp-servers.yaml | Rotate and secure the Secret Keyword |
| 5 | 🟡 Medium | Exposed Token | Secret Keyword found in 08-mcp-servers.yaml | Rotate and secure the Secret Keyword |
| 6 | 🟡 Medium | Exposed Token | Secret Keyword found in reference.yaml | Rotate and secure the Secret Keyword |
| 7 | 🟡 Medium | Exposed Token | Secret Keyword found in reference.yaml | Rotate and secure the Secret Keyword |
| 8 | 🟡 Medium | Exposed Token | Secret Keyword found in reference.yaml | Rotate and secure the Secret Keyword |
| 9 | 🟡 Medium | Exposed Token | Secret Keyword found in reference.yaml | Rotate and secure the Secret Keyword |
| 10 | 🟢 Low | Exposed Token | Secret Keyword found in reference.yaml | Rotate and secure the Secret Keyword |
| 11 | 🟢 Low | Exposed Token | Secret Keyword found in security-auditor.md | Rotate and secure the Secret Keyword |
| 12 | 🟢 Low | Exposed Token | Secret Keyword found in security-checklist.md | Rotate and secure the Secret Keyword |
| 13 | 🟢 Low | Exposed Token | Secret Keyword found in reference.yaml | Rotate and secure the Secret Keyword |
| 14 | 🟡 Medium | Exposed Token | Secret Keyword found in reference.yaml | Rotate and secure the Secret Keyword |
| 15 | 🟡 Medium | Exposed Token | Secret Keyword found in reference.yaml | Rotate and secure the Secret Keyword |
| 16 | 🟡 Medium | Exposed Token | Secret Keyword found in reference.yaml | Rotate and secure the Secret Keyword |
| 17 | 🟡 Medium | Exposed Token | Secret Keyword found in reference.yaml | Rotate and secure the Secret Keyword |
| 18 | 🟢 Low | Exposed Token | Private Key found in output-secrets-scanner.sh | Rotate and secure the Private Key |
| 19 | 🟢 Low | Exposed Token | Secret Keyword found in output-secrets-scanner.sh | Rotate and secure the Secret Keyword |
| 20 | 🟡 Medium | Exposed Token | Secret Keyword found in 13-security.yaml | Rotate and secure the Secret Keyword |
| 21 | 🟡 Medium | Exposed Token | Secret Keyword found in 13-security.yaml | Rotate and secure the Secret Keyword |
| 22 | 🟢 Low | Exposed Token | JSON Web Token found in memory-stack-integration.md | Rotate and secure the JSON Web Token |
| 23 | 🟢 Low | Exposed Token | OpenAI API Key found in ultimate-guide.md | Rotate and secure the OpenAI API Key |
| 24 | 🟢 Low | Exposed Token | OpenAI API Key found in 016-gang-rui-tasks-api-limitations.md | Rotate and secure the OpenAI API Key |
| 25 | 🟢 Low | Exposed Token | OpenAI API Key found in 016-gang-rui-tasks-api-limitations.md | Rotate and secure the OpenAI API Key |
| 26 | 🟢 Low | Exposed Token | OpenAI API Key found in api-gateway.md | Rotate and secure the OpenAI API Key |
| 27 | 🟢 Low | Exposed Token | OpenAI API Key found in api-gateway.md | Rotate and secure the OpenAI API Key |

## Categories

| Category | Count |
|----------|------:|
| Exposed Token | 24 |
| Outdated Version | 1 |
| Exposed Credentials | 1 |
| Insecure Config | 1 |

---

[Back to Dashboard](../mcp-security-grades.md) | *Scanned on 2026-09-07 by [agentsec](https://github.com/debu-sinha/agentsec)*
