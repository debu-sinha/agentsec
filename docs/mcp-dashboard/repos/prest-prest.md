# prest/prest

![Grade](https://img.shields.io/badge/Grade-A-brightgreen?style=for-the-badge) ![Score](https://img.shields.io/badge/Score-95%2F100-brightgreen?style=for-the-badge)

**Repository:** [prest/prest](https://github.com/prest/prest)
**Stars:** 4,610
**Last scan:** 2026-08-10

## Severity Summary

| Severity | Count |
|----------|------:|
| 🟢 Low | **5** |
| 🔵 Info | **1** |
| **Total** | **6** |

## Findings

| # | Severity | Category | Title | Remediation |
|--:|:--------:|----------|-------|-------------|
| 1 | 🔵 Info | Outdated Version | Could not determine agent version | Ensure agent is updated to latest version |
| 2 | 🟢 Low | Exposed Token | Secret Keyword found in conn_test.go | Rotate and secure the Secret Keyword |
| 3 | 🟢 Low | Exposed Token | Secret Keyword found in logsafe_test.go | Rotate and secure the Secret Keyword |
| 4 | 🟢 Low | Exposed Token | Base64 High Entropy String found in config_test.go | Rotate and secure the Base64 High Entropy String |
| 5 | 🟢 Low | Exposed Token | Basic Auth Credentials found in database_registry_test.go | Rotate and secure the Basic Auth Credentials |
| 6 | 🟢 Low | Exposed Token | Generic Connection String found in database_registry_test.go | Rotate and secure the Generic Connection String |

## Categories

| Category | Count |
|----------|------:|
| Exposed Token | 5 |
| Outdated Version | 1 |

---

[Back to Dashboard](../mcp-security-grades.md) | *Scanned on 2026-08-10 by [agentsec](https://github.com/debu-sinha/agentsec)*
