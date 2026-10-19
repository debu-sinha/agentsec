# PrefectHQ/fastmcp

![Grade](https://img.shields.io/badge/Grade-C-yellow?style=for-the-badge) ![Score](https://img.shields.io/badge/Score-79%2F100-yellow?style=for-the-badge)

**Repository:** [PrefectHQ/fastmcp](https://github.com/PrefectHQ/fastmcp)
**Stars:** 28,135
**Last scan:** 2026-10-19

## Severity Summary

| Severity | Count |
|----------|------:|
| 🔴 Critical | **1** |
| 🟢 Low | **6** |
| 🔵 Info | **1** |
| **Total** | **8** |

## Findings

| # | Severity | Category | Title | Remediation |
|--:|:--------:|----------|-------|-------------|
| 1 | 🔵 Info | Outdated Version | Could not determine agent version | Ensure agent is updated to latest version |
| 2 | 🔴 Critical | Data Exfiltration Risk | Hook with network access: session-init | Remove or audit network commands in hooks |
| 3 | 🟢 Low | Exposed Token | Secret Keyword found in test_oauth_proxy.py | Rotate and secure the Secret Keyword |
| 4 | 🟢 Low | Exposed Token | Secret Keyword found in fastmcp-analytics.js | Rotate and secure the Secret Keyword |
| 5 | 🟢 Low | Exposed Token | Secret Keyword found in test_oauth_proxy_storage.py | Rotate and secure the Secret Keyword |
| 6 | 🟢 Low | Exposed Token | Secret Keyword found in test_oidc_proxy.py | Rotate and secure the Secret Keyword |
| 7 | 🟢 Low | Exposed Token | Secret Keyword found in test_keycloak_provider_integration.py | Rotate and secure the Secret Keyword |
| 8 | 🟢 Low | Exposed Token | Secret Keyword found in test_oidc_proxy_token.py | Rotate and secure the Secret Keyword |

## Categories

| Category | Count |
|----------|------:|
| Exposed Token | 6 |
| Outdated Version | 1 |
| Data Exfiltration Risk | 1 |

---

[Back to Dashboard](../mcp-security-grades.md) | *Scanned on 2026-10-19 by [agentsec](https://github.com/debu-sinha/agentsec)*
