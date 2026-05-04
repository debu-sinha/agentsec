# homeassistant-ai/ha-mcp

![Grade](https://img.shields.io/badge/Grade-F-red?style=for-the-badge) ![Score](https://img.shields.io/badge/Score-57%2F100-red?style=for-the-badge)

**Repository:** [homeassistant-ai/ha-mcp](https://github.com/homeassistant-ai/ha-mcp)
**Stars:** 2,679
**Last scan:** 2026-05-04

## Severity Summary

| Severity | Count |
|----------|------:|
| 🟠 High | **5** |
| 🟢 Low | **8** |
| 🔵 Info | **1** |
| **Total** | **14** |

## Findings

| # | Severity | Category | Title | Remediation |
|--:|:--------:|----------|-------|-------------|
| 1 | 🔵 Info | Outdated Version | Could not determine agent version | Ensure agent is updated to latest version |
| 2 | 🟠 High | Config Drift | Suspicious pattern in AGENTS.md: Code execution instruction | Review AGENTS.md for unauthorized modifications |
| 3 | 🟠 High | Config Drift | Suspicious pattern in AGENTS.md: Code execution instruction | Review AGENTS.md for unauthorized modifications |
| 4 | 🟠 High | Config Drift | Suspicious pattern in AGENTS.md: Code execution instruction | Review AGENTS.md for unauthorized modifications |
| 5 | 🟠 High | Config Drift | Suspicious pattern in AGENTS.md: Code execution instruction | Review AGENTS.md for unauthorized modifications |
| 6 | 🟢 Low | Exposed Token | Secret Keyword found in test_custom_component_filesystem.py | Rotate and secure the Secret Keyword |
| 7 | 🟢 Low | Exposed Token | Secret Keyword found in test_custom_component_filesystem.py | Rotate and secure the Secret Keyword |
| 8 | 🟢 Low | Exposed Token | Secret Keyword found in test_webhook_proxy.py | Rotate and secure the Secret Keyword |
| 9 | 🟢 Low | Exposed Token | Secret Keyword found in test_webhook_proxy.py | Rotate and secure the Secret Keyword |
| 10 | 🟢 Low | Exposed Token | JSON Web Token found in test_tools_bug_report.py | Rotate and secure the JSON Web Token |
| 11 | 🟢 Low | Exposed Token | GitHub Token found in test_tools_bug_report.py | Rotate and secure the GitHub Token |
| 12 | 🟠 High | Exposed Token | JSON Web Token found in config.py | Rotate and secure the JSON Web Token |
| 13 | 🟢 Low | Exposed Token | JSON Web Token found in test_constants.py | Rotate and secure the JSON Web Token |
| 14 | 🟢 Low | Exposed Token | JSON Web Token found in .env.test | Rotate and secure the JSON Web Token |

## Categories

| Category | Count |
|----------|------:|
| Exposed Token | 9 |
| Config Drift | 4 |
| Outdated Version | 1 |

---

[Back to Dashboard](../mcp-security-grades.md) | *Scanned on 2026-05-04 by [agentsec](https://github.com/debu-sinha/agentsec)*
