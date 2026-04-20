# homeassistant-ai/ha-mcp

![Grade](https://img.shields.io/badge/Grade-D-orange?style=for-the-badge) ![Score](https://img.shields.io/badge/Score-60%2F100-orange?style=for-the-badge)

**Repository:** [homeassistant-ai/ha-mcp](https://github.com/homeassistant-ai/ha-mcp)
**Stars:** 2,389
**Last scan:** 2026-04-20

## Severity Summary

| Severity | Count |
|----------|------:|
| 🟠 High | **5** |
| 🟢 Low | **5** |
| 🔵 Info | **1** |
| **Total** | **11** |

## Findings

| # | Severity | Category | Title | Remediation |
|--:|:--------:|----------|-------|-------------|
| 1 | 🔵 Info | Outdated Version | Could not determine agent version | Ensure agent is updated to latest version |
| 2 | 🟠 High | Config Drift | Suspicious pattern in AGENTS.md: Code execution instruction | Review AGENTS.md for unauthorized modifications |
| 3 | 🟠 High | Config Drift | Suspicious pattern in AGENTS.md: Code execution instruction | Review AGENTS.md for unauthorized modifications |
| 4 | 🟠 High | Config Drift | Suspicious pattern in AGENTS.md: Code execution instruction | Review AGENTS.md for unauthorized modifications |
| 5 | 🟠 High | Config Drift | Suspicious pattern in AGENTS.md: Code execution instruction | Review AGENTS.md for unauthorized modifications |
| 6 | 🟠 High | Exposed Token | JSON Web Token found in config.py | Rotate and secure the JSON Web Token |
| 7 | 🟢 Low | Exposed Token | Secret Keyword found in test_webhook_proxy.py | Rotate and secure the Secret Keyword |
| 8 | 🟢 Low | Exposed Token | JSON Web Token found in test_constants.py | Rotate and secure the JSON Web Token |
| 9 | 🟢 Low | Exposed Token | Secret Keyword found in test_custom_component_filesystem.py | Rotate and secure the Secret Keyword |
| 10 | 🟢 Low | Exposed Token | Secret Keyword found in test_custom_component_filesystem.py | Rotate and secure the Secret Keyword |
| 11 | 🟢 Low | Exposed Token | JSON Web Token found in .env.test | Rotate and secure the JSON Web Token |

## Categories

| Category | Count |
|----------|------:|
| Exposed Token | 6 |
| Config Drift | 4 |
| Outdated Version | 1 |

---

[Back to Dashboard](../mcp-security-grades.md) | *Scanned on 2026-04-20 by [agentsec](https://github.com/debu-sinha/agentsec)*
