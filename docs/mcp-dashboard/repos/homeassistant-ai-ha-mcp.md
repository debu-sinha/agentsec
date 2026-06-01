# homeassistant-ai/ha-mcp

![Grade](https://img.shields.io/badge/Grade-F-red?style=for-the-badge) ![Score](https://img.shields.io/badge/Score-36%2F100-red?style=for-the-badge)

**Repository:** [homeassistant-ai/ha-mcp](https://github.com/homeassistant-ai/ha-mcp)
**Stars:** 3,187
**Last scan:** 2026-06-01

## Severity Summary

| Severity | Count |
|----------|------:|
| 🟠 High | **7** |
| 🟢 Low | **15** |
| 🔵 Info | **1** |
| **Total** | **23** |

## Findings

| # | Severity | Category | Title | Remediation |
|--:|:--------:|----------|-------|-------------|
| 1 | 🟢 Low | Plaintext Secret | Plaintext Generic Secret in AGENTS.md | Move Generic Secret to OS keychain or secrets manager |
| 2 | 🔵 Info | Outdated Version | Could not determine agent version | Ensure agent is updated to latest version |
| 3 | 🟠 High | Config Drift | Suspicious pattern in AGENTS.md: Code execution instruction | Review AGENTS.md for unauthorized modifications |
| 4 | 🟠 High | Config Drift | Suspicious pattern in AGENTS.md: Code execution instruction | Review AGENTS.md for unauthorized modifications |
| 5 | 🟠 High | Config Drift | Suspicious pattern in AGENTS.md: Code execution instruction | Review AGENTS.md for unauthorized modifications |
| 6 | 🟠 High | Config Drift | Suspicious pattern in AGENTS.md: Code execution instruction | Review AGENTS.md for unauthorized modifications |
| 7 | 🟠 High | Config Drift | Suspicious pattern in AGENTS.md: Code execution instruction | Review AGENTS.md for unauthorized modifications |
| 8 | 🟠 High | Exposed Token | JSON Web Token found in config.py | Rotate and secure the JSON Web Token |
| 9 | 🟢 Low | Exposed Token | Secret Keyword found in test_webhook_proxy.py | Rotate and secure the Secret Keyword |
| 10 | 🟢 Low | Exposed Token | Secret Keyword found in test_webhook_proxy.py | Rotate and secure the Secret Keyword |
| 11 | 🟢 Low | Exposed Token | Secret Keyword found in test_webhook_proxy.py | Rotate and secure the Secret Keyword |
| 12 | 🟢 Low | Exposed Token | Secret Keyword found in test_webhook_proxy.py | Rotate and secure the Secret Keyword |
| 13 | 🟢 Low | Exposed Token | Secret Keyword found in test_webhook_proxy.py | Rotate and secure the Secret Keyword |
| 14 | 🟢 Low | Exposed Token | JSON Web Token found in test_constants.py | Rotate and secure the JSON Web Token |
| 15 | 🟢 Low | Exposed Token | JSON Web Token found in test_constants.py | Rotate and secure the JSON Web Token |
| 16 | 🟢 Low | Exposed Token | Secret Keyword found in test_custom_component_filesystem.py | Rotate and secure the Secret Keyword |
| 17 | 🟢 Low | Exposed Token | Secret Keyword found in test_custom_component_filesystem.py | Rotate and secure the Secret Keyword |
| 18 | 🟠 High | Exposed Token | JSON Web Token found in bake_pagination_seed.py | Rotate and secure the JSON Web Token |
| 19 | 🟢 Low | Exposed Token | JSON Web Token found in test_tools_bug_report.py | Rotate and secure the JSON Web Token |
| 20 | 🟢 Low | Exposed Token | GitHub Token found in test_tools_bug_report.py | Rotate and secure the GitHub Token |
| 21 | 🟢 Low | Exposed Token | Secret Keyword found in test_stdio_settings_sidecar.py | Rotate and secure the Secret Keyword |
| 22 | 🟢 Low | Exposed Token | JSON Web Token found in .env.test | Rotate and secure the JSON Web Token |
| 23 | 🟢 Low | Exposed Token | Secret Keyword found in haos_runtime.py | Rotate and secure the Secret Keyword |

## Categories

| Category | Count |
|----------|------:|
| Exposed Token | 16 |
| Config Drift | 5 |
| Plaintext Secret | 1 |
| Outdated Version | 1 |

---

[Back to Dashboard](../mcp-security-grades.md) | *Scanned on 2026-06-01 by [agentsec](https://github.com/debu-sinha/agentsec)*
