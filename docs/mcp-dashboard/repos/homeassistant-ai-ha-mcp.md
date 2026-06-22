# homeassistant-ai/ha-mcp

![Grade](https://img.shields.io/badge/Grade-C-yellow?style=for-the-badge) ![Score](https://img.shields.io/badge/Score-74%2F100-yellow?style=for-the-badge)

**Repository:** [homeassistant-ai/ha-mcp](https://github.com/homeassistant-ai/ha-mcp)
**Stars:** 3,564
**Last scan:** 2026-06-22

## Severity Summary

| Severity | Count |
|----------|------:|
| 🟠 High | **2** |
| 🟢 Low | **12** |
| 🔵 Info | **1** |
| **Total** | **15** |

## Findings

| # | Severity | Category | Title | Remediation |
|--:|:--------:|----------|-------|-------------|
| 1 | 🟢 Low | Plaintext Secret | Plaintext Generic Secret in AGENTS.md | Move Generic Secret to OS keychain or secrets manager |
| 2 | 🔵 Info | Outdated Version | Could not determine agent version | Ensure agent is updated to latest version |
| 3 | 🟢 Low | Exposed Token | JSON Web Token found in .env.test | Rotate and secure the JSON Web Token |
| 4 | 🟠 High | Exposed Token | JSON Web Token found in bake_pagination_seed.py | Rotate and secure the JSON Web Token |
| 5 | 🟢 Low | Exposed Token | JSON Web Token found in test_constants.py | Rotate and secure the JSON Web Token |
| 6 | 🟢 Low | Exposed Token | JSON Web Token found in test_constants.py | Rotate and secure the JSON Web Token |
| 7 | 🟠 High | Exposed Token | JSON Web Token found in config.py | Rotate and secure the JSON Web Token |
| 8 | 🟢 Low | Exposed Token | Secret Keyword found in test_custom_component_filesystem.py | Rotate and secure the Secret Keyword |
| 9 | 🟢 Low | Exposed Token | Private Key found in test_custom_component_filesystem.py | Rotate and secure the Private Key |
| 10 | 🟢 Low | Exposed Token | Secret Keyword found in test_custom_component_filesystem.py | Rotate and secure the Secret Keyword |
| 11 | 🟢 Low | Exposed Token | Secret Keyword found in haos_runtime.py | Rotate and secure the Secret Keyword |
| 12 | 🟢 Low | Exposed Token | Secret Keyword found in test_advanced_settings_coverage.py | Rotate and secure the Secret Keyword |
| 13 | 🟢 Low | Exposed Token | JSON Web Token found in test_tools_bug_report.py | Rotate and secure the JSON Web Token |
| 14 | 🟢 Low | Exposed Token | GitHub Token found in test_tools_bug_report.py | Rotate and secure the GitHub Token |
| 15 | 🟢 Low | Exposed Token | Secret Keyword found in test_webhook_proxy.py | Rotate and secure the Secret Keyword |

## Categories

| Category | Count |
|----------|------:|
| Exposed Token | 13 |
| Plaintext Secret | 1 |
| Outdated Version | 1 |

---

[Back to Dashboard](../mcp-security-grades.md) | *Scanned on 2026-06-22 by [agentsec](https://github.com/debu-sinha/agentsec)*
