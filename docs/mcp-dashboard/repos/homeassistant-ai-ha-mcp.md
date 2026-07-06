# homeassistant-ai/ha-mcp

![Grade](https://img.shields.io/badge/Grade-F-red?style=for-the-badge) ![Score](https://img.shields.io/badge/Score-45%2F100-red?style=for-the-badge)

**Repository:** [homeassistant-ai/ha-mcp](https://github.com/homeassistant-ai/ha-mcp)
**Stars:** 3,840
**Last scan:** 2026-07-06

## Severity Summary

| Severity | Count |
|----------|------:|
| 🟠 High | **2** |
| 🟡 Medium | **9** |
| 🟢 Low | **14** |
| 🔵 Info | **1** |
| **Total** | **26** |

## Findings

| # | Severity | Category | Title | Remediation |
|--:|:--------:|----------|-------|-------------|
| 1 | 🟢 Low | Plaintext Secret | Plaintext Generic Secret in AGENTS.md | Move Generic Secret to OS keychain or secrets manager |
| 2 | 🔵 Info | Outdated Version | Could not determine agent version | Ensure agent is updated to latest version |
| 3 | 🟠 High | Exposed Token | JSON Web Token found in bake_pagination_seed.py | Rotate and secure the JSON Web Token |
| 4 | 🟡 Medium | Exposed Token | Secret Keyword found in const.py | Rotate and secure the Secret Keyword |
| 5 | 🟢 Low | Exposed Token | Secret Keyword found in test_ha_mcp_server_entry.py | Rotate and secure the Secret Keyword |
| 6 | 🟡 Medium | Exposed Token | Secret Keyword found in en.json | Rotate and secure the Secret Keyword |
| 7 | 🟡 Medium | Exposed Token | Secret Keyword found in en.json | Rotate and secure the Secret Keyword |
| 8 | 🟡 Medium | Exposed Token | Secret Keyword found in en.json | Rotate and secure the Secret Keyword |
| 9 | 🟡 Medium | Exposed Token | Secret Keyword found in en.json | Rotate and secure the Secret Keyword |
| 10 | 🟢 Low | Exposed Token | Secret Keyword found in test_webhook_proxy.py | Rotate and secure the Secret Keyword |
| 11 | 🟢 Low | Exposed Token | JSON Web Token found in .env.test | Rotate and secure the JSON Web Token |
| 12 | 🟠 High | Exposed Token | JSON Web Token found in config.py | Rotate and secure the JSON Web Token |
| 13 | 🟡 Medium | Exposed Token | Secret Keyword found in strings.json | Rotate and secure the Secret Keyword |
| 14 | 🟡 Medium | Exposed Token | Secret Keyword found in strings.json | Rotate and secure the Secret Keyword |
| 15 | 🟡 Medium | Exposed Token | Secret Keyword found in strings.json | Rotate and secure the Secret Keyword |
| 16 | 🟡 Medium | Exposed Token | Secret Keyword found in strings.json | Rotate and secure the Secret Keyword |
| 17 | 🟢 Low | Exposed Token | Secret Keyword found in haos_runtime.py | Rotate and secure the Secret Keyword |
| 18 | 🟢 Low | Exposed Token | Secret Keyword found in test_advanced_settings_coverage.py | Rotate and secure the Secret Keyword |
| 19 | 🟢 Low | Exposed Token | Private Key found in test_custom_component_filesystem.py | Rotate and secure the Private Key |
| 20 | 🟢 Low | Exposed Token | Secret Keyword found in test_custom_component_filesystem.py | Rotate and secure the Secret Keyword |
| 21 | 🟢 Low | Exposed Token | Secret Keyword found in test_custom_component_filesystem.py | Rotate and secure the Secret Keyword |
| 22 | 🟢 Low | Exposed Token | GitHub Token found in test_tools_bug_report.py | Rotate and secure the GitHub Token |
| 23 | 🟢 Low | Exposed Token | JSON Web Token found in test_tools_bug_report.py | Rotate and secure the JSON Web Token |
| 24 | 🟢 Low | Exposed Token | JSON Web Token found in test_tools_bug_report.py | Rotate and secure the JSON Web Token |
| 25 | 🟢 Low | Exposed Token | JSON Web Token found in test_constants.py | Rotate and secure the JSON Web Token |
| 26 | 🟢 Low | Exposed Token | JSON Web Token found in test_constants.py | Rotate and secure the JSON Web Token |

## Categories

| Category | Count |
|----------|------:|
| Exposed Token | 24 |
| Plaintext Secret | 1 |
| Outdated Version | 1 |

---

[Back to Dashboard](../mcp-security-grades.md) | *Scanned on 2026-07-06 by [agentsec](https://github.com/debu-sinha/agentsec)*
