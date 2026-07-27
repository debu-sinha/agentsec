# homeassistant-ai/ha-mcp

![Grade](https://img.shields.io/badge/Grade-F-red?style=for-the-badge) ![Score](https://img.shields.io/badge/Score-5%2F100-red?style=for-the-badge)

**Repository:** [homeassistant-ai/ha-mcp](https://github.com/homeassistant-ai/ha-mcp)
**Stars:** 4,126
**Last scan:** 2026-07-27

## Severity Summary

| Severity | Count |
|----------|------:|
| 🟠 High | **2** |
| 🟡 Medium | **27** |
| 🟢 Low | **29** |
| 🔵 Info | **1** |
| **Total** | **59** |

## Findings

| # | Severity | Category | Title | Remediation |
|--:|:--------:|----------|-------|-------------|
| 1 | 🟢 Low | Plaintext Secret | Plaintext Generic Secret in AGENTS.md | Move Generic Secret to OS keychain or secrets manager |
| 2 | 🔵 Info | Outdated Version | Could not determine agent version | Ensure agent is updated to latest version |
| 3 | 🟡 Medium | Exposed Token | Secret Keyword found in ru.json | Rotate and secure the Secret Keyword |
| 4 | 🟡 Medium | Exposed Token | Secret Keyword found in ru.json | Rotate and secure the Secret Keyword |
| 5 | 🟡 Medium | Exposed Token | Secret Keyword found in ru.json | Rotate and secure the Secret Keyword |
| 6 | 🟡 Medium | Exposed Token | Secret Keyword found in const.py | Rotate and secure the Secret Keyword |
| 7 | 🟢 Low | Exposed Token | Secret Keyword found in locale_source_baseline.json | Rotate and secure the Secret Keyword |
| 8 | 🟢 Low | Exposed Token | Secret Keyword found in locale_source_baseline.json | Rotate and secure the Secret Keyword |
| 9 | 🟢 Low | Exposed Token | Secret Keyword found in locale_source_baseline.json | Rotate and secure the Secret Keyword |
| 10 | 🟢 Low | Exposed Token | Secret Keyword found in locale_source_baseline.json | Rotate and secure the Secret Keyword |
| 11 | 🟢 Low | Exposed Token | Secret Keyword found in locale_source_baseline.json | Rotate and secure the Secret Keyword |
| 12 | 🟢 Low | Exposed Token | Secret Keyword found in test_ha_mcp_server_entry.py | Rotate and secure the Secret Keyword |
| 13 | 🟢 Low | Exposed Token | Secret Keyword found in test_embedded_setup.py | Rotate and secure the Secret Keyword |
| 14 | 🟢 Low | Exposed Token | JSON Web Token found in test_constants.py | Rotate and secure the JSON Web Token |
| 15 | 🟢 Low | Exposed Token | JSON Web Token found in test_constants.py | Rotate and secure the JSON Web Token |
| 16 | 🟢 Low | Exposed Token | Secret Keyword found in test_advanced_settings_coverage.py | Rotate and secure the Secret Keyword |
| 17 | 🟢 Low | Exposed Token | Secret Keyword found in test_advanced_settings_coverage.py | Rotate and secure the Secret Keyword |
| 18 | 🟢 Low | Exposed Token | Secret Keyword found in test_advanced_settings_coverage.py | Rotate and secure the Secret Keyword |
| 19 | 🟠 High | Exposed Token | JSON Web Token found in config.py | Rotate and secure the JSON Web Token |
| 20 | 🟢 Low | Exposed Token | Secret Keyword found in haos_runtime.py | Rotate and secure the Secret Keyword |
| 21 | 🟢 Low | Exposed Token | Private Key found in test_custom_component_filesystem.py | Rotate and secure the Private Key |
| 22 | 🟢 Low | Exposed Token | Secret Keyword found in test_custom_component_filesystem.py | Rotate and secure the Secret Keyword |
| 23 | 🟢 Low | Exposed Token | Secret Keyword found in test_custom_component_filesystem.py | Rotate and secure the Secret Keyword |
| 24 | 🟢 Low | Exposed Token | Secret Keyword found in test_custom_component_filesystem.py | Rotate and secure the Secret Keyword |
| 25 | 🟢 Low | Exposed Token | Secret Keyword found in test_component_ws_search.py | Rotate and secure the Secret Keyword |
| 26 | 🟢 Low | Exposed Token | Secret Keyword found in test_component_ws_search.py | Rotate and secure the Secret Keyword |
| 27 | 🟢 Low | Exposed Token | Secret Keyword found in test_component_ws_search.py | Rotate and secure the Secret Keyword |
| 28 | 🟢 Low | Exposed Token | Secret Keyword found in test_oauth_legacy_component.py | Rotate and secure the Secret Keyword |
| 29 | 🟡 Medium | Exposed Token | Secret Keyword found in fr.json | Rotate and secure the Secret Keyword |
| 30 | 🟡 Medium | Exposed Token | Secret Keyword found in fr.json | Rotate and secure the Secret Keyword |
| 31 | 🟢 Low | Exposed Token | Secret Keyword found in test_component_backup_prep_contract.py | Rotate and secure the Secret Keyword |
| 32 | 🟠 High | Exposed Token | JSON Web Token found in bake_pagination_seed.py | Rotate and secure the JSON Web Token |
| 33 | 🟡 Medium | Exposed Token | Secret Keyword found in zh-Hans.json | Rotate and secure the Secret Keyword |
| 34 | 🟡 Medium | Exposed Token | Secret Keyword found in zh-Hans.json | Rotate and secure the Secret Keyword |
| 35 | 🟡 Medium | Exposed Token | Secret Keyword found in zh-Hans.json | Rotate and secure the Secret Keyword |
| 36 | 🟢 Low | Exposed Token | JSON Web Token found in .env.test | Rotate and secure the JSON Web Token |
| 37 | 🟡 Medium | Exposed Token | Secret Keyword found in en.json | Rotate and secure the Secret Keyword |
| 38 | 🟡 Medium | Exposed Token | Secret Keyword found in en.json | Rotate and secure the Secret Keyword |
| 39 | 🟡 Medium | Exposed Token | Secret Keyword found in en.json | Rotate and secure the Secret Keyword |
| 40 | 🟡 Medium | Exposed Token | Secret Keyword found in en.json | Rotate and secure the Secret Keyword |
| 41 | 🟡 Medium | Exposed Token | Secret Keyword found in en.json | Rotate and secure the Secret Keyword |
| 42 | 🟡 Medium | Exposed Token | Secret Keyword found in en.json | Rotate and secure the Secret Keyword |
| 43 | 🟢 Low | Exposed Token | Secret Keyword found in test_webhook_proxy.py | Rotate and secure the Secret Keyword |
| 44 | 🟢 Low | Exposed Token | GitHub Token found in test_tools_bug_report.py | Rotate and secure the GitHub Token |
| 45 | 🟢 Low | Exposed Token | JSON Web Token found in test_tools_bug_report.py | Rotate and secure the JSON Web Token |
| 46 | 🟢 Low | Exposed Token | JSON Web Token found in test_tools_bug_report.py | Rotate and secure the JSON Web Token |
| 47 | 🟢 Low | Exposed Token | Secret Keyword found in test_component_search_contract.py | Rotate and secure the Secret Keyword |
| 48 | 🟡 Medium | Exposed Token | Secret Keyword found in de.json | Rotate and secure the Secret Keyword |
| 49 | 🟡 Medium | Exposed Token | Secret Keyword found in de.json | Rotate and secure the Secret Keyword |
| 50 | 🟡 Medium | Exposed Token | Secret Keyword found in de.json | Rotate and secure the Secret Keyword |
| 51 | 🟡 Medium | Exposed Token | Secret Keyword found in de.json | Rotate and secure the Secret Keyword |
| 52 | 🟡 Medium | Exposed Token | Secret Keyword found in de.json | Rotate and secure the Secret Keyword |
| 53 | 🟡 Medium | Exposed Token | Secret Keyword found in de.json | Rotate and secure the Secret Keyword |
| 54 | 🟡 Medium | Exposed Token | Secret Keyword found in strings.json | Rotate and secure the Secret Keyword |
| 55 | 🟡 Medium | Exposed Token | Secret Keyword found in strings.json | Rotate and secure the Secret Keyword |
| 56 | 🟡 Medium | Exposed Token | Secret Keyword found in strings.json | Rotate and secure the Secret Keyword |
| 57 | 🟡 Medium | Exposed Token | Secret Keyword found in strings.json | Rotate and secure the Secret Keyword |
| 58 | 🟡 Medium | Exposed Token | Secret Keyword found in strings.json | Rotate and secure the Secret Keyword |
| 59 | 🟡 Medium | Exposed Token | Secret Keyword found in strings.json | Rotate and secure the Secret Keyword |

## Categories

| Category | Count |
|----------|------:|
| Exposed Token | 57 |
| Plaintext Secret | 1 |
| Outdated Version | 1 |

---

[Back to Dashboard](../mcp-security-grades.md) | *Scanned on 2026-07-27 by [agentsec](https://github.com/debu-sinha/agentsec)*
