# homeassistant-ai/ha-mcp

![Grade](https://img.shields.io/badge/Grade-F-red?style=for-the-badge) ![Score](https://img.shields.io/badge/Score-5%2F100-red?style=for-the-badge)

**Repository:** [homeassistant-ai/ha-mcp](https://github.com/homeassistant-ai/ha-mcp)
**Stars:** 4,245
**Last scan:** 2026-08-03

## Severity Summary

| Severity | Count |
|----------|------:|
| 🟠 High | **2** |
| 🟡 Medium | **38** |
| 🟢 Low | **29** |
| 🔵 Info | **1** |
| **Total** | **70** |

## Findings

| # | Severity | Category | Title | Remediation |
|--:|:--------:|----------|-------|-------------|
| 1 | 🟢 Low | Plaintext Secret | Plaintext Generic Secret in AGENTS.md | Move Generic Secret to OS keychain or secrets manager |
| 2 | 🔵 Info | Outdated Version | Could not determine agent version | Ensure agent is updated to latest version |
| 3 | 🟢 Low | Exposed Token | Secret Keyword found in haos_runtime.py | Rotate and secure the Secret Keyword |
| 4 | 🟢 Low | Exposed Token | Secret Keyword found in test_advanced_settings_coverage.py | Rotate and secure the Secret Keyword |
| 5 | 🟢 Low | Exposed Token | Secret Keyword found in test_advanced_settings_coverage.py | Rotate and secure the Secret Keyword |
| 6 | 🟢 Low | Exposed Token | Secret Keyword found in test_advanced_settings_coverage.py | Rotate and secure the Secret Keyword |
| 7 | 🟡 Medium | Exposed Token | Secret Keyword found in en.json | Rotate and secure the Secret Keyword |
| 8 | 🟡 Medium | Exposed Token | Secret Keyword found in en.json | Rotate and secure the Secret Keyword |
| 9 | 🟡 Medium | Exposed Token | Secret Keyword found in en.json | Rotate and secure the Secret Keyword |
| 10 | 🟡 Medium | Exposed Token | Secret Keyword found in en.json | Rotate and secure the Secret Keyword |
| 11 | 🟡 Medium | Exposed Token | Secret Keyword found in en.json | Rotate and secure the Secret Keyword |
| 12 | 🟡 Medium | Exposed Token | Secret Keyword found in en.json | Rotate and secure the Secret Keyword |
| 13 | 🟡 Medium | Exposed Token | Secret Keyword found in zh-Hans.json | Rotate and secure the Secret Keyword |
| 14 | 🟡 Medium | Exposed Token | Secret Keyword found in zh-Hans.json | Rotate and secure the Secret Keyword |
| 15 | 🟡 Medium | Exposed Token | Secret Keyword found in zh-Hans.json | Rotate and secure the Secret Keyword |
| 16 | 🟡 Medium | Exposed Token | Secret Keyword found in es.json | Rotate and secure the Secret Keyword |
| 17 | 🟡 Medium | Exposed Token | Secret Keyword found in es.json | Rotate and secure the Secret Keyword |
| 18 | 🟡 Medium | Exposed Token | Secret Keyword found in es.json | Rotate and secure the Secret Keyword |
| 19 | 🟡 Medium | Exposed Token | Secret Keyword found in es.json | Rotate and secure the Secret Keyword |
| 20 | 🟡 Medium | Exposed Token | Secret Keyword found in es.json | Rotate and secure the Secret Keyword |
| 21 | 🟡 Medium | Exposed Token | Secret Keyword found in es.json | Rotate and secure the Secret Keyword |
| 22 | 🟢 Low | Exposed Token | JSON Web Token found in .env.test | Rotate and secure the JSON Web Token |
| 23 | 🟢 Low | Exposed Token | Secret Keyword found in test_component_backup_prep_contract.py | Rotate and secure the Secret Keyword |
| 24 | 🟢 Low | Exposed Token | Secret Keyword found in locale_source_baseline.json | Rotate and secure the Secret Keyword |
| 25 | 🟢 Low | Exposed Token | Secret Keyword found in locale_source_baseline.json | Rotate and secure the Secret Keyword |
| 26 | 🟢 Low | Exposed Token | Secret Keyword found in locale_source_baseline.json | Rotate and secure the Secret Keyword |
| 27 | 🟢 Low | Exposed Token | Secret Keyword found in locale_source_baseline.json | Rotate and secure the Secret Keyword |
| 28 | 🟢 Low | Exposed Token | Secret Keyword found in locale_source_baseline.json | Rotate and secure the Secret Keyword |
| 29 | 🟢 Low | Exposed Token | Private Key found in test_custom_component_filesystem.py | Rotate and secure the Private Key |
| 30 | 🟢 Low | Exposed Token | Secret Keyword found in test_custom_component_filesystem.py | Rotate and secure the Secret Keyword |
| 31 | 🟢 Low | Exposed Token | Secret Keyword found in test_custom_component_filesystem.py | Rotate and secure the Secret Keyword |
| 32 | 🟢 Low | Exposed Token | Secret Keyword found in test_custom_component_filesystem.py | Rotate and secure the Secret Keyword |
| 33 | 🟢 Low | Exposed Token | Secret Keyword found in test_embedded_setup.py | Rotate and secure the Secret Keyword |
| 34 | 🟢 Low | Exposed Token | Secret Keyword found in test_oauth_legacy_component.py | Rotate and secure the Secret Keyword |
| 35 | 🟢 Low | Exposed Token | JSON Web Token found in test_constants.py | Rotate and secure the JSON Web Token |
| 36 | 🟢 Low | Exposed Token | JSON Web Token found in test_constants.py | Rotate and secure the JSON Web Token |
| 37 | 🟢 Low | Exposed Token | Secret Keyword found in test_ha_mcp_server_entry.py | Rotate and secure the Secret Keyword |
| 38 | 🟢 Low | Exposed Token | Secret Keyword found in test_component_ws_search.py | Rotate and secure the Secret Keyword |
| 39 | 🟢 Low | Exposed Token | Secret Keyword found in test_component_ws_search.py | Rotate and secure the Secret Keyword |
| 40 | 🟢 Low | Exposed Token | Secret Keyword found in test_component_ws_search.py | Rotate and secure the Secret Keyword |
| 41 | 🟡 Medium | Exposed Token | Secret Keyword found in ru.json | Rotate and secure the Secret Keyword |
| 42 | 🟡 Medium | Exposed Token | Secret Keyword found in ru.json | Rotate and secure the Secret Keyword |
| 43 | 🟡 Medium | Exposed Token | Secret Keyword found in ru.json | Rotate and secure the Secret Keyword |
| 44 | 🟠 High | Exposed Token | JSON Web Token found in bake_pagination_seed.py | Rotate and secure the JSON Web Token |
| 45 | 🟢 Low | Exposed Token | Secret Keyword found in test_webhook_proxy.py | Rotate and secure the Secret Keyword |
| 46 | 🟢 Low | Exposed Token | JSON Web Token found in test_tools_bug_report.py | Rotate and secure the JSON Web Token |
| 47 | 🟢 Low | Exposed Token | GitHub Token found in test_tools_bug_report.py | Rotate and secure the GitHub Token |
| 48 | 🟢 Low | Exposed Token | JSON Web Token found in test_tools_bug_report.py | Rotate and secure the JSON Web Token |
| 49 | 🟡 Medium | Exposed Token | Secret Keyword found in const.py | Rotate and secure the Secret Keyword |
| 50 | 🟡 Medium | Exposed Token | Secret Keyword found in fr.json | Rotate and secure the Secret Keyword |
| 51 | 🟡 Medium | Exposed Token | Secret Keyword found in fr.json | Rotate and secure the Secret Keyword |
| 52 | 🟡 Medium | Exposed Token | Secret Keyword found in it.json | Rotate and secure the Secret Keyword |
| 53 | 🟡 Medium | Exposed Token | Secret Keyword found in it.json | Rotate and secure the Secret Keyword |
| 54 | 🟡 Medium | Exposed Token | Secret Keyword found in it.json | Rotate and secure the Secret Keyword |
| 55 | 🟡 Medium | Exposed Token | Secret Keyword found in it.json | Rotate and secure the Secret Keyword |
| 56 | 🟡 Medium | Exposed Token | Secret Keyword found in it.json | Rotate and secure the Secret Keyword |
| 57 | 🟠 High | Exposed Token | JSON Web Token found in config.py | Rotate and secure the JSON Web Token |
| 58 | 🟡 Medium | Exposed Token | Secret Keyword found in strings.json | Rotate and secure the Secret Keyword |
| 59 | 🟡 Medium | Exposed Token | Secret Keyword found in strings.json | Rotate and secure the Secret Keyword |
| 60 | 🟡 Medium | Exposed Token | Secret Keyword found in strings.json | Rotate and secure the Secret Keyword |
| 61 | 🟡 Medium | Exposed Token | Secret Keyword found in strings.json | Rotate and secure the Secret Keyword |
| 62 | 🟡 Medium | Exposed Token | Secret Keyword found in strings.json | Rotate and secure the Secret Keyword |
| 63 | 🟡 Medium | Exposed Token | Secret Keyword found in strings.json | Rotate and secure the Secret Keyword |
| 64 | 🟢 Low | Exposed Token | Secret Keyword found in test_component_search_contract.py | Rotate and secure the Secret Keyword |
| 65 | 🟡 Medium | Exposed Token | Secret Keyword found in de.json | Rotate and secure the Secret Keyword |
| 66 | 🟡 Medium | Exposed Token | Secret Keyword found in de.json | Rotate and secure the Secret Keyword |
| 67 | 🟡 Medium | Exposed Token | Secret Keyword found in de.json | Rotate and secure the Secret Keyword |
| 68 | 🟡 Medium | Exposed Token | Secret Keyword found in de.json | Rotate and secure the Secret Keyword |
| 69 | 🟡 Medium | Exposed Token | Secret Keyword found in de.json | Rotate and secure the Secret Keyword |
| 70 | 🟡 Medium | Exposed Token | Secret Keyword found in de.json | Rotate and secure the Secret Keyword |

## Categories

| Category | Count |
|----------|------:|
| Exposed Token | 68 |
| Plaintext Secret | 1 |
| Outdated Version | 1 |

---

[Back to Dashboard](../mcp-security-grades.md) | *Scanned on 2026-08-03 by [agentsec](https://github.com/debu-sinha/agentsec)*
