# PrefectHQ/fastmcp

![Grade](https://img.shields.io/badge/Grade-D-orange?style=for-the-badge) ![Score](https://img.shields.io/badge/Score-61%2F100-orange?style=for-the-badge)

**Repository:** [PrefectHQ/fastmcp](https://github.com/PrefectHQ/fastmcp)
**Stars:** 25,856
**Last scan:** 2026-06-29

## Severity Summary

| Severity | Count |
|----------|------:|
| 🔴 Critical | **1** |
| 🟡 Medium | **3** |
| 🟢 Low | **22** |
| 🔵 Info | **1** |
| **Total** | **27** |

## Findings

| # | Severity | Category | Title | Remediation |
|--:|:--------:|----------|-------|-------------|
| 1 | 🔵 Info | Outdated Version | Could not determine agent version | Ensure agent is updated to latest version |
| 2 | 🔴 Critical | Data Exfiltration Risk | Hook with network access: session-init | Remove or audit network commands in hooks |
| 3 | 🟢 Low | Exposed Token | Secret Keyword found in test_oidc_proxy_token.py | Rotate and secure the Secret Keyword |
| 4 | 🟢 Low | Exposed Token | Secret Keyword found in test_enhanced_error_responses.py | Rotate and secure the Secret Keyword |
| 5 | 🟢 Low | Exposed Token | Secret Keyword found in test_authorization.py | Rotate and secure the Secret Keyword |
| 6 | 🟡 Medium | Exposed Token | Secret Keyword found in auth0.py | Rotate and secure the Secret Keyword |
| 7 | 🟢 Low | Exposed Token | Secret Keyword found in test_oidc_proxy.py | Rotate and secure the Secret Keyword |
| 8 | 🟢 Low | Exposed Token | Secret Keyword found in test_keycloak_provider_integration.py | Rotate and secure the Secret Keyword |
| 9 | 🟢 Low | Exposed Token | Secret Keyword found in test_keycloak_provider_integration.py | Rotate and secure the Secret Keyword |
| 10 | 🟢 Low | Exposed Token | Secret Keyword found in test_keycloak_provider_integration.py | Rotate and secure the Secret Keyword |
| 11 | 🟢 Low | Exposed Token | Secret Keyword found in test_keycloak_provider_integration.py | Rotate and secure the Secret Keyword |
| 12 | 🟢 Low | Exposed Token | Secret Keyword found in test_oauth_proxy.py | Rotate and secure the Secret Keyword |
| 13 | 🟢 Low | Exposed Token | Secret Keyword found in test_tokens.py | Rotate and secure the Secret Keyword |
| 14 | 🟡 Medium | Exposed Token | Secret Keyword found in google.py | Rotate and secure the Secret Keyword |
| 15 | 🟢 Low | Exposed Token | Secret Keyword found in test_oauth_consent_page.py | Rotate and secure the Secret Keyword |
| 16 | 🟢 Low | Exposed Token | Secret Keyword found in test_oauth_consent_page.py | Rotate and secure the Secret Keyword |
| 17 | 🟢 Low | Exposed Token | Secret Keyword found in test_google.py | Rotate and secure the Secret Keyword |
| 18 | 🟢 Low | Exposed Token | Secret Keyword found in test_oauth_static_client.py | Rotate and secure the Secret Keyword |
| 19 | 🟡 Medium | Exposed Token | Secret Keyword found in discord.py | Rotate and secure the Secret Keyword |
| 20 | 🟢 Low | Exposed Token | Secret Keyword found in test_oauth_proxy_storage.py | Rotate and secure the Secret Keyword |
| 21 | 🟢 Low | Exposed Token | Secret Keyword found in test_oauth_proxy_storage.py | Rotate and secure the Secret Keyword |
| 22 | 🟢 Low | Exposed Token | Secret Keyword found in test_discord.py | Rotate and secure the Secret Keyword |
| 23 | 🟢 Low | Exposed Token | Secret Keyword found in fastmcp-analytics.js | Rotate and secure the Secret Keyword |
| 24 | 🟢 Low | Exposed Token | Secret Keyword found in test_e2e.py | Rotate and secure the Secret Keyword |
| 25 | 🟢 Low | Exposed Token | Secret Keyword found in test_config.py | Rotate and secure the Secret Keyword |
| 26 | 🟢 Low | Exposed Token | Secret Keyword found in test_client_registration.py | Rotate and secure the Secret Keyword |
| 27 | 🟢 Low | Exposed Token | Secret Keyword found in test_oauth_consent_flow.py | Rotate and secure the Secret Keyword |

## Categories

| Category | Count |
|----------|------:|
| Exposed Token | 25 |
| Outdated Version | 1 |
| Data Exfiltration Risk | 1 |

---

[Back to Dashboard](../mcp-security-grades.md) | *Scanned on 2026-06-29 by [agentsec](https://github.com/debu-sinha/agentsec)*
