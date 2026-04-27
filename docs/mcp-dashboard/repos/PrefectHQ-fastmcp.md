# PrefectHQ/fastmcp

![Grade](https://img.shields.io/badge/Grade-F-red?style=for-the-badge) ![Score](https://img.shields.io/badge/Score-34%2F100-red?style=for-the-badge)

**Repository:** [PrefectHQ/fastmcp](https://github.com/PrefectHQ/fastmcp)
**Stars:** 24,875
**Last scan:** 2026-04-27

## Severity Summary

| Severity | Count |
|----------|------:|
| 🔴 Critical | **1** |
| 🟡 Medium | **12** |
| 🟢 Low | **35** |
| 🔵 Info | **1** |
| **Total** | **49** |

## Findings

| # | Severity | Category | Title | Remediation |
|--:|:--------:|----------|-------|-------------|
| 1 | 🔵 Info | Outdated Version | Could not determine agent version | Ensure agent is updated to latest version |
| 2 | 🔴 Critical | Data Exfiltration Risk | Hook with network access: session-init | Remove or audit network commands in hooks |
| 3 | 🟢 Low | Exposed Token | Secret Keyword found in test_e2e.py | Rotate and secure the Secret Keyword |
| 4 | 🟡 Medium | Exposed Token | Secret Keyword found in github.py | Rotate and secure the Secret Keyword |
| 5 | 🟢 Low | Exposed Token | Secret Keyword found in README.md | Rotate and secure the Secret Keyword |
| 6 | 🟡 Medium | Exposed Token | Secret Keyword found in azure.py | Rotate and secure the Secret Keyword |
| 7 | 🟢 Low | Exposed Token | Secret Keyword found in test_azure.py | Rotate and secure the Secret Keyword |
| 8 | 🟢 Low | Exposed Token | Secret Keyword found in test_clerk.py | Rotate and secure the Secret Keyword |
| 9 | 🟢 Low | Exposed Token | Secret Keyword found in test_clerk.py | Rotate and secure the Secret Keyword |
| 10 | 🟡 Medium | Exposed Token | Secret Keyword found in aws.py | Rotate and secure the Secret Keyword |
| 11 | 🟡 Medium | Exposed Token | Secret Keyword found in google.py | Rotate and secure the Secret Keyword |
| 12 | 🟡 Medium | Exposed Token | Secret Keyword found in google.py | Rotate and secure the Secret Keyword |
| 13 | 🟢 Low | Exposed Token | Secret Keyword found in test_oidc_proxy.py | Rotate and secure the Secret Keyword |
| 14 | 🟢 Low | Exposed Token | Secret Keyword found in test_propelauth.py | Rotate and secure the Secret Keyword |
| 15 | 🟢 Low | Exposed Token | Secret Keyword found in README.md | Rotate and secure the Secret Keyword |
| 16 | 🟢 Low | Exposed Token | Secret Keyword found in test_oidc_proxy_token.py | Rotate and secure the Secret Keyword |
| 17 | 🟢 Low | Exposed Token | Secret Keyword found in test_oauth_static_client.py | Rotate and secure the Secret Keyword |
| 18 | 🟢 Low | Exposed Token | Secret Keyword found in fastmcp-analytics.js | Rotate and secure the Secret Keyword |
| 19 | 🟢 Low | Exposed Token | Secret Keyword found in README.md | Rotate and secure the Secret Keyword |
| 20 | 🟢 Low | Exposed Token | Secret Keyword found in README.md | Rotate and secure the Secret Keyword |
| 21 | 🟢 Low | Exposed Token | Secret Keyword found in README.md | Rotate and secure the Secret Keyword |
| 22 | 🟡 Medium | Exposed Token | Secret Keyword found in auth0.py | Rotate and secure the Secret Keyword |
| 23 | 🟢 Low | Exposed Token | Secret Keyword found in test_oauth_consent_page.py | Rotate and secure the Secret Keyword |
| 24 | 🟢 Low | Exposed Token | Secret Keyword found in test_oauth_consent_page.py | Rotate and secure the Secret Keyword |
| 25 | 🟢 Low | Exposed Token | Secret Keyword found in test_keycloak_provider_integration.py | Rotate and secure the Secret Keyword |
| 26 | 🟢 Low | Exposed Token | Secret Keyword found in test_keycloak_provider_integration.py | Rotate and secure the Secret Keyword |
| 27 | 🟢 Low | Exposed Token | Secret Keyword found in test_keycloak_provider_integration.py | Rotate and secure the Secret Keyword |
| 28 | 🟢 Low | Exposed Token | Secret Keyword found in test_keycloak_provider_integration.py | Rotate and secure the Secret Keyword |
| 29 | 🟢 Low | Exposed Token | Secret Keyword found in test_discord.py | Rotate and secure the Secret Keyword |
| 30 | 🟢 Low | Exposed Token | Secret Keyword found in test_client_registration.py | Rotate and secure the Secret Keyword |
| 31 | 🟢 Low | Exposed Token | Secret Keyword found in README.md | Rotate and secure the Secret Keyword |
| 32 | 🟢 Low | Exposed Token | Secret Keyword found in test_enhanced_error_responses.py | Rotate and secure the Secret Keyword |
| 33 | 🟡 Medium | Exposed Token | Secret Keyword found in oidc_proxy.py | Rotate and secure the Secret Keyword |
| 34 | 🟡 Medium | Exposed Token | Secret Keyword found in clerk.py | Rotate and secure the Secret Keyword |
| 35 | 🟢 Low | Exposed Token | Secret Keyword found in test_oauth_proxy_storage.py | Rotate and secure the Secret Keyword |
| 36 | 🟢 Low | Exposed Token | Secret Keyword found in test_oauth_proxy_storage.py | Rotate and secure the Secret Keyword |
| 37 | 🟢 Low | Exposed Token | Secret Keyword found in test_oauth_consent_flow.py | Rotate and secure the Secret Keyword |
| 38 | 🟢 Low | Exposed Token | Secret Keyword found in test_oauth_consent_flow.py | Rotate and secure the Secret Keyword |
| 39 | 🟢 Low | Exposed Token | Secret Keyword found in test_google.py | Rotate and secure the Secret Keyword |
| 40 | 🟢 Low | Exposed Token | Secret Keyword found in README.md | Rotate and secure the Secret Keyword |
| 41 | 🟡 Medium | Exposed Token | Secret Keyword found in propelauth.py | Rotate and secure the Secret Keyword |
| 42 | 🟡 Medium | Exposed Token | Secret Keyword found in introspection.py | Rotate and secure the Secret Keyword |
| 43 | 🟢 Low | Exposed Token | Secret Keyword found in README.md | Rotate and secure the Secret Keyword |
| 44 | 🟢 Low | Exposed Token | Secret Keyword found in test_tokens.py | Rotate and secure the Secret Keyword |
| 45 | 🟢 Low | Exposed Token | Secret Keyword found in test_oauth_proxy.py | Rotate and secure the Secret Keyword |
| 46 | 🟡 Medium | Exposed Token | Secret Keyword found in discord.py | Rotate and secure the Secret Keyword |
| 47 | 🟡 Medium | Exposed Token | Secret Keyword found in discord.py | Rotate and secure the Secret Keyword |
| 48 | 🟢 Low | Exposed Token | Secret Keyword found in test_authorization.py | Rotate and secure the Secret Keyword |
| 49 | 🟢 Low | Exposed Token | Secret Keyword found in test_config.py | Rotate and secure the Secret Keyword |

## Categories

| Category | Count |
|----------|------:|
| Exposed Token | 47 |
| Outdated Version | 1 |
| Data Exfiltration Risk | 1 |

---

[Back to Dashboard](../mcp-security-grades.md) | *Scanned on 2026-04-27 by [agentsec](https://github.com/debu-sinha/agentsec)*
