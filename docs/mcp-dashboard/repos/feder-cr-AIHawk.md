# feder-cr/AIHawk

![Grade](https://img.shields.io/badge/Grade-C-yellow?style=for-the-badge) ![Score](https://img.shields.io/badge/Score-75%2F100-yellow?style=for-the-badge)

**Repository:** [feder-cr/AIHawk](https://github.com/feder-cr/AIHawk)
**Stars:** 31,337
**Last scan:** 2026-09-14

## Severity Summary

| Severity | Count |
|----------|------:|
| 🔴 Critical | **1** |
| 🟢 Low | **10** |
| 🔵 Info | **1** |
| **Total** | **12** |

## Findings

| # | Severity | Category | Title | Remediation |
|--:|:--------:|----------|-------|-------------|
| 1 | 🔵 Info | Outdated Version | Could not determine agent version | Ensure agent is updated to latest version |
| 2 | 🔴 Critical | Malicious Skill | Remote pipe to shell in skill 'setup' | Remove skill 'setup' and investigate |
| 3 | 🟢 Low | Exposed Token | Secret Keyword found in test_openrouter_only.py | Rotate and secure the Secret Keyword |
| 4 | 🟢 Low | Exposed Token | Secret Keyword found in test_openrouter_only.py | Rotate and secure the Secret Keyword |
| 5 | 🟢 Low | Exposed Token | Secret Keyword found in test_env_file.py | Rotate and secure the Secret Keyword |
| 6 | 🟢 Low | Exposed Token | Secret Keyword found in test_env_file.py | Rotate and secure the Secret Keyword |
| 7 | 🟢 Low | Exposed Token | Basic Auth Credentials found in test_one_plan_for_one_session.py | Rotate and secure the Basic Auth Credentials |
| 8 | 🟢 Low | Exposed Token | Basic Auth Credentials found in test_one_plan_for_one_session.py | Rotate and secure the Basic Auth Credentials |
| 9 | 🟢 Low | Exposed Token | IBM Cloud IAM Key found in test_key_isolation.py | Rotate and secure the IBM Cloud IAM Key |
| 10 | 🟢 Low | Exposed Token | OpenAI API Key found in test_cli_surface.py | Rotate and secure the OpenAI API Key |
| 11 | 🟢 Low | Exposed Token | OpenAI API Key found in test_cli_surface.py | Rotate and secure the OpenAI API Key |
| 12 | 🟢 Low | Exposed Token | OpenAI API Key found in test_key_isolation.py | Rotate and secure the OpenAI API Key |

## Categories

| Category | Count |
|----------|------:|
| Exposed Token | 10 |
| Outdated Version | 1 |
| Malicious Skill | 1 |

---

[Back to Dashboard](../mcp-security-grades.md) | *Scanned on 2026-09-14 by [agentsec](https://github.com/debu-sinha/agentsec)*
