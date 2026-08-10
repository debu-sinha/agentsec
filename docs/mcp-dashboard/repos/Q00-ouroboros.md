# Q00/ouroboros

![Grade](https://img.shields.io/badge/Grade-F-red?style=for-the-badge) ![Score](https://img.shields.io/badge/Score-52%2F100-red?style=for-the-badge)

**Repository:** [Q00/ouroboros](https://github.com/Q00/ouroboros)
**Stars:** 5,366
**Last scan:** 2026-08-10

## Severity Summary

| Severity | Count |
|----------|------:|
| 🔴 Critical | **2** |
| 🟡 Medium | **1** |
| 🟢 Low | **26** |
| 🔵 Info | **1** |
| **Total** | **30** |

## Findings

| # | Severity | Category | Title | Remediation |
|--:|:--------:|----------|-------|-------------|
| 1 | 🔵 Info | Outdated Version | Could not determine agent version | Ensure agent is updated to latest version |
| 2 | 🔴 Critical | Malicious Skill | Remote pipe to shell in skill 'setup' | Remove skill 'setup' and investigate |
| 3 | 🔴 Critical | Malicious Skill | Remote pipe to shell in skill 'setup' | Remove skill 'setup' and investigate |
| 4 | 🟡 Medium | Exposed Token | Secret Keyword found in telemetry.py | Rotate and secure the Secret Keyword |
| 5 | 🟢 Low | Exposed Token | Secret Keyword found in test_data_context_lane.py | Rotate and secure the Secret Keyword |
| 6 | 🟢 Low | Exposed Token | Secret Keyword found in test_litellm_proof_worker.py | Rotate and secure the Secret Keyword |
| 7 | 🟢 Low | Exposed Token | JSON Web Token found in test_firewall.py | Rotate and secure the JSON Web Token |
| 8 | 🟢 Low | Exposed Token | Secret Keyword found in test_handlers.py | Rotate and secure the Secret Keyword |
| 9 | 🟢 Low | Exposed Token | Secret Keyword found in test_handlers.py | Rotate and secure the Secret Keyword |
| 10 | 🟢 Low | Exposed Token | Secret Keyword found in test_handlers.py | Rotate and secure the Secret Keyword |
| 11 | 🟢 Low | Exposed Token | Secret Keyword found in test_handlers.py | Rotate and secure the Secret Keyword |
| 12 | 🟢 Low | Exposed Token | Secret Keyword found in test_handlers.py | Rotate and secure the Secret Keyword |
| 13 | 🟢 Low | Exposed Token | Secret Keyword found in test_handlers.py | Rotate and secure the Secret Keyword |
| 14 | 🟢 Low | Exposed Token | Secret Keyword found in test_provider_usage.py | Rotate and secure the Secret Keyword |
| 15 | 🟢 Low | Exposed Token | Secret Keyword found in test_provider_usage.py | Rotate and secure the Secret Keyword |
| 16 | 🟢 Low | Exposed Token | Secret Keyword found in test_provider_usage.py | Rotate and secure the Secret Keyword |
| 17 | 🟢 Low | Exposed Token | Secret Keyword found in test_provider_usage.py | Rotate and secure the Secret Keyword |
| 18 | 🟢 Low | Exposed Token | Secret Keyword found in test_provider_usage.py | Rotate and secure the Secret Keyword |
| 19 | 🟢 Low | Exposed Token | Basic Auth Credentials found in test_provider_usage.py | Rotate and secure the Basic Auth Credentials |
| 20 | 🟢 Low | Exposed Token | JSON Web Token found in test_route_policy.py | Rotate and secure the JSON Web Token |
| 21 | 🟢 Low | Exposed Token | GitLab Token found in test_route_policy.py | Rotate and secure the GitLab Token |
| 22 | 🟢 Low | Exposed Token | Secret Keyword found in test_models.py | Rotate and secure the Secret Keyword |
| 23 | 🟢 Low | Exposed Token | Secret Keyword found in test_config.py | Rotate and secure the Secret Keyword |
| 24 | 🟢 Low | Exposed Token | Secret Keyword found in test_export_interview_latency.py | Rotate and secure the Secret Keyword |
| 25 | 🟢 Low | Exposed Token | Secret Keyword found in test_export_interview_latency.py | Rotate and secure the Secret Keyword |
| 26 | 🟢 Low | Exposed Token | Secret Keyword found in test_export_interview_latency.py | Rotate and secure the Secret Keyword |
| 27 | 🟢 Low | Exposed Token | Secret Keyword found in test_mcp_shell_env.py | Rotate and secure the Secret Keyword |
| 28 | 🟢 Low | Exposed Token | GitLab Token found in test_security.py | Rotate and secure the GitLab Token |
| 29 | 🟢 Low | Exposed Token | JSON Web Token found in test_security.py | Rotate and secure the JSON Web Token |
| 30 | 🟢 Low | Exposed Token | OpenAI API Key found in test_firewall_tool_call_dispatch.py | Rotate and secure the OpenAI API Key |

## Categories

| Category | Count |
|----------|------:|
| Exposed Token | 27 |
| Malicious Skill | 2 |
| Outdated Version | 1 |

---

[Back to Dashboard](../mcp-security-grades.md) | *Scanned on 2026-08-10 by [agentsec](https://github.com/debu-sinha/agentsec)*
