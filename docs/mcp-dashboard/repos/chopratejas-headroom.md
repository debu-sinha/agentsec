# chopratejas/headroom

![Grade](https://img.shields.io/badge/Grade-C-yellow?style=for-the-badge) ![Score](https://img.shields.io/badge/Score-73%2F100-yellow?style=for-the-badge)

**Repository:** [chopratejas/headroom](https://github.com/chopratejas/headroom)
**Stars:** 17,594
**Last scan:** 2026-06-08

## Severity Summary

| Severity | Count |
|----------|------:|
| 🟡 Medium | **4** |
| 🟢 Low | **21** |
| 🔵 Info | **1** |
| **Total** | **26** |

## Findings

| # | Severity | Category | Title | Remediation |
|--:|:--------:|----------|-------|-------------|
| 1 | 🔵 Info | Outdated Version | Could not determine agent version | Ensure agent is updated to latest version |
| 2 | 🟡 Medium | Data Exfiltration Risk | Node child process execution in skill 'openclaw' | Review or remove skill 'openclaw' |
| 3 | 🟡 Medium | Data Exfiltration Risk | Node child process execution in skill 'openclaw' | Review or remove skill 'openclaw' |
| 4 | 🟡 Medium | Data Exfiltration Risk | Node child process execution in skill 'openclaw' | Review or remove skill 'openclaw' |
| 5 | 🟢 Low | Exposed Token | JSON Web Token found in integration_responses_streaming.rs | Rotate and secure the JSON Web Token |
| 6 | 🟢 Low | Exposed Token | Base64 High Entropy String found in integration_bedrock_invoke.rs | Rotate and secure the Base64 High Entropy String |
| 7 | 🟢 Low | Exposed Token | JSON Web Token found in auth_mode.rs | Rotate and secure the JSON Web Token |
| 8 | 🟢 Low | Exposed Token | JSON Web Token found in integration_e4_openai_cache_key.rs | Rotate and secure the JSON Web Token |
| 9 | 🟢 Low | Exposed Token | Base64 High Entropy String found in anthropic_messages_request_real.json | Rotate and secure the Base64 High Entropy String |
| 10 | 🟢 Low | Exposed Token | Base64 High Entropy String found in anthropic_messages_request_real.json | Rotate and secure the Base64 High Entropy String |
| 11 | 🟢 Low | Exposed Token | JSON Web Token found in integration_chat_completions.rs | Rotate and secure the JSON Web Token |
| 12 | 🟢 Low | Exposed Token | JSON Web Token found in test_auth_mode.py | Rotate and secure the JSON Web Token |
| 13 | 🟢 Low | Exposed Token | Secret Keyword found in client-expanded.test.ts | Rotate and secure the Secret Keyword |
| 14 | 🟢 Low | Exposed Token | Secret Keyword found in integration_cache_drift.rs | Rotate and secure the Secret Keyword |
| 15 | 🟢 Low | Exposed Token | JSON Web Token found in integration_responses.rs | Rotate and secure the JSON Web Token |
| 16 | 🟢 Low | Exposed Token | JSON Web Token found in .gitguardian.yaml | Rotate and secure the JSON Web Token |
| 17 | 🟢 Low | Exposed Token | Secret Keyword found in test_universal.py | Rotate and secure the Secret Keyword |
| 18 | 🟢 Low | Exposed Token | Secret Keyword found in test_universal.py | Rotate and secure the Secret Keyword |
| 19 | 🟢 Low | Exposed Token | JSON Web Token found in test_cache_aligner_detector_only.py | Rotate and secure the JSON Web Token |
| 20 | 🟢 Low | Exposed Token | Base64 High Entropy String found in integration_compression.rs | Rotate and secure the Base64 High Entropy String |
| 21 | 🟢 Low | Exposed Token | Base64 High Entropy String found in integration_compression.rs | Rotate and secure the Base64 High Entropy String |
| 22 | 🟡 Medium | Exposed Token | Base64 High Entropy String found in beacon.py | Rotate and secure the Base64 High Entropy String |
| 23 | 🟢 Low | Exposed Token | Anthropic API Key found in .gitguardian.yaml | Rotate and secure the Anthropic API Key |
| 24 | 🟢 Low | Exposed Token | OpenAI API Key found in test_auth_mode.py | Rotate and secure the OpenAI API Key |
| 25 | 🟢 Low | Exposed Token | Anthropic API Key found in test_realignment_live_multi_turn.py | Rotate and secure the Anthropic API Key |
| 26 | 🟢 Low | Exposed Token | OpenAI API Key found in auth_mode.rs | Rotate and secure the OpenAI API Key |

## Categories

| Category | Count |
|----------|------:|
| Exposed Token | 22 |
| Data Exfiltration Risk | 3 |
| Outdated Version | 1 |

---

[Back to Dashboard](../mcp-security-grades.md) | *Scanned on 2026-06-08 by [agentsec](https://github.com/debu-sinha/agentsec)*
