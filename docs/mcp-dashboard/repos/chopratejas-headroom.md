# chopratejas/headroom

![Grade](https://img.shields.io/badge/Grade-F-red?style=for-the-badge) ![Score](https://img.shields.io/badge/Score-45%2F100-red?style=for-the-badge)

**Repository:** [chopratejas/headroom](https://github.com/chopratejas/headroom)
**Stars:** 3,462
**Last scan:** 2026-06-01

## Severity Summary

| Severity | Count |
|----------|------:|
| 🔴 Critical | **2** |
| 🟠 High | **1** |
| 🟡 Medium | **1** |
| 🟢 Low | **24** |
| 🔵 Info | **1** |
| **Total** | **29** |

## Findings

| # | Severity | Category | Title | Remediation |
|--:|:--------:|----------|-------|-------------|
| 1 | 🔵 Info | Outdated Version | Could not determine agent version | Ensure agent is updated to latest version |
| 2 | 🟢 Low | Exposed Token | JSON Web Token found in auth_mode.rs | Rotate and secure the JSON Web Token |
| 3 | 🟠 High | Exposed Token | JSON Web Token found in .gitguardian.yaml | Rotate and secure the JSON Web Token |
| 4 | 🟢 Low | Exposed Token | JSON Web Token found in integration_chat_completions.rs | Rotate and secure the JSON Web Token |
| 5 | 🟢 Low | Exposed Token | JSON Web Token found in integration_e4_openai_cache_key.rs | Rotate and secure the JSON Web Token |
| 6 | 🟢 Low | Exposed Token | JSON Web Token found in integration_responses_streaming.rs | Rotate and secure the JSON Web Token |
| 7 | 🟢 Low | Exposed Token | Secret Keyword found in test_universal.py | Rotate and secure the Secret Keyword |
| 8 | 🟢 Low | Exposed Token | Secret Keyword found in test_universal.py | Rotate and secure the Secret Keyword |
| 9 | 🟢 Low | Exposed Token | Secret Keyword found in test_provider_copilot_wrap.py | Rotate and secure the Secret Keyword |
| 10 | 🟢 Low | Exposed Token | Secret Keyword found in test_ccr_batch_processor.py | Rotate and secure the Secret Keyword |
| 11 | 🟢 Low | Exposed Token | Secret Keyword found in test_ccr_batch_processor.py | Rotate and secure the Secret Keyword |
| 12 | 🟢 Low | Exposed Token | Secret Keyword found in strands_bundle_demo.py | Rotate and secure the Secret Keyword |
| 13 | 🟢 Low | Exposed Token | Base64 High Entropy String found in anthropic_messages_request_real.json | Rotate and secure the Base64 High Entropy String |
| 14 | 🟢 Low | Exposed Token | Base64 High Entropy String found in anthropic_messages_request_real.json | Rotate and secure the Base64 High Entropy String |
| 15 | 🟢 Low | Exposed Token | Base64 High Entropy String found in integration_compression.rs | Rotate and secure the Base64 High Entropy String |
| 16 | 🟢 Low | Exposed Token | Base64 High Entropy String found in integration_compression.rs | Rotate and secure the Base64 High Entropy String |
| 17 | 🟢 Low | Exposed Token | Secret Keyword found in strands_via_proxy_demo.py | Rotate and secure the Secret Keyword |
| 18 | 🟢 Low | Exposed Token | JSON Web Token found in integration_responses.rs | Rotate and secure the JSON Web Token |
| 19 | 🟢 Low | Exposed Token | Secret Keyword found in integration_cache_drift.rs | Rotate and secure the Secret Keyword |
| 20 | 🟡 Medium | Exposed Token | Base64 High Entropy String found in beacon.py | Rotate and secure the Base64 High Entropy String |
| 21 | 🟢 Low | Exposed Token | JSON Web Token found in test_cache_aligner_detector_only.py | Rotate and secure the JSON Web Token |
| 22 | 🟢 Low | Exposed Token | JSON Web Token found in test_auth_mode.py | Rotate and secure the JSON Web Token |
| 23 | 🟢 Low | Exposed Token | Base64 High Entropy String found in integration_bedrock_invoke.rs | Rotate and secure the Base64 High Entropy String |
| 24 | 🟢 Low | Exposed Token | Secret Keyword found in client-expanded.test.ts | Rotate and secure the Secret Keyword |
| 25 | 🔴 Critical | Exposed Token | Anthropic API Key found in .gitguardian.yaml | Rotate and secure the Anthropic API Key |
| 26 | 🟢 Low | Exposed Token | OpenAI API Key found in test_auth_mode.py | Rotate and secure the OpenAI API Key |
| 27 | 🟢 Low | Exposed Token | Anthropic API Key found in test_realignment_live_multi_turn.py | Rotate and secure the Anthropic API Key |
| 28 | 🔴 Critical | Exposed Token | OpenAI API Key found in drift_detector.rs | Rotate and secure the OpenAI API Key |
| 29 | 🟢 Low | Exposed Token | OpenAI API Key found in auth_mode.rs | Rotate and secure the OpenAI API Key |

## Categories

| Category | Count |
|----------|------:|
| Exposed Token | 28 |
| Outdated Version | 1 |

---

[Back to Dashboard](../mcp-security-grades.md) | *Scanned on 2026-06-01 by [agentsec](https://github.com/debu-sinha/agentsec)*
