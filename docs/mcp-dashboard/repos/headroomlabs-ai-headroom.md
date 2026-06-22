# headroomlabs-ai/headroom

![Grade](https://img.shields.io/badge/Grade-F-red?style=for-the-badge) ![Score](https://img.shields.io/badge/Score-46%2F100-red?style=for-the-badge)

**Repository:** [headroomlabs-ai/headroom](https://github.com/headroomlabs-ai/headroom)
**Stars:** 46,012
**Last scan:** 2026-06-22

## Severity Summary

| Severity | Count |
|----------|------:|
| 🟠 High | **3** |
| 🟡 Medium | **6** |
| 🟢 Low | **24** |
| 🔵 Info | **1** |
| **Total** | **34** |

## Findings

| # | Severity | Category | Title | Remediation |
|--:|:--------:|----------|-------|-------------|
| 1 | 🔵 Info | Outdated Version | Could not determine agent version | Ensure agent is updated to latest version |
| 2 | 🟡 Medium | Data Exfiltration Risk | Node child process execution in skill 'openclaw' | Review or remove skill 'openclaw' |
| 3 | 🟡 Medium | Data Exfiltration Risk | Node child process execution in skill 'openclaw' | Review or remove skill 'openclaw' |
| 4 | 🟡 Medium | Data Exfiltration Risk | Node child process execution in skill 'openclaw' | Review or remove skill 'openclaw' |
| 5 | 🟡 Medium | Dangerous Pattern | Dangerous call 'getattr()' in skill 'headroom-oauth2' | Remove or sandbox the 'getattr()' call |
| 6 | 🟡 Medium | Dangerous Pattern | Dangerous call 'getattr()' in skill 'headroom-oauth2' | Remove or sandbox the 'getattr()' call |
| 7 | 🟠 High | Data Exfiltration Risk | Environment variable harvesting in skill 'headroom-oauth2' | Review or remove skill 'headroom-oauth2' |
| 8 | 🟠 High | Data Exfiltration Risk | Environment variable harvesting in skill 'headroom-oauth2' | Review or remove skill 'headroom-oauth2' |
| 9 | 🟠 High | Data Exfiltration Risk | Environment variable harvesting in skill 'headroom-oauth2' | Review or remove skill 'headroom-oauth2' |
| 10 | 🟢 Low | Dangerous Pattern | Dangerous import 'urllib.parse' in skill 'headroom-oauth2' | Review whether 'urllib.parse' is necessary |
| 11 | 🟢 Low | Dangerous Pattern | Dangerous import 'urllib.request' in skill 'headroom-oauth2' | Review whether 'urllib.request' is necessary |
| 12 | 🟢 Low | Dangerous Pattern | Dangerous import 'urllib.error' in skill 'headroom-oauth2' | Review whether 'urllib.error' is necessary |
| 13 | 🟢 Low | Exposed Token | JSON Web Token found in integration_responses_streaming.rs | Rotate and secure the JSON Web Token |
| 14 | 🟢 Low | Exposed Token | JSON Web Token found in integration_e4_openai_cache_key.rs | Rotate and secure the JSON Web Token |
| 15 | 🟢 Low | Exposed Token | JSON Web Token found in integration_chat_completions.rs | Rotate and secure the JSON Web Token |
| 16 | 🟡 Medium | Exposed Token | Base64 High Entropy String found in beacon.py | Rotate and secure the Base64 High Entropy String |
| 17 | 🟢 Low | Exposed Token | Base64 High Entropy String found in anthropic_messages_request_real.json | Rotate and secure the Base64 High Entropy String |
| 18 | 🟢 Low | Exposed Token | Base64 High Entropy String found in anthropic_messages_request_real.json | Rotate and secure the Base64 High Entropy String |
| 19 | 🟢 Low | Exposed Token | JSON Web Token found in integration_responses.rs | Rotate and secure the JSON Web Token |
| 20 | 🟢 Low | Exposed Token | JSON Web Token found in test_cache_aligner_detector_only.py | Rotate and secure the JSON Web Token |
| 21 | 🟢 Low | Exposed Token | JSON Web Token found in .gitguardian.yaml | Rotate and secure the JSON Web Token |
| 22 | 🟢 Low | Exposed Token | Secret Keyword found in client-expanded.test.ts | Rotate and secure the Secret Keyword |
| 23 | 🟢 Low | Exposed Token | Base64 High Entropy String found in integration_bedrock_invoke.rs | Rotate and secure the Base64 High Entropy String |
| 24 | 🟢 Low | Exposed Token | JSON Web Token found in auth_mode.rs | Rotate and secure the JSON Web Token |
| 25 | 🟢 Low | Exposed Token | Secret Keyword found in test_universal.py | Rotate and secure the Secret Keyword |
| 26 | 🟢 Low | Exposed Token | Secret Keyword found in test_universal.py | Rotate and secure the Secret Keyword |
| 27 | 🟢 Low | Exposed Token | Base64 High Entropy String found in integration_compression.rs | Rotate and secure the Base64 High Entropy String |
| 28 | 🟢 Low | Exposed Token | Base64 High Entropy String found in integration_compression.rs | Rotate and secure the Base64 High Entropy String |
| 29 | 🟢 Low | Exposed Token | Secret Keyword found in integration_cache_drift.rs | Rotate and secure the Secret Keyword |
| 30 | 🟢 Low | Exposed Token | JSON Web Token found in test_auth_mode.py | Rotate and secure the JSON Web Token |
| 31 | 🟢 Low | Exposed Token | Anthropic API Key found in .gitguardian.yaml | Rotate and secure the Anthropic API Key |
| 32 | 🟢 Low | Exposed Token | OpenAI API Key found in test_auth_mode.py | Rotate and secure the OpenAI API Key |
| 33 | 🟢 Low | Exposed Token | Anthropic API Key found in test_realignment_live_multi_turn.py | Rotate and secure the Anthropic API Key |
| 34 | 🟢 Low | Exposed Token | OpenAI API Key found in auth_mode.rs | Rotate and secure the OpenAI API Key |

## Categories

| Category | Count |
|----------|------:|
| Exposed Token | 22 |
| Data Exfiltration Risk | 6 |
| Dangerous Pattern | 5 |
| Outdated Version | 1 |

---

[Back to Dashboard](../mcp-security-grades.md) | *Scanned on 2026-06-22 by [agentsec](https://github.com/debu-sinha/agentsec)*
