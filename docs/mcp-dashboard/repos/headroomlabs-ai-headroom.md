# headroomlabs-ai/headroom

![Grade](https://img.shields.io/badge/Grade-F-red?style=for-the-badge) ![Score](https://img.shields.io/badge/Score-25%2F100-red?style=for-the-badge)

**Repository:** [headroomlabs-ai/headroom](https://github.com/headroomlabs-ai/headroom)
**Stars:** 67,319
**Last scan:** 2026-08-24

## Severity Summary

| Severity | Count |
|----------|------:|
| 🔴 Critical | **1** |
| 🟠 High | **3** |
| 🟡 Medium | **8** |
| 🟢 Low | **36** |
| 🔵 Info | **1** |
| **Total** | **49** |

## Findings

| # | Severity | Category | Title | Remediation |
|--:|:--------:|----------|-------|-------------|
| 1 | 🔵 Info | Outdated Version | Could not determine agent version | Ensure agent is updated to latest version |
| 2 | 🟢 Low | Dangerous Pattern | Dangerous import 'urllib.error' in skill 'headroom-oauth2' | Review whether 'urllib.error' is necessary |
| 3 | 🟡 Medium | Dangerous Pattern | Dangerous call 'setattr()' in skill 'headroom-oauth2' | Remove or sandbox the 'setattr()' call |
| 4 | 🟡 Medium | Dangerous Pattern | Dangerous call 'getattr()' in skill 'headroom-oauth2' | Remove or sandbox the 'getattr()' call |
| 5 | 🟡 Medium | Dangerous Pattern | Dangerous call 'getattr()' in skill 'headroom-oauth2' | Remove or sandbox the 'getattr()' call |
| 6 | 🟠 High | Data Exfiltration Risk | Environment variable harvesting in skill 'headroom-oauth2' | Review or remove skill 'headroom-oauth2' |
| 7 | 🟠 High | Data Exfiltration Risk | Environment variable harvesting in skill 'headroom-oauth2' | Review or remove skill 'headroom-oauth2' |
| 8 | 🟠 High | Data Exfiltration Risk | Environment variable harvesting in skill 'headroom-oauth2' | Review or remove skill 'headroom-oauth2' |
| 9 | 🟢 Low | Dangerous Pattern | Dangerous import 'urllib.parse' in skill 'headroom-oauth2' | Review whether 'urllib.parse' is necessary |
| 10 | 🟢 Low | Dangerous Pattern | Dangerous import 'urllib.request' in skill 'headroom-oauth2' | Review whether 'urllib.request' is necessary |
| 11 | 🟢 Low | Dangerous Pattern | Dangerous import 'urllib.error' in skill 'headroom-oauth2' | Review whether 'urllib.error' is necessary |
| 12 | 🟡 Medium | Data Exfiltration Risk | Node child process execution in skill 'openclaw' | Review or remove skill 'openclaw' |
| 13 | 🟡 Medium | Data Exfiltration Risk | Node child process execution in skill 'openclaw' | Review or remove skill 'openclaw' |
| 14 | 🟡 Medium | Data Exfiltration Risk | Node child process execution in skill 'openclaw' | Review or remove skill 'openclaw' |
| 15 | 🟢 Low | Exposed Token | JSON Web Token found in auth_mode.rs | Rotate and secure the JSON Web Token |
| 16 | 🟢 Low | Exposed Token | JSON Web Token found in test_auth_policy.py | Rotate and secure the JSON Web Token |
| 17 | 🟢 Low | Exposed Token | Secret Keyword found in test_auth_policy.py | Rotate and secure the Secret Keyword |
| 18 | 🟢 Low | Exposed Token | JSON Web Token found in integration_responses.rs | Rotate and secure the JSON Web Token |
| 19 | 🟢 Low | Exposed Token | JSON Web Token found in test_cache_aligner_detector_only.py | Rotate and secure the JSON Web Token |
| 20 | 🟢 Low | Exposed Token | Secret Keyword found in test_masks.py | Rotate and secure the Secret Keyword |
| 21 | 🟢 Low | Exposed Token | Secret Keyword found in test_wire_debug_redaction_policy.py | Rotate and secure the Secret Keyword |
| 22 | 🟢 Low | Exposed Token | Secret Keyword found in client-expanded.test.ts | Rotate and secure the Secret Keyword |
| 23 | 🟢 Low | Exposed Token | Secret Keyword found in test_universal.py | Rotate and secure the Secret Keyword |
| 24 | 🟢 Low | Exposed Token | JSON Web Token found in integration_anthropic_model_sanitize.rs | Rotate and secure the JSON Web Token |
| 25 | 🟢 Low | Exposed Token | Secret Keyword found in test_upstream_guard.py | Rotate and secure the Secret Keyword |
| 26 | 🟢 Low | Exposed Token | JSON Web Token found in integration_responses_streaming.rs | Rotate and secure the JSON Web Token |
| 27 | 🟢 Low | Exposed Token | JSON Web Token found in test_auth_mode.py | Rotate and secure the JSON Web Token |
| 28 | 🟢 Low | Exposed Token | Secret Keyword found in test_universal.py | Rotate and secure the Secret Keyword |
| 29 | 🟢 Low | Exposed Token | Secret Keyword found in test_universal.py | Rotate and secure the Secret Keyword |
| 30 | 🟢 Low | Exposed Token | Secret Keyword found in integration_cache_drift.rs | Rotate and secure the Secret Keyword |
| 31 | 🟢 Low | Exposed Token | JSON Web Token found in integration_chat_completions.rs | Rotate and secure the JSON Web Token |
| 32 | 🟢 Low | Exposed Token | Base64 High Entropy String found in integration_bedrock_invoke.rs | Rotate and secure the Base64 High Entropy String |
| 33 | 🟡 Medium | Exposed Token | Secret Keyword found in vscode.py | Rotate and secure the Secret Keyword |
| 34 | 🟡 Medium | Exposed Token | Secret Keyword found in vscode.py | Rotate and secure the Secret Keyword |
| 35 | 🟢 Low | Exposed Token | Secret Keyword found in test_issue_1779_remote_control_gate.py | Rotate and secure the Secret Keyword |
| 36 | 🟢 Low | Exposed Token | Secret Keyword found in test_issue_1779_remote_control_gate.py | Rotate and secure the Secret Keyword |
| 37 | 🟢 Low | Exposed Token | JSON Web Token found in .gitguardian.yaml | Rotate and secure the JSON Web Token |
| 38 | 🟢 Low | Exposed Token | Base64 High Entropy String found in tailwind.min.js | Rotate and secure the Base64 High Entropy String |
| 39 | 🟢 Low | Exposed Token | Base64 High Entropy String found in integration_compression.rs | Rotate and secure the Base64 High Entropy String |
| 40 | 🟢 Low | Exposed Token | Base64 High Entropy String found in integration_compression.rs | Rotate and secure the Base64 High Entropy String |
| 41 | 🟢 Low | Exposed Token | JSON Web Token found in integration_e4_openai_cache_key.rs | Rotate and secure the JSON Web Token |
| 42 | 🟢 Low | Exposed Token | Base64 High Entropy String found in anthropic_messages_request_real.json | Rotate and secure the Base64 High Entropy String |
| 43 | 🟢 Low | Exposed Token | Base64 High Entropy String found in anthropic_messages_request_real.json | Rotate and secure the Base64 High Entropy String |
| 44 | 🟢 Low | Exposed Token | Secret Keyword found in test_cli_doctor.py | Rotate and secure the Secret Keyword |
| 45 | 🟢 Low | Exposed Token | Anthropic API Key found in .gitguardian.yaml | Rotate and secure the Anthropic API Key |
| 46 | 🔴 Critical | Exposed Token | OpenAI API Key found in headroom-sbom.spdx.json | Rotate and secure the OpenAI API Key |
| 47 | 🟢 Low | Exposed Token | OpenAI API Key found in test_auth_mode.py | Rotate and secure the OpenAI API Key |
| 48 | 🟢 Low | Exposed Token | Anthropic API Key found in test_realignment_live_multi_turn.py | Rotate and secure the Anthropic API Key |
| 49 | 🟢 Low | Exposed Token | OpenAI API Key found in auth_mode.rs | Rotate and secure the OpenAI API Key |

## Categories

| Category | Count |
|----------|------:|
| Exposed Token | 35 |
| Dangerous Pattern | 7 |
| Data Exfiltration Risk | 6 |
| Outdated Version | 1 |

---

[Back to Dashboard](../mcp-security-grades.md) | *Scanned on 2026-08-24 by [agentsec](https://github.com/debu-sinha/agentsec)*
