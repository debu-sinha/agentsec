# headroomlabs-ai/headroom

![Grade](https://img.shields.io/badge/Grade-F-red?style=for-the-badge) ![Score](https://img.shields.io/badge/Score-19%2F100-red?style=for-the-badge)

**Repository:** [headroomlabs-ai/headroom](https://github.com/headroomlabs-ai/headroom)
**Stars:** 74,441
**Last scan:** 2026-10-05

## Severity Summary

| Severity | Count |
|----------|------:|
| 🔴 Critical | **1** |
| 🟠 High | **3** |
| 🟡 Medium | **10** |
| 🟢 Low | **43** |
| 🔵 Info | **1** |
| **Total** | **58** |

## Findings

| # | Severity | Category | Title | Remediation |
|--:|:--------:|----------|-------|-------------|
| 1 | 🔵 Info | Outdated Version | Could not determine agent version | Ensure agent is updated to latest version |
| 2 | 🟡 Medium | Dangerous Pattern | Dangerous call 'setattr()' in skill 'headroom-oauth2' | Remove or sandbox the 'setattr()' call |
| 3 | 🟡 Medium | Dangerous Pattern | Dangerous call 'setattr()' in skill 'headroom-oauth2' | Remove or sandbox the 'setattr()' call |
| 4 | 🟢 Low | Dangerous Pattern | Dangerous import 'urllib.error' in skill 'headroom-oauth2' | Review whether 'urllib.error' is necessary |
| 5 | 🟡 Medium | Dangerous Pattern | Dangerous call 'setattr()' in skill 'headroom-oauth2' | Remove or sandbox the 'setattr()' call |
| 6 | 🟢 Low | Dangerous Pattern | Dangerous import 'urllib.parse' in skill 'headroom-oauth2' | Review whether 'urllib.parse' is necessary |
| 7 | 🟢 Low | Dangerous Pattern | Dangerous import 'urllib.request' in skill 'headroom-oauth2' | Review whether 'urllib.request' is necessary |
| 8 | 🟢 Low | Dangerous Pattern | Dangerous import 'urllib.error' in skill 'headroom-oauth2' | Review whether 'urllib.error' is necessary |
| 9 | 🟢 Low | Dangerous Pattern | Dangerous import 'urllib.parse' in skill 'headroom-oauth2' | Review whether 'urllib.parse' is necessary |
| 10 | 🟡 Medium | Dangerous Pattern | Dangerous call 'getattr()' in skill 'headroom-oauth2' | Remove or sandbox the 'getattr()' call |
| 11 | 🟡 Medium | Dangerous Pattern | Dangerous call 'getattr()' in skill 'headroom-oauth2' | Remove or sandbox the 'getattr()' call |
| 12 | 🟠 High | Data Exfiltration Risk | Environment variable harvesting in skill 'headroom-oauth2' | Review or remove skill 'headroom-oauth2' |
| 13 | 🟠 High | Data Exfiltration Risk | Environment variable harvesting in skill 'headroom-oauth2' | Review or remove skill 'headroom-oauth2' |
| 14 | 🟠 High | Data Exfiltration Risk | Environment variable harvesting in skill 'headroom-oauth2' | Review or remove skill 'headroom-oauth2' |
| 15 | 🟡 Medium | Data Exfiltration Risk | Node child process execution in skill 'openclaw' | Review or remove skill 'openclaw' |
| 16 | 🟡 Medium | Data Exfiltration Risk | Node child process execution in skill 'openclaw' | Review or remove skill 'openclaw' |
| 17 | 🟡 Medium | Data Exfiltration Risk | Node child process execution in skill 'openclaw' | Review or remove skill 'openclaw' |
| 18 | 🟢 Low | Exposed Token | JSON Web Token found in integration_chat_completions.rs | Rotate and secure the JSON Web Token |
| 19 | 🟢 Low | Exposed Token | Base64 High Entropy String found in integration_bedrock_invoke.rs | Rotate and secure the Base64 High Entropy String |
| 20 | 🟢 Low | Exposed Token | JSON Web Token found in integration_responses.rs | Rotate and secure the JSON Web Token |
| 21 | 🟢 Low | Exposed Token | Secret Keyword found in integration_cache_drift.rs | Rotate and secure the Secret Keyword |
| 22 | 🟢 Low | Exposed Token | Secret Keyword found in test_masks.py | Rotate and secure the Secret Keyword |
| 23 | 🟢 Low | Exposed Token | Secret Keyword found in test_issue_1779_remote_control_gate.py | Rotate and secure the Secret Keyword |
| 24 | 🟢 Low | Exposed Token | Secret Keyword found in test_issue_1779_remote_control_gate.py | Rotate and secure the Secret Keyword |
| 25 | 🟢 Low | Exposed Token | Base64 High Entropy String found in integration_compression.rs | Rotate and secure the Base64 High Entropy String |
| 26 | 🟢 Low | Exposed Token | Base64 High Entropy String found in integration_compression.rs | Rotate and secure the Base64 High Entropy String |
| 27 | 🟢 Low | Exposed Token | Secret Keyword found in test_memory_tool_stream.py | Rotate and secure the Secret Keyword |
| 28 | 🟢 Low | Exposed Token | JSON Web Token found in integration_responses_streaming.rs | Rotate and secure the JSON Web Token |
| 29 | 🟡 Medium | Exposed Token | Secret Keyword found in vscode.py | Rotate and secure the Secret Keyword |
| 30 | 🟡 Medium | Exposed Token | Secret Keyword found in vscode.py | Rotate and secure the Secret Keyword |
| 31 | 🟢 Low | Exposed Token | Secret Keyword found in test_upstream_guard.py | Rotate and secure the Secret Keyword |
| 32 | 🟢 Low | Exposed Token | JSON Web Token found in integration_e4_openai_cache_key.rs | Rotate and secure the JSON Web Token |
| 33 | 🟢 Low | Exposed Token | JSON Web Token found in auth_mode.rs | Rotate and secure the JSON Web Token |
| 34 | 🟢 Low | Exposed Token | Secret Keyword found in test_universal.py | Rotate and secure the Secret Keyword |
| 35 | 🟢 Low | Exposed Token | Secret Keyword found in test_universal.py | Rotate and secure the Secret Keyword |
| 36 | 🟢 Low | Exposed Token | Secret Keyword found in test_universal.py | Rotate and secure the Secret Keyword |
| 37 | 🟢 Low | Exposed Token | Secret Keyword found in test_wire_debug_redaction_policy.py | Rotate and secure the Secret Keyword |
| 38 | 🟢 Low | Exposed Token | Secret Keyword found in test_auth_policy.py | Rotate and secure the Secret Keyword |
| 39 | 🟢 Low | Exposed Token | JSON Web Token found in test_auth_policy.py | Rotate and secure the JSON Web Token |
| 40 | 🟢 Low | Exposed Token | JSON Web Token found in test_auth_mode.py | Rotate and secure the JSON Web Token |
| 41 | 🟢 Low | Exposed Token | Secret Keyword found in test_cli_doctor.py | Rotate and secure the Secret Keyword |
| 42 | 🟢 Low | Exposed Token | Base64 High Entropy String found in tailwind.min.js | Rotate and secure the Base64 High Entropy String |
| 43 | 🟢 Low | Exposed Token | JSON Web Token found in integration_anthropic_model_sanitize.rs | Rotate and secure the JSON Web Token |
| 44 | 🟢 Low | Exposed Token | Secret Keyword found in test_cache_breakpoint_diagnostics.py | Rotate and secure the Secret Keyword |
| 45 | 🟢 Low | Exposed Token | Secret Keyword found in client-expanded.test.ts | Rotate and secure the Secret Keyword |
| 46 | 🟢 Low | Exposed Token | Secret Keyword found in client-expanded.test.ts | Rotate and secure the Secret Keyword |
| 47 | 🟢 Low | Exposed Token | Secret Keyword found in client-expanded.test.ts | Rotate and secure the Secret Keyword |
| 48 | 🟢 Low | Exposed Token | JSON Web Token found in .gitguardian.yaml | Rotate and secure the JSON Web Token |
| 49 | 🟢 Low | Exposed Token | JSON Web Token found in test_cache_aligner_detector_only.py | Rotate and secure the JSON Web Token |
| 50 | 🟢 Low | Exposed Token | Base64 High Entropy String found in anthropic_messages_request_real.json | Rotate and secure the Base64 High Entropy String |
| 51 | 🟢 Low | Exposed Token | Base64 High Entropy String found in anthropic_messages_request_real.json | Rotate and secure the Base64 High Entropy String |
| 52 | 🟢 Low | Exposed Token | Anthropic API Key found in .gitguardian.yaml | Rotate and secure the Anthropic API Key |
| 53 | 🔴 Critical | Exposed Token | OpenAI API Key found in headroom-sbom.spdx.json | Rotate and secure the OpenAI API Key |
| 54 | 🟢 Low | Exposed Token | OpenAI API Key found in test_direct_chat_ccr_resolution.py | Rotate and secure the OpenAI API Key |
| 55 | 🟢 Low | Exposed Token | Anthropic API Key found in test_proxy_tenant_key_integration.py | Rotate and secure the Anthropic API Key |
| 56 | 🟢 Low | Exposed Token | OpenAI API Key found in test_auth_mode.py | Rotate and secure the OpenAI API Key |
| 57 | 🟢 Low | Exposed Token | Anthropic API Key found in test_realignment_live_multi_turn.py | Rotate and secure the Anthropic API Key |
| 58 | 🟢 Low | Exposed Token | OpenAI API Key found in auth_mode.rs | Rotate and secure the OpenAI API Key |

## Categories

| Category | Count |
|----------|------:|
| Exposed Token | 41 |
| Dangerous Pattern | 10 |
| Data Exfiltration Risk | 6 |
| Outdated Version | 1 |

---

[Back to Dashboard](../mcp-security-grades.md) | *Scanned on 2026-10-05 by [agentsec](https://github.com/debu-sinha/agentsec)*
