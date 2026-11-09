# headroomlabs-ai/headroom

![Grade](https://img.shields.io/badge/Grade-F-red?style=for-the-badge) ![Score](https://img.shields.io/badge/Score-5%2F100-red?style=for-the-badge)

**Repository:** [headroomlabs-ai/headroom](https://github.com/headroomlabs-ai/headroom)
**Stars:** 79,214
**Last scan:** 2026-11-09

## Severity Summary

| Severity | Count |
|----------|------:|
| 🔴 Critical | **1** |
| 🟠 High | **6** |
| 🟡 Medium | **28** |
| 🟢 Low | **53** |
| 🔵 Info | **1** |
| **Total** | **89** |

## Findings

| # | Severity | Category | Title | Remediation |
|--:|:--------:|----------|-------|-------------|
| 1 | 🔵 Info | Outdated Version | Could not determine agent version | Ensure agent is updated to latest version |
| 2 | 🟡 Medium | Data Exfiltration Risk | Node child process execution in skill 'openclaw' | Review or remove skill 'openclaw' |
| 3 | 🟡 Medium | Data Exfiltration Risk | Node child process execution in skill 'openclaw' | Review or remove skill 'openclaw' |
| 4 | 🟡 Medium | Data Exfiltration Risk | Node child process execution in skill 'openclaw' | Review or remove skill 'openclaw' |
| 5 | 🟡 Medium | Dangerous Pattern | Dangerous import 'socket' in skill 'opencode' | Review whether 'socket' is necessary |
| 6 | 🟠 High | Dangerous Pattern | Dangerous import 'subprocess' in skill 'opencode' | Review whether 'subprocess' is necessary |
| 7 | 🟢 Low | Dangerous Pattern | Dangerous import 'tempfile' in skill 'opencode' | Review whether 'tempfile' is necessary |
| 8 | 🟢 Low | Dangerous Pattern | Dangerous import 'urllib.request' in skill 'opencode' | Review whether 'urllib.request' is necessary |
| 9 | 🟠 High | Data Exfiltration Risk | Environment variable harvesting in skill 'opencode' | Review or remove skill 'opencode' |
| 10 | 🟠 High | Data Exfiltration Risk | Environment variable harvesting in skill 'opencode' | Review or remove skill 'opencode' |
| 11 | 🟡 Medium | Data Exfiltration Risk | Node dynamic require in skill 'opencode' | Review or remove skill 'opencode' |
| 12 | 🟡 Medium | Data Exfiltration Risk | Node dynamic require in skill 'opencode' | Review or remove skill 'opencode' |
| 13 | 🟡 Medium | Data Exfiltration Risk | Node dynamic require in skill 'opencode' | Review or remove skill 'opencode' |
| 14 | 🟡 Medium | Data Exfiltration Risk | Node dynamic require in skill 'opencode' | Review or remove skill 'opencode' |
| 15 | 🟡 Medium | Data Exfiltration Risk | Node dynamic require in skill 'opencode' | Review or remove skill 'opencode' |
| 16 | 🟡 Medium | Data Exfiltration Risk | Node dynamic require in skill 'opencode' | Review or remove skill 'opencode' |
| 17 | 🟡 Medium | Data Exfiltration Risk | Node dynamic require in skill 'opencode' | Review or remove skill 'opencode' |
| 18 | 🟡 Medium | Data Exfiltration Risk | Node dynamic require in skill 'opencode' | Review or remove skill 'opencode' |
| 19 | 🟡 Medium | Data Exfiltration Risk | Node dynamic require in skill 'opencode' | Review or remove skill 'opencode' |
| 20 | 🟡 Medium | Data Exfiltration Risk | Node dynamic require in skill 'opencode' | Review or remove skill 'opencode' |
| 21 | 🟡 Medium | Data Exfiltration Risk | Node dynamic require in skill 'opencode' | Review or remove skill 'opencode' |
| 22 | 🟡 Medium | Data Exfiltration Risk | Node dynamic require in skill 'opencode' | Review or remove skill 'opencode' |
| 23 | 🟡 Medium | Data Exfiltration Risk | Node dynamic require in skill 'opencode' | Review or remove skill 'opencode' |
| 24 | 🟡 Medium | Data Exfiltration Risk | Node dynamic require in skill 'opencode' | Review or remove skill 'opencode' |
| 25 | 🟡 Medium | Data Exfiltration Risk | Node dynamic require in skill 'opencode' | Review or remove skill 'opencode' |
| 26 | 🟡 Medium | Data Exfiltration Risk | Node dynamic require in skill 'opencode' | Review or remove skill 'opencode' |
| 27 | 🟡 Medium | Data Exfiltration Risk | Node dynamic require in skill 'opencode' | Review or remove skill 'opencode' |
| 28 | 🟢 Low | Dangerous Pattern | Dangerous import 'urllib.error' in skill 'headroom-oauth2' | Review whether 'urllib.error' is necessary |
| 29 | 🟡 Medium | Dangerous Pattern | Dangerous call 'setattr()' in skill 'headroom-oauth2' | Remove or sandbox the 'setattr()' call |
| 30 | 🟡 Medium | Dangerous Pattern | Dangerous call 'setattr()' in skill 'headroom-oauth2' | Remove or sandbox the 'setattr()' call |
| 31 | 🟡 Medium | Dangerous Pattern | Dangerous call 'setattr()' in skill 'headroom-oauth2' | Remove or sandbox the 'setattr()' call |
| 32 | 🟢 Low | Dangerous Pattern | Dangerous import 'urllib.parse' in skill 'headroom-oauth2' | Review whether 'urllib.parse' is necessary |
| 33 | 🟢 Low | Dangerous Pattern | Dangerous import 'urllib.request' in skill 'headroom-oauth2' | Review whether 'urllib.request' is necessary |
| 34 | 🟢 Low | Dangerous Pattern | Dangerous import 'urllib.error' in skill 'headroom-oauth2' | Review whether 'urllib.error' is necessary |
| 35 | 🟢 Low | Dangerous Pattern | Dangerous import 'urllib.parse' in skill 'headroom-oauth2' | Review whether 'urllib.parse' is necessary |
| 36 | 🟡 Medium | Dangerous Pattern | Dangerous call 'getattr()' in skill 'headroom-oauth2' | Remove or sandbox the 'getattr()' call |
| 37 | 🟡 Medium | Dangerous Pattern | Dangerous call 'getattr()' in skill 'headroom-oauth2' | Remove or sandbox the 'getattr()' call |
| 38 | 🟠 High | Data Exfiltration Risk | Environment variable harvesting in skill 'headroom-oauth2' | Review or remove skill 'headroom-oauth2' |
| 39 | 🟠 High | Data Exfiltration Risk | Environment variable harvesting in skill 'headroom-oauth2' | Review or remove skill 'headroom-oauth2' |
| 40 | 🟠 High | Data Exfiltration Risk | Environment variable harvesting in skill 'headroom-oauth2' | Review or remove skill 'headroom-oauth2' |
| 41 | 🟡 Medium | Exposed Token | Secret Keyword found in vscode.py | Rotate and secure the Secret Keyword |
| 42 | 🟡 Medium | Exposed Token | Secret Keyword found in vscode.py | Rotate and secure the Secret Keyword |
| 43 | 🟢 Low | Exposed Token | Secret Keyword found in test_auth_policy.py | Rotate and secure the Secret Keyword |
| 44 | 🟢 Low | Exposed Token | JSON Web Token found in test_auth_policy.py | Rotate and secure the JSON Web Token |
| 45 | 🟢 Low | Exposed Token | Base64 High Entropy String found in tailwind.min.js | Rotate and secure the Base64 High Entropy String |
| 46 | 🟢 Low | Exposed Token | Secret Keyword found in client-expanded.test.ts | Rotate and secure the Secret Keyword |
| 47 | 🟢 Low | Exposed Token | Secret Keyword found in client-expanded.test.ts | Rotate and secure the Secret Keyword |
| 48 | 🟢 Low | Exposed Token | Secret Keyword found in client-expanded.test.ts | Rotate and secure the Secret Keyword |
| 49 | 🟢 Low | Exposed Token | Secret Keyword found in test_cli_doctor.py | Rotate and secure the Secret Keyword |
| 50 | 🟢 Low | Exposed Token | Secret Keyword found in test_cache_breakpoint_diagnostics.py | Rotate and secure the Secret Keyword |
| 51 | 🟢 Low | Exposed Token | Secret Keyword found in test_universal.py | Rotate and secure the Secret Keyword |
| 52 | 🟢 Low | Exposed Token | Basic Auth Credentials found in test_adapter_hooks.py | Rotate and secure the Basic Auth Credentials |
| 53 | 🟢 Low | Exposed Token | Secret Keyword found in integration_cache_drift.rs | Rotate and secure the Secret Keyword |
| 54 | 🟢 Low | Exposed Token | Secret Keyword found in test_memory_tool_stream.py | Rotate and secure the Secret Keyword |
| 55 | 🟢 Low | Exposed Token | JSON Web Token found in integration_responses_streaming.rs | Rotate and secure the JSON Web Token |
| 56 | 🟢 Low | Exposed Token | JSON Web Token found in test_auth_mode.py | Rotate and secure the JSON Web Token |
| 57 | 🟢 Low | Exposed Token | Base64 High Entropy String found in integration_bedrock_invoke.rs | Rotate and secure the Base64 High Entropy String |
| 58 | 🟢 Low | Exposed Token | JSON Web Token found in integration_responses.rs | Rotate and secure the JSON Web Token |
| 59 | 🟢 Low | Exposed Token | JSON Web Token found in integration_anthropic_model_sanitize.rs | Rotate and secure the JSON Web Token |
| 60 | 🟢 Low | Exposed Token | Basic Auth Credentials found in test_install_cli.py | Rotate and secure the Basic Auth Credentials |
| 61 | 🟢 Low | Exposed Token | JSON Web Token found in test_cache_aligner_detector_only.py | Rotate and secure the JSON Web Token |
| 62 | 🟢 Low | Exposed Token | JSON Web Token found in auth_mode.rs | Rotate and secure the JSON Web Token |
| 63 | 🟢 Low | Exposed Token | JSON Web Token found in .gitguardian.yaml | Rotate and secure the JSON Web Token |
| 64 | 🟢 Low | Exposed Token | Base64 High Entropy String found in anthropic_messages_request_real.json | Rotate and secure the Base64 High Entropy String |
| 65 | 🟢 Low | Exposed Token | Base64 High Entropy String found in anthropic_messages_request_real.json | Rotate and secure the Base64 High Entropy String |
| 66 | 🟢 Low | Exposed Token | JSON Web Token found in integration_chat_completions.rs | Rotate and secure the JSON Web Token |
| 67 | 🟢 Low | Exposed Token | Secret Keyword found in test_wrap_omp.py | Rotate and secure the Secret Keyword |
| 68 | 🟢 Low | Exposed Token | JSON Web Token found in integration_e4_openai_cache_key.rs | Rotate and secure the JSON Web Token |
| 69 | 🟢 Low | Exposed Token | Secret Keyword found in test_masks.py | Rotate and secure the Secret Keyword |
| 70 | 🟢 Low | Exposed Token | Base64 High Entropy String found in integration_compression.rs | Rotate and secure the Base64 High Entropy String |
| 71 | 🟢 Low | Exposed Token | Base64 High Entropy String found in integration_compression.rs | Rotate and secure the Base64 High Entropy String |
| 72 | 🟢 Low | Exposed Token | GitHub Token found in test_copilot_inline_client_auth.py | Rotate and secure the GitHub Token |
| 73 | 🟢 Low | Exposed Token | Basic Auth Credentials found in test_ccr_redis_backend.py | Rotate and secure the Basic Auth Credentials |
| 74 | 🟢 Low | Exposed Token | Anthropic API Key found in .gitguardian.yaml | Rotate and secure the Anthropic API Key |
| 75 | 🟢 Low | Exposed Token | OpenAI API Key found in test_ccr_rust_marker_hash_bridge.py | Rotate and secure the OpenAI API Key |
| 76 | 🟢 Low | Exposed Token | OpenAI API Key found in test_auth_mode.py | Rotate and secure the OpenAI API Key |
| 77 | 🟢 Low | Exposed Token | Anthropic API Key found in test_proxy_tenant_key_integration.py | Rotate and secure the Anthropic API Key |
| 78 | 🟢 Low | Exposed Token | Anthropic API Key found in test_savings_pricing_fallback_logging.py | Rotate and secure the Anthropic API Key |
| 79 | 🟢 Low | Exposed Token | Generic Connection String found in test_ccr_redis_backend.py | Rotate and secure the Generic Connection String |
| 80 | 🟢 Low | Exposed Token | Generic Connection String found in test_adapter_hooks.py | Rotate and secure the Generic Connection String |
| 81 | 🟢 Low | Exposed Token | OpenAI API Key found in test_litellm_probe_fallback_logs.py | Rotate and secure the OpenAI API Key |
| 82 | 🟢 Low | Exposed Token | OpenAI API Key found in test_direct_chat_ccr_resolution.py | Rotate and secure the OpenAI API Key |
| 83 | 🟢 Low | Exposed Token | OpenAI API Key found in test_transforms_failure_logging.py | Rotate and secure the OpenAI API Key |
| 84 | 🟢 Low | Exposed Token | Anthropic API Key found in test_saved_settings_apply_logging.py | Rotate and secure the Anthropic API Key |
| 85 | 🟢 Low | Exposed Token | Anthropic API Key found in test_realignment_live_multi_turn.py | Rotate and secure the Anthropic API Key |
| 86 | 🟢 Low | Exposed Token | Anthropic API Key found in test_proxy_hardening.py | Rotate and secure the Anthropic API Key |
| 87 | 🔴 Critical | Exposed Token | OpenAI API Key found in headroom-sbom.spdx.json | Rotate and secure the OpenAI API Key |
| 88 | 🟢 Low | Exposed Token | Generic Connection String found in test_registry.py | Rotate and secure the Generic Connection String |
| 89 | 🟢 Low | Exposed Token | OpenAI API Key found in auth_mode.rs | Rotate and secure the OpenAI API Key |

## Categories

| Category | Count |
|----------|------:|
| Exposed Token | 49 |
| Data Exfiltration Risk | 25 |
| Dangerous Pattern | 14 |
| Outdated Version | 1 |

---

[Back to Dashboard](../mcp-security-grades.md) | *Scanned on 2026-11-09 by [agentsec](https://github.com/debu-sinha/agentsec)*
