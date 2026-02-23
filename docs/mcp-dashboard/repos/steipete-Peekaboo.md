# steipete/Peekaboo

![Grade](https://img.shields.io/badge/Grade-D-orange?style=for-the-badge) ![Score](https://img.shields.io/badge/Score-67%2F100-orange?style=for-the-badge)

**Repository:** [steipete/Peekaboo](https://github.com/steipete/Peekaboo)
**Stars:** 2,181
**Last scan:** 2026-02-17

## Severity Summary

| Severity | Count |
|----------|------:|
| 🔴 Critical | **1** |
| 🟠 High | **1** |
| 🟡 Medium | **3** |
| 🟢 Low | **2** |
| 🔵 Info | **1** |
| **Total** | **8** |

## Findings

| # | Severity | Category | Title | Remediation |
|--:|:--------:|----------|-------|-------------|
| 1 | 🟡 Medium | Exposed Token | Secret Keyword found in EndToEndTests.swift | Rotate and secure the Secret Keyword |
| 2 | 🟢 Low | Exposed Token | Secret Keyword found in ConfigurationTests.swift | Rotate and secure the Secret Keyword |
| 3 | 🟡 Medium | Exposed Token | Secret Keyword found in RealtimeVoiceServiceTests.swift | Rotate and secure the Secret Keyword |
| 4 | 🟡 Medium | Exposed Token | Secret Keyword found in SettingsServiceTests.swift | Rotate and secure the Secret Keyword |
| 5 | 🟢 Low | Exposed Token | Anthropic API Key found in README.md | Rotate and secure the Anthropic API Key |
| 6 | 🔴 Critical | Exposed Token | OpenAI API Key found in SettingsServiceTests.swift | Rotate and secure the OpenAI API Key |
| 7 | 🔵 Info | Outdated Version | Could not determine agent version | Ensure agent is updated to latest version |
| 8 | 🟠 High | Config Drift | Suspicious pattern in AGENTS.md: Code execution instruction | Review AGENTS.md for unauthorized modifications |

## Categories

| Category | Count |
|----------|------:|
| Exposed Token | 6 |
| Outdated Version | 1 |
| Config Drift | 1 |

---

[Back to Dashboard](../mcp-security-grades.md) | *Scanned on 2026-02-17 by [agentsec](https://github.com/debu-sinha/agentsec)*
