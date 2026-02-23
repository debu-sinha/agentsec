# opensumi/core

![Grade](https://img.shields.io/badge/Grade-F-red?style=for-the-badge) ![Score](https://img.shields.io/badge/Score-55%2F100-red?style=for-the-badge)

**Repository:** [opensumi/core](https://github.com/opensumi/core)
**Stars:** 3,598
**Last scan:** 2026-02-17

## Severity Summary

| Severity | Count |
|----------|------:|
| 🔴 Critical | **2** |
| 🟡 Medium | **5** |
| 🔵 Info | **1** |
| **Total** | **8** |

## Findings

| # | Severity | Category | Title | Remediation |
|--:|:--------:|----------|-------|-------------|
| 1 | 🟡 Medium | Exposed Token | Base64 High Entropy String found in md5.wasm.json | Rotate and secure the Base64 High Entropy String |
| 2 | 🟡 Medium | Exposed Token | Secret Keyword found in crypto.server.ts | Rotate and secure the Secret Keyword |
| 3 | 🟡 Medium | Exposed Token | Secret Keyword found in ai-native.ts | Rotate and secure the Secret Keyword |
| 4 | 🟡 Medium | Exposed Token | Secret Keyword found in ai-native.ts | Rotate and secure the Secret Keyword |
| 5 | 🟡 Medium | Exposed Token | Secret Keyword found in ai-native.ts | Rotate and secure the Secret Keyword |
| 6 | 🔴 Critical | Exposed Token | OpenAI API Key found in problem-line-matcher.ts | Rotate and secure the OpenAI API Key |
| 7 | 🔴 Critical | Exposed Token | OpenAI API Key found in problem-matcher.ts | Rotate and secure the OpenAI API Key |
| 8 | 🔵 Info | Outdated Version | Could not determine agent version | Ensure agent is updated to latest version |

## Categories

| Category | Count |
|----------|------:|
| Exposed Token | 7 |
| Outdated Version | 1 |

---

[Back to Dashboard](../mcp-security-grades.md) | *Scanned on 2026-02-17 by [agentsec](https://github.com/debu-sinha/agentsec)*
