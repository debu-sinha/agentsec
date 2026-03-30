# epiral/bb-browser

![Grade](https://img.shields.io/badge/Grade-B-green?style=for-the-badge) ![Score](https://img.shields.io/badge/Score-83%2F100-green?style=for-the-badge)

**Repository:** [epiral/bb-browser](https://github.com/epiral/bb-browser)
**Stars:** 3,256
**Last scan:** 2026-03-30

## Severity Summary

| Severity | Count |
|----------|------:|
| 🟠 High | **2** |
| 🟡 Medium | **1** |
| 🔵 Info | **1** |
| **Total** | **4** |

## Findings

| # | Severity | Category | Title | Remediation |
|--:|:--------:|----------|-------|-------------|
| 1 | 🔵 Info | Outdated Version | Could not determine agent version | Ensure agent is updated to latest version |
| 2 | 🟠 High | Config Drift | Suspicious pattern in AGENTS.md: Code execution instruction | Review AGENTS.md for unauthorized modifications |
| 3 | 🟠 High | Prompt Injection Vector | Prompt injection in skill instructions 'bb-browser' | --- |
| 4 | 🟡 Medium | Exposed Token | Base64 High Entropy String found in bb-browserd.ts | Rotate and secure the Base64 High Entropy String |

## Categories

| Category | Count |
|----------|------:|
| Outdated Version | 1 |
| Config Drift | 1 |
| Prompt Injection Vector | 1 |
| Exposed Token | 1 |

---

[Back to Dashboard](../mcp-security-grades.md) | *Scanned on 2026-03-30 by [agentsec](https://github.com/debu-sinha/agentsec)*
