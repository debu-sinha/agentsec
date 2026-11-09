# wonderwhy-er/DesktopCommanderMCP

![Grade](https://img.shields.io/badge/Grade-F-red?style=for-the-badge) ![Score](https://img.shields.io/badge/Score-5%2F100-red?style=for-the-badge)

**Repository:** [wonderwhy-er/DesktopCommanderMCP](https://github.com/wonderwhy-er/DesktopCommanderMCP)
**Stars:** 10,273
**Last scan:** 2026-11-09

## Severity Summary

| Severity | Count |
|----------|------:|
| 🔴 Critical | **12** |
| 🟠 High | **7** |
| 🟡 Medium | **1** |
| 🟢 Low | **2** |
| 🔵 Info | **1** |
| **Total** | **23** |

## Findings

| # | Severity | Category | Title | Remediation |
|--:|:--------:|----------|-------|-------------|
| 1 | 🟠 High | Insecure Permissions | World-readable sensitive file: config.json | Restrict permissions on config.json to owner-only |
| 2 | 🔵 Info | Outdated Version | Could not determine agent version | Ensure agent is updated to latest version |
| 3 | 🔴 Critical | Malicious Skill | Remote pipe to shell in skill 'ai-tools-setup' | Remove skill 'ai-tools-setup' and investigate |
| 4 | 🔴 Critical | Malicious Skill | PowerShell remote execution in skill 'ai-tools-setup' | Remove skill 'ai-tools-setup' and investigate |
| 5 | 🟠 High | Malicious Skill | Credential path targeting in skill 'ai-tools-setup' | Remove skill 'ai-tools-setup' and investigate |
| 6 | 🟠 High | Malicious Skill | Credential path targeting in skill 'ai-tools-setup' | Remove skill 'ai-tools-setup' and investigate |
| 7 | 🔴 Critical | Malicious Skill | Remote pipe to shell in skill 'terminal' | Remove skill 'terminal' and investigate |
| 8 | 🔴 Critical | Malicious Skill | Remote pipe to shell in skill 'terminal' | Remove skill 'terminal' and investigate |
| 9 | 🔴 Critical | Malicious Skill | Remote pipe to shell in skill 'cursor' | Remove skill 'cursor' and investigate |
| 10 | 🔴 Critical | Malicious Skill | Remote pipe to shell in skill 'cursor' | Remove skill 'cursor' and investigate |
| 11 | 🔴 Critical | Malicious Skill | Remote pipe to shell in skill 'cursor' | Remove skill 'cursor' and investigate |
| 12 | 🔴 Critical | Malicious Skill | PowerShell remote execution in skill 'cursor' | Remove skill 'cursor' and investigate |
| 13 | 🟠 High | Malicious Skill | Credential path targeting in skill 'cursor' | Remove skill 'cursor' and investigate |
| 14 | 🟠 High | Malicious Skill | Credential path targeting in skill 'cursor' | Remove skill 'cursor' and investigate |
| 15 | 🔴 Critical | Malicious Skill | Remote pipe to shell in skill 'claude' | Remove skill 'claude' and investigate |
| 16 | 🔴 Critical | Malicious Skill | Remote pipe to shell in skill 'claude' | Remove skill 'claude' and investigate |
| 17 | 🔴 Critical | Malicious Skill | Remote pipe to shell in skill 'claude' | Remove skill 'claude' and investigate |
| 18 | 🔴 Critical | Malicious Skill | PowerShell remote execution in skill 'claude' | Remove skill 'claude' and investigate |
| 19 | 🟠 High | Malicious Skill | Credential path targeting in skill 'claude' | Remove skill 'claude' and investigate |
| 20 | 🟠 High | Malicious Skill | Credential path targeting in skill 'claude' | Remove skill 'claude' and investigate |
| 21 | 🟡 Medium | Exposed Token | Secret Keyword found in redact.ts | Rotate and secure the Secret Keyword |
| 22 | 🟢 Low | Exposed Token | JSON Web Token found in test-redact.js | Rotate and secure the JSON Web Token |
| 23 | 🟢 Low | Exposed Token | Basic Auth Credentials found in mqtt-enrollment.test.js | Rotate and secure the Basic Auth Credentials |

## Categories

| Category | Count |
|----------|------:|
| Malicious Skill | 18 |
| Exposed Token | 3 |
| Insecure Permissions | 1 |
| Outdated Version | 1 |

---

[Back to Dashboard](../mcp-security-grades.md) | *Scanned on 2026-11-09 by [agentsec](https://github.com/debu-sinha/agentsec)*
