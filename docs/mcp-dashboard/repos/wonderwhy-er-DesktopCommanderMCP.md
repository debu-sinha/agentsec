# wonderwhy-er/DesktopCommanderMCP

![Grade](https://img.shields.io/badge/Grade-F-red?style=for-the-badge) ![Score](https://img.shields.io/badge/Score-5%2F100-red?style=for-the-badge)

**Repository:** [wonderwhy-er/DesktopCommanderMCP](https://github.com/wonderwhy-er/DesktopCommanderMCP)
**Stars:** 8,096
**Last scan:** 2026-07-13

## Severity Summary

| Severity | Count |
|----------|------:|
| 🔴 Critical | **12** |
| 🟠 High | **7** |
| 🔵 Info | **1** |
| **Total** | **20** |

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

## Categories

| Category | Count |
|----------|------:|
| Malicious Skill | 18 |
| Insecure Permissions | 1 |
| Outdated Version | 1 |

---

[Back to Dashboard](../mcp-security-grades.md) | *Scanned on 2026-07-13 by [agentsec](https://github.com/debu-sinha/agentsec)*
