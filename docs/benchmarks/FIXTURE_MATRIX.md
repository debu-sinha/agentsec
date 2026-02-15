# Benchmark Fixture Matrix

Use this table as the canonical benchmark inventory.

| Fixture ID | Module | Scenario | Risk Level | Expected Findings | Notes |
|---|---|---|---|---|---|
| F-001 | installation | Loopback + auth + safe defaults | clean | 0 | false-positive guard |
| F-002 | installation | gateway bind lan, auth disabled | critical | CGW-001, CGW-002 | exposure baseline |
| F-003 | installation | dmPolicy open + full tools + sandbox off | critical | CID-001, CTO-001, CTO-003 | doom combo |
| F-004 | installation | permissive exec approvals | high | CEX-002 | cascading risk |
| F-005 | installation | vulnerable OpenClaw version | critical | CVE detections | CVE coverage |
| F-006 | skill | benign skill | clean | 0 | false-positive guard |
| F-007 | skill | remote pipe-to-shell in instructions | critical | CSK-001 | instruction malware |
| F-008 | skill | credential path targeting | high | CSK-003 | exfiltration |
| F-009 | skill | obfuscation/decoder pattern | medium | CSK-002 | malware evasion |
| F-010 | skill | dangerous eval/exec use | critical/high | dangerous pattern checks | code risk |
| F-011 | mcp | local auth'd MCP | clean | 0 | false-positive guard |
| F-012 | mcp | remote MCP without auth | high | CMCP-002 | access control |
| F-013 | mcp | high privilege tool set | critical | CMCP-001 | agency risk |
| F-014 | mcp | unverified npx/unpinned deps | medium | CMCP-003 | supply chain |
| F-015 | credential | no secrets fixture | clean | 0 | false-positive guard |
| F-016 | credential | provider token in file | critical/high | credential finding | secret detection |
| F-017 | credential | high entropy non-secret strings | clean/mixed | limited or 0 | entropy calibration |
| F-018 | gate | npm package with install hooks | high | gate finding | pre-install risk |
| F-019 | gate | known-malicious package (blocklist) | critical | gate blocklist finding | must block |
| F-020 | gate | clean package | clean | allow install | gate sanity check |

## Required Artifacts Per Fixture

- Fixture source path
- Expected findings manifest
- Scan command used
- Raw output file (`json` preferred)
- Reviewer note (if disputed)

