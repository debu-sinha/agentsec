# agentsec Security Checks Catalog

Stable reference for all agentsec security checks. Each check has a unique ID, maps to one or more OWASP Agentic Top 10 categories, and produces actionable remediation guidance.

Use these IDs in policy documents, audit reports, and CI/CD configuration.

## Gateway Exposure (CGW)

| ID | Check | Default Severity | OWASP | Detection |
|----|-------|:---:|-------|-----------|
| CGW-001 | Gateway bound to non-loopback interface | Critical | ASI05, ASI02 | Checks `gatewayHostname` for 0.0.0.0, LAN, or public bind addresses |
| CGW-002 | Gateway auth missing on exposed interface | Critical | ASI05 | Detects non-loopback bind without `authRequired: true` |
| CGW-003 | Control UI insecure auth / dangerouslyDisable flags | Critical | ASI05 | Flags `dangerouslyDisableDeviceAuth`, `dangerouslyDisableAuth`, and `allowInsecureAuth` on control UI |
| CGW-004 | Reverse proxy without trustedProxies | Medium | ASI05 | Detects proxy headers without `trustedProxies` allowlist |
| CGW-005 | No SSRF protection for URL-based inputs | High | ASI05, ASI02 | Checks for missing SSRF deny policies on tools that accept URLs |

## Identity Policy (CID)

| ID | Check | Default Severity | OWASP | Detection |
|----|-------|:---:|-------|-----------|
| CID-001 | DM policy set to open | Critical | ASI01, ASI02, ASI10 | Checks `dmPolicy` for `open` value allowing unauthenticated message injection |
| CID-002 | Group policy open / wildcard allowlist | High | ASI01, ASI02 | Detects `groupPolicy: open` or `allowList: ["*"]` |
| CID-003 | DM scope not per-channel-peer | Medium | ASI07 | Flags shared DM scope that allows cross-conversation data leakage |

## Tool Policy and Sandboxing (CTO)

| ID | Check | Default Severity | OWASP | Detection |
|----|-------|:---:|-------|-----------|
| CTO-001 | Full tool profile with open inbound | Critical | ASI02, ASI01 | Detects `toolProfile: full` combined with open DM/group policy |
| CTO-002 | group:runtime enabled for untrusted routes | High | ASI02 | Flags `group:runtime` tools available to non-paired conversations |
| CTO-003 | Sandbox disabled with full tools + open input | High | ASI02 | Detects disabled sandbox (`sandbox: false`) when full tools and open input are present |

## Exec Approvals (CEX)

| ID | Check | Default Severity | OWASP | Detection |
|----|-------|:---:|-------|-----------|
| CEX-001 | Exec approvals file missing | High | ASI08, ASI02 | No `exec-approvals.json` found -- host execution is uncontrolled. Only fires when an OpenClaw config (`openclaw.json` or `clawdbot.json`) is present. |
| CEX-002 | Exec approvals defaults too permissive | High | ASI08 | Detects `defaultApproval: always` or overly broad approval rules |
| CEX-003 | safeBins expanded beyond defaults | Medium | ASI08, ASI02 | Flags additional binaries added to `safeBins` beyond the default set |

## Skill and Plugin Analysis (CSK)

| ID | Check | Default Severity | OWASP | Detection |
|----|-------|:---:|-------|-----------|
| CSK-001 | Remote pipe-to-shell in skill instructions | Critical | ASI03, ASI01 | Pattern match for `curl|wget` piped to `sh|bash` in markdown instructions |
| CSK-002 | Obfuscation / decoder patterns | Medium | ASI03 | Detects base64 decode, hex decode, and code obfuscation patterns |
| CSK-003 | Credential path targeting | High | ASI01 | Matches paths like `~/.ssh`, `~/.aws/credentials`, `~/.gnupg` in skill code |
| CSK-004 | Setup scripts requesting external execution | High | ASI03 | Flags skills that download and execute remote scripts during setup |
| CSK-005 | disable-model-invocation absent on capable skills | Medium | ASI01, ASI03 | Skills with dangerous capabilities (exec, network) missing the DMI flag |

## Plugin Allowlist (CPL)

| ID | Check | Default Severity | OWASP | Detection |
|----|-------|:---:|-------|-----------|
| CPL-001 | Plugins installed without explicit allowlist | Medium | ASI03, ASI02 | No `pluginAllowlist` configured, all plugins are auto-approved |

## File and Directory Permissions (CFS)

| ID | Check | Default Severity | OWASP | Detection |
|----|-------|:---:|-------|-----------|
| CFS-001 | Agent config directory not 700 | High | ASI05 | Config directories (`.openclaw`, `.config/openclaw`) accessible to other users |
| CFS-002 | Sensitive files world-readable | High | ASI05 | Auth profiles, session files, or `.env` files readable by group/other |

## Built-in Safety Scanner (CSF)

| ID | Check | Default Severity | OWASP | Detection |
|----|-------|:---:|-------|-----------|
| CSF-001 | Built-in safety scanner disabled | High | ASI03, ASI10 | Version-gated (v2026.2.6+). Detects `safetyScanner: disabled` in config |
| CSF-002 | Credential redaction disabled | Medium | ASI05 | Version-gated (v2026.2.6+). Detects `credentialRedaction: disabled` |

## MCP Server Security (CMCP)

| ID | Check | Default Severity | OWASP | Detection |
|----|-------|:---:|-------|-----------|
| CMCP-001 | Tool poisoning / dangerous parameter schemas | Critical | ASI01, ASI03, ASI02 | Regex patterns for prompt injection in tool descriptions + dangerous input schema parameter names (shell, exec, eval, command, code) |
| CMCP-002 | Remote MCP endpoint without authentication | High | ASI03, ASI05 | Detects `https://` MCP servers and URL-based servers missing `auth` or `headers` config |
| CMCP-003 | Unpinned MCP dependencies / unverified npx | Medium | ASI03 | Flags `npx` invocations not from `@anthropic/` or `@modelcontextprotocol/` namespaces |

## Credential Detection (dynamic)

The credential scanner does not use fixed check IDs. It generates findings dynamically based on:

- **17 regex patterns** covering: OpenAI, Anthropic, AWS, GitHub (PAT, OAuth, App), Slack (Bot, User), Stripe, Telegram, Discord, Google, Databricks, HuggingFace, Private Key (PEM), JWT, Generic Connection String (Postgres/MySQL/MongoDB/Redis/AMQP)
- **Shannon entropy detection**: Strings with entropy >= 4.5 in secret-adjacent contexts
- **Git config credentials**: Plaintext passwords in `.gitconfig` or `.git-credentials`

All credential findings map to ASI05 (Insecure Output Handling / Secret Exposure).

## Severity Escalation

Severities listed above are defaults. The OWASP scorer applies context-sensitive escalation:

- **Doom combo**: Open DM + full tools + no sandbox = score capped at 20/100
- **Severity escalation**: Open group policy + disabled auth escalates affected findings from HIGH to CRITICAL
- **Score floor**: Minimum score is 5.0 (distinguishes minimal controls from zero security)

See [ADR-0002](adr/ADR-0002-owasp-scoring-formula.md) for the full scoring methodology.

## OWASP Agentic Top 10 Coverage

| OWASP Category | Check IDs |
|----------------|-----------|
| ASI01 - Prompt Injection | CID-001, CID-002, CTO-001, CSK-001, CSK-003, CSK-005, CMCP-001 |
| ASI02 - Excessive Agency | CGW-001, CGW-005, CID-001, CID-002, CTO-001, CTO-002, CTO-003, CEX-001, CEX-003, CPL-001, CMCP-001 |
| ASI03 - Supply Chain | CSK-001, CSK-002, CSK-004, CSK-005, CPL-001, CSF-001, CMCP-001, CMCP-002, CMCP-003 |
| ASI05 - Insecure Output / Secrets | CGW-001, CGW-002, CGW-003, CGW-004, CGW-005, CFS-001, CFS-002, CSF-002, CMCP-002, credentials |
| ASI04 - Knowledge Poisoning / Data Integrity | installation (workspace integrity) |
| ASI06 - Memory & Context Manipulation | installation (workspace integrity) |
| ASI07 - Multi-Agent Exploitation | CID-003 |
| ASI08 - Uncontrolled Cascading | CEX-001, CEX-002, CEX-003 |
| ASI09 - Repudiation / Insufficient Audit | installation (discovery config) |
| ASI10 - Insufficient Monitoring | CID-001, CGW-003, CTO-001, CSF-001 |

## Summary

- **27 named checks** across 9 check families
- **Dynamic credential detection** covering 17 regex patterns + entropy heuristics
- **5 known CVE detections** (CVE-2026-25253, CVE-2026-24763, CVE-2026-25157, CVE-2026-25593, CVE-2026-25475)
- All findings map to OWASP Agentic Top 10 (ASI01-ASI10)
