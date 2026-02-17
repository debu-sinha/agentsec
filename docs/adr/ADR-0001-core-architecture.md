# ADR-0001: Core Architecture for agentsec

## Status
Accepted

## Context
The agentic AI ecosystem (OpenClaw, MCP servers, skill marketplaces) has severe security gaps. Published research reports indicate widespread exposure of agent installations, hundreds of malicious skills in public marketplaces, and a high proportion of MCP server configurations with authentication or authorization gaps. Multiple CVEs have been assigned against core agent platform components. Existing tools are fragmented: ClawSec covers config drift, mcp-scan covers MCP servers, Astrix covers detection-only. No tool provides comprehensive scanning across the full agent attack surface with OWASP-aligned scoring.

We need to decide on the foundational architecture for a security scanner that covers installations, skills, MCP servers, and credentials holistically.

## Decision
Build agentsec as a **standalone Python CLI tool** with a **pluggable scanner architecture** and **OWASP Agentic Top 10 scoring engine**.

Key decisions:
1. **Standalone CLI** (not an OpenClaw skill or wrapper around existing tools)
2. **Plugin architecture** via BaseScanner abstract class with ScanContext for cross-scanner state sharing
3. **Native detection** using Python AST analysis + regex patterns (not YARA-only)
4. **OWASP-first scoring** mapping every finding to the 2026 Agentic Top 10
5. **Zero-config UX** with auto-detection of agent type
6. **Open core model** with Apache-2.0 license

## Alternatives Considered

### 1) Build as OpenClaw Skill
- Pros: Runs inside agent, auto-discovers config
- Cons: Requires OpenClaw installed, can't scan other agents, chicken-and-egg problem
- Rejected: Too narrow scope, dependency on scanned system

### 2) Wrapper around mcp-scan + ClawSec
- Pros: Faster initial development, leverages community work
- Cons: Dependent on external tools, fragmented detection quality, can't customize deeply
- Rejected: Need full control over detection quality and deep customization

### 3) YARA-only detection engine
- Pros: Industry standard, large rule community
- Cons: Can't do AST analysis, requires native dependency, overkill for config checking
- Rejected: Made optional dependency; core uses native Python for broader accessibility

## Consequences

### Positive
- Single tool covers the full agent attack surface (installation + skills + MCP + credentials)
- OWASP alignment provides standardized risk communication
- Zero-config UX lowers adoption barrier
- Plugin architecture enables community extensions
- Standalone tool can scan any agent type (not locked to OpenClaw)

### Negative
- Must maintain detection patterns as upstream config formats evolve
- Duplicates some detection that mcp-scan already does (MCP scanning)
- Standalone tool can't leverage OpenClaw's built-in audit internals

### Neutral
- Open-source under Apache-2.0 allows broad adoption but also competition

## Scalability & Cost Notes
- Scanning is CPU-bound and single-threaded in v0.1; parallel scanning planned for v0.2
- Memory usage scales linearly with number of findings (bounded by file count)
- No external service dependencies -- runs fully offline

## Security & Governance
- Tool itself must be secure: secrets always sanitized, no eval/exec on scanned content
- No network calls during scanning (offline-only)
- Read-only by default; hardening requires explicit `--apply` flag
- Finding evidence is truncated to prevent accidental secret leakage

## Rollout / Migration Plan
1. v0.1.0: Core scanners, OWASP scoring, CLI -- publish to PyPI (shipped)
2. v0.2.0: Hardener with 3 profiles, SARIF reporter (shipped)
3. v0.3.0: 5 CVE detections, filesystem watcher, shell hooks (shipped)
4. v0.4.0: Pre-install gate, context-sensitive escalation, benchmark suite (shipped)
