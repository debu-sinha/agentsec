# Static Security Analysis for Autonomous AI Agent Installations

> **arXiv Preprint Outline** — Target: cs.CR (Cryptography and Security)
> Secondary: cs.SE (Software Engineering), cs.AI (Artificial Intelligence)

---

## Abstract (~250 words)

**Problem.** Autonomous AI agents (OpenClaw, Claude Code, Cursor, Windsurf) now execute
tools, manage credentials, install extensions, and communicate over networks — inheriting
the full attack surface of the software they orchestrate. The OWASP Top 10 for Agentic
Applications (2026) identifies ten categories of risk, but no systematic static analysis
framework exists to detect these misconfigurations before deployment.

**Approach.** We present agentsec, an open-source static security scanner that audits AI
agent installations across four attack surfaces: configuration, skills/plugins, MCP tool
definitions, and credential storage. The scanner implements 27 named checks, 34 credential
detection patterns (via Yelp's detect-secrets plus 11 custom provider patterns), AST-based
malware analysis for skills, and tool poisoning detection for MCP servers. Findings map to
all 10 OWASP Agentic categories (ASI01–ASI10) and produce a composite posture score with
context-sensitive severity escalation.

**Results.** We evaluate agentsec against a benchmark of 20 curated fixtures spanning all
scanner modules, achieving 1.00 recall and 0.82 precision (F1 = 0.90) with zero false
negatives on critical findings. We then apply the scanner to 50 popular MCP servers,
finding 593 security issues across the ecosystem, including 9 critical findings in 6
repositories. A multi-stage false positive hardening pipeline (known-value allowlisting,
placeholder detection, entropy gating, context-aware severity) reduced critical false
positives by 87% compared to naive pattern matching.

**Contribution.** To our knowledge, this is the first systematic static analysis framework
for AI agent installations mapped to OWASP's agentic threat taxonomy.

---

## 1. Introduction (~1.5 pages)

### 1.1 The Agent Security Gap

- AI agents have evolved from chat interfaces to autonomous systems that execute shell
  commands, manage API credentials, install third-party extensions, and expose network
  services
- Traditional application security (SAST, DAST, SCA) does not cover agent-specific attack
  surfaces: tool poisoning, goal hijacking via skill injection, "doom combo" misconfigurations
- Real-world incidents motivating this work:
  - **ClawHavoc** (Jan 2026): 1,184 malicious skills on ClawHub, 12% of the marketplace
  - **LayerX** (Feb 2026): Claude Desktop Extensions RCE, CVSS 10/10
  - **CVE-2026-25593**: Unauthenticated WebSocket RCE in OpenClaw gateway
  - **MCP Tool Poisoning** (Invariant Labs): 84.2% success rate with auto-approval

### 1.2 OWASP Agentic Top 10 (2026)

- Brief overview of ASI01–ASI10 categories
- Observation: no existing tool maps findings to this taxonomy
- Our contribution: first scanner with complete ASI01–ASI10 mapping

### 1.3 Contributions

1. A formal threat model for AI agent installations identifying 5 adversary profiles,
   4 attack surfaces, and 21 STRIDE-mapped threats (Section 3)
2. A static analysis framework with 150+ detection rules across 4 scanner modules
   mapped to all 10 OWASP Agentic categories (Section 4)
3. A false positive hardening pipeline that reduces critical FPs by 87% while
   maintaining 100% critical recall (Section 5)
4. An empirical study of 50 MCP servers revealing systemic credential and configuration
   weaknesses in the ecosystem (Section 6)
5. An open-source implementation with 348 tests, cross-platform support, and CI/CD
   integration via SARIF output (Section 7)

---

## 2. Background and Related Work (~1.5 pages)

### 2.1 AI Agent Architectures

- Model Context Protocol (MCP) — tool interface standard (Anthropic, 2024)
- OpenClaw architecture: gateway, identity, tools, skills, sandbox, exec-approvals
- Claude Code / Cursor / Windsurf: MCP-based tool dispatch
- Multi-agent systems: DM policies, group policies, agent-to-agent trust

### 2.2 OWASP Top 10 for Agentic Applications

- Table: ASI01–ASI10 with one-line descriptions
- Mapping to traditional OWASP Top 10 (Web) where applicable
- Categories unique to agentic systems: ASI01 (goal hijacking), ASI06 (memory
  manipulation), ASI07 (multi-agent exploitation)

### 2.3 Existing Security Tools

- **Traditional SAST**: Semgrep, CodeQL, Bandit — scan source code, not agent configs
- **Secret scanners**: detect-secrets, TruffleHog, Gitleaks — find credentials but miss
  agent-specific context (tool profiles, DM policies, MCP tool descriptions)
- **Supply chain**: Snyk, Dependabot, pip-audit — package vulnerabilities, not skill
  content analysis
- **MCP-specific**: No published static analysis tools for MCP tool descriptions
- **Gap**: None of the above tools understand agent configuration semantics (doom combo,
  tool profile + DM policy interaction, skill-level prompt injection)

### 2.4 Threat Modeling for AI Systems

- STRIDE (Microsoft) applied to LLM systems
- MITRE ATLAS: adversarial threat landscape for AI systems
- Recent work on prompt injection taxonomy (Greshake et al., 2023)
- Our extension: STRIDE analysis specific to autonomous agent installations

---

## 3. Threat Model (~2 pages)

### 3.1 System Model

- Architecture diagram: config → skills → MCP → credentials → LLM runtime → system interface
- Trust boundaries: user↔agent, agent↔tools, agent↔network, agent↔extensions, agent↔agents
- Asset inventory: 9 asset categories with CIA ratings (Table 1)

### 3.2 Adversary Profiles

| Profile | Motivation | Capability | Historical Precedent |
|---------|-----------|------------|---------------------|
| Malicious Skill Author | Credential theft, cryptomining | Publish skills to marketplace | ClawHavoc (1,184 skills) |
| Compromised MCP Server | Data exfiltration, behavioral manipulation | Serve poisoned tool definitions | Invariant Labs study (84.2%) |
| Network Attacker | RCE, credential theft | Send traffic to exposed endpoints | CVE-2026-25593 |
| Local Process | Credential theft | Read world-readable files | Standard local privilege escalation |
| Supply Chain Attacker | Mass compromise | Publish/compromise packages | event-stream, ua-parser-js |

### 3.3 Attack Surface Analysis

- **Configuration surface**: The "doom combo" (open DM + full tools + no sandbox) and
  12 additional configuration risks
- **Skill surface**: AST-level dangerous calls (6 types), dangerous imports (17 modules),
  8 malware patterns, 6 prompt injection patterns
- **MCP surface**: 6 tool poisoning vectors, 8 dangerous parameter names, npx supply chain
- **Credential surface**: Scattered across .env, config, docker-compose, skill source, MCP env

### 3.4 STRIDE Analysis

- Full STRIDE table mapping 21 threats to attacks, OWASP categories, and detection checks
- Key insight: agent-specific threats (tool poisoning, doom combo, skill injection) have no
  analogue in traditional STRIDE applications

---

## 4. Detection Architecture (~3 pages)

### 4.1 System Overview

```
CLI → Orchestrator → [Scanner₁ ‖ Scanner₂ ‖ Scanner₃ ‖ Scanner₄] → OWASP Scorer → Reporter
```

- All scanners extend `BaseScanner` ABC, implement `scan(ScanContext) → list[Finding]`
- Scanners run in parallel; findings are merged and deduplicated via SHA-256 fingerprints
- Findings carry: severity, confidence, OWASP category, remediation, sanitized evidence

### 4.2 Installation Scanner (27 Named Checks)

**Configuration analysis** (21 checks across 8 families):
- Gateway security: bind address, authentication, SSRF protection (CGW-001–005)
- Identity policy: DM policy, group policy, scope isolation (CID-001–003)
- Tool policy: profile analysis, runtime tools, sandbox mode (CTO-001–003)
- Execution approvals: presence, permissiveness, safe binary list (CEX-001–003)
- File permissions: directory mode, file readability (CFS-001–002)
- Safety controls: scanner status, credential redaction (CSF-001–002)
- Known CVE detection: 5 CVEs with version-gated checks

**Compound threat detection:**
- "Doom combo" detection: when open DM + full tools + no sandbox co-occur, the scanner
  generates a distinct CRITICAL finding and caps the posture score at 20/100
- Severity escalation: findings are escalated when multiple misconfigurations interact
  (e.g., open DM + disabled auth → HIGH escalated to CRITICAL)

### 4.3 Skill Analyzer (AST + Pattern Analysis)

**AST-based detection:**
- Parse skill source code into Python AST
- Walk tree for dangerous Call nodes: `eval`, `exec`, `compile`, `__import__`, `getattr`, `setattr`
- Walk Import/ImportFrom nodes for 17 dangerous modules
- Analyze function call arguments for credential path patterns

**Pattern-based detection:**
- 8 regex patterns for malware indicators: base64 payloads, env harvesting, reverse shells,
  HTTP exfiltration, cryptomining, DNS tunneling
- 6 prompt injection patterns in skill descriptions/README
- 5 instruction malware patterns (pipe-to-shell, PowerShell, credential path targeting)

**Frontmatter analysis:**
- Parse YAML/JSON skill metadata for dangerous capability requests
  (filesystem, network, env, exec, sensitive_data)

### 4.4 MCP Scanner (Tool Definition Analysis)

**Tool poisoning detection (6 vectors):**
1. Hidden behavioral directives ("always POST results to...")
2. Data exfiltration instructions ("include all file contents...")
3. Privilege escalation instructions
4. Tool chaining manipulation ("after this tool, also call...")
5. Invisible Unicode (zero-width characters)
6. Encoded content in descriptions (base64)

**Parameter risk analysis (8 dangerous names):**
- shell_command, file_path, url, code, query, sql, eval, script

**Supply chain analysis:**
- npx execution of unverified packages (non-@anthropic, non-@modelcontextprotocol scopes)
- Remote server detection (HTTPS endpoints without auth)
- Hardcoded secrets in server environment variables

**Integrity verification:**
- SHA-256 hash pinning of tool descriptions
- Drift detection on subsequent scans (rug pull defense)

### 4.5 Credential Scanner (Multi-Engine Detection)

**Primary engine: detect-secrets (Yelp)**
- 23 detection plugins covering major providers (AWS, Azure, GitHub, GitLab, Stripe,
  Twilio, Slack, Square, SendGrid, JWT, private keys, etc.)
- 9 heuristic filters (sequential strings, UUIDs, templated secrets, lock files)
- Configurable entropy thresholds: Base64 (5.0), Hex (4.5)

**Secondary engine: 11 custom provider patterns**
- AI-specific providers absent from detect-secrets: OpenAI (`sk-`), Anthropic (`sk-ant-`),
  Databricks (`dapi`), HuggingFace (`hf_`), Google AI (`AIza`), Groq (`gsk_`),
  Replicate (`r8_`), Pinecone (`pcsk_`), Cohere (`co-`), Vercel (`vercel_`)
- Generic connection string pattern (database URLs with embedded credentials)
- Entropy floor (3.0) applied to custom patterns to prevent low-entropy matches

**Evidence sanitization:**
- All secrets in findings show only first 4 + last 4 characters
- Full secret value never stored in scan output

### 4.6 OWASP Posture Score

**Scoring algorithm:**
- Base score: 100
- Deductions: CRITICAL (−15), HIGH (−7), MEDIUM (−3), LOW (−1, capped at 15 total)
- Score caps: doom combo or 3+ CRITICAL → cap 20; 1+ CRITICAL → cap 55; 5+ HIGH → cap 65
- Floor: 5.0 (distinguishes minimal controls from zero)
- Grade: A (90–100), B (80–89), C (70–79), D (60–69), F (0–59)

**Context-sensitive escalation:**
- Open DM/group policy + disabled auth → HIGH findings escalated to CRITICAL
- Risky tool groups + open inbound messages → HIGH findings escalated to CRITICAL
- Escalation is idempotent (guard prevents double-escalation)

---

## 5. False Positive Hardening (~1.5 pages)

### 5.1 The False Positive Problem

- Credential scanners are notorious for high FP rates in real codebases
- Documentation files, test fixtures, example configs, and lock files generate noise
- Agent ecosystems exacerbate this: MCP configs, docker-compose files, and .env.example
  files are everywhere
- A tool with high FP rates loses developer trust and gets disabled

### 5.2 Multi-Stage Filtering Pipeline

**Stage 1: Known example values**
- Allowlist of canonical example credentials (AWS `AKIAIOSFODNN7EXAMPLE`, jwt.io token,
  Databricks documentation token)
- Exact match and prefix match for stable example prefixes

**Stage 2: Placeholder detection**
- 33 known placeholder password values ("changeme", "mysecretpassword", "password123", etc.)
- Multi-word placeholder phrases ("your-api-key", "replace_me", "for_testing_only")
- Sequential pattern detection ("1234567890", "abcdefghij" in alphanumeric-normalized value)
- Environment variable references (`${VAR}`, `$VAR_NAME`)
- Template syntax (`<password>`, `{{secret}}`)

**Stage 3: Character class diversity**
- Require minimum diversity across character classes (uppercase, lowercase, digits, special)
- Suppresses obvious documentation tokens ("sk-this-is-docs-not-key") that pass entropy checks

**Stage 4: Context-aware severity**
- Files in test/doc/example directories or with doc filenames → CRITICAL/HIGH downgraded to LOW
- Lock files (package-lock.json, yarn.lock, Pipfile.lock) → skipped entirely
- `.md` files → treated as documentation context
- Mock/fixture/stub files → treated as test context

**Stage 5: Entropy gating**
- Shannon entropy thresholds: 3.0 (custom patterns), 4.5 (hex), 5.0 (base64)
- Values below threshold are suppressed even if pattern matches
- Prevents matching on low-entropy strings like "test-api-key-here"

### 5.3 Evaluation of FP Reduction

| Metric | Before Hardening | After Hardening | Reduction |
|--------|-----------------|-----------------|-----------|
| Critical findings (ecosystem study) | 71 | 9 | −87% |
| Repos with CRITICAL/HIGH | 49 | 6 | −88% |
| Benchmark precision | 0.65 (credential) | 1.00 | +54% |
| Benchmark recall | 1.00 | 1.00 | Maintained |

### 5.4 Lessons from the IBM Incident

- A maintainer opened an issue reporting 14 CRITICAL findings, all false positives
- Root causes: `FAKE-EXAMPLE-KEY` matched patterns, documentation strings matched entropy
  thresholds, known example values were not allowlisted
- This incident drove the implementation of all 5 hardening stages
- Post-fix: the same codebase produces 0 findings (all suppressed correctly)

---

## 6. Empirical Study: State of MCP Security (~2 pages)

### 6.1 Methodology

**Selection criteria:**
- Top 50 MCP servers by GitHub stars (as of February 2026)
- Include official Anthropic servers and community-maintained servers
- Cover diverse tool categories: filesystem, database, API integration, browser, search

**Scan configuration:**
- agentsec v0.4.4 with all scanner modules enabled
- `--fail-on none` to collect all findings without early termination
- JSON output for automated analysis
- Post-scan deduplication by stable SHA-256 fingerprints

### 6.2 Aggregate Results

| Severity | Finding Count | Repos Affected |
|----------|--------------|----------------|
| CRITICAL | 9 | 6 |
| HIGH | ~80 | ~15 |
| MEDIUM | ~200 | ~30 |
| LOW | ~300 | ~40 |
| **Total** | **593** | **50** |

### 6.3 Finding Categories

- **Most common**: Credential exposure (hardcoded API keys, connection strings with
  plaintext passwords)
- **Most severe**: MCP tool poisoning patterns (hidden behavioral directives in tool
  descriptions), unsafe npx execution
- **Systemic**: Missing authentication on remote MCP servers, world-readable config files

### 6.4 Case Studies

**Case 1: Credential exposure in MCP server config**
- Connection strings with plaintext passwords in docker-compose.yml
- API keys hardcoded in server source code
- .env files committed to version control without .gitignore

**Case 2: Tool poisoning in community MCP server**
- Tool description containing hidden behavioral directive
- Dangerous parameter names (shell_command, code, eval)
- No tool integrity verification (no pinning)

**Case 3: Supply chain risk via npx**
- MCP server installed via `npx some-unverified-package`
- No scope verification, no SHA pinning
- Typosquatting risk on npm registry

### 6.5 Responsible Disclosure

- All critical findings reported to maintainers via GitHub issues
- 90-day disclosure window
- Several findings resolved post-disclosure

---

## 7. Implementation and Evaluation (~1.5 pages)

### 7.1 Implementation

- **Language**: Python 3.10+ (3,500+ LOC in scanner modules)
- **Dependencies**: click (CLI), Pydantic (models), Rich (terminal), detect-secrets
  (credential detection), watchdog (filesystem monitoring)
- **Output formats**: Rich terminal tables, JSON (CI/CD), SARIF (GitHub Code Scanning)
- **Distribution**: PyPI (`agentsec-ai`), Apache-2.0 license

### 7.2 Benchmark Evaluation

**Fixture design:**
- 20 curated fixtures (F-001 through F-020) with known-good and known-bad configurations
- Each fixture targets specific scanner modules and finding types
- Ground truth labels for all expected findings

**Results (Table):**

| Module | Precision | Recall | F1 | Notes |
|--------|-----------|--------|-----|-------|
| Installation | 0.65 | 1.00 | 0.79 | 6 "FPs" are valid findings outside expected set |
| Skill | 1.00 | 1.00 | 1.00 | |
| MCP | 1.00 | 1.00 | 1.00 | |
| Credential | 1.00 | 1.00 | 1.00 | After FP hardening |
| Gate | 1.00 | 1.00 | 1.00 | |
| **Overall** | **0.82** | **1.00** | **0.90** | |

**Critical finding recall: 1.00** — no critical finding in any fixture was missed.

Note: Installation scanner's 0.65 precision reflects findings that are *technically correct*
(valid security issues) but were not in the expected fixture set. These are "bonus" findings
that would be true positives in a real deployment.

### 7.3 Performance

| Platform | p50 Latency | p95 Latency |
|----------|------------|------------|
| Windows 11 | 3.2 ms | 28.5 ms |
| Ubuntu (GitHub Actions) | 2.3 ms | 27.3 ms |
| macOS ARM (GitHub Actions) | 4.8 ms | 30.0 ms |

Scan time for a typical agent installation: <5 seconds.

### 7.4 Test Suite

- 348 tests (unit + integration + CLI)
- 1 skipped (Windows symlink privilege)
- 4 xfail (known limitations documented)
- CI matrix: Python 3.10, 3.12, 3.13 on Ubuntu + macOS

### 7.5 Mitigation Capabilities

Beyond detection, agentsec provides:
- **Automated hardening**: 3 profiles (workstation, vps, public-bot) with 9–10 actions each
- **Pre-install gate**: Blocks known-malicious packages (19 npm + 16 PyPI) before installation,
  then scans package contents against all scanner modules
- **Continuous monitoring**: Filesystem watcher triggers re-scan on config/skill/MCP changes
- **Tool integrity**: SHA-256 pinning of MCP tool descriptions for drift detection

---

## 8. Discussion (~1 page)

### 8.1 The Static-Runtime Gap

- agentsec detects *conditions* that enable attacks, not attacks themselves
- Analogy: network scanner finds open ports and misconfigured firewalls, not active intrusions
- Runtime categories (ASI06 memory manipulation, ASI08 cascading failures, ASI09 audit)
  require hooking into the agent execution layer — a distinct product category (RASP for AI)
- Static analysis remains valuable: most agent compromises exploit misconfigurations that
  could have been caught before deployment

### 8.2 Limitations

- **Language coverage**: Skill AST analysis limited to Python; JavaScript/TypeScript skills
  require separate parser
- **Obfuscation resistance**: Determined adversaries can evade static pattern matching
  (multi-stage encoding, runtime generation, steganography)
- **Configuration completeness**: Scanner assumes agent configuration follows documented
  schema; undocumented settings may be missed
- **Ground truth quality**: Benchmark fixtures are curated by tool authors; independent
  third-party validation would strengthen claims
- **Ecosystem study bias**: Top-50-by-stars selection may not represent the long tail of
  less-maintained MCP servers

### 8.3 Ethical Considerations

- All ecosystem study findings reported via responsible disclosure
- Tool designed for defensive use; detection patterns could theoretically inform attack design
- Credential evidence is always sanitized in output (first 4 + last 4 characters only)

---

## 9. Conclusion (~0.5 pages)

- First systematic static analysis framework for AI agent installations
- Maps to all 10 OWASP Agentic categories with 150+ detection rules
- Achieves 1.00 recall on critical findings with practical FP suppression
- Ecosystem study reveals systemic security weaknesses in popular MCP servers
- Open-source availability enables community adoption and extension

### Future Work

- Runtime behavior monitoring (RASP for AI agents)
- Policy-as-code engine for declarative security requirements
- Machine learning classifier for novel obfuscation patterns
- Multi-language skill analysis (JavaScript, TypeScript, Go)
- Longitudinal ecosystem security tracking

---

## Appendix A: OWASP Category Mapping

Full table mapping all 27 named checks + dynamic credential detection to ASI01–ASI10.

## Appendix B: Detection Rule Catalog

Complete catalog of all 150+ detection rules with pattern, severity, OWASP mapping,
and example match.

## Appendix C: Benchmark Fixture Descriptions

F-001 through F-020 fixture descriptions with expected findings and ground truth labels.

## Appendix D: Ecosystem Study — Per-Repository Summary

Table of all 50 MCP servers with finding counts by severity.

---

## References (~30 entries)

### Standards and Taxonomies
1. OWASP Top 10 for Agentic Applications (2026)
2. OWASP Top 10 for LLM Applications v1.1 (2025)
3. MITRE ATLAS: Adversarial Threat Landscape for AI Systems
4. Microsoft STRIDE Threat Model
5. CWE (Common Weakness Enumeration) — relevant entries

### Incidents and Vulnerabilities
6. ClawHavoc Supply Chain Attack Analysis (Jan-Feb 2026)
7. LayerX Claude Desktop Extensions RCE Disclosure (Feb 2026)
8. CVE-2026-25253: OpenClaw gateway configuration vulnerability
9. CVE-2026-25593: Unauthenticated WebSocket RCE
10. CVE-2026-24763: OpenClaw privilege escalation
11. CVE-2026-25157: OpenClaw authentication bypass
12. CVE-2026-25475: OpenClaw sandbox escape

### Research
13. Greshake et al., "Not what you've signed up for: Compromising Real-World LLM-Integrated
    Applications with Indirect Prompt Injection" (2023)
14. Invariant Labs, "MCP Tool Poisoning: Security Risks in AI Tool Integration" (2025-2026)
15. Perez & Ribeiro, "Ignore This Title and HackAPrompt" (2023)
16. Zou et al., "Universal and Transferable Adversarial Attacks on Aligned Language Models" (2023)

### Tools and Libraries
17. Yelp detect-secrets: https://github.com/Yelp/detect-secrets
18. Model Context Protocol Specification: https://modelcontextprotocol.io
19. Semgrep: https://semgrep.dev
20. CodeQL: https://codeql.github.com
21. TruffleHog: https://github.com/trufflesecurity/trufflehog
22. Bandit: https://bandit.readthedocs.io

### Agent Platforms
23. OpenClaw Documentation
24. Claude Code (Anthropic)
25. Cursor IDE
26. Windsurf IDE

### Security Standards
27. SARIF (Static Analysis Results Interchange Format) v2.1.0
28. CycloneDX SBOM Specification
29. Sigstore: Software Supply Chain Security
30. NIST AI Risk Management Framework (AI RMF 1.0)

---

## Metadata

**Estimated length**: 12–15 pages (single column) or 8–10 pages (double column, ACM/IEEE format)

**Target venues** (in priority order):
1. **arXiv cs.CR** — immediate preprint for citation and visibility
2. **USENIX Security 2027** — top-tier systems security venue
3. **IEEE S&P (Oakland) 2027** — top-tier security venue
4. **ACM CCS 2027** — top-tier security venue
5. **NDSS 2027** — network and distributed systems security
6. **AISec Workshop (co-located with CCS)** — AI security focused

**Keywords**: AI agent security, static analysis, OWASP agentic, MCP tool poisoning,
credential detection, supply chain security, threat modeling

**Data availability**: Scanner source code, benchmark fixtures, and ecosystem study
methodology available at https://github.com/debu-sinha/agentsec under Apache-2.0 license.
Ecosystem study raw findings available upon request (after responsible disclosure period).
