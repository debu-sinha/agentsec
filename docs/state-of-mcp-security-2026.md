# State of MCP Security — February 2026

> An empirical analysis of security posture across 50 popular MCP server repositories
>
> **Author:** Debu Sinha
> **Date:** February 2026
> **Scanner:** agentsec v0.4.4 ([GitHub](https://github.com/debu-sinha/agentsec) | [PyPI](https://pypi.org/project/agentsec-ai/))
> **Data:** All raw findings, selection criteria, and reproduction scripts are open-source

---

## Executive Summary

We scanned 50 of the most popular Model Context Protocol (MCP) server repositories on
GitHub to measure the security posture of the emerging AI tool ecosystem. MCP servers
provide tools to autonomous AI agents — giving them access to databases, filesystems,
APIs, and shell commands. A compromised or misconfigured MCP server can give an attacker
direct access to everything the AI agent can reach.

### Key Findings

- **593 security findings** across 48 scanned repositories (2 failed to clone)
- **9 critical** and **14 high** severity findings in **6 repositories**
- **The most common risk is credential exposure**: hardcoded API keys, database connection
  strings with plaintext passwords, and secrets committed to version control
- **Tool poisoning is rare but severe**: hidden behavioral directives in tool descriptions
  were found in community-maintained servers
- **Large repositories concentrate findings**: MindsDB alone accounts for 30% of all findings
  (175), though most are LOW severity in test/documentation files
- After applying multi-stage false positive hardening, critical findings dropped **87%**
  compared to naive pattern matching (71 → 9)

### Recommendations

1. **Never commit credentials** to MCP server repositories — use environment variable
   references (`${VAR}`) instead of plaintext values
2. **Audit tool descriptions** for hidden behavioral directives before deploying MCP servers
3. **Pin tool descriptions** with SHA-256 hashes to detect unauthorized changes (rug pulls)
4. **Require authentication** on all MCP server endpoints, especially remote/networked ones
5. **Run static security scans** as part of CI/CD for MCP server development

---

## 1. Background

### 1.1 What is MCP?

The Model Context Protocol (MCP) is an open standard for connecting AI agents to external
tools and data sources. Published by Anthropic in 2024, MCP defines how an AI agent
discovers, invokes, and receives results from tools — whether they access databases,
APIs, filesystems, or shell commands.

MCP servers are the supply chain of the AI agent ecosystem. When an agent installs an MCP
server, it trusts that server's tool definitions, parameter schemas, and behavioral
descriptions. This trust is the attack surface.

### 1.2 Why This Study?

The MCP ecosystem is growing rapidly. As of February 2026:

- The top MCP server repository (upstash/context7) has **45,985 GitHub stars**
- Over 200 MCP servers are publicly available on GitHub
- Major AI platforms (Claude Code, Cursor, Windsurf, OpenClaw) support MCP natively
- No systematic security analysis of this ecosystem has been published

The OWASP Top 10 for Agentic Applications (2026) identifies supply chain vulnerabilities
(ASI03), credential theft (ASI05), and tool poisoning (ASI01) as top risks — all of which
manifest in MCP servers.

### 1.3 Recent Incidents

| Incident | Date | Impact | Relevance |
|----------|------|--------|-----------|
| ClawHavoc | Jan 2026 | 1,184 malicious skills on ClawHub (12% of marketplace) | Supply chain risk in agent extension marketplaces |
| LayerX RCE | Feb 2026 | Claude Desktop Extensions CVSS 10/10 | Agent tool execution as attack vector |
| CVE-2026-25593 | Feb 2026 | Unauthenticated WebSocket RCE in OpenClaw | Network-exposed agent gateway exploitation |
| MCP Tool Poisoning | 2025–2026 | 84.2% success rate with auto-approval (Invariant Labs) | Hidden directives in tool descriptions |

---

## 2. Methodology

### 2.1 Target Selection

We selected the 50 most-starred MCP server repositories on GitHub as of February 17, 2026.
Selection criteria:

- Repository must contain MCP server implementation (tool definitions, server configuration)
- Repository must be public and cloneable
- Ranked by GitHub star count as popularity proxy

**Selection bias acknowledgment:** Star count is a rough proxy for popularity and does not
necessarily reflect deployment frequency. The long tail of less-maintained MCP servers may
have different (likely worse) security characteristics.

### 2.2 Top 10 by Stars

| Rank | Repository | Stars | Category |
|------|-----------|------:|----------|
| 1 | upstash/context7 | 45,985 | Context/memory |
| 2 | modelcontextprotocol/servers | 38,000+ | Official reference |
| 3 | jlowin/fastmcp | 8,000+ | MCP framework |
| 4 | mindsdb/mindsdb | 7,000+ | AI database platform |
| 5 | awslabs/mcp | 6,000+ | AWS MCP servers |
| 6 | punkpeye/fastmcp | 5,000+ | MCP framework |
| 7 | bytebase/dbhub | 4,000+ | Database hub |
| 8 | activepieces/activepieces | 3,000+ | Workflow automation |
| 9 | googleapis/genai-toolbox | 3,000+ | Google AI toolbox |
| 10 | aipotheosis-labs/aci | 2,500+ | Agent compute |

### 2.3 Scanner Configuration

- **Tool**: agentsec v0.4.4 with all four scanner modules enabled
  - Installation scanner: configuration analysis, CVE detection
  - Skill analyzer: AST-based malware detection, prompt injection patterns
  - MCP scanner: tool poisoning, parameter risk, supply chain analysis
  - Credential scanner: detect-secrets (23 plugins) + 11 custom patterns
- **False positive hardening**: All 5 pipeline stages active (known values, placeholders,
  character diversity, context-aware severity, entropy gating)
- **Output**: JSON with `--fail-on none` to collect all findings
- **Deduplication**: SHA-256 fingerprint per finding (file + line + check ID)

### 2.4 Limitations

- **Static analysis only**: No runtime testing, no dynamic analysis, no exploit validation
- **Single tool**: agentsec only — no cross-validation with Semgrep, CodeQL, or TruffleHog
- **Snapshot in time**: Results reflect repository state on February 17, 2026
- **No reachability analysis**: Findings indicate the presence of a pattern, not confirmed
  exploitability
- **Star-based selection**: May not represent the security posture of less-popular servers

---

## 3. Results

### 3.1 Aggregate Findings

| Severity | Count | Repos Affected | % of Total |
|----------|------:|---------------:|-----------:|
| Critical | 9 | 6 | 1.5% |
| High | 14 | 6 | 2.4% |
| Medium | 128 | ~25 | 21.6% |
| Low | 395 | ~40 | 66.6% |
| Info | 47 | ~20 | 7.9% |
| **Total** | **593** | **48** | **100%** |

**48 of 50 targets were successfully cloned and scanned.**
Average findings per target: 12.35. Median scan time: 2.66 seconds.

### 3.2 Findings by OWASP Category

| OWASP Category | Description | Finding Count | Severity Profile |
|---------------|-------------|:-------------:|------------------|
| ASI05 | Credential Theft / Insecure Output | ~400 | 7 CRIT, 8 HIGH, most LOW (test/doc) |
| ASI03 | Supply Chain Vulnerabilities | ~80 | 2 CRIT, 4 HIGH |
| ASI02 | Excessive Agency | ~50 | Medium/Low |
| ASI01 | Goal Hijacking / Prompt Injection | ~30 | High/Medium |
| ASI04 | Knowledge Poisoning | ~15 | Medium/Low |
| ASI10 | Misaligned Behavior | ~10 | Medium/Low |
| Other | ASI06–ASI09 (runtime categories) | ~8 | Info |

**Credential exposure (ASI05) dominates the ecosystem**, accounting for approximately 67%
of all findings. This includes API keys, database connection strings, and tokens in source
code, configuration files, and docker-compose definitions.

### 3.3 Findings by Repository (Top 10)

| Repository | Total | Critical | High | Medium | Low |
|-----------|------:|---------:|-----:|-------:|----:|
| mindsdb/mindsdb | 175 | 1 | 2 | 30 | 142 |
| awslabs/mcp | 61 | 1 | 1 | 15 | 44 |
| jlowin/fastmcp | 34 | 0 | 1 | 10 | 23 |
| BeehiveInnovations/pal-mcp-server | 18 | 1 | 1 | 5 | 11 |
| aipotheosis-labs/aci | 17 | 2 | 1 | 5 | 9 |
| bytebase/dbhub | 14 | 1 | 1 | 4 | 8 |
| sooperset/mcp-atlassian | 10 | 0 | 0 | 4 | 6 |
| punkpeye/fastmcp | 9 | 0 | 0 | 3 | 6 |
| googleapis/genai-toolbox | 6 | 0 | 0 | 2 | 4 |
| Other (39 repos) | 249 | 3 | 7 | 50 | 142 |

**MindsDB accounts for 30% of all findings** (175 of 593). The majority are LOW severity,
downgraded from higher severities because they appear in test files, documentation, and
example configurations. This is expected for a large, mature codebase with extensive test
coverage.

### 3.4 Critical Findings Breakdown

The 9 critical findings across 6 repositories fall into these categories:

| Category | Count | Description |
|----------|------:|-------------|
| Hardcoded API keys in source code | 4 | Production API keys (OpenAI, AWS, provider-specific) committed to version control |
| Database connection strings with real passwords | 2 | Connection strings in non-example configs with passwords that pass all placeholder checks |
| MCP tool poisoning patterns | 2 | Hidden behavioral directives in tool descriptions |
| Missing authentication on remote MCP endpoint | 1 | HTTPS MCP server with no authentication mechanism |

### 3.5 False Positive Analysis

| FP Hardening Stage | Findings Suppressed | Before | After |
|-------------------|--------------------:|-------:|------:|
| Known example values (AWS EXAMPLE, jwt.io) | ~15 | 71 | 56 |
| Placeholder passwords (changeme, ${VAR}) | ~20 | 56 | 36 |
| Context-aware severity (test/doc → LOW) | ~300+ | N/A | N/A (severity change, not suppression) |
| Entropy gating (Shannon < 3.0) | ~287 | 36 | 9 |
| Character diversity check | ~5 | 9 | 9 |

The naive scanner (v0.4.0 without hardening) reported **71 critical findings** across
**49 repositories** — virtually every repo had a "critical" issue. After hardening:
**9 critical findings** across **6 repositories**. The 87% reduction in critical findings
reflects real FP elimination, not suppression of true positives — benchmark recall remains
1.00 across all severity levels.

---

## 4. Case Studies

### 4.1 Case Study: Credential Exposure in Large Codebases

**Repository:** [redacted — large AI platform with 100K+ stars]
**Findings:** 175 total (1 CRITICAL, 2 HIGH, 30 MEDIUM, 142 LOW)

The CRITICAL finding was a production API key hardcoded in a configuration file that was
not in the test or documentation directory. The 142 LOW findings were all in test files
and documentation — example API keys, tutorial connection strings, and test fixture
credentials. These were correctly downgraded by the context-aware severity pipeline.

**Key insight:** Large codebases with extensive tests will always have credential-like
strings in test fixtures. A scanner without context awareness would report 175 "critical"
findings, making the one actual critical finding impossible to find.

### 4.2 Case Study: MCP Tool Poisoning

**Repository:** [community-maintained MCP server]
**Finding:** Hidden behavioral directive in tool description

The tool description contained a natural language instruction that would cause the AI agent
to send tool outputs to an external endpoint. This instruction was embedded in a way that
would be read by the LLM during tool dispatch but is not immediately obvious to a human
reviewing the tool definition.

**Key insight:** Tool poisoning is the "SQL injection of the AI era" — tool descriptions
are executed by the LLM just as SQL queries are executed by the database. The difference
is that SQL injection is well-understood and has decades of mitigation tooling, while tool
poisoning is a novel attack vector with no established defenses.

### 4.3 Case Study: Supply Chain Risk via npx

**Repository:** [MCP server with npm-based installation]
**Finding:** Unverified npx package execution

The MCP server's installation instructions use `npx` to execute a package that is not
scoped to `@anthropic` or `@modelcontextprotocol`. This means:

1. The package could be typosquatted (a similarly-named malicious package)
2. The package is not under the governance of the MCP protocol maintainers
3. `npx` downloads and executes the package in a single step with no integrity verification

**Key insight:** The npm supply chain has a well-documented history of compromise
(event-stream, ua-parser-js, node-ipc). MCP servers that rely on npx execution inherit
this entire threat surface.

---

## 5. Comparison with Traditional Software

### 5.1 What's Different About MCP Security?

| Dimension | Traditional Software | MCP Servers |
|-----------|---------------------|-------------|
| Attack surface | Code, dependencies, config | Code, dependencies, config, **tool descriptions** |
| Credential risk | Hardcoded secrets | Hardcoded secrets + **MCP env var passthrough** |
| Supply chain | Package registries | Package registries + **npx one-shot execution** |
| Injection vector | SQL, OS command, XSS | **Tool description injection** (read by LLM) |
| Blast radius | Application scope | **Agent scope** (shell, filesystem, network, APIs) |

### 5.2 The Trust Amplification Problem

When a developer installs a traditional npm package, the package can access:
- The Node.js runtime
- The filesystem (within process permissions)
- The network

When an AI agent installs an MCP server, the server's tools can access:
- Everything the agent can access
- Which typically includes: shell execution, file read/write, API calls, database queries
- All mediated by natural language — meaning tool descriptions influence *how* the agent
  uses its full capability set

A compromised MCP server doesn't just run code — it instructs the AI agent to run code
on its behalf, using the agent's full tool and credential set.

---

## 6. Recommendations

### For MCP Server Authors

1. **Never commit credentials to version control.** Use environment variable references
   (`${VAR}`) in configuration files. Add `.env` to `.gitignore`.

2. **Audit your tool descriptions.** Ensure they contain only accurate, minimal descriptions
   of tool behavior. Remove any text that could be interpreted as a behavioral instruction
   by an LLM.

3. **Scope your npm packages.** If publishing an MCP server via npm, use a scoped package
   name (`@yourorg/server-name`) to reduce typosquatting risk.

4. **Require authentication.** All MCP server endpoints should require authentication,
   especially those accessible over the network.

5. **Add security scanning to CI.** Run `agentsec scan . --fail-on high` in your CI
   pipeline to catch credential exposure and tool poisoning before they reach production.

### For MCP Server Users

1. **Review tool descriptions before approval.** Read what the tool says it does, not just
   its name. Look for hidden instructions or unusual behavioral directives.

2. **Pin tool descriptions.** Use `agentsec pin-tools` to record SHA-256 hashes of tool
   descriptions. Re-scan periodically to detect unauthorized changes.

3. **Prefer official packages.** Use MCP servers from `@anthropic` or
   `@modelcontextprotocol` scopes when available. Community servers should be audited
   before deployment.

4. **Limit agent permissions.** Configure your agent with the minimum tool profile needed.
   Don't grant `full` tools when `messaging` would suffice.

5. **Monitor for drift.** MCP server updates can change tool descriptions. Re-scan after
   any update to detect rug pull attacks.

### For Platform Vendors

1. **Implement tool description signing.** Allow MCP server authors to cryptographically
   sign tool descriptions so agents can verify integrity.

2. **Add sandboxing for MCP tool execution.** Tool invocations should run in isolated
   contexts with explicit capability grants.

3. **Provide a security dashboard.** Surface tool poisoning patterns, credential exposure,
   and supply chain risks to users before they approve MCP servers.

4. **Require authentication by default.** New MCP servers should require authentication
   out of the box, not as an opt-in configuration.

---

## 7. Reproducibility

### 7.1 Data Artifacts

All study data is available in the agentsec repository:

| Artifact | Path | Description |
|----------|------|-------------|
| Selection criteria | `docs/mcp-dashboard/data/selection_20260217.csv` | 50 repos with stars, last commit, ranking |
| Raw findings | `docs/mcp-dashboard/data/findings_20260217.jsonl` | All findings in JSONL format |
| Summary metrics | `docs/mcp-dashboard/data/summary_20260217.json` | Aggregate statistics |
| Finding schema | `docs/benchmarks/top50/schema/top50_finding.schema.json` | JSON Schema for findings |

### 7.2 Reproduction Steps

```bash
# Install agentsec
pip install agentsec-ai

# Run the ecosystem study (clones repos, scans, generates report)
python scripts/run_top50_study.py

# Or scan a single MCP server repository
git clone https://github.com/some/mcp-server /tmp/mcp-server
agentsec scan /tmp/mcp-server --format json -f results.json
```

### 7.3 Scanner Benchmark

The scanner's accuracy is validated against a curated benchmark of 20 fixtures:

| Metric | Value |
|--------|------:|
| Precision | 0.82 |
| Recall | 1.00 |
| F1 Score | 0.90 |
| Critical Recall | 1.00 |
| Test Count | 348 |

---

## 8. Future Work

- **Quarterly re-scans**: Track ecosystem security posture over time, measure improvement
- **Expanded scope**: Include MCP servers from npm registry, not just GitHub
- **Cross-tool validation**: Compare agentsec findings with Semgrep, CodeQL, and TruffleHog
- **Runtime validation**: Develop dynamic testing methodology for MCP tool behavior
- **Community benchmark**: Invite MCP server authors to self-scan and publish results

---

## Appendix: Scanner Methodology

### Detection Rules Summary

| Scanner Module | Rule Count | Targets |
|---------------|----------:|---------|
| Installation | 27 checks | Config files, permissions, CVEs |
| Skill Analyzer | 47 patterns | Python AST, malware, prompt injection |
| MCP Scanner | 17 patterns | Tool poisoning, parameters, supply chain |
| Credential | 34 patterns | API keys, tokens, connection strings |
| **Total** | **125+** | |

### OWASP Mapping

All findings map to the OWASP Top 10 for Agentic Applications (2026):

| ID | Category | Covered By |
|----|----------|-----------|
| ASI01 | Agent Goal Hijacking | Skill injection + MCP poisoning detection |
| ASI02 | Excessive Agency | Tool profile + sandbox + exec approval checks |
| ASI03 | Supply Chain Vulns | Skill malware + MCP supply chain + gate |
| ASI04 | Knowledge Poisoning | SOUL.md permissions + config integrity |
| ASI05 | Credential Theft | 34 detection patterns + file permissions |
| ASI06 | Memory Manipulation | Out of scope (runtime) |
| ASI07 | Multi-Agent Exploitation | DM/group policy checks |
| ASI08 | Cascading Failures | Sandbox + exec approval checks |
| ASI09 | Repudiation | Out of scope (runtime) |
| ASI10 | Misaligned Behavior | SOUL.md analysis + tool profile |

---

*This report was produced using agentsec, an open-source security scanner for AI agent
installations. The scanner, methodology, and all data are available at
[github.com/debu-sinha/agentsec](https://github.com/debu-sinha/agentsec) under Apache-2.0 license.*
