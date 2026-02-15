# Top-50 MCP Security Study

- Study ID: `mcp-top50-2026-02`
- Snapshot date: `2026-02-15`
- Author(s): Debu Sinha
- Tool versions:
  - `agentsec`: `0.4.0`
  - `semgrep`: `1.151.0`
  - `gitleaks`: `8.24.2`

## Goal

Measure real-world security posture across the 50 most popular MCP servers using reproducible static analysis with a merged scanner pipeline (`agentsec` + `semgrep` + `gitleaks`).

## Scope

- In scope:
  - Public MCP server repositories on GitHub
  - Static scanning of code, config, package metadata, and skill/plugin directories
- Out of scope:
  - Intrusive testing against private or production endpoints
  - Exploit development
  - Runtime behavioral analysis

## Data Sources

- GitHub search API: `mcp server`, sorted by stars, top 60 results
- Filtered to exclude awesome-lists, registries, and non-server repositories
- Final selection: 50 targets, 49 successfully cloned (1 failed due to invalid path characters)

## Selection Method

Ranking formula:

`rank_score = GitHub stars (primary sort)`

Repos were ranked by star count after filtering. A weighted z-score formula (stars 60%, recency 25%, adoption 15%) is defined in the schema for future iterations but this snapshot uses stars-only ranking for simplicity.

Selection process:

1. Pulled top 60 public MCP server repos via `gh search repos`.
2. Filtered out awesome-lists, registries, inspectors, and client libraries.
3. Took top 50 by star count.
4. Cloned each at HEAD (shallow, depth=1) and froze commit SHA.

Full selection: `docs/benchmarks/top50/data/top50_selection_20260215.csv`

## Execution

1. Resolved each target to a shallow clone at HEAD with commit SHA recorded.
2. Ran `agentsec scan <target> -o json --fail-on none` on each clone.
3. Ran `semgrep scan --config scripts/semgrep-top50-rules.yml --json`.
4. Ran `gitleaks detect --report-format json`.
5. Normalized all findings into JSONL per the `top50_finding.schema.json` schema.
6. Computed aggregate metrics.

Scan script: `scripts/run_top50_study.py`

## Key Metrics

| Metric | Value |
|---|---:|
| Targets in selection | 50 |
| Targets cloned successfully | 49 |
| Targets with critical or high findings | 49 (100% of cloned targets) |
| Critical findings | 71 |
| High findings | 724 |
| Medium findings | 70 |
| Low findings | 8 |
| Info findings | 48 |
| Total findings | 921 |
| Avg findings/target | 18.80 |
| Median scan time | 8.19 s |
| P95 scan time | 39.38 s |

## Top Recurring Findings

| Category | Count | Description |
|---|---:|---|
| `secret` category findings | 410 | Dominated by gitleaks detections (for example `generic-api-key`, `curl-auth-header`) and requires manual triage |
| `other` category findings | 376 | Mixed scanner output, including semgrep findings not mapped to a narrower category |
| `exec_risk` category findings | 129 | Dynamic execution and command-execution risk patterns |
| Dangerous `compile()` calls | 99 | Still present and still mostly `re.compile()` false positives from skill scanning |
| Semgrep `mcp-js-child-process-exec` | 93 | Frequent use of `exec`/`execSync` style APIs in Node/TS projects |
| `curl-auth-header` secret rule | 79 | Potential credential-bearing HTTP headers in code/config strings |

## Analysis

**Expected noise (not actionable):**
- "Exec approvals file missing" and "Could not determine agent version" still appear for most non-OpenClaw repos (48 each). These are environment/context checks, not direct code vulnerabilities.
- `compile()` findings are largely regex compilation (`re.compile()`), not Python code compilation. This remains a precision gap in the skill scanner.
- A non-trivial subset of gitleaks findings are likely test fixtures, sample keys, or intentionally fake values. Manual validation is required before labeling as incidents.

**Actionable findings:**
- **Potential secret exposure surface is broad** (410 secret-category findings): this is the highest-priority triage stream, especially for repositories with production integration code.
- **Command execution primitives are common** (for example semgrep `mcp-js-child-process-exec`: 93): these need context-aware review for user-input reachability and sanitization.
- **High-concentration repositories** include `IBM/mcp-context-forge` (310 findings), `awslabs/mcp` (157), and `mindsdb/mindsdb` (117), making them strong candidates for detailed case-study triage.

**Precision considerations:**
- The `compile()` false positive remains the single biggest agentsec precision issue. A fix that distinguishes `re.compile()` from builtin `compile()` would immediately reduce noise by ~99 findings in this dataset.
- `false_positive_rate_sampled` is intentionally `null` in summary because no statistically valid manual sampling pass was completed yet.

## Targets by Finding Count (Top 10)

| Target | Findings | Stars | Notes |
|---|---:|---:|---|
| IBM/mcp-context-forge | 310 | 3,278 | Monorepo with many bundled skills and broad scan surface |
| awslabs/mcp | 157 | 8,153 | Multi-server AWS MCP package |
| mindsdb/mindsdb | 117 | 38,478 | Large codebase, federated query engine |
| wonderwhy-er/DesktopCommanderMCP | 36 | 5,467 | Desktop automation server |
| jlowin/fastmcp | 31 | 22,850 | FastMCP Python framework |
| steipete/Peekaboo | 31 | 2,110 | macOS screenshot MCP |
| opensumi/core | 29 | 3,600 | Monorepo with mixed tooling |
| bytebase/dbhub | 25 | 2,117 | Database MCP server |
| hangwin/mcp-chrome | 17 | 10,395 | Browser automation integration |
| BeehiveInnovations/pal-mcp-server | 11 | 11,065 | Multi-model MCP server |

## Limitations

- Single snapshot in time; MCP ecosystem changes rapidly.
- Static analysis only - no runtime or behavioral checks.
- `compile()` false positives inflate exec-risk counts significantly.
- This merged run increases coverage but also increases noise; manual sampling is needed to estimate true positive rate by scanner/rule.
- Star count is a rough popularity proxy; download/install metrics would be better.
- One target (activepieces/activepieces) failed to clone due to path encoding issues.

## Responsible Disclosure

- All targets are public open-source repositories.
- No secret-like values from actual findings are included in this document.
- Evidence fields in the JSONL are truncated to 200 characters and contain only pattern match context.
- No exploit code or weaponized payloads are published.

## Next Steps

1. Fix `compile()` FP: distinguish `re.compile()` from builtin `compile()` in skill scanner AST analysis.
2. Run a stratified manual triage sample (by scanner + rule family) and publish measured precision/false-positive rate.
3. Split and publish scanner-specific breakdowns (agentsec/semgrep/gitleaks) for transparent comparability.
4. Re-run study quarterly to track ecosystem security posture over time.
5. Add weighted ranking formula (stars + recency + adoption signals).

## Artifacts

- Selection table: `docs/benchmarks/top50/data/top50_selection_20260215.csv`
- Findings JSONL: `docs/benchmarks/top50/reports/top50_findings_20260215.jsonl`
- Summary JSON: `docs/benchmarks/top50/reports/top50_summary_20260215.json`
- Repro script: `scripts/run_top50_study.py`
- PowerShell repro: `scripts/reproduce_top50_study.ps1`
