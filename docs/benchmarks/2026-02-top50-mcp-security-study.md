# Top-50 MCP Security Study

- Study ID: `mcp-top50-2026-02`
- Snapshot date: `2026-02-15`
- Author(s): Debu Sinha
- Tool versions:
  - `agentsec`: `0.4.0`
  - `semgrep`: not run (future iteration)
  - `gitleaks`: not run (future iteration)

## Goal

Measure real-world security posture across the 50 most popular MCP servers using reproducible static analysis with agentsec.

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
3. Normalized all findings into JSONL per the `top50_finding.schema.json` schema.
4. Computed aggregate metrics.

Scan script: `scripts/run_top50_study.py`

## Key Metrics

| Metric | Value |
|---|---:|
| Targets in selection | 50 |
| Targets cloned successfully | 49 |
| Targets with critical or high findings | 48 (98%) |
| Critical findings | 71 |
| High findings | 172 |
| Medium findings | 53 |
| Low findings | 8 |
| Info findings | 48 |
| Total findings | 352 |
| Avg findings/target | 7.18 |
| Median scan time | 1.06 s |
| P95 scan time | 22.53 s |

## Top Recurring Findings

| Category | Count | Description |
|---|---:|---|
| Exec approvals missing | 48 | No exec-approvals.json - expected since these are standalone MCP servers, not OpenClaw installations |
| Version detection | 48 | Could not determine agent version (info-level, cosmetic) |
| Dangerous `compile()` calls | 99 | Regex compilation in Python skills flagged as dynamic code. Mostly false positives from `re.compile()` usage |
| Potential secrets | 111 | Token-like findings (76) + high-entropy strings (35) in docs, tests, and config examples |
| Prompt injection patterns | 5 | Instruction override or remote script references in skill descriptions |
| `getattr()` usage | 16 | Dynamic attribute access in plugin code |

## Analysis

**Expected noise (not actionable):**
- "Exec approvals file missing" fires on every non-OpenClaw repo (48/49). This is by design - the installation scanner checks for OpenClaw-specific config. In a real deployment, this check is meaningful.
- "Could not determine agent version" is info-level and cosmetic.
- `compile()` findings are regex compilation (`re.compile()`), not `compile()` for code execution. This is a known precision gap in the skill scanner's AST check that should be fixed in a future release.

**Actionable findings:**
- **Potential secrets in documentation and test files** (111 findings): Connection strings, API keys, and high-entropy tokens in README files and test data. Some are intentional examples, others may be real credentials committed accidentally.
- **Prompt injection patterns** (5 findings): Skill descriptions containing instruction override patterns or references to remote scripts. These are the highest-signal findings from a security perspective.
- **IBM/mcp-context-forge** (186 findings): This monorepo contains many bundled skills with Python code, triggering the skill scanner extensively. Most findings are `compile()` FPs.

**Precision considerations:**
- The `compile()` false positive is the single biggest precision issue. A fix to distinguish `re.compile()` from the builtin `compile()` would eliminate 99 findings.
- Excluding `compile()` and the two expected-noise categories, 157 findings remain. Manual triage is required to determine true actionable count.

## Targets by Finding Count (Top 10)

| Target | Findings | Stars | Notes |
|---|---:|---:|---|
| IBM/mcp-context-forge | 186 | 3,278 | Monorepo with many bundled skills |
| awslabs/mcp | 24 | 8,153 | Multi-server AWS MCP package |
| mindsdb/mindsdb | 21 | 38,478 | Large codebase, federated query engine |
| bytebase/dbhub | 17 | 2,117 | Database MCP server |
| BeehiveInnovations/pal-mcp-server | 9 | 11,065 | Multi-model MCP server |
| jlowin/fastmcp | 4 | 22,850 | FastMCP Python framework |
| steipete/Peekaboo | 4 | 2,110 | macOS screenshot MCP |
| microsoft/playwright-mcp | 3 | 27,181 | Browser automation MCP |
| wonderwhy-er/DesktopCommanderMCP | 3 | 5,466 | Desktop automation |
| aipotheosis-labs/aci | 3 | 4,713 | Tool-calling platform |

## Clean Target

- **AmoyLab/Unla**: 0 findings (MCP gateway, minimal code surface)

## Limitations

- Single snapshot in time; MCP ecosystem changes rapidly.
- Static analysis only - no runtime or behavioral checks.
- `compile()` false positives inflate exec_risk counts significantly.
- agentsec-only scan; semgrep and gitleaks would catch additional patterns (planned for next iteration).
- Star count is a rough popularity proxy; download/install metrics would be better.
- One target (activepieces/activepieces) failed to clone due to path encoding issues.

## Responsible Disclosure

- All targets are public open-source repositories.
- No secret-like values from actual findings are included in this document.
- Evidence fields in the JSONL are truncated to 200 characters and contain only pattern match context.
- No exploit code or weaponized payloads are published.

## Next Steps

1. Fix `compile()` FP: distinguish `re.compile()` from builtin `compile()` in skill scanner AST analysis.
2. Run semgrep + gitleaks as supplementary scanners for broader coverage.
3. Manual triage of the 157 post-noise findings (especially secrets + prompt injection).
4. Re-run study quarterly to track ecosystem security posture over time.
5. Add weighted ranking formula (stars + recency + adoption signals).

## Artifacts

- Selection table: `docs/benchmarks/top50/data/top50_selection_20260215.csv`
- Findings JSONL: `docs/benchmarks/top50/reports/top50_findings_20260215.jsonl`
- Summary JSON: `docs/benchmarks/top50/reports/top50_summary_20260215.json`
- Repro script: `scripts/run_top50_study.py`
- PowerShell repro: `scripts/reproduce_top50_study.ps1`
