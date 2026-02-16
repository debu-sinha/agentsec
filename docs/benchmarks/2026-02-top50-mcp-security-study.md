# Top-50 MCP Security Study (Agentsec-Only Repro Run)

- Study ID: `mcp-top50-2026-02`
- Snapshot date: `2026-02-16`
- Author(s): Debu Sinha
- Tool version:
  - `agentsec`: `0.4.0`
- Repro mode:
  - `scripts/reproduce_top50_study.ps1 -DateStamp 20260215 -SkipSemgrep -SkipGitleaks`

## Goal

Measure security posture across 50 popular MCP repositories using a reproducible, local-first scanner workflow.

This document reflects the current checked-in **agentsec-only** repro output (semgrep and gitleaks are intentionally skipped in this run).

## Scope

- In scope:
  - Public MCP server repositories selected from GitHub
  - Static scanning of repository contents with `agentsec`
- Out of scope:
  - Runtime or dynamic testing
  - Exploit development
  - semgrep/gitleaks merged analysis in this specific run profile

## Data Sources

- Selection input: `docs/benchmarks/top50/data/top50_selection_20260215.csv`
- Findings output: `docs/benchmarks/top50/reports/top50_findings_20260215.jsonl`
- Summary output: `docs/benchmarks/top50/reports/top50_summary_20260215.json`

## Execution

1. Load the Top-50 selection CSV.
2. Clone each repository shallow (`--depth 1`).
3. Run `agentsec scan <target> -o json --fail-on none --quiet`.
4. Normalize findings into JSONL.
5. Compute aggregate summary metrics.

Repro command:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\reproduce_top50_study.ps1 -DateStamp 20260215 -SkipSemgrep -SkipGitleaks
```

## Key Metrics

| Metric | Value |
|---|---:|
| Targets in selection | 50 |
| Targets with critical or high findings | 49 |
| Critical findings | 71 |
| High findings | 74 |
| Medium findings | 53 |
| Low findings | 8 |
| Info findings | 49 |
| Total findings | 255 |
| Avg findings/target | 5.1 |
| Median scan time | 0.6989 s |
| P95 scan time | 7.8058 s |

## Scanner Mix

| Scanner | Findings |
|---|---:|
| agentsec | 255 |

## Top Recurring Categories

| Category | Count |
|---|---:|
| `exposed_token` | 78 |
| `outdated_version` | 49 |
| `insecure_default` | 49 |
| `plaintext_secret` | 38 |
| `dangerous_pattern` | 25 |
| `data_exfiltration_risk` | 5 |
| `prompt_injection_vector` | 5 |
| `config_drift` | 4 |

## Targets by Finding Count (Top 10)

| Target | Findings |
|---|---:|
| IBM/mcp-context-forge | 87 |
| awslabs/mcp | 24 |
| mindsdb/mindsdb | 21 |
| bytebase/dbhub | 17 |
| BeehiveInnovations/pal-mcp-server | 9 |
| jlowin/fastmcp | 4 |
| steipete/Peekaboo | 4 |
| microsoft/playwright-mcp | 3 |
| wonderwhy-er/DesktopCommanderMCP | 3 |
| aipotheosis-labs/aci | 3 |

## Limitations

- This report is **agentsec-only**; semgrep/gitleaks were skipped.
- Findings include scanner noise that requires manual triage.
- Static analysis only; no runtime reachability validation.
- Star-ranking is a rough popularity proxy and may bias sample composition.
- Some repos have checkout/ref issues on Windows, which can affect per-target depth.

## Responsible Disclosure

- All targets are public repositories.
- No exploit payloads are included.
- JSONL evidence is normalized for analysis and should still be manually reviewed before publication.

## Next Steps

1. Add semgrep and gitleaks into the PowerShell repro script (currently placeholders).
2. Emit explicit `targets_cloned_successfully` in summary output.
3. Add a manual triage sample and report measured false-positive rate.
4. Publish scanner-specific precision estimates by category/rule family.

## Artifacts

- Selection CSV: `docs/benchmarks/top50/data/top50_selection_20260215.csv`
- Findings JSONL: `docs/benchmarks/top50/reports/top50_findings_20260215.jsonl`
- Summary JSON: `docs/benchmarks/top50/reports/top50_summary_20260215.json`
- Repro scripts:
  - `scripts/run_top50_study.py`
  - `scripts/reproduce_top50_study.ps1`
