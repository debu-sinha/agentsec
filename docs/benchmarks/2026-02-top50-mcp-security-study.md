# Top-50 MCP Security Study

- Study ID: `mcp-top50-2026-02`
- Snapshot date: `2026-02-17`
- Author(s): Debu Sinha
- Tool version:
  - `agentsec`: `0.4.2` (detect-secrets integration + FP hardening)

## Goal

Measure security posture across 50 popular MCP repositories using a reproducible, local-first scanner workflow.

## Scanner Changes (v0.4.2)

This study replaces the v0.4.0 baseline run (2026-02-15) which was retracted due to
high false positive rates in credential detection. Key changes:

- Credential scanner migrated from custom regex to Yelp's `detect-secrets` library
- 23 detection plugins with 11 heuristic filters for FP suppression
- Lock file exclusion (pnpm-lock.yaml, package-lock.json, yarn.lock, etc.)
- Connection string placeholder password detection (changeme, env vars, angle brackets)
- File-path context awareness: severity downgrade for test/doc/mock files
  - Python: `test_*.py`, `*_test.py`, `conftest.py`
  - JS/TS: `*.test.ts`, `*.spec.js`, etc.
  - Go: `*_test.go`
  - Mock/fixture files
  - All `.md`/`.rst` files, docker-compose, alembic.ini templates
- Sequential pattern detection for obviously fake keys
- Expanded placeholder password dictionary (37 common values)

The previous baseline (255 findings, 71 critical) was inflated by false positives:
AWS example keys, jwt.io canonical tokens, docker-compose placeholder passwords,
lock file integrity hashes, and test fixtures. Those data files have been removed.

## Scope

- In scope:
  - Public MCP server repositories selected from GitHub
  - Static scanning of repository contents with `agentsec`
- Out of scope:
  - Runtime or dynamic testing
  - Exploit development

## Data Sources

- Dashboard data: `docs/mcp-dashboard/data/findings_20260217.jsonl`
- Selection: `docs/mcp-dashboard/data/selection_20260217.csv`
- Summary: `docs/mcp-dashboard/data/summary_20260217.json`

## Key Metrics

| Metric | Value |
|---|---:|
| Targets in selection | 50 |
| Targets cloned | 48 |
| Targets with critical or high findings | 6 |
| Critical findings | 9 |
| High findings | 14 |
| Medium findings | 128 |
| Low findings | 395 |
| Info findings | 47 |
| Total findings | 593 |
| Avg findings/target | 12.35 |
| Median scan time | 2.66 s |
| P95 scan time | 58.21 s |

## Comparison with Retracted v0.4.0 Baseline

| Metric | v0.4.0 (retracted) | v0.4.2 (current) | Change |
|---|---:|---:|---|
| Critical | 71 | 9 | -87% (FP elimination) |
| High | 74 | 14 | -81% |
| Medium | 53 | 128 | +142% (KeywordDetector coverage) |
| Low | 8 | 395 | +4838% (test/doc/mock severity downgrade) |
| Total | 255 | 593 | +133% |
| Repos with critical/high | 49 | 6 | -88% |

The critical/high count dropped dramatically due to comprehensive FP suppression:
lock file exclusion, placeholder password detection, test/doc context awareness,
and sequential pattern filtering. Total findings increased because detect-secrets'
KeywordDetector catches legitimate patterns (password assignments, secret keywords)
that the old regex scanner missed, and test/doc findings are now downgraded to LOW
rather than suppressed entirely.

## Targets by Finding Count (Top 10)

| Target | Findings |
|---|---:|
| mindsdb/mindsdb | 175 |
| awslabs/mcp | 61 |
| jlowin/fastmcp | 34 |
| BeehiveInnovations/pal-mcp-server | 18 |
| aipotheosis-labs/aci | 17 |
| bytebase/dbhub | 14 |
| sooperset/mcp-atlassian | 10 |
| punkpeye/fastmcp | 9 |
| googleapis/genai-toolbox | 6 |

## Limitations

- This report is **agentsec-only**; semgrep/gitleaks were not used.
- Findings include scanner noise that requires manual triage.
- Static analysis only; no runtime reachability validation.
- Star-ranking is a rough popularity proxy and may bias sample composition.
- High finding counts in large repos (e.g. mindsdb) include test/example
  credentials downgraded to low severity.

## Responsible Disclosure

- All targets are public repositories.
- No exploit payloads are included.
- Credential evidence is redacted (first 4 + last 4 characters only).
- JSONL evidence should still be manually reviewed before publication.

## Artifacts

- Dashboard: `docs/mcp-security-grades.md`
- Findings: `docs/mcp-dashboard/data/findings_20260217.jsonl`
- Selection: `docs/mcp-dashboard/data/selection_20260217.csv`
- Summary: `docs/mcp-dashboard/data/summary_20260217.json`
- Repro scripts:
  - `scripts/generate_mcp_dashboard.py --scan`
  - `scripts/run_top50_study.py`
  - `scripts/reproduce_top50_study.ps1`
