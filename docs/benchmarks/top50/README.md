# Top-50 MCP Study Kit

This folder contains data, schemas, and reports for the Top-50 MCP security study.

## Layout

- `schema/top50_finding.schema.json` - JSON Schema for normalized findings
- `data/top50_selection_YYYYMMDD.csv` - selected top 50 targets with ranking
- `reports/top50_findings_YYYYMMDD.jsonl` - normalized per-finding output
- `reports/top50_summary_YYYYMMDD.json` - aggregated metrics

## Current Snapshot

- **2026-02-16**: 50 targets, 255 findings in the current agentsec-only repro run (`-SkipSemgrep -SkipGitleaks`). See `../2026-02-top50-mcp-security-study.md` for full analysis.

## Quick Start

1. Run `python scripts/run_top50_study.py` (full study path with agentsec + optional semgrep/gitleaks integration in that script).
2. Or populate `data/` manually and run `scripts/reproduce_top50_study.ps1` (PowerShell reproducibility path with agentsec and optional semgrep/gitleaks when installed).
3. Review results in `../2026-02-top50-mcp-security-study.md`.

## Safety

- Redact all local paths and token-like strings before publishing.
- Do not run intrusive network testing against production endpoints.
- Findings with `confidence: needs_review` require manual triage before publication.

