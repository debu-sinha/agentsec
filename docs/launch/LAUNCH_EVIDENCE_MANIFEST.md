# Launch Evidence Manifest (v0.4.0)

Date: 2026-02-16  
Purpose: claim-to-artifact map for launch review and external evidence checks.

## Product Claims Backed by Repository Artifacts

| Claim | Evidence | Status |
|---|---|---|
| 27 named checks are implemented | `docs/checks-catalog.md` | Verified |
| Fixture benchmark quality is P=0.82 / R=1.00 / F1=0.90 | `docs/benchmarks/results/2026-02-15-v0.4.0.json` (`aggregate`) and `docs/benchmarks/results/2026-02-15-v0.4.0.md` | Verified |
| Top-50 MCP study scanned 50 targets with 49 having critical/high findings | `docs/benchmarks/top50/reports/top50_summary_20260215.json` | Verified |
| Case study 001 metrics are reproducibly documented | `docs/case-studies/001-insecure-openclaw-workstation.md`, `docs/case-studies/artifacts/case1-before.json`, `docs/case-studies/artifacts/case1-after.json` | Verified |
| Case study 002 metrics are reproducibly documented | `docs/case-studies/002-public-bot-vps-hardening.md`, `docs/case-studies/artifacts/case2-before.json`, `docs/case-studies/artifacts/case2-after.json` | Verified |
| Pre-install gate blocks known malicious packages | `src/agentsec/gate.py`, `tests/unit/test_gate.py` | Verified |
| Findings map to OWASP ASI01-ASI10 | `docs/checks-catalog.md`, `src/agentsec/analyzers/owasp_scorer.py` | Verified |

## Repro Commands

```bash
# Consistency checks (docs vs artifacts)
python scripts/repo_consistency_audit.py

# Benchmark fixture suite
python docs/benchmarks/run_benchmark.py

# Top-50 study pipeline
powershell -ExecutionPolicy Bypass -File scripts\reproduce_top50_study.ps1 -DateStamp 20260215

# Gate behavior check
python -m agentsec.cli gate --dry-run npm install event-stream
```

## Known Environment Caveat

- On this Windows 11 / Python 3.14.2 environment, full `pytest` runs terminate with a `PermissionError` during pytest temp-dir cleanup (`cleanup_dead_symlinks`).  
- This affects local launch-gate reliability for the full test run in this environment and should be resolved or documented in CI release criteria.
