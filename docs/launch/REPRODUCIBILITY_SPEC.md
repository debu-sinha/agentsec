# Reproducibility Spec

Date: 2026-02-16

This repository's launch artifacts are reproducible with the following pinned environment:

- OS: Windows 11
- Python: 3.14.2
- agentsec: 0.4.0 (`python -m agentsec.cli --version`)
- pip: recent pip compatible with Python 3.14
- npm: required for npm package gate checks (`event-stream`, `express` paths)

## Canonical Repro Script

Run:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\reproduce_local_evidence.ps1
```

This script regenerates:

- `docs/case-studies/artifacts/case1-before.json`
- `docs/case-studies/artifacts/case1-after.json`
- `docs/case-studies/artifacts/case2-before.json`
- `docs/case-studies/artifacts/case2-after.json`
- `docs/case-studies/artifacts/case3-gate-findings.json`
- `docs/case-studies/artifacts/case4-scan-results.json`
- `docs/benchmarks/results/2026-02-15-v0.4.0.json`

## Notes

- If npm is unavailable, npm gate checks still run blocklist logic but clean-package npm download/scan paths will be advisory.
- On Windows, filesystem permission findings can remain after hardening due ACL semantics.
- Full pytest runs may require Developer Mode/admin privilege for symlink tests.
