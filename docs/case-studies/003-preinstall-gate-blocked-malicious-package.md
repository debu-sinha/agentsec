# Case Study: Pre-Install Gate Blocks Known-Malicious Packages

- Date: 2026-02-16
- Environment type: Developer workstation (Windows 11, Python 3.14.2)
- Scope: gate (blocklist + download-and-scan)
- Tool version: agentsec 0.4.0

## Scenario

`agentsec gate` checks install targets before package installation. This case validates blocklist behavior for known-malicious package names and pass-through behavior for clean packages.

## Detection Summary

Seven packages tested - five blocked, two allowed:

| Package | Manager | Decision | Trigger | Time |
|---|---|---|---|---:|
| event-stream | npm | BLOCKED | Blocklist hit | 0.1 ms |
| crossenv | npm | BLOCKED | Blocklist hit | < 0.1 ms |
| flatmap-stream | npm | BLOCKED | Blocklist hit | < 0.1 ms |
| colourama | pip | BLOCKED | Blocklist hit | < 0.1 ms |
| noblesse | pip | BLOCKED | Blocklist hit | < 0.1 ms |
| express | npm | ALLOWED | Clean (npm not found -> non-blocking advisory finding) | ~5-20 ms |
| requests | pip | ALLOWED | Clean (downloaded + scanned, 0 findings) | ~5 s |

## Repro Commands

```bash
# Blocklist validation
python -c "
from agentsec.gate import gate_check
for pm,p in [('npm','event-stream'),('npm','crossenv'),('npm','flatmap-stream'),('pip','colourama'),('pip','noblesse')]:
    r = gate_check(pm, ['install', p])
    print(pm, p, r.allowed, r.blocklist_hit, len(r.findings))
"

# Clean package path
python -c "
from agentsec.gate import gate_check
r = gate_check('pip', ['install', 'requests'])
print(r.allowed, r.blocklist_hit, len(r.findings))
"

# CLI dry-run
agentsec gate --dry-run --fail-on critical npm install event-stream
```

## Artifacts

- Gate findings: `docs/case-studies/artifacts/case3-gate-findings.json`

## Notes

- Blocklist checks are effectively instant.
- npm clean-package scan behavior depends on `npm` availability in PATH; if unavailable, gate emits a non-blocking advisory finding.
