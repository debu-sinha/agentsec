# Case Study: Pre-Install Gate Blocks Known-Malicious Packages

- Date: 2026-02-15
- Environment type: Developer workstation (Windows 11, Python 3.14.2)
- Scope: gate (blocklist + download-and-scan)
- Tool version: agentsec 0.4.0

## Scenario

A developer runs `npm install` or `pip install` for a package that is either typosquatting a popular library or is a known supply-chain attack vector. `agentsec gate` intercepts the install, checks the package name against a curated blocklist, and blocks the operation before any code executes on the developer's machine.

This case study tests five known-malicious packages across npm and pip, plus two legitimate packages (express, requests) to confirm they pass through without false blocks.

## Commands Executed

```bash
# Blocklist check (Python API - no network needed)
python -c "
from agentsec.gate import gate_check
r = gate_check('npm', ['install', 'event-stream'])
print(f'Allowed: {r.allowed}, Blocklist: {r.blocklist_hit}')
print(f'Findings: {[f.title for f in r.findings]}')
"

# CLI dry-run equivalent
agentsec gate --dry-run --fail-on critical npm install event-stream
```

## Detection Summary

Seven packages tested - five blocked, two allowed:

| Package | Manager | Decision | Trigger | Time |
|---|---|---|---|---:|
| event-stream | npm | BLOCKED | Blocklist hit | 0.2 ms |
| crossenv | npm | BLOCKED | Blocklist hit | < 0.1 ms |
| flatmap-stream | npm | BLOCKED | Blocklist hit | < 0.1 ms |
| colourama | pip | BLOCKED | Blocklist hit | < 0.1 ms |
| noblesse | pip | BLOCKED | Blocklist hit | 0.1 ms |
| express | npm | ALLOWED | Clean (no blocklist match) | 10.7 ms |
| requests | pip | ALLOWED | Clean (downloaded + scanned, 0 findings) | 29.7 s |

All five malicious packages produced a single CRITICAL finding each:

- `event-stream`: "Blocked package: event-stream" (backdoored via flatmap-stream dependency, 2018)
- `crossenv`: "Blocked package: crossenv" (typosquatting cross-env, credential exfiltration)
- `flatmap-stream`: "Blocked package: flatmap-stream" (payload that targeted copay bitcoin wallet)
- `colourama`: "Blocked package: colourama" (typosquatting colorama, clipboard hijack)
- `noblesse`: "Blocked package: noblesse" (Discord token stealer + credential harvester)

## Why They Were Blocked

- Triggered control: **Blocklist match** - package name found in `_KNOWN_BAD_NPM` or `_KNOWN_BAD_PIP` sets compiled from npm advisories, Phylum, Socket.dev, and Checkmarx supply-chain research
- Risk explanation: These packages have documented histories of credential theft, backdoor injection, or clipboard hijacking. Installing them executes attacker-controlled code during `npm install` hooks or `pip setup.py`

## Business Impact

| Metric | Value |
|---|---:|
| Risky installs prevented | 5 |
| Time to verdict (blocklist) | < 1 ms |
| Time to verdict (full scan) | ~30 s |
| Manual review time saved | 2-4 hours per package |
| Potential blast radius avoided | Credential theft, supply-chain compromise |

Blocklist checks are effectively instant (sub-millisecond). The full download-and-scan path for clean packages takes longer (~30s for pip download + extraction + scanner execution) but only runs when the package is not on the blocklist.

## False Positive Check

Both legitimate packages passed through correctly:
- **express** (npm): Allowed. npm pack was unavailable in the test environment, so the scan produced a non-blocking advisory. On a system with npm installed, this would download, extract, and scan the tarball.
- **requests** (pip): Allowed. Package was downloaded, extracted, and scanned by skill + MCP scanners. Zero findings - no false block.

## Follow-Up Actions

1. Integrate `agentsec gate` as a pre-install hook in CI pipelines
2. Add the `--fail-on high` flag to catch packages with risky install hooks (not just blocklist hits)
3. Monitor for new supply-chain advisories and update the blocklist via `agentsec` releases
4. For pip packages not on the blocklist, the full download-and-scan path catches install hooks, dangerous imports, and MCP tool poisoning patterns

## Repro Commands

```bash
# Quick blocklist validation (no network)
python -c "
from agentsec.gate import gate_check
for pm, pkg in [('npm','event-stream'), ('npm','crossenv'), ('pip','colourama'), ('pip','noblesse')]:
    r = gate_check(pm, ['install', pkg])
    status = 'BLOCKED' if not r.allowed else 'ALLOWED'
    print(f'{pkg:20s} {pm:4s} {status}  blocklist={r.blocklist_hit}')
"

# Full scan of a clean package (requires pip)
python -c "
from agentsec.gate import gate_check
r = gate_check('pip', ['install', 'requests'])
print(f'Allowed: {r.allowed}, Findings: {len(r.findings)}')
"

# CLI usage
agentsec gate --dry-run --fail-on critical npm install event-stream
agentsec gate --dry-run --fail-on high pip install requests
```

## Artifacts

- Raw gate results: reproducible via repro commands above
- Blocklist source: `src/agentsec/gate.py` lines 31-81

## Notes

- All package names in this case study are publicly documented malicious packages with published advisories. No coordinated disclosure concerns.
- Blocklist timing excludes Python import overhead (first call includes module loading). Subsequent calls are sub-millisecond.
- The `requests` scan time (29.7s) includes pip download over the network. In CI with a package cache, this drops significantly.
