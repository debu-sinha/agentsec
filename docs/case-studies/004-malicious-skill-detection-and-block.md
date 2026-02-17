# Case Study: Malicious Skill Detection and Pre-Install Block

- Date: 2026-02-16
- Environment type: OpenClaw skill ecosystem (developer workstation, Windows 11, Python 3.14.2)
- Scope: skill scanner (code analysis + instruction malware)
- Tool version: agentsec 0.4.0

## Scenario

Two malicious skills were planted in an OpenClaw agent's `skills/` directory alongside a benign skill. The first skill (`data-exporter`) contains credential-access and exfiltration patterns. The second skill (`quick-setup`) contains instruction-malware patterns (pipe-to-shell and remote script execution). A third skill (`hello-world`) is a clean control.

## Baseline Scan

```bash
agentsec scan /tmp/case4 -o json -f case4-results.json -s skill --fail-on none
```

- Total findings: **18** (4 critical, 10 high, 4 medium, 0 low, 0 info)
- Score: **5.0/100 (F)**
- Skill-level distribution:
  - `data-exporter`: 9 findings (2 critical, 3 high, 4 medium)
  - `quick-setup`: 9 findings (2 critical, 7 high)
  - `hello-world`: 0 findings

## Detection Summary

- `data-exporter` detections include:
  - base64 payload execution indicators
  - environment variable harvesting indicators
  - sensitive file-read targeting
  - reverse-shell pattern indicators
  - HTTP exfiltration indicators
  - unpinned dependency findings
- `quick-setup` detections include:
  - remote pipe-to-shell commands
  - PowerShell remote execution commands
  - credential path targeting
  - remote script-install references
  - instruction prompt-injection pattern

## False Positive Check

- Clean control skill `hello-world` produced **0 findings** in the same run set.

## Repro Commands

```bash
# Use the exact fixture creation commands in this file's prior revision,
# then run the skill-only scan:
agentsec scan /tmp/case4 -o json -f case4-results.json -s skill --fail-on none

# Clean control check
agentsec scan /tmp/case4-clean -o json -f case4-clean.json -s skill --fail-on none
```

## Artifacts

- Scan results: `docs/case-studies/artifacts/case4-scan-results.json`
