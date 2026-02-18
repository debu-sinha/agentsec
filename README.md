<p align="center">
  <img src="https://raw.githubusercontent.com/debu-sinha/agentsec/main/docs/demo/screenshots/hero-banner.png" alt="agentsec - AI Agent Security Scanner" width="600">
</p>

<p align="center">
  <a href="https://github.com/debu-sinha/agentsec/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-blue.svg" alt="License"></a>
  <a href="https://www.python.org/"><img src="https://img.shields.io/badge/python-3.10%2B-blue.svg" alt="Python"></a>
  <a href="https://github.com/debu-sinha/agentsec/actions/workflows/ci.yml"><img src="https://github.com/debu-sinha/agentsec/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://pypi.org/project/agentsec-ai/"><img src="https://img.shields.io/pypi/v/agentsec-ai.svg" alt="PyPI"></a>
  <a href="https://pypi.org/project/agentsec-ai/"><img src="https://img.shields.io/pypi/dm/agentsec-ai.svg" alt="Downloads"></a>
  <a href="https://genai.owasp.org/"><img src="https://img.shields.io/badge/OWASP-ASI01--ASI10-orange.svg" alt="OWASP"></a>
</p>

# agentsec

**Static configuration scanner and hardener for AI agent installations.** Detects misconfigurations, credential leaks, supply-chain risks, and MCP tool poisoning — then maps every finding to the [OWASP Top 10 for Agentic Applications (2026)](https://genai.owasp.org/).

Supports OpenClaw, Claude Code, Cursor, Windsurf, Gemini CLI, and MCP server ecosystems.

> **Scope:** agentsec performs static configuration and file analysis. It does not provide runtime protection, behavioral monitoring, or real-time threat detection. Use as one layer in a defense-in-depth strategy.

## Quick Start

```bash
pip install agentsec-ai
agentsec scan
```

Scan a specific installation:

```bash
agentsec scan ~/.openclaw
```

## What agentsec checks

| Module | Scope |
|---|---|
| `installation` | Gateway exposure, auth posture, DM/group policy, tool/sandbox settings, SSRF and safety checks, known CVE version checks, sensitive file/dir permissions |
| `skill` | Instruction malware, risky code patterns (`eval/exec/subprocess`), prompt-injection patterns, frontmatter capability risk, dependency/install-hook risk |
| `mcp` | Tool poisoning patterns, auth gaps on remote endpoints, dangerous schema/permissions, unverified `npx` usage |
| `credential` | detect-secrets engine (23 plugins) + 11 custom patterns (OpenAI, Anthropic, AWS, Databricks, HuggingFace, etc.), high-entropy detection, git credential leakage |

Reference catalog:
- [Checks Catalog](https://github.com/debu-sinha/agentsec/blob/main/docs/checks-catalog.md) (27 named checks + dynamic credential findings)
- [CLI Reference](https://github.com/debu-sinha/agentsec/blob/main/docs/cli-reference.md) (full command/options guide)

## Core Commands

```bash
# Full installation scan (all scanners, default target=. )
agentsec scan

# JSON report for CI parsing and pipelines
agentsec scan -o json -f report.json

# SARIF output for GitHub code scanning upload
agentsec scan -o sarif -f results.sarif

# Run only selected scanners for focused checks
agentsec scan -s installation,mcp

# Fail build only at/above selected severity
agentsec scan --fail-on critical
```

```bash
# Preview profile changes without writing config
agentsec harden -p workstation

# Apply profile and write hardened config values
agentsec harden -p workstation --apply

# Watch files and auto re-scan on security-relevant changes
agentsec watch ~/.openclaw -i 2

# Pre-install package gate (scan before install)
agentsec gate npm install express

# Pin MCP tool descriptions for rug-pull detection
agentsec pin-tools

# Generate shell hook wrappers for npm/pip install flows
agentsec hook --shell zsh
```

List available scanners (names + descriptions):

```bash
agentsec list-scanners
```

## Hardening Profiles

| Profile | Intended use |
|---|---|
| `workstation` | Single-owner local usage |
| `vps` | Remote/self-hosted deployment |
| `public-bot` | Highest restriction for untrusted public input |

Use `agentsec show-profile <name>` to inspect exact changes before applying.

## Output and Exit Codes

Output formats:
- `terminal` (default)
- `json`
- `sarif`

Exit codes:
- `0`: no findings at/above threshold
- `1`: findings found at/above threshold
- `2`: usage error (e.g., unknown scanner name)
- `3`: runtime error (e.g., file access failure)

## GitHub Actions

Use the bundled composite action:

```yaml
name: Agent Security
on: [push, pull_request]

jobs:
  agentsec:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@v4
      - uses: debu-sinha/agentsec@v0.4.4
        with:
          fail-on: high
          output: sarif
          upload-sarif: 'true'
```

Action definition:
- [action.yml](https://github.com/debu-sinha/agentsec/blob/main/action.yml)

## Screenshots

Screenshots below show the experimental demo sandbox flow (intentionally insecure configuration for detection and hardening demonstration). Gate and hook behavior are documented in `docs/case-studies/003-preinstall-gate-blocked-malicious-package.md` and `docs/adr/ADR-0004-pre-install-gate.md`.

### Step 1: Initial scan on intentionally insecure demo config

![agentsec scan - intentionally insecure demo config](https://raw.githubusercontent.com/debu-sinha/agentsec/main/docs/demo/screenshots/scan-before.png)

### Step 2: Apply workstation hardening profile

![agentsec harden - workstation profile applied](https://raw.githubusercontent.com/debu-sinha/agentsec/main/docs/demo/screenshots/harden-apply.png)

### Step 3: Re-scan findings after hardening

![agentsec scan - post-hardening findings](https://raw.githubusercontent.com/debu-sinha/agentsec/main/docs/demo/screenshots/scan-after-findings.png)

### Step 4: OWASP posture view after hardening

![agentsec scan - OWASP posture after hardening](https://raw.githubusercontent.com/debu-sinha/agentsec/main/docs/demo/screenshots/scan-after-posture.png)

## MCP Ecosystem Security Dashboard

Weekly automated security scan of the top 50 MCP server repositories, graded A through F.

[![Ecosystem Grade](https://img.shields.io/badge/Ecosystem_Grade-B-green?style=flat-square)](https://github.com/debu-sinha/agentsec/blob/main/docs/mcp-security-grades.md) [![Repos Scanned](https://img.shields.io/badge/Repos_Scanned-50-blue?style=flat-square)](https://github.com/debu-sinha/agentsec/blob/main/docs/mcp-security-grades.md)

**[View the full dashboard](https://github.com/debu-sinha/agentsec/blob/main/docs/mcp-security-grades.md)** - updated every Monday via GitHub Actions.

## Benchmarks and Studies

- [Fixture benchmark](https://github.com/debu-sinha/agentsec/blob/main/docs/benchmarks/results/2026-02-15-v0.4.0.md) — precision/recall/F1 over a 20-fixture suite (self-authored fixtures, not independently validated).
- [Top-50 MCP study](https://github.com/debu-sinha/agentsec/blob/main/docs/benchmarks/2026-02-top50-mcp-security-study.md) — agentsec-only repro run with normalized findings output.
- [Top-50 study kit](https://github.com/debu-sinha/agentsec/blob/main/docs/benchmarks/top50/README.md) — schema, selection CSV, JSONL findings, and summary JSON.

Current checked-in Top-50 summary data:
- `docs/benchmarks/top50/reports/top50_summary_20260215.json`
- `docs/benchmarks/top50/reports/top50_findings_20260215.jsonl`

## Reproducibility

Fixture benchmark:

```bash
python docs/benchmarks/run_benchmark.py
```

Top-50 study repro:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\reproduce_top50_study.ps1 -DateStamp 20260215
```

Note: semgrep and gitleaks baseline runs are optional in the PowerShell repro script and require those tools on PATH.

Adversarial consistency audit (docs vs artifacts):

```bash
python scripts/repo_consistency_audit.py
```

## Case Studies

- [001: Insecure workstation remediation](https://github.com/debu-sinha/agentsec/blob/main/docs/case-studies/001-insecure-openclaw-workstation.md)
- [002: Public bot hardening on VPS](https://github.com/debu-sinha/agentsec/blob/main/docs/case-studies/002-public-bot-vps-hardening.md)
- [003: Pre-install gate blocked malicious package](https://github.com/debu-sinha/agentsec/blob/main/docs/case-studies/003-preinstall-gate-blocked-malicious-package.md)
- [004: Malicious skill detection and block](https://github.com/debu-sinha/agentsec/blob/main/docs/case-studies/004-malicious-skill-detection-and-block.md)

## Launch Evidence

- [Launch Evidence Manifest](https://github.com/debu-sinha/agentsec/blob/main/docs/launch/LAUNCH_EVIDENCE_MANIFEST.md)
- [Reproducibility Spec](https://github.com/debu-sinha/agentsec/blob/main/docs/launch/REPRODUCIBILITY_SPEC.md)

## Development

```bash
git clone https://github.com/debu-sinha/agentsec.git
cd agentsec
pip install -c requirements/constraints-dev.txt -e ".[dev]"
ruff check src tests
pytest
```

Contribution guide:
- [CONTRIBUTING.md](https://github.com/debu-sinha/agentsec/blob/main/CONTRIBUTING.md)

Security policy:
- [SECURITY.md](https://github.com/debu-sinha/agentsec/blob/main/SECURITY.md)

## Governance

- [Code of Conduct](https://github.com/debu-sinha/agentsec/blob/main/CODE_OF_CONDUCT.md)
- [Security Policy](https://github.com/debu-sinha/agentsec/blob/main/SECURITY.md)
- [Contribution Guide](https://github.com/debu-sinha/agentsec/blob/main/CONTRIBUTING.md)

Issue intake is template-driven under `.github/ISSUE_TEMPLATE/` to keep triage and reproduction quality high.
## License

Apache-2.0








