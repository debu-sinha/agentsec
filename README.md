<p align="center">
  <img src="https://raw.githubusercontent.com/debu-sinha/agentsec/main/docs/demo/screenshots/hero-banner.png" alt="agentsec — AI Agent Security Scanner" width="600">
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-blue.svg" alt="License"></a>
  <a href="https://www.python.org/"><img src="https://img.shields.io/badge/python-3.10%2B-blue.svg" alt="Python"></a>
  <a href="https://github.com/debu-sinha/agentsec/actions"><img src="https://img.shields.io/badge/tests-CI-brightgreen.svg" alt="Tests"></a>
  <a href="https://pypi.org/project/agentsec-ai/"><img src="https://img.shields.io/pypi/v/agentsec-ai.svg" alt="PyPI"></a>
  <a href="https://pypi.org/project/agentsec-ai/"><img src="https://img.shields.io/pypi/dm/agentsec-ai.svg" alt="Downloads"></a>
  <a href="https://genai.owasp.org/"><img src="https://img.shields.io/badge/OWASP-ASI01--ASI10-orange.svg" alt="OWASP"></a>
</p>

# agentsec

Security scanner and hardener for agentic AI installations.

agentsec focuses on practical misconfigurations and supply-chain risk in:
- OpenClaw installations
- MCP server configurations and code
- Agent skill/plugin ecosystems
- Credential exposure in local files

All findings map to the OWASP Top 10 for Agentic Applications (2026).

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
| `credential` | 17 secret patterns (OpenAI, Anthropic, AWS, GitHub, Slack, Stripe, etc.), high-entropy detection, git credential leakage |

Reference catalog:
- [checks-catalog.md](docs/checks-catalog.md) (27 named checks + dynamic credential findings)
- [CLI reference](docs/cli-reference.md) (full command/options guide)

## Core Commands

```bash
# Full scan
agentsec scan

# JSON output for CI
agentsec scan -o json -f report.json

# SARIF for GitHub Code Scanning
agentsec scan -o sarif -f results.sarif

# Run only selected scanners
agentsec scan -s installation,mcp

# Control CI failure threshold
agentsec scan --fail-on critical
```

```bash
# Hardening preview (default: preview only)
agentsec harden -p workstation

# Apply hardening profile
agentsec harden -p workstation --apply

# Watch mode
agentsec watch ~/.openclaw -i 2

# Pre-install security gate
agentsec gate npm install some-skill

# Generate shell hook for auto scan workflow
agentsec hook --shell zsh
```

List available scanners:

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
- `1-127`: count of findings at/above threshold (capped)
- `2`: runtime/usage error

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
      - uses: debu-sinha/agentsec@v0.4.1
        with:
          fail-on: high
          output: sarif
          upload-sarif: 'true'
```

Action definition:
- [action.yml](action.yml)

## Screenshots

Screenshots below focus on scan/harden flow. Gate and hook behavior are documented in the case studies and ADRs (`docs/case-studies/003-preinstall-gate-blocked-malicious-package.md`, `docs/adr/ADR-0004-pre-install-gate.md`).

### Step 1: Scan an insecure installation

<img src="https://raw.githubusercontent.com/debu-sinha/agentsec/main/docs/demo/screenshots/scan-before.png" alt="agentsec scan — insecure installation" width="900">

### Step 2: Apply hardening profile

<img src="https://raw.githubusercontent.com/debu-sinha/agentsec/main/docs/demo/screenshots/harden-apply.png" alt="agentsec harden — workstation profile applied" width="900">

### Step 3: Re-scan after hardening (14 findings remain — credentials need manual rotation)

<img src="https://raw.githubusercontent.com/debu-sinha/agentsec/main/docs/demo/screenshots/scan-after-findings.png" alt="agentsec scan — after hardening, findings view" width="900">

<img src="https://raw.githubusercontent.com/debu-sinha/agentsec/main/docs/demo/screenshots/scan-after-posture.png" alt="agentsec scan — after hardening, OWASP posture" width="900">

## Benchmarks and Studies

- [Fixture benchmark (v0.4.0, dated 2026-02-15)](docs/benchmarks/results/2026-02-15-v0.4.0.md)  
  Precision/recall/F1 over a 20-fixture suite.
- [Top-50 MCP study (snapshot 2026-02-16)](docs/benchmarks/2026-02-top50-mcp-security-study.md)  
  Agentsec-only repro run with normalized findings output.
- [Top-50 study kit](docs/benchmarks/top50/README.md)  
  Schema, selection CSV, JSONL findings, and summary JSON.

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

- [001: Insecure workstation remediation](docs/case-studies/001-insecure-openclaw-workstation.md)
- [002: Public bot hardening on VPS](docs/case-studies/002-public-bot-vps-hardening.md)
- [003: Pre-install gate blocked malicious package](docs/case-studies/003-preinstall-gate-blocked-malicious-package.md)
- [004: Malicious skill detection and block](docs/case-studies/004-malicious-skill-detection-and-block.md)

## Launch Evidence

- [Launch Evidence Manifest](docs/launch/LAUNCH_EVIDENCE_MANIFEST.md)
- [Reproducibility Spec](docs/launch/REPRODUCIBILITY_SPEC.md)

## Development

```bash
git clone https://github.com/debu-sinha/agentsec.git
cd agentsec
pip install -c requirements/constraints-dev.txt -e ".[dev]"
ruff check src tests
pytest
```

Contribution guide:
- [CONTRIBUTING.md](CONTRIBUTING.md)

Security policy:
- [SECURITY.md](SECURITY.md)

## Governance

- [Code of Conduct](CODE_OF_CONDUCT.md)
- [Security Policy](SECURITY.md)
- [Contribution Guide](CONTRIBUTING.md)

Issue intake is template-driven under `.github/ISSUE_TEMPLATE/` to keep triage and reproduction quality high.
## License

Apache-2.0





