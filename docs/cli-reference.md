# CLI Reference

This document is the command-level reference for `agentsec`.

## Install

```bash
pip install agentsec-ai
```

## Global Help and Version

```bash
agentsec --help
agentsec --version
```

## Command Overview

- `scan` - run security scan and generate terminal/JSON/SARIF output.
- `harden` - preview or apply hardening profiles to config.
- `gate` - pre-install security checks for npm/pip packages.
- `watch` - watch files and re-scan on relevant changes.
- `show-profile` - inspect profile changes before hardening.
- `hook` - generate shell wrappers for auto post-install scans.
- `list-scanners` - show available scanner modules.

## scan

Scan an installation path (default: current directory).

```bash
agentsec scan [TARGET]
```

Options:

- `-o, --output terminal|json|sarif` (default: `terminal`)
- `-f, --output-file <path>`
- `-s, --scanners <csv>` (example: `installation,mcp`)
- `--fail-on critical|high|medium|low|info|none` (default: `high`)
- `-v, --verbose`
- `-q, --quiet`

Examples:

```bash
agentsec scan
agentsec scan ~/.openclaw
agentsec scan -o json -f report.json
agentsec scan -o sarif -f results.sarif
agentsec scan -s installation,mcp --fail-on critical
```

Exit codes:

- `0`: no findings at/above threshold
- `1-127`: number of findings at/above threshold (capped)
- `2`: usage/runtime error

## list-scanners

```bash
agentsec list-scanners
```

Shows scanner names and descriptions.

## harden

Preview or apply profile-based hardening.

```bash
agentsec harden [TARGET] -p workstation|vps|public-bot [--apply]
```

Options:

- `-p, --profile workstation|vps|public-bot` (required)
- `--apply` (default is preview/dry run)
- `-v, --verbose`

Examples:

```bash
agentsec harden -p workstation
agentsec harden ~/.openclaw -p vps --apply
agentsec harden ~/.openclaw -p public-bot --apply
```

Notes:

- `harden` only changes configuration files.
- It does not rotate secrets or patch vulnerable dependencies.

## show-profile

Show exact changes a profile would apply.

```bash
agentsec show-profile workstation
```

Accepted profiles:

- `workstation`
- `vps`
- `public-bot`

## watch

Watch installation files and re-scan on security-relevant changes.

```bash
agentsec watch [TARGET] [-i SECONDS]
```

Options:

- `-i, --interval <seconds>` (default: `2.0`)
- `-v, --verbose`

Examples:

```bash
agentsec watch
agentsec watch ~/.openclaw
agentsec watch ~/.openclaw -i 5
```

## hook

Generate shell hooks that wrap npm/pip install workflows.

```bash
agentsec hook --shell zsh
agentsec hook --shell bash
```

Use in shell profile:

```bash
eval "$(agentsec hook --shell zsh)"
```

## gate

Pre-install security gate for npm/pip installs.

```bash
agentsec gate [--fail-on LEVEL] [--force] [--dry-run] <npm|pip|pip3> install <package>
```

Options:

- `--fail-on critical|high|medium|low|info` (default: `critical`)
- `--force` (allow install despite findings)
- `--dry-run` (scan without running install)

Examples:

```bash
agentsec gate npm install some-skill
agentsec gate pip install some-mcp-server
agentsec gate --fail-on high npm install some-skill
agentsec gate --dry-run npm install event-stream
```

Behavior summary:

- Blocks immediately on known-malicious blocklist hits.
- Blocks findings at/above `--fail-on` unless `--force` is used.
- If allowed and not dry-run, executes the real package-manager command.

## JSON and SARIF

JSON for automation:

```bash
agentsec scan -o json -f report.json
```

SARIF for GitHub Code Scanning:

```bash
agentsec scan -o sarif -f results.sarif
```

## Troubleshooting

- Unknown scanner name: run `agentsec list-scanners`.
- Permission errors: run scan on a readable path.
- npm not available: gate npm download-scan paths become advisory.
- Windows symlink tests may require Developer Mode/admin privilege.
