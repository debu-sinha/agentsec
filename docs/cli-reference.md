# CLI Reference

This document is the command-level reference for `agentsec`.

## Install

```bash
# Install agentsec CLI from PyPI
pip install agentsec-ai
```

## Global Help and Version

```bash
# Show all commands, options, and workflow order
agentsec --help

# Print installed agentsec version
agentsec --version
```

## Command Overview

- `scan` - run security scan and generate terminal/JSON/SARIF output.
- `harden` - preview or apply hardening profiles to config.
- `gate` - pre-install security checks for npm/pip packages.
- `watch` - watch files and re-scan on relevant changes.
- `show-profile` - inspect profile changes before hardening.
- `hook` - generate shell wrappers for auto post-install scans.
- `pin-tools` - pin MCP tool descriptions for rug-pull detection.
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
# Scan current directory for all supported risk categories
agentsec scan

# Scan a specific OpenClaw installation path
agentsec scan ~/.openclaw

# Generate machine-readable JSON for CI parsing or pipelines
agentsec scan -o json -f report.json

# Generate SARIF for GitHub code scanning integrations
agentsec scan -o sarif -f results.sarif

# Run only selected scanners and fail build on critical findings
agentsec scan -s installation,mcp --fail-on critical
```

Exit codes:

- `0`: no findings at/above threshold
- `1`: findings found at/above threshold
- `2`: usage error (e.g., unknown scanner name)
- `3`: runtime error (e.g., file access failure)

## list-scanners

```bash
# List scanner modules and descriptions before selective runs
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
# Preview workstation-safe config changes without writing files
agentsec harden -p workstation

# Apply VPS profile for remote-hosted agent hardening
agentsec harden ~/.openclaw -p vps --apply

# Apply strict profile for public, untrusted-input bots
agentsec harden ~/.openclaw -p public-bot --apply
```

Notes:

- `harden` only changes configuration files.
- It does not rotate secrets or patch vulnerable dependencies.

## show-profile

Show exact changes a profile would apply.

```bash
# Inspect exact keys/values that a profile will change
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
# Watch current directory for security-relevant changes
agentsec watch

# Watch a specific installation and auto re-scan on updates
agentsec watch ~/.openclaw

# Reduce scan frequency for lower overhead environments
agentsec watch ~/.openclaw -i 5
```

## hook

Generate shell hooks that wrap npm/pip install workflows.

```bash
# Generate zsh wrapper functions for auto post-install scanning
agentsec hook --shell zsh

# Generate bash wrapper functions for the same workflow
agentsec hook --shell bash
```

Use in shell profile:

```bash
# Activate generated shell hook in current shell session
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
# Pre-scan npm package before install; block on critical findings
agentsec gate npm install express

# Pre-scan pip package before install
agentsec gate pip install requests

# Enforce stricter policy: block on high and above
agentsec gate --fail-on high npm install express

# Simulate gate decision without executing real install
agentsec gate --dry-run npm install event-stream
```

Behavior summary:

- Blocks immediately on known-malicious blocklist hits.
- Blocks findings at/above `--fail-on` unless `--force` is used.
- If allowed and not dry-run, executes the real package-manager command.

## pin-tools

Pin MCP tool descriptions to detect rug-pull attacks (tool description drift).

```bash
agentsec pin-tools [TARGET]
```

Creates or updates `.agentsec-pins.json` with SHA-256 hashes of current tool descriptions. Subsequent scans compare live descriptions against pinned hashes and flag changes.

Examples:

```bash
# Pin tool descriptions in current directory
agentsec pin-tools

# Pin tools for a specific installation
agentsec pin-tools ~/.openclaw
```

Findings produced on drift:

- **Description changed** (HIGH): tool description differs from pinned hash.
- **Tool removed** (MEDIUM): a previously pinned tool is no longer present.

## JSON and SARIF

JSON for automation:

```bash
# Persist findings/posture in JSON for automation workflows
agentsec scan -o json -f report.json
```

SARIF for GitHub Code Scanning:

```bash
# Persist SARIF for upload to GitHub security dashboards
agentsec scan -o sarif -f results.sarif
```

## Troubleshooting

- Unknown scanner name: run `agentsec list-scanners`.
- Permission errors: run scan on a readable path.
- npm not available: gate npm download-scan paths become advisory.
- Windows symlink tests may require Developer Mode/admin privilege.
