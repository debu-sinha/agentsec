# agentsec Demo Sandbox

Scan a real OpenClaw installation with deliberately insecure configuration.
Captures before/after screenshots for the project README.

## What This Does

The Docker image installs **real OpenClaw** (pinned to `2026.2.12` for
reproducibility) and applies an insecure configuration on top:

- Gateway bound to `0.0.0.0` (network-exposed)
- Open DM and group policies (no access control)
- Sandbox disabled, full tool access
- Plaintext API keys in `.env` (OpenAI, Anthropic, AWS, GitHub, Slack)
- Untrusted skills with `subprocess` calls and credential path access
- MCP server with hardcoded API key in config

agentsec detects all of these as security findings mapped to the OWASP
Top 10 for Agentic Applications.

## Quick Start

```bash
# Build from local source (run from repo root, --no-cache ensures fresh OpenClaw install)
docker build --no-cache -f docs/demo/Dockerfile.dev -t agentsec-demo .

# Launch the sandbox
docker run -it --rm agentsec-demo
```

To pin a different OpenClaw version:

```bash
docker build --no-cache -f docs/demo/Dockerfile.dev \
  --build-arg OPENCLAW_VERSION=2026.2.15 \
  -t agentsec-demo .
```

## Inside the Container

### Step 1: BEFORE scan (insecure installation)

```bash
agentsec scan ~
```

You should see findings across all 4 scanners (installation, skill, MCP,
credential) with a low security grade.

### Step 2: Harden

```bash
# Preview what will change
agentsec harden ~ -p workstation

# Apply hardening
agentsec harden ~ -p workstation --apply
```

### Step 3: AFTER scan (hardened installation)

```bash
agentsec scan ~
```

Configuration findings are fixed. Credential and skill findings remain
(hardening only fixes config — secrets must be moved to a keychain or
secrets manager manually).

## Export Reports

```bash
# JSON report
agentsec scan ~ -o json -f /tmp/report.json

# SARIF for GitHub Code Scanning
agentsec scan ~ -o sarif -f /tmp/results.sarif

# Full before/after HTML report
python /opt/agentsec-src/docs/demo/render_report.py
```

## Copy Files Out

```bash
# From host, while container is running:
docker cp <container_id>:/home/testuser/agentsec_report.html ./docs/demo/screenshots/
```
