# agentsec Demo Sandbox

Run agentsec against a real OpenClaw installation inside Docker.

## Quick Start

```bash
docker build -t agentsec-demo .
docker run -it --rm agentsec-demo
```

## Inside the Container

```bash
# Scan the installation
agentsec scan ~ --verbose

# Preview hardening changes
agentsec harden ~ -p workstation --dry-run

# Apply hardening
agentsec harden ~ -p workstation --apply

# Scan again to see the improvement
agentsec scan ~ --verbose
```

## Capture Output

```bash
# JSON report
agentsec scan ~ -o json -f /tmp/report.json

# SARIF for GitHub Code Scanning
agentsec scan ~ -o sarif -f /tmp/results.sarif
```
