# Case Study: Public OpenClaw Bot Hardening on VPS

- Date: 2026-02-16
- Environment type: Public bot on internet-exposed VPS
- Scope: installation + mcp + credential
- Tool version: agentsec 0.4.1

## Starting Risk Posture

- Overall score/grade: 5.0/100, F
- Findings: 15 total, 8 critical, 7 high, 0 medium, 0 low, 0 info

## Actions Taken

1. Baseline scan:
   - `agentsec scan /opt/openclaw -o json -f case2-before.json --fail-on none`
   - Result: 15 findings, score 5.0/100 (F)
2. Applied strict hardening profile:
   - `agentsec harden /opt/openclaw -p public-bot --apply`
3. Re-scan after hardening:
   - `agentsec scan /opt/openclaw -o json -f case2-after.json --fail-on none`
   - Result: 6 findings, score 42.0/100 (F)

## Measurable Outcomes

| Metric | Before | After | Delta |
|---|---:|---:|---:|
| Score | 5.0 | 42.0 | +37.0 |
| Grade | F | F | -- |
| Critical findings | 8 | 2 | -6 |
| High findings | 7 | 4 | -3 |
| Total findings | 15 | 6 | -9 |

## What Automation Fixed vs Manual

- Auto-fixed by `harden -p public-bot`:
  - `dmPolicy`: open -> paired
  - `groupPolicy`: open -> allowlist
  - `tools.profile`: full -> messaging
  - `gateway.bind`: all interfaces -> loopback
  - `sandbox`: disabled -> enabled
  - `discovery.mdns.mode`: default -> disabled
  - `session.dmScope`: default -> per-channel-peer
  - `dangerouslyDisableAuth`: true -> false
- Manual fixes required:
  - Rotate and move Slack bot token to environment variable
  - Add `auth` or `headers` config to remote MCP server
  - Set file permissions to 700/600 on config directory and files

## Residual Risk

- Remaining critical findings (2):
  - Plaintext Slack Token in env.json (installation scanner)
  - Slack Bot Token found in env.json (credential scanner)
- Remaining high findings (4):
  - World-readable sensitive file: exec-approvals.json
  - World-readable sensitive file: openclaw.json
  - Agent config directory world-accessible: .openclaw
  - MCP server 'remote-tools' has no authentication configured

## Repro Commands

```bash
# Create test config (simulating insecure VPS deployment)
mkdir -p /tmp/test-vps/.openclaw
cat > /tmp/test-vps/.openclaw/openclaw.json << 'EOF'
{
  "version": "2026.2.10",
  "gateway": {"bind": "0.0.0.0"},
  "dmPolicy": "open",
  "groupPolicy": "open"
}
EOF

cat > /tmp/test-vps/.openclaw/exec-approvals.json << 'EOF'
{
  "askFallback": "full"
}
EOF

cat > /tmp/test-vps/.openclaw/mcp.json << 'EOF'
{
  "mcpServers": {
    "remote-tools": {"url": "https://mcp.example.com/tools"},
    "local-safe": {"command": "node", "args": ["server.js"]}
  }
}
EOF

cat > /tmp/test-vps/.openclaw/env.json << 'EOF'
{
  "openai_api_key": "sk-test-0123456789abcdef0123456789abcdef",
  "slack_token": "xoxb-123456789012-123456789012-abcdefghijklmnopqrstuvwx"
}
EOF

# Baseline
agentsec scan /tmp/test-vps -o json -f case2-before.json --fail-on none

# Harden
agentsec harden /tmp/test-vps -p public-bot --apply

# Validate
agentsec scan /tmp/test-vps -o json -f case2-after.json --fail-on none
```

## Artifacts

- Raw report JSON (before): `docs/case-studies/artifacts/case2-before.json`
- Raw report JSON (after): `docs/case-studies/artifacts/case2-after.json`
