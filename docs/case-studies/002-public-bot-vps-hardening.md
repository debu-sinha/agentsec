# Case Study: Public OpenClaw Bot Hardening on VPS

- Date: 2026-02-15
- Environment type: Public bot on internet-exposed VPS
- Scope: installation + mcp + credential
- Tool version: agentsec 0.4.0

## Starting Risk Posture

- Overall score/grade: 5.0/100, F
- Findings: 12 total, 4 critical, 7 high, 0 medium, 1 info
- Top blockers:
  1. DM policy set to 'open' - anyone can message the agent (critical)
  2. Full tool profile with open inbound access (critical)
  3. Plaintext Slack Token in config file (critical, detected by both installation and credential scanners)
  4. Slack Bot Token found in env.json (critical)
  5. Exec approvals file missing - host execution uncontrolled (high)
  6. Sandboxing disabled with full tool access and open input (high)
  7. MCP server 'remote-tools' has no authentication configured (high)

The configuration simulates a common VPS deployment: gateway bound to all interfaces, no authentication, open DM/group policies, full tool profile, a remote MCP server without auth headers, and a Slack bot token stored in plaintext. Score of 5.0 represents the minimum floor - nearly zero security controls.

## Actions Taken

1. Baseline scan:
   - `agentsec scan /opt/openclaw -o json -f case2-before.json --fail-on none`
   - Result: 12 findings, score 5.0/100 (F)
2. Applied strict hardening profile:
   - `agentsec harden /opt/openclaw -p public-bot --apply`
   - Profile applied 8 config changes targeting all policy and gateway settings
3. Re-scan after hardening:
   - `agentsec scan /opt/openclaw -o json -f case2-after.json --fail-on none`
   - Result: 6 findings, score 49.0/100 (F)
4. Manual follow-up fixes required:
   - Move Slack bot token from env.json to environment variable or secrets manager
   - Add authentication headers to remote MCP server configuration
   - Fix file permissions: `chmod 700 .openclaw && chmod 600 .openclaw/*.json`

## Measurable Outcomes

| Metric | Before | After | Delta |
|---|---:|---:|---:|
| Score | 5.0 | 49.0 | +44.0 |
| Grade | F | F | -- |
| Critical findings | 4 | 2 | -2 |
| High findings | 7 | 3 | -4 |
| Total findings | 12 | 6 | -6 |

Note: Grade remains F because residual critical findings (plaintext credentials, unauthenticated MCP) keep the score below passing threshold. These require manual remediation.

## What Automation Fixed vs Manual

- Auto-fixed by `harden -p public-bot`:
  - `dmPolicy`: open -> paired
  - `groupPolicy`: open -> allowlist
  - `toolProfile`: full -> messaging
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
- Remaining high findings (3):
  - World-readable sensitive file: openclaw.json
  - Agent config directory world-accessible: .openclaw
  - MCP server 'remote-tools' has no authentication configured
- Remaining info (1):
  - Could not determine agent version
- Accepted risks and rationale:
  - File permission findings resolve automatically on Linux with `chmod` commands in the manual fix step
  - Version detection is cosmetic and does not affect security posture

## Operator Feedback

> The public-bot profile eliminated all the policy-level critical findings in one command, but credentials and MCP auth need manual attention. On a real VPS you'd also want firewall rules and reverse proxy in front of the gateway - agentsec flags the config-level issues but network hardening is out of scope.

## Repro Commands

```bash
# Create test config (simulating insecure VPS deployment)
mkdir -p /tmp/test-vps/.openclaw
cat > /tmp/test-vps/.openclaw/openclaw.json << 'EOF'
{
  "gatewayHostname": "0.0.0.0",
  "gatewayPort": 40000,
  "authRequired": false,
  "dmPolicy": "open",
  "groupPolicy": "open",
  "toolProfile": "full"
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
  "openai_api_key": "sk-proj-abc123def456ghi789jklmnopqrstuvwxyz012345",
  "slack_token": "xoxb-123456789012-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx"
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

- Raw report JSON (before): reproducible via repro commands above
- Raw report JSON (after): reproducible via repro commands above
- Config backup: `.openclaw/openclaw.json.bak` (created by `harden --apply`)
