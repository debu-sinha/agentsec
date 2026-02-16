# Case Study: Insecure OpenClaw Developer Workstation

- Date: 2026-02-15
- Environment type: OpenClaw developer workstation
- Scope: installation
- Tool version: agentsec 0.4.0

## Starting Risk Posture

- Overall score/grade: 20.0/100, F
- Findings: 9 total, 2 critical, 6 high, 0 medium, 1 info
- Top blockers:
  1. DM policy set to 'open' - anyone can message the agent (critical)
  2. Full tool profile with open inbound access (critical)
  3. Group policy is 'open' - agent responds in any group (high)
  4. Sandboxing disabled with full tool access and open input (high)
  5. World-readable sensitive file: exec-approvals.json (high)
  6. No SSRF protection configured for URL-based inputs (high)

The configuration under test represents a common default setup: gateway bound to `0.0.0.0`, authentication disabled, DM and group policies both set to `open`, and the full tool profile enabled. This is roughly what you get if you stand up OpenClaw with minimal configuration and start developing against it.

## Actions Taken

1. Ran `agentsec scan` against the unconfigured installation (9 findings, grade F)
2. Applied hardening profile: `workstation`
3. Re-scanned to validate (4 findings, grade C)
4. Reviewed residual findings - three high-severity filesystem permission issues plus one informational version-detection finding remain

## Measurable Outcomes

| Metric | Before | After | Delta |
|---|---:|---:|---:|
| Score | 20.0 | 79.0 | +59.0 |
| Grade | F | C | -- |
| Critical findings | 2 | 0 | -2 |
| High findings | 6 | 3 | -3 |
| Total findings | 9 | 4 | -5 |

## What Automation Fixed vs Manual

- Auto-fixed by `harden` (workstation profile):
  - `dmPolicy`: open -> paired
  - `groupPolicy`: open -> allowlist
  - `tools.profile`: full -> messaging
  - `gateway.bind`: (unset) -> loopback
  - `discovery.mdns.mode`: (unset) -> minimal
  - `session.dmScope`: (unset) -> per-channel-peer
  - `dangerouslyDisableDeviceAuth`: (unset) -> false
  - `dangerouslyDisableAuth`: (unset) -> false
- Manual fixes required:
  - File permissions on `exec-approvals.json` (detected as world-readable; needs `chmod 600`)
  - File permissions on `openclaw.json` (detected as world-readable; needs `chmod 600`)
  - Directory permissions on `.openclaw/` (detected as world-accessible; needs `chmod 700`)

Note: The `harden` command does attempt to tighten permissions via `os.chmod`, but effectiveness depends on the filesystem. On NTFS (Windows) and some network-mounted volumes, POSIX permission changes may not take effect. On Linux/macOS with standard filesystems, these two findings are typically resolved automatically.

## Residual Risk

- Remaining high findings (3):
  - World-readable sensitive file: exec-approvals.json
  - World-readable sensitive file: openclaw.json
  - Agent config directory world-accessible: .openclaw
- Remaining info findings (1):
  - Could not determine agent version (no version metadata in config)
- Accepted risks and rationale:
  - The version detection info finding is cosmetic and does not affect security posture
  - File permission findings on Windows require ACL-level fixes outside the scope of the hardener

## Operator Feedback

> The workstation profile resolved all the critical and most high-severity findings in a single command. The three remaining highs are filesystem permission issues that need manual attention on Windows. On a Linux workstation, the same run would likely land at 0 critical, 0 high.

## Repro Commands

```bash
# Create an insecure test config
mkdir -p /tmp/test-openclaw/.openclaw
cat > /tmp/test-openclaw/.openclaw/openclaw.json << 'EOF'
{
  "version": "2026.2.10",
  "gateway": {
    "bind": "0.0.0.0"
  },
  "dmPolicy": "open",
  "groupPolicy": "open"
}
EOF

# Include exec approvals file to reproduce world-readable permission finding
cat > /tmp/test-openclaw/.openclaw/exec-approvals.json << 'EOF'
{
  "askFallback": "full"
}
EOF

# Scan before hardening
agentsec scan /tmp/test-openclaw -o json -f before.json --fail-on none

# Apply workstation hardening
agentsec harden /tmp/test-openclaw -p workstation --apply

# Scan after hardening
agentsec scan /tmp/test-openclaw -o json -f after.json --fail-on none

# Validate no critical/high (may still have permission findings on some OSes)
agentsec scan /tmp/test-openclaw --fail-on high
```

## Artifacts

- Raw report JSON (before): `before.json`
- Raw report JSON (after): `after.json`
- Config backup: `.openclaw/openclaw.json.bak` (created by `harden --apply`)
