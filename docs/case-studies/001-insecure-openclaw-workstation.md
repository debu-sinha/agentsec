# Case Study: Insecure OpenClaw Developer Workstation

- Date: 2026-02-16
- Environment type: OpenClaw developer workstation
- Scope: installation
- Tool version: agentsec 0.4.0

## Starting Risk Posture

- Overall score/grade: 5.0/100, F
- Findings: 12 total, 6 critical, 6 high, 0 medium, 0 info
- Top blockers:
  1. DM policy set to 'open' - anyone can message the agent (critical)
  2. Full tool profile with open inbound access (critical)
  3. Authentication disabled on non-loopback agent (critical)
  4. Gateway bound to non-loopback interface (high)
  5. World-readable sensitive file: exec-approvals.json (high)
  6. No SSRF protection configured for URL-based inputs (high)

## Actions Taken

1. Ran `agentsec scan` against the unconfigured installation (12 findings, grade F)
2. Applied hardening profile: `workstation`
3. Re-scanned to validate (3 findings, grade C)
4. Reviewed residual findings - all remaining findings are filesystem permission issues on Windows

## Measurable Outcomes

| Metric | Before | After | Delta |
|---|---:|---:|---:|
| Score | 5.0 | 79.0 | +74.0 |
| Grade | F | C | -- |
| Critical findings | 6 | 0 | -6 |
| High findings | 6 | 3 | -3 |
| Total findings | 12 | 3 | -9 |

## What Automation Fixed vs Manual

- Auto-fixed by `harden` (workstation profile):
  - `dmPolicy`: open -> paired
  - `groupPolicy`: open -> allowlist
  - `tools.profile`: full -> messaging
  - `gateway.bind`: `0.0.0.0` -> loopback
  - `discovery.mdns.mode`: (unset) -> minimal
  - `session.dmScope`: (unset) -> per-channel-peer
  - `dangerouslyDisableDeviceAuth`: (unset) -> false
  - `dangerouslyDisableAuth`: (unset) -> false
- Manual fixes required:
  - File permissions on `exec-approvals.json` (detected as world-readable; needs `chmod 600`)
  - File permissions on `openclaw.json` (detected as world-readable; needs `chmod 600`)
  - Directory permissions on `.openclaw/` (detected as world-accessible; needs `chmod 700`)

## Residual Risk

- Remaining high findings (3):
  - World-readable sensitive file: exec-approvals.json
  - World-readable sensitive file: openclaw.json
  - Agent config directory world-accessible: .openclaw
- Accepted risks and rationale:
  - File permission findings on Windows require ACL-level fixes outside the scope of the hardener

## Repro Commands

```bash
# Create an insecure test config
mkdir -p /tmp/test-openclaw/.openclaw
cat > /tmp/test-openclaw/.openclaw/openclaw.json << 'EOF'
{
  "version": "2026.2.10",
  "gateway": {"bind": "0.0.0.0"},
  "dmPolicy": "open",
  "groupPolicy": "open"
}
EOF

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

# Validate no critical findings (high permission findings may remain on Windows)
agentsec scan /tmp/test-openclaw --fail-on critical
```

## Artifacts

- Raw report JSON (before): `docs/case-studies/artifacts/case1-before.json`
- Raw report JSON (after): `docs/case-studies/artifacts/case1-after.json`
