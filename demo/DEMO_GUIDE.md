# agentsec LinkedIn Demo — Complete Production Guide

## Quick Start

```bash
# 1. Build the vulnerable demo environment
cd agentsec/
python demo/setup_demo.py

# 2. Verify it works — should show Grade: F
agentsec scan demo/demo-target

# 3. Record using the shot list below
# 4. Clean up when done
python demo/setup_demo.py --clean
```

## What the Demo Environment Contains

| File | Scanner | Findings Triggered |
|------|---------|-------------------|
| `.openclaw/openclaw.json` | Installation | CGW-001 (LAN bind), CGW-002 (no auth), CID-001 (open DM), CTO-001 (full tools + open), CTO-003 (no sandbox), CVE-2026-25253/24763/25157/25593/25475 |
| (missing) `exec-approvals.json` | Installation | CEX-001 (no exec control) |
| `.openclaw/mcp.json` | MCP | CMCP-001 (tool poisoning), CMCP-002 (dangerous params: shell_command, eval, code, file_path), CMCP-002 (no auth on URL), CMCP-003 (npx unverified) |
| `skills/devops-helper/README.md` | Skill | Pipe-to-shell (curl\|bash), credential path targeting (~/.aws, ~/.ssh) |
| `skills/devops-helper/helper.py` | Skill | eval/exec, subprocess, base64 payload, env harvesting, HTTP exfiltration |
| `.openclaw/integrations.json` | Credential | OpenAI key, AWS access key, GitHub PAT |
| `docker-compose.yml` | Credential | PostgreSQL + Redis connection strings with passwords |
| `.env` | Credential | 5 provider API keys (OpenAI, Anthropic, Stripe, GitHub) + DB connection string |
| `.openclaw/SOUL.md` | Skill | Overly permissive agent instructions |

## Honesty / Non-Misleading Guidelines

This demo uses a **purpose-built vulnerable fixture** — not someone's real installation.
Be transparent about this in the video:

- **Say explicitly**: "I built a deliberately vulnerable setup to show what the scanner catches"
- **Don't imply** the F grade is from scanning your actual production agent
- **Show the real work**: The grade doesn't magically jump — it takes both auto-fix AND
  manual remediation (removing creds, deleting malicious skills, upgrading versions)
- **The credential findings use realistic-looking but fake keys** — this is a demo fixture
- **The CTA is honest**: "Scan YOUR setup — you might be surprised what it finds"

Every finding the scanner reports is a **real security issue** that the scanner genuinely
detects. The fixture just concentrates them for dramatic effect.

## Expected Output

### First Scan (Grade: F)
- **CRITICAL**: ~22 findings
- **HIGH**: ~20 findings
- **MEDIUM**: ~7 findings
- **LOW**: ~4 findings
- **Grade**: F (5.0/100)
- **Total**: ~53 findings across all 4 scanners

### After Hardening + Manual Fixes (Grade: A)
- Config findings auto-fixed by hardener (gateway, sandbox, DM policy, etc.)
- Manual fixes: remove credentials, delete malicious skill, upgrade version, add auth
- Grade jumps to C (72/100) with 4 remaining file-permission findings (auto-fixable)
- Projected: **A (100/100)** after running harden one more time

## Terminal Setup for Recording

```
Font:        JetBrains Mono, 20pt (or Cascadia Code)
Theme:       Dark (#0D1117 background, high contrast)
Columns:     ~105 wide
Rows:        ~35 tall
Window:      Full screen, no OS chrome
Cursor:      Block, blinking
Prompt:      Simple "$ " (no git info, no fancy prompt)
```

## OBS Studio Settings

```
Resolution:  1920x1080 (Canvas and Output)
FPS:         30
Encoder:     x264
Bitrate:     12000 Kbps (CBR)
Format:      MP4
Audio:       Record voiceover on separate track
```

## Recording Checklist

- [ ] Demo environment built (`python demo/setup_demo.py`)
- [ ] Terminal configured (font, theme, size)
- [ ] OBS recording at 1080p/30fps/12Mbps
- [ ] Notifications disabled (DND mode)
- [ ] Desktop clean (no sensitive windows)
- [ ] Test scan works: `agentsec scan demo/demo-target`
- [ ] Grade shows F on first scan
- [ ] Hardener works: `agentsec harden demo/demo-target -p workstation --dry-run`

## Post-Production Checklist

- [ ] Add burned-in captions (CapCut or DaVinci Resolve)
- [ ] Add hook text overlay on first frame
- [ ] Create 90-second cut for LinkedIn feed
- [ ] Create thumbnail (Grade F screenshot with text overlay)
- [ ] Export as 1080x1080 (square) MP4 for LinkedIn
- [ ] Export as 1920x1080 (landscape) for YouTube full version
- [ ] Write LinkedIn post text (template below)
- [ ] Prepare first comment with links

## LinkedIn Post Template

```
pip install agentsec-ai

I built a typical AI agent setup and scanned it. Grade: F.

53 findings. Gateway on the network. No sandbox. API keys in plaintext.
MCP tools with hidden instructions I never audited.

These are all real issues agentsec catches — I just concentrated them
to show the full range.

After hardening + cleanup: Grade A.

Open source, Apache 2.0. Scan your own setup — you might be surprised.

github.com/debu-sinha/agentsec

What does your agent score?

#aiagents #security #opensource
```

## First Comment Template

```
Full 5-minute walkthrough: [YouTube link]

Commands from the video:
  pip install agentsec-ai
  agentsec scan ~
  agentsec harden ~ -p workstation --apply
  agentsec scan ~

GitHub: https://github.com/debu-sinha/agentsec
Docs: https://github.com/debu-sinha/agentsec#readme
```
