# Immunize Your OpenClaw: Why Your AI Agent Needs a Security Checkup

**By Debu Sinha** | February 2026

---

This post focuses on evidence you can reproduce from this repository.

I built **agentsec** to detect recurring OpenClaw security misconfigurations and secret exposures, and to harden the risky defaults in one workflow.

## The Problem: Security Is Optional, Attackers Are Not

OpenClaw's own documentation admits: *"There is no 'perfectly secure' setup."* That's honest, but it creates a gap. The default configuration ships with:

- Gateway bound to localhost (good), but no guidance on what happens when you expose it
- No exec approval rules out of the box
- Full tool profiles enabled by default
- No SSRF protection until v2026.2.12
- Skills installed without behavioral analysis

Repository-backed evidence:

| What we measured in this repo | Number | Artifact |
|--------------|--------|--------|
| Named checks | 27 | `docs/checks-catalog.md` |
| Fixture benchmark | P=0.82 / R=1.00 / F1=0.90 | `docs/benchmarks/results/2026-02-15-v0.4.0.json` |
| Case studies | 4 | `docs/case-studies/` |
| Top-50 study targets | 50 | `docs/benchmarks/top50/reports/top50_summary_20260216.json` |

Any external ecosystem statistics should be cited separately in a references section before publication.

## What agentsec Does

agentsec is an open-source security scanner and hardener for OpenClaw installations. One command gives you a complete security posture assessment:

```bash
pip install agentsec-ai
agentsec scan
```

It runs 27 named checks plus dynamic credential detection across four scanners:

**Installation Scanner** -- checks your OpenClaw configuration for gateway exposure, identity policy misconfigurations, overpermissive tool profiles, missing exec approvals, disabled sandboxing, SSRF vulnerabilities, and 5 known CVEs.

**Skill Scanner** -- performs AST-based analysis of installed skills looking for instruction malware (pipe-to-shell patterns, credential path targeting, remote script execution), dangerous code patterns, and prompt injection in tool descriptions.

**MCP Server Scanner** -- audits MCP server configurations for tool poisoning, hardcoded credentials, missing authentication, and unverified packages.

**Credential Scanner** -- deep recursive scan for secrets using 16 provider-specific patterns (OpenAI, Anthropic, AWS, GitHub, Slack, and more) plus Shannon entropy detection for custom tokens.

Every finding maps to the **OWASP Top 10 for Agentic Applications (ASI01-ASI10)**. You get a posture grade from A to F.

## The Five CVEs Every OpenClaw User Should Know

If you're running OpenClaw below v2026.1.30, you're vulnerable to all five:

| CVE | What it does | CVSS |
|-----|-------------|------|
| **CVE-2026-25253** | One-click RCE via WebSocket hijacking -- attacker sends a link, steals your auth token | 8.8 |
| **CVE-2026-24763** | Command injection through Docker sandbox PATH variable | 8.8 |
| **CVE-2026-25157** | SSH command injection via sshNodeCommand -- arbitrary commands on remote hosts | 7.8 |
| **CVE-2026-25593** | Unauthenticated config write via WebSocket API -- full system takeover | Critical |
| **CVE-2026-25475** | Path traversal via MEDIA: extraction -- read any file on the system | High |

agentsec detects all five and tells you exactly what version to update to.

## Not Just Detection: Hardening

Most security tools stop at telling you what's wrong. agentsec also fixes it.

Three hardening profiles apply safe configuration changes directly to your openclaw.json:

```bash
# See what would change (safe preview)
agentsec harden -p workstation

# Apply the changes
agentsec harden -p workstation --apply
```

| Profile | Who it's for | What it does |
|---------|-------------|-------------|
| **workstation** | Solo developer, local use | Binds to localhost, paired DMs only, messaging-only tools, minimal mDNS |
| **vps** | Cloud/remote hosting | All of workstation + group allowlists, mDNS off, device auth enforced |
| **public-bot** | Untrusted input (Discord bot, public API) | Maximum lockdown: sandbox everything, deny exec/browser/web, allowlist-only access |

The hardener creates a backup before writing changes. Completely reversible.

## CI/CD: Shift Left on Agent Security

agentsec produces SARIF output that integrates directly with GitHub Code Scanning:

```yaml
- name: Run security scan
  run: agentsec scan -o sarif -f results.sarif --fail-on high

- name: Upload to GitHub Code Scanning
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

Security findings appear as annotations on your pull requests. Same workflow as CodeQL, Semgrep, or Trivy -- but for your AI agent configuration.

## Scope

This repository demonstrates an offline CLI workflow with:

- installation + skill + mcp + credential scanning
- OWASP ASI01-ASI10 mapping
- hardening profiles
- JSON/SARIF output for CI

Claims about comparative market position are intentionally omitted here unless backed by reproducible side-by-side benchmarks.

## What's Next

agentsec v0.5 will add:

- **`.agentsec.yaml`** -- per-project configuration with ignore rules
- **Baseline/diff mode** -- only alert on new findings since last scan
- **`agentsec skill quarantine`** -- isolate suspicious skills before analysis
- **Community rule repository** -- share and import custom detection rules

## Get Started

```bash
pip install agentsec-ai
agentsec scan ~/.openclaw
```

The scan takes seconds and produces artifact-backed findings you can verify.

---

*agentsec is open source under the Apache-2.0 license. Contributions welcome.*

*GitHub: [github.com/debu-sinha/agentsec](https://github.com/debu-sinha/agentsec)*
