# Immunize Your OpenClaw: Why Your AI Agent Needs a Security Checkup

**By Debu Sinha** | February 2026

---

OpenClaw crossed 180,000 GitHub stars in early February 2026. In the same week, security researchers found over 135,000 exposed instances leaking API keys, chat histories, and credentials. Cisco tested a third-party skill and watched it silently exfiltrate data. Trend Micro documented 341 malicious skills on ClawHub. Five CVEs were published in a two-week span.

The agentic AI revolution is here. So are the attackers.

I built **agentsec** because I kept finding the same security anti-patterns in every OpenClaw installation I reviewed -- and there was no tool that checked for all of them at once.

## The Problem: Security Is Optional, Attackers Are Not

OpenClaw's own documentation admits: *"There is no 'perfectly secure' setup."* That's honest, but it creates a gap. The default configuration ships with:

- Gateway bound to localhost (good), but no guidance on what happens when you expose it
- No exec approval rules out of the box
- Full tool profiles enabled by default
- No SSRF protection until v2026.2.12
- Skills installed without behavioral analysis

The numbers tell the story:

| What we found | Number | Source |
|--------------|--------|--------|
| Exposed OpenClaw instances on the internet | 135,000+ | Bitdefender |
| ClawHub skills with vulnerabilities | 36.82% | Snyk ToxicSkills |
| Confirmed malicious skill payloads | 76 | Snyk |
| MCP servers with critical vulnerabilities | 32% | Enkrypt AI |
| Average vulnerabilities per MCP server | 5.2 | Enkrypt AI |
| MCP servers using insecure static secrets | 53% | Astrix |
| Enterprise genAI use that is shadow IT | 72% | Netskope |

And these are just the ones that have been publicly documented.

## What agentsec Does

agentsec is an open-source security scanner and hardener for OpenClaw installations. One command gives you a complete security posture assessment:

```bash
pip install agentsec-ai
agentsec scan
```

It runs 35+ checks across four scanners:

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

## How agentsec Compares

The agentic AI security tooling space is growing fast. Here's where agentsec fits:

- **Snyk agent-scan** (formerly mcp-scan): Excellent MCP tool-poisoning detection with a unique proxy mode. But no installation config scanning, no hardening, no OWASP mapping, and sends data to Snyk cloud by default.

- **Cisco Skill Scanner**: Sophisticated 6-layer analysis with LLM-as-Judge. But requires cloud connectivity and an LLM, no hardening, no credential scanning.

- **Agentic Radar (SplxAI/Zscaler)**: Strong workflow visualization. But focused on agentic frameworks (LangGraph, CrewAI), not OpenClaw installation security.

agentsec is the only tool that maps findings to the OWASP Agentic Top 10 (ASI01-ASI10) while also providing installation hardening, credential scanning, and SARIF output in a single offline CLI. No cloud. No LLM dependency. No data leaves your machine.

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

The scan takes seconds. The report might save you from being one of the 135,000.

---

*agentsec is open source under the Apache-2.0 license. Contributions welcome.*

*GitHub: [github.com/debu-sinha/agentsec](https://github.com/debu-sinha/agentsec)*
