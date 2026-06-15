# MCP Ecosystem Security Dashboard

![Ecosystem Grade](https://img.shields.io/badge/Ecosystem_Grade-A-brightgreen?style=for-the-badge) ![Avg Score](https://img.shields.io/badge/Avg_Score-90%2F100-brightgreen?style=for-the-badge) ![Repos Scanned](https://img.shields.io/badge/Repos_Scanned-50-blue?style=for-the-badge) ![Last Updated](https://img.shields.io/badge/Last_Scan-2026-06-15-grey?style=for-the-badge)

Automated weekly security scan of the top MCP server repositories, powered by [agentsec](https://github.com/debu-sinha/agentsec). Findings are mapped to the [OWASP Top 10 for Agentic Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/).

**Jump to:** [Summary](#at-a-glance) | [Grades](#grade-distribution) | [Repos Requiring Attention](#repos-requiring-attention) | [All Repos](#all-scanned-repos) | [Methodology](#methodology) | [Disclaimer](#disclaimer)

> **10 repos** scored below B. **agentgateway/agentgateway** alone has **0 critical** and **93 total findings**.

## At a Glance

| Metric | Value |
|--------|------:|
| Repositories scanned | **50** |
| Total findings | **404** |
| 🔴 Critical | **1** |
| 🟠 High | **8** |
| 🟡 Medium | **97** |
| 🟢 Low | **251** |
| 🔵 Info | **47** |
| Repos with zero critical/high findings | **44** |
| Repos with critical findings | **1** |

## Ecosystem Trend

| Date | Avg Score | Grade | Repos Improving | Repos Degrading |
|------|----------:|:-----:|----------------:|----------------:|
| 2026-05-04 | 85 | 🟢 B | 1 | 6 |
| 2026-05-11 | 85 | 🟢 B | 1 | 1 |
| 2026-05-18 | 84 | 🟢 B | 1 | 4 |
| 2026-05-25 | 83 | 🟢 B | 0 | 3 |
| 2026-06-01 | 82 | 🟢 B | 1 | 2 |
| 2026-06-05 | 90 | ✅ A | 23 | 0 |
| 2026-06-08 | 90 | ✅ A | 0 | 2 |
| 2026-06-15 | 89 | 🟢 B | 0 | 4 |

## Grade Distribution

**A** `█████████████████████░░░░░░░░░` 36 repos (72%)
**B** `██░░░░░░░░░░░░░░░░░░░░░░░░░░░░` 4 repos (8%)
**C** `█░░░░░░░░░░░░░░░░░░░░░░░░░░░░░` 3 repos (6%)
**D** `█░░░░░░░░░░░░░░░░░░░░░░░░░░░░░` 3 repos (6%)
**F** `██░░░░░░░░░░░░░░░░░░░░░░░░░░░░` 4 repos (8%)

## Most Common Finding Categories

| # | Category | OWASP | Findings | Share |
|--:|----------|:-----:|--------:|------:|
| 1 | Exposed Token | ASI05 | 341 | 84% |
| 2 | Outdated Version | ASI03 | 47 | 12% |
| 3 | Data Exfiltration | ASI05 | 7 | 2% |
| 4 | Dangerous Pattern | ASI02 | 6 | 1% |
| 5 | Config Drift | ASI10 | 1 | 0% |
| 6 | Insecure Permissions | ASI05 | 1 | 0% |
| 7 | Plaintext Secret | ASI05 | 1 | 0% |

## Repos Requiring Attention

> 10 repositories scored below B and have actionable findings.

| # | Repository | Grade | Score | Trend | Critical | High | Medium | Low | Total |
|--:|------------|:-----:|------:|:-----:|---------:|-----:|-------:|----:|------:|
| 1 | [u14app/deep-research](mcp-dashboard/repos/u14app-deep-research.md) | ![F](https://img.shields.io/badge/F-red?style=flat-square) | 40 | → | 0 | 0 | 20 | 0 | 21 |
| 2 | [chopratejas/headroom](mcp-dashboard/repos/chopratejas-headroom.md) | ![F](https://img.shields.io/badge/F-red?style=flat-square) | 46 | ↓ | 0 | **3** | 6 | 24 | 34 |
| 3 | [openclaw/Peekaboo](mcp-dashboard/repos/openclaw-Peekaboo.md) | ![F](https://img.shields.io/badge/F-red?style=flat-square) | 50 | ↓ | 0 | 0 | 16 | 2 | 19 |
| 4 | [agentgateway/agentgateway](mcp-dashboard/repos/agentgateway-agentgateway.md) | ![F](https://img.shields.io/badge/F-red?style=flat-square) | 52 | → | 0 | 0 | 11 | 81 | 93 |
| 5 | [PrefectHQ/fastmcp](mcp-dashboard/repos/PrefectHQ-fastmcp.md) | ![D](https://img.shields.io/badge/D-orange?style=flat-square) | 61 | → | **1** | 0 | 3 | 22 | 27 |
| 6 | [opensumi/core](mcp-dashboard/repos/opensumi-core.md) | ![D](https://img.shields.io/badge/D-orange?style=flat-square) | 61 | → | 0 | 0 | 13 | 0 | 14 |
| 7 | [googleapis/mcp-toolbox](mcp-dashboard/repos/googleapis-mcp-toolbox.md) | ![D](https://img.shields.io/badge/D-orange?style=flat-square) | 69 | → | 0 | **1** | 3 | 17 | 22 |
| 8 | [webiny/webiny-js](mcp-dashboard/repos/webiny-webiny-js.md) | ![C](https://img.shields.io/badge/C-yellow?style=flat-square) | 73 | → | 0 | 0 | 4 | 31 | 36 |
| 9 | [BeehiveInnovations/pal-mcp-server](mcp-dashboard/repos/BeehiveInnovations-pal-mcp-server.md) | ![C](https://img.shields.io/badge/C-yellow?style=flat-square) | 74 | → | 0 | 0 | 5 | 11 | 17 |
| 10 | [homeassistant-ai/ha-mcp](mcp-dashboard/repos/homeassistant-ai-ha-mcp.md) | ![C](https://img.shields.io/badge/C-yellow?style=flat-square) | 74 | → | 0 | **2** | 0 | 12 | 15 |

## All Scanned Repos

> 40 repositories scored A or B.

<details>
<summary>View all 40 clean repos</summary>

| Repository | Stars | Grade | Score | Trend |
|------------|------:|:-----:|------:|:-----:|
| [BrowserMCP/mcp](mcp-dashboard/repos/BrowserMCP-mcp.md) | 6,677 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 100 | → |
| [Coding-Solo/godot-mcp](mcp-dashboard/repos/Coding-Solo-godot-mcp.md) | 4,179 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 100 | → |
| [DeusData/codebase-memory-mcp](mcp-dashboard/repos/DeusData-codebase-memory-mcp.md) | 3,534 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 100 | → |
| [LaurieWired/GhidraMCP](mcp-dashboard/repos/LaurieWired-GhidraMCP.md) | 9,224 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 100 | → |
| [MarkusPfundstein/mcp-obsidian](mcp-dashboard/repos/MarkusPfundstein-mcp-obsidian.md) | 3,913 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 100 | → |
| [Minidoracat/mcp-feedback-enhanced](mcp-dashboard/repos/Minidoracat-mcp-feedback-enhanced.md) | 3,791 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 100 | → |
| [Pimzino/spec-workflow-mcp](mcp-dashboard/repos/Pimzino-spec-workflow-mcp.md) | 4,226 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 100 | → |
| [activepieces/activepieces](mcp-dashboard/repos/activepieces-activepieces.md) | 22,768 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 100 |  |
| [antvis/mcp-server-chart](mcp-dashboard/repos/antvis-mcp-server-chart.md) | 4,161 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 100 | → |
| [awslabs/mcp](mcp-dashboard/repos/awslabs-mcp.md) | 9,269 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 100 | → |
| [browserbase/mcp-server-browserbase](mcp-dashboard/repos/browserbase-mcp-server-browserbase.md) | 3,373 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 100 | → |
| [cloudflare/mcp-server-cloudflare](mcp-dashboard/repos/cloudflare-mcp-server-cloudflare.md) | 3,860 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 100 | → |
| [epiral/bb-browser](mcp-dashboard/repos/epiral-bb-browser.md) | 5,798 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 100 | → |
| [exa-labs/exa-mcp-server](mcp-dashboard/repos/exa-labs-exa-mcp-server.md) | 4,578 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 100 | → |
| [hangwin/mcp-chrome](mcp-dashboard/repos/hangwin-mcp-chrome.md) | 11,926 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 100 | → |
| [haris-musa/excel-mcp-server](mcp-dashboard/repos/haris-musa-excel-mcp-server.md) | 3,934 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 100 | → |
| [kreuzberg-dev/kreuzberg](mcp-dashboard/repos/kreuzberg-dev-kreuzberg.md) | 8,490 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 100 |  |
| [kucherenko/jscpd](mcp-dashboard/repos/kucherenko-jscpd.md) | 5,774 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 100 | → |
| [laravel/boost](mcp-dashboard/repos/laravel-boost.md) | 3,508 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 100 | → |
| [lharries/whatsapp-mcp](mcp-dashboard/repos/lharries-whatsapp-mcp.md) | 5,784 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 100 | → |
| [makenotion/notion-mcp-server](mcp-dashboard/repos/makenotion-notion-mcp-server.md) | 4,421 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 100 | → |
| [0x4m4/hexstrike-ai](mcp-dashboard/repos/0x4m4-hexstrike-ai.md) | 9,588 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 99 | → |
| [google-labs-code/stitch-skills](mcp-dashboard/repos/google-labs-code-stitch-skills.md) | 6,024 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 99 | → |
| [microsoft/playwright-mcp](mcp-dashboard/repos/microsoft-playwright-mcp.md) | 33,938 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 99 | → |
| [Manavarya09/design-extract](mcp-dashboard/repos/Manavarya09-design-extract.md) | 3,226 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 98 | → |
| [getsentry/XcodeBuildMCP](mcp-dashboard/repos/getsentry-XcodeBuildMCP.md) | 5,899 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 98 | → |
| [21st-dev/magic-mcp](mcp-dashboard/repos/21st-dev-magic-mcp.md) | 5,131 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 97 | → |
| [CursorTouch/Windows-MCP](mcp-dashboard/repos/CursorTouch-Windows-MCP.md) | 5,986 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 97 | → |
| [GLips/Figma-Context-MCP](mcp-dashboard/repos/GLips-Figma-Context-MCP.md) | 15,110 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 97 | → |
| [firecrawl/firecrawl-mcp-server](mcp-dashboard/repos/firecrawl-firecrawl-mcp-server.md) | 6,579 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 97 | → |
| [idosal/git-mcp](mcp-dashboard/repos/idosal-git-mcp.md) | 8,169 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 97 | → |
| [aipotheosis-labs/aci](mcp-dashboard/repos/aipotheosis-labs-aci.md) | 4,802 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 95 | → |
| [Gentleman-Programming/engram](mcp-dashboard/repos/Gentleman-Programming-engram.md) | 4,354 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 94 | → |
| [wonderwhy-er/DesktopCommanderMCP](mcp-dashboard/repos/wonderwhy-er-DesktopCommanderMCP.md) | 6,172 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 93 | → |
| [punkpeye/fastmcp](mcp-dashboard/repos/punkpeye-fastmcp.md) | 3,194 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 92 | → |
| [sooperset/mcp-atlassian](mcp-dashboard/repos/sooperset-mcp-atlassian.md) | 5,395 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 91 | → |
| [github/github-mcp-server](mcp-dashboard/repos/github-github-mcp-server.md) | 30,691 | ![B](https://img.shields.io/badge/B-green?style=flat-square) | 89 | → |
| [jacob-bd/notebooklm-mcp-cli](mcp-dashboard/repos/jacob-bd-notebooklm-mcp-cli.md) | 4,888 | ![B](https://img.shields.io/badge/B-green?style=flat-square) | 88 | → |
| [CodeGraphContext/CodeGraphContext](mcp-dashboard/repos/CodeGraphContext-CodeGraphContext.md) | 3,737 | ![B](https://img.shields.io/badge/B-green?style=flat-square) | 85 | → |
| [grafana/mcp-grafana](mcp-dashboard/repos/grafana-mcp-grafana.md) | 3,153 | ![B](https://img.shields.io/badge/B-green?style=flat-square) | 82 | → |

</details>

## Methodology

### Scoring Formula

```
Score = 100 - (Critical x 15) - (High x 7) - (Medium x 3) - (Low x 1)
Score is clamped to [5, 100]
```

Info-severity findings are tracked but do not affect the score.

### Grade Scale

| Grade | Score Range | Meaning |
|:-----:|:----------:|---------|
| ✅ A | 90 -- 100 | Excellent -- minimal risk |
| 🟢 B | 80 -- 89  | Good -- minor issues only |
| 🟡 C | 70 -- 79  | Fair -- some high-severity issues |
| 🟠 D | 60 -- 69  | Poor -- multiple high-severity issues |
| 🔴 F | 5 -- 59   | Critical -- immediate action required |

### Scanner Coverage

Each repository is scanned with [agentsec](https://pypi.org/project/agentsec-ai/) which runs 33 named security checks + 16 custom credential patterns + detect-secrets (23 plugins) across the OWASP Agentic Top 10 categories (ASI01 -- ASI10).

### Sampling Methodology & Known Bias

**Current approach:** The top 50 MCP repositories are selected by GitHub star count. This is a convenience sample that favors popular, well-maintained projects.

**Known limitations:**

- **Popularity bias**: High-star repos tend to have more contributors, code review, and security practices. The long tail of less-popular MCP servers (which users still install) may have worse security posture but is invisible in this dashboard.
- **Survivorship bias**: Abandoned or deleted repos are not tracked, even if they were once widely installed.
- **Static analysis only**: No runtime or dynamic testing is performed. Some vulnerability classes (e.g., SSRF, logic bugs) cannot be detected statically.
- **False positives**: Findings may include false positives (e.g., test fixtures with intentional dummy credentials). Manual triage is recommended.

**Future improvements:**

- Stratified sampling: include repos from different popularity tiers (e.g., top 25 by stars + 25 random from 100-1000 stars)
- npm/pip download counts as alternative popularity signal
- Expand sample size to 100+ repositories

## How to Improve Your Grade

If your repository appears on this dashboard, here is how to improve your score:

1. **Install agentsec** and run it locally: `pip install agentsec-ai && agentsec scan .`
2. **Review findings** -- each includes a remediation summary and OWASP category
3. **Fix critical/high issues first** -- they have the largest impact on your score
4. **Rotate exposed credentials** -- even if redacted here, leaked secrets must be rotated
5. **Re-scan after fixes** to verify your improvements

> Findings are point-in-time snapshots. Your grade will update automatically in the next weekly scan.

## Responsible Disclosure

- All targets are **public** open-source repositories
- No exploit payloads are included in this report
- Credential evidence is redacted (first 4 + last 4 characters only)
- This dashboard is intended to improve ecosystem security, not to shame maintainers
- **Contest a finding**: open an issue at [agentsec/issues](https://github.com/debu-sinha/agentsec/issues) with the repo name and finding ID

## Disclaimer

This dashboard is provided **as-is** for informational purposes only. It is generated by automated static analysis and may contain false positives or miss certain vulnerability classes. Grades reflect a point-in-time snapshot and do not constitute a comprehensive security audit. No warranty of accuracy, completeness, or fitness for any purpose is expressed or implied. Repository maintainers are encouraged to run their own security assessments.

---

*Generated on 2026-06-15 by [agentsec](https://github.com/debu-sinha/agentsec) v0.5.0 | [Install](https://pypi.org/project/agentsec-ai/) | [Report an issue](https://github.com/debu-sinha/agentsec/issues)*
