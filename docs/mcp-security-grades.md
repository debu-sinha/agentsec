# MCP Ecosystem Security Dashboard

![Ecosystem Grade](https://img.shields.io/badge/Ecosystem_Grade-B-green?style=for-the-badge) ![Avg Score](https://img.shields.io/badge/Avg_Score-85%2F100-green?style=for-the-badge) ![Repos Scanned](https://img.shields.io/badge/Repos_Scanned-50-blue?style=for-the-badge) ![Last Updated](https://img.shields.io/badge/Last_Scan-2026-05-18-grey?style=for-the-badge)

Automated weekly security scan of the top MCP server repositories, powered by [agentsec](https://github.com/debu-sinha/agentsec). Findings are mapped to the [OWASP Top 10 for Agentic Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/).

**Jump to:** [Summary](#at-a-glance) | [Grades](#grade-distribution) | [Repos Requiring Attention](#repos-requiring-attention) | [All Repos](#all-scanned-repos) | [Methodology](#methodology) | [Disclaimer](#disclaimer)

> **13 repos** scored below B. **agentgateway/agentgateway** alone has **5 critical** and **99 total findings**.

## At a Glance

| Metric | Value |
|--------|------:|
| Repositories scanned | **50** |
| Total findings | **537** |
| 🔴 Critical | **15** |
| 🟠 High | **12** |
| 🟡 Medium | **109** |
| 🟢 Low | **354** |
| 🔵 Info | **47** |
| Repos with zero critical/high findings | **42** |
| Repos with critical findings | **4** |

## Ecosystem Trend

| Date | Avg Score | Grade | Repos Improving | Repos Degrading |
|------|----------:|:-----:|----------------:|----------------:|
| 2026-03-30 | 88 | 🟢 B | 0 | 1 |
| 2026-04-06 | 87 | 🟢 B | 1 | 2 |
| 2026-04-13 | 88 | 🟢 B | 1 | 2 |
| 2026-04-20 | 88 | 🟢 B | 1 | 0 |
| 2026-04-27 | 86 | 🟢 B | 1 | 2 |
| 2026-05-04 | 85 | 🟢 B | 1 | 6 |
| 2026-05-11 | 85 | 🟢 B | 1 | 1 |
| 2026-05-18 | 84 | 🟢 B | 1 | 4 |

## Grade Distribution

**A** `██████████████████░░░░░░░░░░░░` 31 repos (62%)
**B** `███░░░░░░░░░░░░░░░░░░░░░░░░░░░` 6 repos (12%)
**C** `██░░░░░░░░░░░░░░░░░░░░░░░░░░░░` 4 repos (8%)
**D** `██░░░░░░░░░░░░░░░░░░░░░░░░░░░░` 4 repos (8%)
**F** `███░░░░░░░░░░░░░░░░░░░░░░░░░░░` 5 repos (10%)

## Most Common Finding Categories

| # | Category | OWASP | Findings | Share |
|--:|----------|:-----:|--------:|------:|
| 1 | Exposed Token | ASI05 | 479 | 89% |
| 2 | Outdated Version | ASI03 | 47 | 9% |
| 3 | Config Drift | ASI10 | 8 | 1% |
| 4 | Data Exfiltration | ASI05 | 1 | 0% |
| 5 | Insecure Permissions | ASI05 | 1 | 0% |
| 6 | Plaintext Secret | ASI05 | 1 | 0% |

## Repos Requiring Attention

> 13 repositories scored below B and have actionable findings.

| # | Repository | Grade | Score | Trend | Critical | High | Medium | Low | Total |
|--:|------------|:-----:|------:|:-----:|---------:|-----:|-------:|----:|------:|
| 1 | [agentgateway/agentgateway](mcp-dashboard/repos/agentgateway-agentgateway.md) | ![F](https://img.shields.io/badge/F-red?style=flat-square) | 5 | → | **5** | 0 | 13 | 80 | 99 |
| 2 | [getsentry/XcodeBuildMCP](mcp-dashboard/repos/getsentry-XcodeBuildMCP.md) | ![F](https://img.shields.io/badge/F-red?style=flat-square) | 5 | ↓ | **8** | 0 | 0 | 1 | 10 |
| 3 | [homeassistant-ai/ha-mcp](mcp-dashboard/repos/homeassistant-ai-ha-mcp.md) | ![F](https://img.shields.io/badge/F-red?style=flat-square) | 32 | ↓ | 0 | **8** | 0 | 12 | 21 |
| 4 | [PrefectHQ/fastmcp](mcp-dashboard/repos/PrefectHQ-fastmcp.md) | ![F](https://img.shields.io/badge/F-red?style=flat-square) | 34 | → | **1** | 0 | 12 | 35 | 49 |
| 5 | [u14app/deep-research](mcp-dashboard/repos/u14app-deep-research.md) | ![F](https://img.shields.io/badge/F-red?style=flat-square) | 40 | → | 0 | 0 | 20 | 0 | 21 |
| 6 | [Gentleman-Programming/engram](mcp-dashboard/repos/Gentleman-Programming-engram.md) | ![D](https://img.shields.io/badge/D-orange?style=flat-square) | 60 | → | **1** | **1** | 1 | 15 | 19 |
| 7 | [opensumi/core](mcp-dashboard/repos/opensumi-core.md) | ![D](https://img.shields.io/badge/D-orange?style=flat-square) | 61 | → | 0 | 0 | 13 | 0 | 14 |
| 8 | [BeehiveInnovations/pal-mcp-server](mcp-dashboard/repos/BeehiveInnovations-pal-mcp-server.md) | ![D](https://img.shields.io/badge/D-orange?style=flat-square) | 67 | → | 0 | 0 | 6 | 42 | 49 |
| 9 | [googleapis/mcp-toolbox](mcp-dashboard/repos/googleapis-mcp-toolbox.md) | ![D](https://img.shields.io/badge/D-orange?style=flat-square) | 69 | → | 0 | **1** | 3 | 22 | 27 |
| 10 | [wonderwhy-er/DesktopCommanderMCP](mcp-dashboard/repos/wonderwhy-er-DesktopCommanderMCP.md) | ![C](https://img.shields.io/badge/C-yellow?style=flat-square) | 72 | → | 0 | **1** | 7 | 0 | 9 |
| 11 | [openclaw/Peekaboo](mcp-dashboard/repos/openclaw-Peekaboo.md) | ![C](https://img.shields.io/badge/C-yellow?style=flat-square) | 73 | ↓ | 0 | 0 | 7 | 6 | 14 |
| 12 | [webiny/webiny-js](mcp-dashboard/repos/webiny-webiny-js.md) | ![C](https://img.shields.io/badge/C-yellow?style=flat-square) | 73 | → | 0 | 0 | 4 | 27 | 32 |
| 13 | [grafana/mcp-grafana](mcp-dashboard/repos/grafana-mcp-grafana.md) | ![C](https://img.shields.io/badge/C-yellow?style=flat-square) | 79 | → | 0 | 0 | 7 | 0 | 8 |

## All Scanned Repos

> 37 repositories scored A or B.

<details>
<summary>View all 37 clean repos</summary>

| Repository | Stars | Grade | Score | Trend |
|------------|------:|:-----:|------:|:-----:|
| [BrowserMCP/mcp](mcp-dashboard/repos/BrowserMCP-mcp.md) | 6,520 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 100 | → |
| [Coding-Solo/godot-mcp](mcp-dashboard/repos/Coding-Solo-godot-mcp.md) | 3,703 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 100 | → |
| [Jpisnice/shadcn-ui-mcp-server](mcp-dashboard/repos/Jpisnice-shadcn-ui-mcp-server.md) | 2,768 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 100 | → |
| [LaurieWired/GhidraMCP](mcp-dashboard/repos/LaurieWired-GhidraMCP.md) | 8,925 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 100 | → |
| [Manavarya09/design-extract](mcp-dashboard/repos/Manavarya09-design-extract.md) | 2,681 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 100 | → |
| [MarkusPfundstein/mcp-obsidian](mcp-dashboard/repos/MarkusPfundstein-mcp-obsidian.md) | 3,710 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 100 | → |
| [Minidoracat/mcp-feedback-enhanced](mcp-dashboard/repos/Minidoracat-mcp-feedback-enhanced.md) | 3,783 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 100 | → |
| [Pimzino/spec-workflow-mcp](mcp-dashboard/repos/Pimzino-spec-workflow-mcp.md) | 4,182 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 100 | → |
| [activepieces/activepieces](mcp-dashboard/repos/activepieces-activepieces.md) | 22,242 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 100 |  |
| [antvis/mcp-server-chart](mcp-dashboard/repos/antvis-mcp-server-chart.md) | 4,070 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 100 | → |
| [awslabs/mcp](mcp-dashboard/repos/awslabs-mcp.md) | 9,078 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 100 | → |
| [blazickjp/arxiv-mcp-server](mcp-dashboard/repos/blazickjp-arxiv-mcp-server.md) | 2,740 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 100 | → |
| [google-labs-code/stitch-skills](mcp-dashboard/repos/google-labs-code-stitch-skills.md) | 5,457 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 100 | → |
| [hangwin/mcp-chrome](mcp-dashboard/repos/hangwin-mcp-chrome.md) | 11,641 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 100 | → |
| [haris-musa/excel-mcp-server](mcp-dashboard/repos/haris-musa-excel-mcp-server.md) | 3,835 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 100 | → |
| [kreuzberg-dev/kreuzberg](mcp-dashboard/repos/kreuzberg-dev-kreuzberg.md) | 8,328 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 100 |  |
| [laravel/boost](mcp-dashboard/repos/laravel-boost.md) | 3,471 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 100 | → |
| [lharries/whatsapp-mcp](mcp-dashboard/repos/lharries-whatsapp-mcp.md) | 5,648 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 100 | → |
| [makenotion/notion-mcp-server](mcp-dashboard/repos/makenotion-notion-mcp-server.md) | 4,340 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 100 | → |
| [microsoft/playwright-mcp](mcp-dashboard/repos/microsoft-playwright-mcp.md) | 32,663 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 99 | → |
| [0x4m4/hexstrike-ai](mcp-dashboard/repos/0x4m4-hexstrike-ai.md) | 8,796 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 97 | → |
| [21st-dev/magic-mcp](mcp-dashboard/repos/21st-dev-magic-mcp.md) | 4,877 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 97 | → |
| [CursorTouch/Windows-MCP](mcp-dashboard/repos/CursorTouch-Windows-MCP.md) | 5,624 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 97 | → |
| [cloudflare/mcp-server-cloudflare](mcp-dashboard/repos/cloudflare-mcp-server-cloudflare.md) | 3,754 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 97 | → |
| [idosal/git-mcp](mcp-dashboard/repos/idosal-git-mcp.md) | 8,083 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 97 | → |
| [GLips/Figma-Context-MCP](mcp-dashboard/repos/GLips-Figma-Context-MCP.md) | 14,782 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 96 | → |
| [kucherenko/jscpd](mcp-dashboard/repos/kucherenko-jscpd.md) | 5,661 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 96 |  |
| [firecrawl/firecrawl-mcp-server](mcp-dashboard/repos/firecrawl-firecrawl-mcp-server.md) | 6,328 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 94 | → |
| [CodeGraphContext/CodeGraphContext](mcp-dashboard/repos/CodeGraphContext-CodeGraphContext.md) | 3,310 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 93 | → |
| [epiral/bb-browser](mcp-dashboard/repos/epiral-bb-browser.md) | 5,321 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 93 | → |
| [exa-labs/exa-mcp-server](mcp-dashboard/repos/exa-labs-exa-mcp-server.md) | 4,440 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 93 | → |
| [github/github-mcp-server](mcp-dashboard/repos/github-github-mcp-server.md) | 29,937 | ![B](https://img.shields.io/badge/B-green?style=flat-square) | 89 | → |
| [browserbase/mcp-server-browserbase](mcp-dashboard/repos/browserbase-mcp-server-browserbase.md) | 3,343 | ![B](https://img.shields.io/badge/B-green?style=flat-square) | 88 | → |
| [bytebase/dbhub](mcp-dashboard/repos/bytebase-dbhub.md) | 2,775 | ![B](https://img.shields.io/badge/B-green?style=flat-square) | 85 | → |
| [punkpeye/fastmcp](mcp-dashboard/repos/punkpeye-fastmcp.md) | 3,117 | ![B](https://img.shields.io/badge/B-green?style=flat-square) | 85 | → |
| [sooperset/mcp-atlassian](mcp-dashboard/repos/sooperset-mcp-atlassian.md) | 5,200 | ![B](https://img.shields.io/badge/B-green?style=flat-square) | 85 | → |
| [aipotheosis-labs/aci](mcp-dashboard/repos/aipotheosis-labs-aci.md) | 4,773 | ![B](https://img.shields.io/badge/B-green?style=flat-square) | 82 | → |

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

*Generated on 2026-05-18 by [agentsec](https://github.com/debu-sinha/agentsec) v0.4.5 | [Install](https://pypi.org/project/agentsec-ai/) | [Report an issue](https://github.com/debu-sinha/agentsec/issues)*
