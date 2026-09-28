# MCP Ecosystem Security Dashboard

![Ecosystem Grade](https://img.shields.io/badge/Ecosystem_Grade-C-yellow?style=for-the-badge) ![Avg Score](https://img.shields.io/badge/Avg_Score-76%2F100-yellow?style=for-the-badge) ![Repos Scanned](https://img.shields.io/badge/Repos_Scanned-50-blue?style=for-the-badge) ![Last Updated](https://img.shields.io/badge/Last_Scan-2026-09-28-grey?style=for-the-badge)

Automated weekly security scan of the top MCP server repositories, powered by [agentsec](https://github.com/debu-sinha/agentsec). Findings are mapped to the [OWASP Top 10 for Agentic Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/).

**Jump to:** [Summary](#at-a-glance) | [Grades](#grade-distribution) | [Repos Requiring Attention](#repos-requiring-attention) | [All Repos](#all-scanned-repos) | [Methodology](#methodology) | [Disclaimer](#disclaimer)

> **17 repos** scored below B. **t8y2/dbx** alone has **20 critical** and **813 total findings**.

## At a Glance

| Metric | Value |
|--------|------:|
| Repositories scanned | **50** |
| Total findings | **1987** |
| 🔴 Critical | **38** |
| 🟠 High | **17** |
| 🟡 Medium | **1172** |
| 🟢 Low | **712** |
| 🔵 Info | **48** |
| Repos with zero critical/high findings | **41** |
| Repos with critical findings | **7** |

## Ecosystem Trend

| Date | Avg Score | Grade | Repos Improving | Repos Degrading |
|------|----------:|:-----:|----------------:|----------------:|
| 2026-08-10 | 76 | 🟡 C | 1 | 1 |
| 2026-08-17 | 76 | 🟡 C | 0 | 4 |
| 2026-08-24 | 77 | 🟡 C | 2 | 0 |
| 2026-08-31 | 77 | 🟡 C | 0 | 2 |
| 2026-09-07 | 75 | 🟡 C | 0 | 0 |
| 2026-09-14 | 73 | 🟡 C | 1 | 2 |
| 2026-09-21 | 72 | 🟡 C | 0 | 4 |
| 2026-09-28 | 75 | 🟡 C | 1 | 2 |

## Grade Distribution

**A** `████████████████░░░░░░░░░░░░░░` 28 repos (56%)
**B** `███░░░░░░░░░░░░░░░░░░░░░░░░░░░` 5 repos (10%)
**C** `██░░░░░░░░░░░░░░░░░░░░░░░░░░░░` 4 repos (8%)
**D** `█░░░░░░░░░░░░░░░░░░░░░░░░░░░░░` 2 repos (4%)
**F** `██████░░░░░░░░░░░░░░░░░░░░░░░░` 11 repos (22%)

## Most Common Finding Categories

| # | Category | OWASP | Findings | Share |
|--:|----------|:-----:|--------:|------:|
| 1 | Exposed Token | ASI05 | 1898 | 96% |
| 2 | Outdated Version | ASI03 | 48 | 2% |
| 3 | Malicious Skill | ASI03 | 22 | 1% |
| 4 | Dangerous Pattern | ASI02 | 8 | 0% |
| 5 | Data Exfiltration | ASI05 | 7 | 0% |
| 6 | Config Drift | ASI10 | 1 | 0% |
| 7 | Insecure Permissions | ASI05 | 1 | 0% |
| 8 | Exposed Credentials | ASI05 | 1 | 0% |

## Repos Requiring Attention

> 17 repositories scored below B and have actionable findings.

| # | Repository | Grade | Score | Trend | Critical | High | Medium | Low | Total |
|--:|------------|:-----:|------:|:-----:|---------:|-----:|-------:|----:|------:|
| 1 | [TabularisDB/tabularis](mcp-dashboard/repos/TabularisDB-tabularis.md) | ![F](https://img.shields.io/badge/F-red?style=flat-square) | 5 | → | 0 | 0 | 239 | 8 | 248 |
| 2 | [homeassistant-ai/ha-mcp](mcp-dashboard/repos/homeassistant-ai-ha-mcp.md) | ![F](https://img.shields.io/badge/F-red?style=flat-square) | 5 | → | 0 | **3** | 82 | 37 | 123 |
| 3 | [openclaw/Peekaboo](mcp-dashboard/repos/openclaw-Peekaboo.md) | ![F](https://img.shields.io/badge/F-red?style=flat-square) | 5 | → | 0 | 0 | 49 | 13 | 63 |
| 4 | [t8y2/dbx](mcp-dashboard/repos/t8y2-dbx.md) | ![F](https://img.shields.io/badge/F-red?style=flat-square) | 5 | → | **20** | **2** | 675 | 115 | 813 |
| 5 | [wonderwhy-er/DesktopCommanderMCP](mcp-dashboard/repos/wonderwhy-er-DesktopCommanderMCP.md) | ![F](https://img.shields.io/badge/F-red?style=flat-square) | 5 | → | **12** | **7** | 0 | 0 | 20 |
| 6 | [Evil0ctal/Douyin_TikTok_Download_API](mcp-dashboard/repos/Evil0ctal-Douyin_TikTok_Download_API.md) | ![F](https://img.shields.io/badge/F-red?style=flat-square) | 7 | → | 0 | 0 | 26 | 86 | 113 |
| 7 | [agentgateway/agentgateway](mcp-dashboard/repos/agentgateway-agentgateway.md) | ![F](https://img.shields.io/badge/F-red?style=flat-square) | 10 | → | 0 | 0 | 25 | 112 | 138 |
| 8 | [headroomlabs-ai/headroom](mcp-dashboard/repos/headroomlabs-ai-headroom.md) | ![F](https://img.shields.io/badge/F-red?style=flat-square) | 25 | → | **1** | **3** | 8 | 39 | 52 |
| 9 | [FlorianBruniaux/claude-code-ultimate-guide](mcp-dashboard/repos/FlorianBruniaux-claude-code-ultimate-guide.md) | ![F](https://img.shields.io/badge/F-red?style=flat-square) | 28 | → | **1** | **1** | 12 | 14 | 29 |
| 10 | [u14app/deep-research](mcp-dashboard/repos/u14app-deep-research.md) | ![F](https://img.shields.io/badge/F-red?style=flat-square) | 40 | → | 0 | 0 | 20 | 0 | 21 |
| 11 | [Q00/ouroboros](mcp-dashboard/repos/Q00-ouroboros.md) | ![F](https://img.shields.io/badge/F-red?style=flat-square) | 52 | → | **2** | 0 | 1 | 27 | 31 |
| 12 | [PrefectHQ/fastmcp](mcp-dashboard/repos/PrefectHQ-fastmcp.md) | ![D](https://img.shields.io/badge/D-orange?style=flat-square) | 61 | → | **1** | 0 | 3 | 33 | 38 |
| 13 | [googleapis/mcp-toolbox](mcp-dashboard/repos/googleapis-mcp-toolbox.md) | ![D](https://img.shields.io/badge/D-orange?style=flat-square) | 66 | → | 0 | **1** | 4 | 19 | 25 |
| 14 | [awslabs/mcp](mcp-dashboard/repos/awslabs-mcp.md) | ![C](https://img.shields.io/badge/C-yellow?style=flat-square) | 70 | → | 0 | 0 | 5 | 68 | 74 |
| 15 | [webiny/webiny-js](mcp-dashboard/repos/webiny-webiny-js.md) | ![C](https://img.shields.io/badge/C-yellow?style=flat-square) | 70 | → | 0 | 0 | 5 | 47 | 53 |
| 16 | [BeehiveInnovations/pal-mcp-server](mcp-dashboard/repos/BeehiveInnovations-pal-mcp-server.md) | ![C](https://img.shields.io/badge/C-yellow?style=flat-square) | 74 | → | 0 | 0 | 5 | 11 | 17 |
| 17 | [feder-cr/invisible_playwright_mcp](mcp-dashboard/repos/feder-cr-invisible_playwright_mcp.md) | ![C](https://img.shields.io/badge/C-yellow?style=flat-square) | 74 |  | **1** | 0 | 0 | 11 | 13 |

## All Scanned Repos

> 33 repositories scored A or B.

<details>
<summary>View all 33 clean repos</summary>

| Repository | Stars | Grade | Score | Trend |
|------------|------:|:-----:|------:|:-----:|
| [BrowserMCP/mcp](mcp-dashboard/repos/BrowserMCP-mcp.md) | 7,140 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 100 | → |
| [Coding-Solo/godot-mcp](mcp-dashboard/repos/Coding-Solo-godot-mcp.md) | 5,856 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 100 | → |
| [DeusData/codebase-memory-mcp](mcp-dashboard/repos/DeusData-codebase-memory-mcp.md) | 45,245 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 100 | → |
| [LaurieWired/GhidraMCP](mcp-dashboard/repos/LaurieWired-GhidraMCP.md) | 10,211 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 100 | → |
| [MarkusPfundstein/mcp-obsidian](mcp-dashboard/repos/MarkusPfundstein-mcp-obsidian.md) | 4,450 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 100 | → |
| [activepieces/activepieces](mcp-dashboard/repos/activepieces-activepieces.md) | 24,764 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 100 |  |
| [antvis/mcp-server-chart](mcp-dashboard/repos/antvis-mcp-server-chart.md) | 4,386 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 100 | → |
| [atilaahmettaner/tradingview-mcp](mcp-dashboard/repos/atilaahmettaner-tradingview-mcp.md) | 4,673 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 100 | → |
| [epiral/bb-browser](mcp-dashboard/repos/epiral-bb-browser.md) | 6,232 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 100 | → |
| [hangwin/mcp-chrome](mcp-dashboard/repos/hangwin-mcp-chrome.md) | 12,454 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 100 | → |
| [jacob-bd/gemini-notebook-mcp-cli](mcp-dashboard/repos/jacob-bd-gemini-notebook-mcp-cli.md) | 6,175 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 100 | → |
| [kucherenko/jscpd](mcp-dashboard/repos/kucherenko-jscpd.md) | 6,281 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 100 | → |
| [lharries/whatsapp-mcp](mcp-dashboard/repos/lharries-whatsapp-mcp.md) | 6,324 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 100 | → |
| [makenotion/notion-mcp-server](mcp-dashboard/repos/makenotion-notion-mcp-server.md) | 4,649 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 100 | → |
| [xberg-io/xberg](mcp-dashboard/repos/xberg-io-xberg.md) | 9,345 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 100 |  |
| [0x4m4/hexstrike-ai](mcp-dashboard/repos/0x4m4-hexstrike-ai.md) | 12,195 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 99 | → |
| [google-labs-code/stitch-skills](mcp-dashboard/repos/google-labs-code-stitch-skills.md) | 8,385 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 99 | → |
| [microsoft/playwright-mcp](mcp-dashboard/repos/microsoft-playwright-mcp.md) | 37,646 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 99 | → |
| [CursorTouch/Windows-MCP](mcp-dashboard/repos/CursorTouch-Windows-MCP.md) | 7,389 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 97 | → |
| [GLips/Figma-Context-MCP](mcp-dashboard/repos/GLips-Figma-Context-MCP.md) | 15,925 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 97 | → |
| [budtmo/docker-android](mcp-dashboard/repos/budtmo-docker-android.md) | 15,888 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 97 | → |
| [exa-labs/exa-mcp-server](mcp-dashboard/repos/exa-labs-exa-mcp-server.md) | 5,056 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 97 | → |
| [firecrawl/firecrawl-mcp-server](mcp-dashboard/repos/firecrawl-firecrawl-mcp-server.md) | 7,528 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 97 | → |
| [getsentry/MobileBuildMCP](mcp-dashboard/repos/getsentry-MobileBuildMCP.md) | 6,437 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 97 |  |
| [idosal/git-mcp](mcp-dashboard/repos/idosal-git-mcp.md) | 8,436 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 97 | → |
| [aipotheosis-labs/aci](mcp-dashboard/repos/aipotheosis-labs-aci.md) | 4,903 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 95 | → |
| [Gentleman-Programming/engram](mcp-dashboard/repos/Gentleman-Programming-engram.md) | 6,907 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 93 | → |
| [prest/prest](mcp-dashboard/repos/prest-prest.md) | 4,618 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 93 | → |
| [apify/apify-mcp-server](mcp-dashboard/repos/apify-apify-mcp-server.md) | 8,807 | ![B](https://img.shields.io/badge/B-green?style=flat-square) | 88 | → |
| [sooperset/mcp-atlassian](mcp-dashboard/repos/sooperset-mcp-atlassian.md) | 5,945 | ![B](https://img.shields.io/badge/B-green?style=flat-square) | 88 | → |
| [github/github-mcp-server](mcp-dashboard/repos/github-github-mcp-server.md) | 33,257 | ![B](https://img.shields.io/badge/B-green?style=flat-square) | 86 | → |
| [Gentleman-Programming/gentle-ai](mcp-dashboard/repos/Gentleman-Programming-gentle-ai.md) | 7,359 | ![B](https://img.shields.io/badge/B-green?style=flat-square) | 85 | → |
| [callstack/agent-device](mcp-dashboard/repos/callstack-agent-device.md) | 4,800 | ![B](https://img.shields.io/badge/B-green?style=flat-square) | 85 | → |

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

*Generated on 2026-09-28 by [agentsec](https://github.com/debu-sinha/agentsec) v0.5.0 | [Install](https://pypi.org/project/agentsec-ai/) | [Report an issue](https://github.com/debu-sinha/agentsec/issues)*
