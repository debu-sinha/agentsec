# MCP Ecosystem Security Dashboard

![Ecosystem Grade](https://img.shields.io/badge/Ecosystem_Grade-B-green?style=for-the-badge) ![Avg Score](https://img.shields.io/badge/Avg_Score-82%2F100-green?style=for-the-badge) ![Repos Scanned](https://img.shields.io/badge/Repos_Scanned-50-blue?style=for-the-badge) ![Last Updated](https://img.shields.io/badge/Last_Scan-2026-11-09-grey?style=for-the-badge)

Automated weekly security scan of the top MCP server repositories, powered by [agentsec](https://github.com/debu-sinha/agentsec). Findings are mapped to the [OWASP Top 10 for Agentic Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/).

**Jump to:** [Summary](#at-a-glance) | [Grades](#grade-distribution) | [Repos Requiring Attention](#repos-requiring-attention) | [All Repos](#all-scanned-repos) | [Methodology](#methodology) | [Disclaimer](#disclaimer)

> **13 repos** scored below B. **TabularisDB/tabularis** alone has **0 critical** and **229 total findings**.

## At a Glance

| Metric | Value |
|--------|------:|
| Repositories scanned | **50** |
| Total findings | **951** |
| 🔴 Critical | **16** |
| 🟠 High | **15** |
| 🟡 Medium | **210** |
| 🟢 Low | **667** |
| 🔵 Info | **43** |
| Repos with zero critical/high findings | **44** |
| Repos with critical findings | **5** |

## Ecosystem Trend

| Date | Avg Score | Grade | Repos Improving | Repos Degrading |
|------|----------:|:-----:|----------------:|----------------:|
| 2026-09-21 | 72 | 🟡 C | 0 | 4 |
| 2026-09-28 | 75 | 🟡 C | 1 | 2 |
| 2026-10-05 | 77 | 🟡 C | 1 | 4 |
| 2026-10-12 | 83 | 🟢 B | 15 | 3 |
| 2026-10-19 | 82 | 🟢 B | 0 | 3 |
| 2026-10-26 | 80 | 🟢 B | 1 | 3 |
| 2026-11-02 | 81 | 🟢 B | 0 | 2 |
| 2026-11-09 | 79 | 🟡 C | 0 | 2 |

## Grade Distribution

**A** `████████████████████░░░░░░░░░░` 34 repos (68%)
**B** `█░░░░░░░░░░░░░░░░░░░░░░░░░░░░░` 3 repos (6%)
**C** `█░░░░░░░░░░░░░░░░░░░░░░░░░░░░░` 2 repos (4%)
**D** `█░░░░░░░░░░░░░░░░░░░░░░░░░░░░░` 3 repos (6%)
**F** `████░░░░░░░░░░░░░░░░░░░░░░░░░░` 8 repos (16%)

## Most Common Finding Categories

| # | Category | OWASP | Findings | Share |
|--:|----------|:-----:|--------:|------:|
| 1 | Exposed Token | ASI05 | 844 | 89% |
| 2 | Outdated Version | ASI03 | 43 | 5% |
| 3 | Data Exfiltration | ASI05 | 25 | 3% |
| 4 | Malicious Skill | ASI03 | 19 | 2% |
| 5 | Dangerous Pattern | ASI02 | 15 | 2% |
| 6 | Config Drift | ASI10 | 1 | 0% |
| 7 | Supply Chain | ASI03 | 1 | 0% |
| 8 | Insecure Permissions | ASI05 | 1 | 0% |

## Repos Requiring Attention

> 13 repositories scored below B and have actionable findings.

| # | Repository | Grade | Score | Trend | Critical | High | Medium | Low | Total |
|--:|------------|:-----:|------:|:-----:|---------:|-----:|-------:|----:|------:|
| 1 | [ccfos/nightingale](mcp-dashboard/repos/ccfos-nightingale.md) | ![F](https://img.shields.io/badge/F-red?style=flat-square) | 5 | → | 0 | 0 | 31 | 10 | 42 |
| 2 | [headroomlabs-ai/headroom](mcp-dashboard/repos/headroomlabs-ai-headroom.md) | ![F](https://img.shields.io/badge/F-red?style=flat-square) | 5 | ↓ | **1** | **6** | 28 | 53 | 89 |
| 3 | [openclaw/Peekaboo](mcp-dashboard/repos/openclaw-Peekaboo.md) | ![F](https://img.shields.io/badge/F-red?style=flat-square) | 5 | → | 0 | 0 | 55 | 7 | 63 |
| 4 | [wonderwhy-er/DesktopCommanderMCP](mcp-dashboard/repos/wonderwhy-er-DesktopCommanderMCP.md) | ![F](https://img.shields.io/badge/F-red?style=flat-square) | 5 | → | **12** | **7** | 1 | 2 | 23 |
| 5 | [Gentleman-Programming/gentle-ai](mcp-dashboard/repos/Gentleman-Programming-gentle-ai.md) | ![F](https://img.shields.io/badge/F-red?style=flat-square) | 13 | → | 0 | 0 | 24 | 15 | 40 |
| 6 | [FlorianBruniaux/claude-code-ultimate-guide](mcp-dashboard/repos/FlorianBruniaux-claude-code-ultimate-guide.md) | ![F](https://img.shields.io/badge/F-red?style=flat-square) | 30 | → | **1** | **1** | 12 | 12 | 27 |
| 7 | [agentgateway/agentgateway](mcp-dashboard/repos/agentgateway-agentgateway.md) | ![F](https://img.shields.io/badge/F-red?style=flat-square) | 37 | → | 0 | 0 | 16 | 103 | 120 |
| 8 | [DayuanJiang/next-ai-draw-io](mcp-dashboard/repos/DayuanJiang-next-ai-draw-io.md) | ![F](https://img.shields.io/badge/F-red?style=flat-square) | 53 | → | 0 | 0 | 12 | 11 | 24 |
| 9 | [Evil0ctal/Douyin_TikTok_Download_API](mcp-dashboard/repos/Evil0ctal-Douyin_TikTok_Download_API.md) | ![D](https://img.shields.io/badge/D-orange?style=flat-square) | 61 | → | 0 | 0 | 8 | 103 | 112 |
| 10 | [googleapis/mcp-toolbox](mcp-dashboard/repos/googleapis-mcp-toolbox.md) | ![D](https://img.shields.io/badge/D-orange?style=flat-square) | 66 | → | 0 | **1** | 4 | 18 | 24 |
| 11 | [Q00/ouroboros](mcp-dashboard/repos/Q00-ouroboros.md) | ![D](https://img.shields.io/badge/D-orange?style=flat-square) | 67 | ↑ | **1** | 0 | 1 | 48 | 51 |
| 12 | [github/github-mcp-server](mcp-dashboard/repos/github-github-mcp-server.md) | ![C](https://img.shields.io/badge/C-yellow?style=flat-square) | 77 | ↓ | 0 | 0 | 5 | 8 | 14 |
| 13 | [TabularisDB/tabularis](mcp-dashboard/repos/TabularisDB-tabularis.md) | ![C](https://img.shields.io/badge/C-yellow?style=flat-square) | 79 | → | 0 | 0 | 2 | 226 | 229 |

## All Scanned Repos

> 37 repositories scored A or B.

<details>
<summary>View all 37 clean repos</summary>

| Repository | Stars | Grade | Score | Trend |
|------------|------:|:-----:|------:|:-----:|
| [Coding-Solo/godot-mcp](mcp-dashboard/repos/Coding-Solo-godot-mcp.md) | 6,575 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 100 | → |
| [LaurieWired/GhidraMCP](mcp-dashboard/repos/LaurieWired-GhidraMCP.md) | 11,857 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 100 | → |
| [Ryze-AI-Adgent/open-seo-mcp-skills](mcp-dashboard/repos/Ryze-AI-Adgent-open-seo-mcp-skills.md) | 9,019 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 100 | → |
| [activepieces/activepieces](mcp-dashboard/repos/activepieces-activepieces.md) | 25,445 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 100 |  |
| [atilaahmettaner/tradingview-mcp](mcp-dashboard/repos/atilaahmettaner-tradingview-mcp.md) | 5,249 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 100 | → |
| [awslabs/mcp](mcp-dashboard/repos/awslabs-mcp.md) | 9,895 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 100 | → |
| [beenuar/AiSOC](mcp-dashboard/repos/beenuar-AiSOC.md) | 6,880 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 100 |  |
| [bethington/ghidra-mcp](mcp-dashboard/repos/bethington-ghidra-mcp.md) | 6,176 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 100 | → |
| [budtmo/docker-android](mcp-dashboard/repos/budtmo-docker-android.md) | 16,109 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 100 | → |
| [epiral/bb-browser](mcp-dashboard/repos/epiral-bb-browser.md) | 6,259 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 100 | → |
| [hangwin/mcp-chrome](mcp-dashboard/repos/hangwin-mcp-chrome.md) | 12,539 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 100 | → |
| [homarr-labs/dashboard-icons](mcp-dashboard/repos/homarr-labs-dashboard-icons.md) | 9,045 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 100 | → |
| [idosal/git-mcp](mcp-dashboard/repos/idosal-git-mcp.md) | 8,510 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 100 | → |
| [irinabuht12-oss/google-ads-meta-ads-mcp](mcp-dashboard/repos/irinabuht12-oss-google-ads-meta-ads-mcp.md) | 7,159 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 100 | → |
| [jacob-bd/gemini-notebook-mcp-cli](mcp-dashboard/repos/jacob-bd-gemini-notebook-mcp-cli.md) | 6,483 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 100 | → |
| [lharries/whatsapp-mcp](mcp-dashboard/repos/lharries-whatsapp-mcp.md) | 6,844 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 100 | → |
| [liketrek/TREK](mcp-dashboard/repos/liketrek-TREK.md) | 15,456 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 100 |  |
| [t8y2/dbx](mcp-dashboard/repos/t8y2-dbx.md) | 29,706 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 100 | → |
| [webiny/webiny-js](mcp-dashboard/repos/webiny-webiny-js.md) | 8,049 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 100 | → |
| [xerj-org/xerj](mcp-dashboard/repos/xerj-org-xerj.md) | 18,656 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 100 |  |
| [0x4m4/hexstrike-ai](mcp-dashboard/repos/0x4m4-hexstrike-ai.md) | 13,467 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 99 | → |
| [google-labs-code/stitch-skills](mcp-dashboard/repos/google-labs-code-stitch-skills.md) | 8,709 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 99 | → |
| [microsoft/playwright-mcp](mcp-dashboard/repos/microsoft-playwright-mcp.md) | 39,375 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 99 | → |
| [BrowserMCP/mcp](mcp-dashboard/repos/BrowserMCP-mcp.md) | 7,321 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 97 | → |
| [CursorTouch/Windows-MCP](mcp-dashboard/repos/CursorTouch-Windows-MCP.md) | 11,406 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 97 | → |
| [GLips/Figma-Context-MCP](mcp-dashboard/repos/GLips-Figma-Context-MCP.md) | 16,180 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 97 | → |
| [Gentleman-Programming/engram](mcp-dashboard/repos/Gentleman-Programming-engram.md) | 7,872 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 97 | → |
| [exa-labs/exa-mcp-server](mcp-dashboard/repos/exa-labs-exa-mcp-server.md) | 5,219 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 97 | → |
| [firecrawl/firecrawl-mcp-server](mcp-dashboard/repos/firecrawl-firecrawl-mcp-server.md) | 7,788 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 97 | → |
| [getsentry/MobileBuildMCP](mcp-dashboard/repos/getsentry-MobileBuildMCP.md) | 6,555 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 97 | → |
| [sooperset/mcp-atlassian](mcp-dashboard/repos/sooperset-mcp-atlassian.md) | 6,100 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 97 | → |
| [mobile-next/mobile-mcp](mcp-dashboard/repos/mobile-next-mobile-mcp.md) | 10,435 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 94 | → |
| [callstack/agent-device](mcp-dashboard/repos/callstack-agent-device.md) | 5,313 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 92 | → |
| [PrefectHQ/fastmcp](mcp-dashboard/repos/PrefectHQ-fastmcp.md) | 28,362 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 91 | → |
| [BeehiveInnovations/pal-mcp-server](mcp-dashboard/repos/BeehiveInnovations-pal-mcp-server.md) | 11,831 | ![B](https://img.shields.io/badge/B-green?style=flat-square) | 86 | → |
| [kucherenko/jscpd](mcp-dashboard/repos/kucherenko-jscpd.md) | 6,521 | ![B](https://img.shields.io/badge/B-green?style=flat-square) | 85 | → |
| [apify/apify-mcp-server](mcp-dashboard/repos/apify-apify-mcp-server.md) | 15,397 | ![B](https://img.shields.io/badge/B-green?style=flat-square) | 80 | → |

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

*Generated on 2026-11-09 by [agentsec](https://github.com/debu-sinha/agentsec) v0.5.1 | [Install](https://pypi.org/project/agentsec-ai/) | [Report an issue](https://github.com/debu-sinha/agentsec/issues)*
