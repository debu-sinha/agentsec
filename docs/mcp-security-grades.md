# MCP Ecosystem Security Dashboard

![Ecosystem Grade](https://img.shields.io/badge/Ecosystem_Grade-B-green?style=for-the-badge) ![Avg Score](https://img.shields.io/badge/Avg_Score-84%2F100-green?style=for-the-badge) ![Repos Scanned](https://img.shields.io/badge/Repos_Scanned-50-blue?style=for-the-badge) ![Last Updated](https://img.shields.io/badge/Last_Scan-2026-11-23-grey?style=for-the-badge)

Automated weekly security scan of the top MCP server repositories, powered by [agentsec](https://github.com/debu-sinha/agentsec). Findings are mapped to the [OWASP Top 10 for Agentic Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/).

**Jump to:** [Summary](#at-a-glance) | [Grades](#grade-distribution) | [Repos Requiring Attention](#repos-requiring-attention) | [All Repos](#all-scanned-repos) | [Methodology](#methodology) | [Disclaimer](#disclaimer)

> **13 repos** scored below B. **TabularisDB/tabularis** alone has **1 critical** and **240 total findings**.

## At a Glance

| Metric | Value |
|--------|------:|
| Repositories scanned | **50** |
| Total findings | **932** |
| 🔴 Critical | **15** |
| 🟠 High | **9** |
| 🟡 Medium | **238** |
| 🟢 Low | **630** |
| 🔵 Info | **40** |
| Repos with zero critical/high findings | **45** |
| Repos with critical findings | **4** |

## Ecosystem Trend

| Date | Avg Score | Grade | Repos Improving | Repos Degrading |
|------|----------:|:-----:|----------------:|----------------:|
| 2026-10-05 | 77 | 🟡 C | 1 | 4 |
| 2026-10-12 | 83 | 🟢 B | 15 | 3 |
| 2026-10-19 | 82 | 🟢 B | 0 | 3 |
| 2026-10-26 | 80 | 🟢 B | 1 | 3 |
| 2026-11-02 | 81 | 🟢 B | 0 | 2 |
| 2026-11-09 | 79 | 🟡 C | 0 | 2 |
| 2026-11-16 | 77 | 🟡 C | 1 | 5 |
| 2026-11-23 | 80 | 🟢 B | 1 | 3 |

## Grade Distribution

**A** `█████████████████████░░░░░░░░░` 35 repos (70%)
**B** `█░░░░░░░░░░░░░░░░░░░░░░░░░░░░░` 2 repos (4%)
**C** `██░░░░░░░░░░░░░░░░░░░░░░░░░░░░` 4 repos (8%)
**D** `█░░░░░░░░░░░░░░░░░░░░░░░░░░░░░` 2 repos (4%)
**F** `████░░░░░░░░░░░░░░░░░░░░░░░░░░` 7 repos (14%)

## Most Common Finding Categories

| # | Category | OWASP | Findings | Share |
|--:|----------|:-----:|--------:|------:|
| 1 | Exposed Token | ASI05 | 866 | 93% |
| 2 | Outdated Version | ASI03 | 40 | 4% |
| 3 | Malicious Skill | ASI03 | 18 | 2% |
| 4 | Data Exfiltration | ASI05 | 2 | 0% |
| 5 | Config Drift | ASI10 | 1 | 0% |
| 6 | Dangerous Pattern | ASI02 | 1 | 0% |
| 7 | Supply Chain | ASI03 | 1 | 0% |
| 8 | Insecure Permissions | ASI05 | 1 | 0% |

## Repos Requiring Attention

> 13 repositories scored below B and have actionable findings.

| # | Repository | Grade | Score | Trend | Critical | High | Medium | Low | Total |
|--:|------------|:-----:|------:|:-----:|---------:|-----:|-------:|----:|------:|
| 1 | [ccfos/nightingale](mcp-dashboard/repos/ccfos-nightingale.md) | ![F](https://img.shields.io/badge/F-red?style=flat-square) | 5 | → | 0 | 0 | 31 | 10 | 42 |
| 2 | [qybaihe/bla](mcp-dashboard/repos/qybaihe-bla.md) | ![F](https://img.shields.io/badge/F-red?style=flat-square) | 5 | ↓ | 0 | 0 | 111 | 6 | 118 |
| 3 | [wonderwhy-er/DesktopCommanderMCP](mcp-dashboard/repos/wonderwhy-er-DesktopCommanderMCP.md) | ![F](https://img.shields.io/badge/F-red?style=flat-square) | 5 | → | **12** | **7** | 1 | 2 | 23 |
| 4 | [Gentleman-Programming/gentle-ai](mcp-dashboard/repos/Gentleman-Programming-gentle-ai.md) | ![F](https://img.shields.io/badge/F-red?style=flat-square) | 14 | → | 0 | 0 | 24 | 14 | 39 |
| 5 | [FlorianBruniaux/claude-code-ultimate-guide](mcp-dashboard/repos/FlorianBruniaux-claude-code-ultimate-guide.md) | ![F](https://img.shields.io/badge/F-red?style=flat-square) | 29 | → | **1** | **1** | 12 | 13 | 28 |
| 6 | [agentgateway/agentgateway](mcp-dashboard/repos/agentgateway-agentgateway.md) | ![F](https://img.shields.io/badge/F-red?style=flat-square) | 37 | → | 0 | 0 | 16 | 110 | 127 |
| 7 | [DayuanJiang/next-ai-draw-io](mcp-dashboard/repos/DayuanJiang-next-ai-draw-io.md) | ![F](https://img.shields.io/badge/F-red?style=flat-square) | 52 | → | 0 | 0 | 12 | 12 | 25 |
| 8 | [Evil0ctal/Douyin_TikTok_Download_API](mcp-dashboard/repos/Evil0ctal-Douyin_TikTok_Download_API.md) | ![D](https://img.shields.io/badge/D-orange?style=flat-square) | 61 | → | 0 | 0 | 8 | 109 | 118 |
| 9 | [TabularisDB/tabularis](mcp-dashboard/repos/TabularisDB-tabularis.md) | ![D](https://img.shields.io/badge/D-orange?style=flat-square) | 64 | ↓ | **1** | 0 | 2 | 236 | 240 |
| 10 | [googleapis/mcp-toolbox](mcp-dashboard/repos/googleapis-mcp-toolbox.md) | ![C](https://img.shields.io/badge/C-yellow?style=flat-square) | 72 | → | 0 | **1** | 2 | 19 | 23 |
| 11 | [github/github-mcp-server](mcp-dashboard/repos/github-github-mcp-server.md) | ![C](https://img.shields.io/badge/C-yellow?style=flat-square) | 77 | → | 0 | 0 | 5 | 8 | 14 |
| 12 | [apify/apify-mcp-server](mcp-dashboard/repos/apify-apify-mcp-server.md) | ![C](https://img.shields.io/badge/C-yellow?style=flat-square) | 78 | → | 0 | 0 | 3 | 13 | 17 |
| 13 | [czlonkowski/n8n-mcp](mcp-dashboard/repos/czlonkowski-n8n-mcp.md) | ![C](https://img.shields.io/badge/C-yellow?style=flat-square) | 79 | → | 0 | 0 | 2 | 43 | 46 |

## All Scanned Repos

> 37 repositories scored A or B.

<details>
<summary>View all 37 clean repos</summary>

| Repository | Stars | Grade | Score | Trend |
|------------|------:|:-----:|------:|:-----:|
| [Coding-Solo/godot-mcp](mcp-dashboard/repos/Coding-Solo-godot-mcp.md) | 6,743 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 100 | → |
| [LaurieWired/GhidraMCP](mcp-dashboard/repos/LaurieWired-GhidraMCP.md) | 12,013 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 100 | → |
| [Q00/ouroboros](mcp-dashboard/repos/Q00-ouroboros.md) | 6,387 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 100 | ↓ |
| [Ryze-AI-Adgent/open-seo-mcp-skills](mcp-dashboard/repos/Ryze-AI-Adgent-open-seo-mcp-skills.md) | 10,645 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 100 | → |
| [activepieces/activepieces](mcp-dashboard/repos/activepieces-activepieces.md) | 25,688 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 100 |  |
| [awslabs/mcp](mcp-dashboard/repos/awslabs-mcp.md) | 9,944 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 100 | → |
| [beenuar/AiSOC](mcp-dashboard/repos/beenuar-AiSOC.md) | 7,546 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 100 |  |
| [bethington/ghidra-mcp](mcp-dashboard/repos/bethington-ghidra-mcp.md) | 6,328 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 100 | → |
| [budtmo/docker-android](mcp-dashboard/repos/budtmo-docker-android.md) | 16,195 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 100 | → |
| [epiral/bb-browser](mcp-dashboard/repos/epiral-bb-browser.md) | 6,266 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 100 | → |
| [hangwin/mcp-chrome](mcp-dashboard/repos/hangwin-mcp-chrome.md) | 12,558 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 100 | → |
| [headroomlabs-ai/headroom](mcp-dashboard/repos/headroomlabs-ai-headroom.md) | 80,639 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 100 | → |
| [homarr-labs/dashboard-icons](mcp-dashboard/repos/homarr-labs-dashboard-icons.md) | 9,147 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 100 | → |
| [idosal/git-mcp](mcp-dashboard/repos/idosal-git-mcp.md) | 8,533 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 100 | → |
| [irinabuht12-oss/google-ads-meta-ads-mcp](mcp-dashboard/repos/irinabuht12-oss-google-ads-meta-ads-mcp.md) | 8,320 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 100 | → |
| [jacob-bd/gemini-notebook-mcp-cli](mcp-dashboard/repos/jacob-bd-gemini-notebook-mcp-cli.md) | 6,562 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 100 | → |
| [kajisho5/ffmpeg-skill](mcp-dashboard/repos/kajisho5-ffmpeg-skill.md) | 10,115 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 100 | → |
| [lharries/whatsapp-mcp](mcp-dashboard/repos/lharries-whatsapp-mcp.md) | 6,943 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 100 | → |
| [liketrek/TREK](mcp-dashboard/repos/liketrek-TREK.md) | 15,895 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 100 |  |
| [t8y2/dbx](mcp-dashboard/repos/t8y2-dbx.md) | 31,220 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 100 | → |
| [tonhowtf/omniget](mcp-dashboard/repos/tonhowtf-omniget.md) | 14,578 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 100 | → |
| [webiny/webiny-js](mcp-dashboard/repos/webiny-webiny-js.md) | 8,055 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 100 | → |
| [xerj-org/xerj](mcp-dashboard/repos/xerj-org-xerj.md) | 20,207 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 100 |  |
| [0x4m4/hexstrike-ai](mcp-dashboard/repos/0x4m4-hexstrike-ai.md) | 13,846 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 99 | → |
| [microsoft/playwright-mcp](mcp-dashboard/repos/microsoft-playwright-mcp.md) | 40,058 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 99 | → |
| [BrowserMCP/mcp](mcp-dashboard/repos/BrowserMCP-mcp.md) | 7,406 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 97 | → |
| [CursorTouch/Windows-MCP](mcp-dashboard/repos/CursorTouch-Windows-MCP.md) | 12,058 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 97 | → |
| [GLips/Figma-Context-MCP](mcp-dashboard/repos/GLips-Figma-Context-MCP.md) | 16,288 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 97 | → |
| [Gentleman-Programming/engram](mcp-dashboard/repos/Gentleman-Programming-engram.md) | 8,274 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 97 | → |
| [getsentry/MobileBuildMCP](mcp-dashboard/repos/getsentry-MobileBuildMCP.md) | 6,598 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 97 | → |
| [firecrawl/firecrawl-mcp-server](mcp-dashboard/repos/firecrawl-firecrawl-mcp-server.md) | 7,890 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 96 | → |
| [sooperset/mcp-atlassian](mcp-dashboard/repos/sooperset-mcp-atlassian.md) | 6,147 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 95 | → |
| [mobile-next/mobile-mcp](mcp-dashboard/repos/mobile-next-mobile-mcp.md) | 10,825 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 94 | → |
| [google-labs-code/stitch-skills](mcp-dashboard/repos/google-labs-code-stitch-skills.md) | 12,180 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 93 | ↓ |
| [PrefectHQ/fastmcp](mcp-dashboard/repos/PrefectHQ-fastmcp.md) | 28,719 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 91 | → |
| [BeehiveInnovations/pal-mcp-server](mcp-dashboard/repos/BeehiveInnovations-pal-mcp-server.md) | 11,847 | ![B](https://img.shields.io/badge/B-green?style=flat-square) | 86 | → |
| [kucherenko/jscpd](mcp-dashboard/repos/kucherenko-jscpd.md) | 6,604 | ![B](https://img.shields.io/badge/B-green?style=flat-square) | 85 | → |

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

*Generated on 2026-11-23 by [agentsec](https://github.com/debu-sinha/agentsec) v0.5.2 | [Install](https://pypi.org/project/agentsec-ai/) | [Report an issue](https://github.com/debu-sinha/agentsec/issues)*
