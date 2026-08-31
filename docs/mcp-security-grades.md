# MCP Ecosystem Security Dashboard

![Ecosystem Grade](https://img.shields.io/badge/Ecosystem_Grade-B-green?style=for-the-badge) ![Avg Score](https://img.shields.io/badge/Avg_Score-80%2F100-green?style=for-the-badge) ![Repos Scanned](https://img.shields.io/badge/Repos_Scanned-50-blue?style=for-the-badge) ![Last Updated](https://img.shields.io/badge/Last_Scan-2026-08-31-grey?style=for-the-badge)

Automated weekly security scan of the top MCP server repositories, powered by [agentsec](https://github.com/debu-sinha/agentsec). Findings are mapped to the [OWASP Top 10 for Agentic Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/).

**Jump to:** [Summary](#at-a-glance) | [Grades](#grade-distribution) | [Repos Requiring Attention](#repos-requiring-attention) | [All Repos](#all-scanned-repos) | [Methodology](#methodology) | [Disclaimer](#disclaimer)

> **14 repos** scored below B. **TabularisDB/tabularis** alone has **0 critical** and **218 total findings**.

## At a Glance

| Metric | Value |
|--------|------:|
| Repositories scanned | **50** |
| Total findings | **960** |
| 🔴 Critical | **18** |
| 🟠 High | **17** |
| 🟡 Medium | **478** |
| 🟢 Low | **402** |
| 🔵 Info | **45** |
| Repos with zero critical/high findings | **41** |
| Repos with critical findings | **6** |

## Ecosystem Trend

| Date | Avg Score | Grade | Repos Improving | Repos Degrading |
|------|----------:|:-----:|----------------:|----------------:|
| 2026-07-13 | 83 | 🟢 B | 0 | 5 |
| 2026-07-20 | 80 | 🟢 B | 0 | 4 |
| 2026-07-27 | 76 | 🟡 C | 0 | 3 |
| 2026-08-03 | 77 | 🟡 C | 1 | 3 |
| 2026-08-10 | 76 | 🟡 C | 1 | 1 |
| 2026-08-17 | 76 | 🟡 C | 0 | 4 |
| 2026-08-24 | 77 | 🟡 C | 2 | 0 |
| 2026-08-31 | 77 | 🟡 C | 0 | 2 |

## Grade Distribution

**A** `███████████████████░░░░░░░░░░░` 33 repos (66%)
**B** `█░░░░░░░░░░░░░░░░░░░░░░░░░░░░░` 3 repos (6%)
**C** `█░░░░░░░░░░░░░░░░░░░░░░░░░░░░░` 2 repos (4%)
**D** `█░░░░░░░░░░░░░░░░░░░░░░░░░░░░░` 2 repos (4%)
**F** `██████░░░░░░░░░░░░░░░░░░░░░░░░` 10 repos (20%)

## Most Common Finding Categories

| # | Category | OWASP | Findings | Share |
|--:|----------|:-----:|--------:|------:|
| 1 | Exposed Token | ASI05 | 875 | 91% |
| 2 | Outdated Version | ASI03 | 45 | 5% |
| 3 | Malicious Skill | ASI03 | 20 | 2% |
| 4 | Dangerous Pattern | ASI02 | 8 | 1% |
| 5 | Data Exfiltration | ASI05 | 7 | 1% |
| 6 | Config Drift | ASI10 | 1 | 0% |
| 7 | Insecure Permissions | ASI05 | 1 | 0% |
| 8 | Exposed Credentials | ASI05 | 1 | 0% |

## Repos Requiring Attention

> 14 repositories scored below B and have actionable findings.

| # | Repository | Grade | Score | Trend | Critical | High | Medium | Low | Total |
|--:|------------|:-----:|------:|:-----:|---------:|-----:|-------:|----:|------:|
| 1 | [MODSetter/SurfSense](mcp-dashboard/repos/MODSetter-SurfSense.md) | ![F](https://img.shields.io/badge/F-red?style=flat-square) | 5 | → | **1** | **1** | 73 | 24 | 100 |
| 2 | [TabularisDB/tabularis](mcp-dashboard/repos/TabularisDB-tabularis.md) | ![F](https://img.shields.io/badge/F-red?style=flat-square) | 5 | → | 0 | 0 | 208 | 9 | 218 |
| 3 | [homeassistant-ai/ha-mcp](mcp-dashboard/repos/homeassistant-ai-ha-mcp.md) | ![F](https://img.shields.io/badge/F-red?style=flat-square) | 5 | → | 0 | **3** | 70 | 36 | 110 |
| 4 | [openclaw/Peekaboo](mcp-dashboard/repos/openclaw-Peekaboo.md) | ![F](https://img.shields.io/badge/F-red?style=flat-square) | 5 | → | 0 | 0 | 41 | 13 | 55 |
| 5 | [wonderwhy-er/DesktopCommanderMCP](mcp-dashboard/repos/wonderwhy-er-DesktopCommanderMCP.md) | ![F](https://img.shields.io/badge/F-red?style=flat-square) | 5 | → | **12** | **7** | 0 | 0 | 20 |
| 6 | [agentgateway/agentgateway](mcp-dashboard/repos/agentgateway-agentgateway.md) | ![F](https://img.shields.io/badge/F-red?style=flat-square) | 16 | → | 0 | 0 | 23 | 108 | 132 |
| 7 | [headroomlabs-ai/headroom](mcp-dashboard/repos/headroomlabs-ai-headroom.md) | ![F](https://img.shields.io/badge/F-red?style=flat-square) | 25 | → | **1** | **3** | 8 | 36 | 49 |
| 8 | [FlorianBruniaux/claude-code-ultimate-guide](mcp-dashboard/repos/FlorianBruniaux-claude-code-ultimate-guide.md) | ![F](https://img.shields.io/badge/F-red?style=flat-square) | 30 | → | **1** | **1** | 12 | 12 | 27 |
| 9 | [u14app/deep-research](mcp-dashboard/repos/u14app-deep-research.md) | ![F](https://img.shields.io/badge/F-red?style=flat-square) | 40 | → | 0 | 0 | 20 | 0 | 21 |
| 10 | [Q00/ouroboros](mcp-dashboard/repos/Q00-ouroboros.md) | ![F](https://img.shields.io/badge/F-red?style=flat-square) | 52 | → | **2** | 0 | 1 | 26 | 30 |
| 11 | [PrefectHQ/fastmcp](mcp-dashboard/repos/PrefectHQ-fastmcp.md) | ![D](https://img.shields.io/badge/D-orange?style=flat-square) | 61 | → | **1** | 0 | 3 | 32 | 37 |
| 12 | [googleapis/mcp-toolbox](mcp-dashboard/repos/googleapis-mcp-toolbox.md) | ![D](https://img.shields.io/badge/D-orange?style=flat-square) | 66 | → | 0 | **1** | 4 | 19 | 25 |
| 13 | [BeehiveInnovations/pal-mcp-server](mcp-dashboard/repos/BeehiveInnovations-pal-mcp-server.md) | ![C](https://img.shields.io/badge/C-yellow?style=flat-square) | 74 | → | 0 | 0 | 5 | 11 | 17 |
| 14 | [CodeGraphContext/CodeGraphContext](mcp-dashboard/repos/CodeGraphContext-CodeGraphContext.md) | ![C](https://img.shields.io/badge/C-yellow?style=flat-square) | 78 | → | 0 | **1** | 0 | 19 | 21 |

## All Scanned Repos

> 36 repositories scored A or B.

<details>
<summary>View all 36 clean repos</summary>

| Repository | Stars | Grade | Score | Trend |
|------------|------:|:-----:|------:|:-----:|
| [BrowserMCP/mcp](mcp-dashboard/repos/BrowserMCP-mcp.md) | 7,032 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 100 | → |
| [Coding-Solo/godot-mcp](mcp-dashboard/repos/Coding-Solo-godot-mcp.md) | 5,441 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 100 | → |
| [DeusData/codebase-memory-mcp](mcp-dashboard/repos/DeusData-codebase-memory-mcp.md) | 41,424 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 100 | → |
| [LaurieWired/GhidraMCP](mcp-dashboard/repos/LaurieWired-GhidraMCP.md) | 9,895 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 100 | → |
| [MarkusPfundstein/mcp-obsidian](mcp-dashboard/repos/MarkusPfundstein-mcp-obsidian.md) | 4,357 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 100 | → |
| [Pimzino/spec-workflow-mcp](mcp-dashboard/repos/Pimzino-spec-workflow-mcp.md) | 4,291 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 100 | → |
| [activepieces/activepieces](mcp-dashboard/repos/activepieces-activepieces.md) | 24,144 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 100 |  |
| [antvis/mcp-server-chart](mcp-dashboard/repos/antvis-mcp-server-chart.md) | 4,346 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 100 | → |
| [atilaahmettaner/tradingview-mcp](mcp-dashboard/repos/atilaahmettaner-tradingview-mcp.md) | 4,308 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 100 | → |
| [awslabs/mcp](mcp-dashboard/repos/awslabs-mcp.md) | 9,646 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 100 | → |
| [epiral/bb-browser](mcp-dashboard/repos/epiral-bb-browser.md) | 6,158 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 100 | → |
| [hangwin/mcp-chrome](mcp-dashboard/repos/hangwin-mcp-chrome.md) | 12,363 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 100 | → |
| [haris-musa/excel-mcp-server](mcp-dashboard/repos/haris-musa-excel-mcp-server.md) | 4,145 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 100 | → |
| [jacob-bd/gemini-notebook-mcp-cli](mcp-dashboard/repos/jacob-bd-gemini-notebook-mcp-cli.md) | 5,982 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 100 | → |
| [kucherenko/jscpd](mcp-dashboard/repos/kucherenko-jscpd.md) | 6,082 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 100 | → |
| [lharries/whatsapp-mcp](mcp-dashboard/repos/lharries-whatsapp-mcp.md) | 6,216 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 100 | → |
| [makenotion/notion-mcp-server](mcp-dashboard/repos/makenotion-notion-mcp-server.md) | 4,617 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 100 | → |
| [t8y2/dbx](mcp-dashboard/repos/t8y2-dbx.md) | 17,564 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 100 | → |
| [webiny/webiny-js](mcp-dashboard/repos/webiny-webiny-js.md) | 8,031 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 100 | → |
| [xberg-io/xberg](mcp-dashboard/repos/xberg-io-xberg.md) | 9,238 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 100 |  |
| [0x4m4/hexstrike-ai](mcp-dashboard/repos/0x4m4-hexstrike-ai.md) | 11,463 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 99 | → |
| [google-labs-code/stitch-skills](mcp-dashboard/repos/google-labs-code-stitch-skills.md) | 8,224 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 99 | → |
| [microsoft/playwright-mcp](mcp-dashboard/repos/microsoft-playwright-mcp.md) | 36,652 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 99 | → |
| [CursorTouch/Windows-MCP](mcp-dashboard/repos/CursorTouch-Windows-MCP.md) | 6,858 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 97 | → |
| [GLips/Figma-Context-MCP](mcp-dashboard/repos/GLips-Figma-Context-MCP.md) | 15,742 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 97 | → |
| [exa-labs/exa-mcp-server](mcp-dashboard/repos/exa-labs-exa-mcp-server.md) | 4,947 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 97 | → |
| [firecrawl/firecrawl-mcp-server](mcp-dashboard/repos/firecrawl-firecrawl-mcp-server.md) | 7,357 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 97 | → |
| [getsentry/XcodeBuildMCP](mcp-dashboard/repos/getsentry-XcodeBuildMCP.md) | 6,314 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 97 | → |
| [idosal/git-mcp](mcp-dashboard/repos/idosal-git-mcp.md) | 8,364 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 97 | → |
| [aipotheosis-labs/aci](mcp-dashboard/repos/aipotheosis-labs-aci.md) | 4,887 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 95 | → |
| [Gentleman-Programming/engram](mcp-dashboard/repos/Gentleman-Programming-engram.md) | 6,242 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 94 | → |
| [prest/prest](mcp-dashboard/repos/prest-prest.md) | 4,612 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 93 | → |
| [callstack/agent-device](mcp-dashboard/repos/callstack-agent-device.md) | 4,295 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 90 | → |
| [apify/apify-mcp-server](mcp-dashboard/repos/apify-apify-mcp-server.md) | 5,476 | ![B](https://img.shields.io/badge/B-green?style=flat-square) | 88 | → |
| [sooperset/mcp-atlassian](mcp-dashboard/repos/sooperset-mcp-atlassian.md) | 5,815 | ![B](https://img.shields.io/badge/B-green?style=flat-square) | 88 | → |
| [github/github-mcp-server](mcp-dashboard/repos/github-github-mcp-server.md) | 32,621 | ![B](https://img.shields.io/badge/B-green?style=flat-square) | 86 | → |

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

*Generated on 2026-08-31 by [agentsec](https://github.com/debu-sinha/agentsec) v0.5.0 | [Install](https://pypi.org/project/agentsec-ai/) | [Report an issue](https://github.com/debu-sinha/agentsec/issues)*
