# MCP Ecosystem Security Dashboard

![Ecosystem Grade](https://img.shields.io/badge/Ecosystem_Grade-B-green?style=for-the-badge) ![Avg Score](https://img.shields.io/badge/Avg_Score-89%2F100-green?style=for-the-badge) ![Repos Scanned](https://img.shields.io/badge/Repos_Scanned-49-blue?style=for-the-badge) ![Last Updated](https://img.shields.io/badge/Last_Scan-2026-02-17-grey?style=for-the-badge)

Automated weekly security scan of the top MCP server repositories, powered by [agentsec](https://github.com/debu-sinha/agentsec). Findings are mapped to the [OWASP Top 10 for Agentic Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/).

**Jump to:** [Summary](#at-a-glance) | [Grades](#grade-distribution) | [Repos Requiring Attention](#repos-requiring-attention) | [All Repos](#all-scanned-repos) | [Methodology](#methodology) | [Disclaimer](#disclaimer)

> **9 repos** scored below B. **mindsdb/mindsdb** alone has **4 critical** and **145 total findings**.

## At a Glance

| Metric | Value |
|--------|------:|
| Repositories scanned | **49** |
| Total findings | **516** |
| 🔴 Critical | **9** |
| 🟠 High | **4** |
| 🟡 Medium | **92** |
| 🟢 Low | **363** |
| 🔵 Info | **48** |
| Repos with zero critical/high findings | **42** |
| Repos with critical findings | **5** |

## Grade Distribution

**A** `██████████████████░░░░░░░░░░░░` 31 repos (63%)
**B** `█████░░░░░░░░░░░░░░░░░░░░░░░░░` 9 repos (18%)
**C** `█░░░░░░░░░░░░░░░░░░░░░░░░░░░░░` 3 repos (6%)
**D** `█░░░░░░░░░░░░░░░░░░░░░░░░░░░░░` 3 repos (6%)
**F** `█░░░░░░░░░░░░░░░░░░░░░░░░░░░░░` 3 repos (6%)

## Most Common Finding Categories

| # | Category | OWASP | Findings | Share |
|--:|----------|:-----:|--------:|------:|
| 1 | Exposed Token | ASI05 | 465 | 90% |
| 2 | Outdated Version | ASI03 | 48 | 9% |
| 3 | Config Drift | ASI10 | 2 | 0% |
| 4 | Insecure Permissions | ASI05 | 1 | 0% |

## Repos Requiring Attention

> 9 repositories scored below B and have actionable findings.

| # | Repository | Grade | Score | Trend | Critical | High | Medium | Low | Total |
|--:|------------|:-----:|------:|:-----:|---------:|-----:|-------:|----:|------:|
| 1 | [mindsdb/mindsdb](mcp-dashboard/repos/mindsdb-mindsdb.md) | ![F](https://img.shields.io/badge/F-red?style=flat-square) | 5 |  | **4** | **1** | 16 | 123 | 145 |
| 2 | [jlowin/fastmcp](mcp-dashboard/repos/jlowin-fastmcp.md) | ![F](https://img.shields.io/badge/F-red?style=flat-square) | 55 |  | 0 | 0 | 10 | 25 | 36 |
| 3 | [opensumi/core](mcp-dashboard/repos/opensumi-core.md) | ![F](https://img.shields.io/badge/F-red?style=flat-square) | 55 |  | **2** | 0 | 5 | 0 | 8 |
| 4 | [BeehiveInnovations/pal-mcp-server](mcp-dashboard/repos/BeehiveInnovations-pal-mcp-server.md) | ![D](https://img.shields.io/badge/D-orange?style=flat-square) | 60 |  | 0 | **1** | 6 | 47 | 55 |
| 5 | [awslabs/mcp](mcp-dashboard/repos/awslabs-mcp.md) | ![D](https://img.shields.io/badge/D-orange?style=flat-square) | 64 |  | 0 | 0 | 7 | 61 | 69 |
| 6 | [steipete/Peekaboo](mcp-dashboard/repos/steipete-Peekaboo.md) | ![D](https://img.shields.io/badge/D-orange?style=flat-square) | 67 |  | **1** | **1** | 3 | 2 | 8 |
| 7 | [AmoyLab/Unla](mcp-dashboard/repos/AmoyLab-Unla.md) | ![C](https://img.shields.io/badge/C-yellow?style=flat-square) | 70 |  | 0 | 0 | 10 | 0 | 10 |
| 8 | [googleapis/genai-toolbox](mcp-dashboard/repos/googleapis-genai-toolbox.md) | ![C](https://img.shields.io/badge/C-yellow?style=flat-square) | 73 |  | 0 | 0 | 4 | 18 | 23 |
| 9 | [kreuzberg-dev/kreuzberg](mcp-dashboard/repos/kreuzberg-dev-kreuzberg.md) | ![C](https://img.shields.io/badge/C-yellow?style=flat-square) | 76 |  | **1** | 0 | 2 | 3 | 7 |

## All Scanned Repos

> 40 repositories scored A or B.

<details>
<summary>View all 40 clean repos</summary>

| Repository | Stars | Grade | Score | Trend |
|------------|------:|:-----:|------:|:-----:|
| [0x4m4/hexstrike-ai](mcp-dashboard/repos/0x4m4-hexstrike-ai.md) | 6,886 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 100 |  |
| [BrowserMCP/mcp](mcp-dashboard/repos/BrowserMCP-mcp.md) | 5,795 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 100 |  |
| [GLips/Figma-Context-MCP](mcp-dashboard/repos/GLips-Figma-Context-MCP.md) | 13,154 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 100 |  |
| [Jpisnice/shadcn-ui-mcp-server](mcp-dashboard/repos/Jpisnice-shadcn-ui-mcp-server.md) | 2,651 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 100 |  |
| [LaurieWired/GhidraMCP](mcp-dashboard/repos/LaurieWired-GhidraMCP.md) | 7,617 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 100 |  |
| [MarkusPfundstein/mcp-obsidian](mcp-dashboard/repos/MarkusPfundstein-mcp-obsidian.md) | 2,856 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 100 |  |
| [Minidoracat/mcp-feedback-enhanced](mcp-dashboard/repos/Minidoracat-mcp-feedback-enhanced.md) | 3,568 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 100 |  |
| [Pimzino/spec-workflow-mcp](mcp-dashboard/repos/Pimzino-spec-workflow-mcp.md) | 3,888 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 100 |  |
| [activepieces/activepieces](mcp-dashboard/repos/activepieces-activepieces.md) | 20,852 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 100 |  |
| [antvis/mcp-server-chart](mcp-dashboard/repos/antvis-mcp-server-chart.md) | 3,677 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 100 |  |
| [blazickjp/arxiv-mcp-server](mcp-dashboard/repos/blazickjp-arxiv-mcp-server.md) | 2,181 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 100 |  |
| [brightdata/brightdata-mcp](mcp-dashboard/repos/brightdata-brightdata-mcp.md) | 2,033 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 100 |  |
| [getsentry/XcodeBuildMCP](mcp-dashboard/repos/getsentry-XcodeBuildMCP.md) | 4,328 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 100 |  |
| [hangwin/mcp-chrome](mcp-dashboard/repos/hangwin-mcp-chrome.md) | 10,407 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 100 |  |
| [haris-musa/excel-mcp-server](mcp-dashboard/repos/haris-musa-excel-mcp-server.md) | 3,339 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 100 |  |
| [jamubc/gemini-mcp-tool](mcp-dashboard/repos/jamubc-gemini-mcp-tool.md) | 1,988 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 100 |  |
| [laravel/boost](mcp-dashboard/repos/laravel-boost.md) | 3,257 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 100 |  |
| [lharries/whatsapp-mcp](mcp-dashboard/repos/lharries-whatsapp-mcp.md) | 5,329 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 100 |  |
| [makenotion/notion-mcp-server](mcp-dashboard/repos/makenotion-notion-mcp-server.md) | 3,887 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 100 |  |
| [oraios/serena](mcp-dashboard/repos/oraios-serena.md) | 20,321 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 100 |  |
| [microsoft/playwright-mcp](mcp-dashboard/repos/microsoft-playwright-mcp.md) | 27,282 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 98 |  |
| [21st-dev/magic-mcp](mcp-dashboard/repos/21st-dev-magic-mcp.md) | 4,271 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 97 |  |
| [agentset-ai/agentset](mcp-dashboard/repos/agentset-ai-agentset.md) | 1,861 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 97 |  |
| [cloudflare/mcp-server-cloudflare](mcp-dashboard/repos/cloudflare-mcp-server-cloudflare.md) | 3,417 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 97 |  |
| [exa-labs/exa-mcp-server](mcp-dashboard/repos/exa-labs-exa-mcp-server.md) | 3,811 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 97 |  |
| [idosal/git-mcp](mcp-dashboard/repos/idosal-git-mcp.md) | 7,595 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 97 |  |
| [cyberagiinc/DevDocs](mcp-dashboard/repos/cyberagiinc-DevDocs.md) | 2,027 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 95 |  |
| [upstash/context7](mcp-dashboard/repos/upstash-context7.md) | 45,985 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 95 |  |
| [CursorTouch/Windows-MCP](mcp-dashboard/repos/CursorTouch-Windows-MCP.md) | 4,357 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 94 |  |
| [firecrawl/firecrawl-mcp-server](mcp-dashboard/repos/firecrawl-firecrawl-mcp-server.md) | 5,516 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 94 |  |
| [perplexityai/modelcontextprotocol](mcp-dashboard/repos/perplexityai-modelcontextprotocol.md) | 1,956 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 93 |  |
| [github/github-mcp-server](mcp-dashboard/repos/github-github-mcp-server.md) | 27,019 | ![B](https://img.shields.io/badge/B-green?style=flat-square) | 89 |  |
| [browserbase/mcp-server-browserbase](mcp-dashboard/repos/browserbase-mcp-server-browserbase.md) | 3,131 | ![B](https://img.shields.io/badge/B-green?style=flat-square) | 88 |  |
| [sooperset/mcp-atlassian](mcp-dashboard/repos/sooperset-mcp-atlassian.md) | 4,302 | ![B](https://img.shields.io/badge/B-green?style=flat-square) | 87 |  |
| [punkpeye/fastmcp](mcp-dashboard/repos/punkpeye-fastmcp.md) | 2,943 | ![B](https://img.shields.io/badge/B-green?style=flat-square) | 86 |  |
| [bytebase/dbhub](mcp-dashboard/repos/bytebase-dbhub.md) | 2,128 | ![B](https://img.shields.io/badge/B-green?style=flat-square) | 85 |  |
| [u14app/deep-research](mcp-dashboard/repos/u14app-deep-research.md) | 4,430 | ![B](https://img.shields.io/badge/B-green?style=flat-square) | 85 |  |
| [aipotheosis-labs/aci](mcp-dashboard/repos/aipotheosis-labs-aci.md) | 4,713 | ![B](https://img.shields.io/badge/B-green?style=flat-square) | 82 |  |
| [grafana/mcp-grafana](mcp-dashboard/repos/grafana-mcp-grafana.md) | 2,317 | ![B](https://img.shields.io/badge/B-green?style=flat-square) | 82 |  |
| [wonderwhy-er/DesktopCommanderMCP](mcp-dashboard/repos/wonderwhy-er-DesktopCommanderMCP.md) | 5,472 | ![B](https://img.shields.io/badge/B-green?style=flat-square) | 81 |  |

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

*Generated on 2026-02-17 by [agentsec](https://github.com/debu-sinha/agentsec) v0.4.5 | [Install](https://pypi.org/project/agentsec-ai/) | [Report an issue](https://github.com/debu-sinha/agentsec/issues)*
