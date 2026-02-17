# MCP Ecosystem Security Dashboard

![Ecosystem Grade](https://img.shields.io/badge/Ecosystem_Grade-B-green?style=for-the-badge) ![Avg Score](https://img.shields.io/badge/Avg_Score-82%2F100-green?style=for-the-badge) ![Repos Scanned](https://img.shields.io/badge/Repos_Scanned-50-blue?style=for-the-badge) ![Last Updated](https://img.shields.io/badge/Last_Scan-2026-02-15-grey?style=for-the-badge)

Automated weekly security scan of the top MCP server repositories, powered by [agentsec](https://github.com/debu-sinha/agentsec). Findings are mapped to the [OWASP Top 10 for Agentic Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/).

## At a Glance

| Metric | Value |
|--------|------:|
| Repositories scanned | **50** |
| Total findings | **255** |
| 🔴 Critical | **71** |
| 🟠 High | **74** |
| 🟡 Medium | **53** |
| 🟢 Low | **8** |
| 🔵 Info | **49** |
| Repos with zero critical/high findings | **1** |
| Repos with critical findings | **8** |

## Grade Distribution

**A** `██████████████████████░░░░░░░░` 38 repos (76%)
**B** `███░░░░░░░░░░░░░░░░░░░░░░░░░░░` 5 repos (10%)
**C** `█░░░░░░░░░░░░░░░░░░░░░░░░░░░░░` 2 repos (4%)
**D** `░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░` 0 repos (0%)
**F** `███░░░░░░░░░░░░░░░░░░░░░░░░░░░` 5 repos (10%)

## Most Common Finding Categories

| # | Category | Findings | Share |
|--:|----------|--------:|------:|
| 1 | Exposed Token | 78 | 31% |
| 2 | Outdated Version | 49 | 19% |
| 3 | Insecure Default | 49 | 19% |
| 4 | Plaintext Secret | 38 | 15% |
| 5 | Dangerous Pattern | 25 | 10% |
| 6 | Data Exfiltration | 5 | 2% |
| 7 | Prompt Injection | 5 | 2% |
| 8 | Config Drift | 4 | 2% |

## Security Leaderboard

> Sorted by security score (highest first). Grade badges link to the repository on GitHub.

| # | Repository | Stars | Grade | Score | Crit | High | Med | Low | Total |
|--:|------------|------:|:-----:|------:|-----:|-----:|----:|----:|------:|
| 1 | [AmoyLab/Unla](https://github.com/AmoyLab/Unla) | 2,035 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 100 | 0 | 0 | 0 | 0 | 0 |
| 2 | [0x4m4/hexstrike-ai](https://github.com/0x4m4/hexstrike-ai) | 6,830 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 92 | 0 | **1** | 0 | 0 | 2 |
| 3 | [21st-dev/magic-mcp](https://github.com/21st-dev/magic-mcp) | 4,264 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 92 | 0 | **1** | 0 | 0 | 2 |
| 4 | [BrowserMCP/mcp](https://github.com/BrowserMCP/mcp) | 5,779 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 92 | 0 | **1** | 0 | 0 | 2 |
| 5 | [GLips/Figma-Context-MCP](https://github.com/GLips/Figma-Context-MCP) | 13,141 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 92 | 0 | **1** | 0 | 0 | 2 |
| 6 | [Jpisnice/shadcn-ui-mcp-server](https://github.com/Jpisnice/shadcn-ui-mcp-server) | 2,650 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 92 | 0 | **1** | 0 | 0 | 2 |
| 7 | [LaurieWired/GhidraMCP](https://github.com/LaurieWired/GhidraMCP) | 7,580 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 92 | 0 | **1** | 0 | 0 | 2 |
| 8 | [MarkusPfundstein/mcp-obsidian](https://github.com/MarkusPfundstein/mcp-obsidian) | 2,850 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 92 | 0 | **1** | 0 | 0 | 2 |
| 9 | [Minidoracat/mcp-feedback-enhanced](https://github.com/Minidoracat/mcp-feedback-enhanced) | 3,568 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 92 | 0 | **1** | 0 | 0 | 2 |
| 10 | [Pimzino/spec-workflow-mcp](https://github.com/Pimzino/spec-workflow-mcp) | 3,889 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 92 | 0 | **1** | 0 | 0 | 2 |
| 11 | [activepieces/activepieces](https://github.com/activepieces/activepieces) | 20,841 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 92 | 0 | **1** | 0 | 0 | 2 |
| 12 | [agentset-ai/agentset](https://github.com/agentset-ai/agentset) | 1,857 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 92 | 0 | **1** | 0 | 0 | 2 |
| 13 | [antvis/mcp-server-chart](https://github.com/antvis/mcp-server-chart) | 3,670 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 92 | 0 | **1** | 0 | 0 | 2 |
| 14 | [blazickjp/arxiv-mcp-server](https://github.com/blazickjp/arxiv-mcp-server) | 2,174 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 92 | 0 | **1** | 0 | 0 | 2 |
| 15 | [brightdata/brightdata-mcp](https://github.com/brightdata/brightdata-mcp) | 2,028 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 92 | 0 | **1** | 0 | 0 | 2 |
| 16 | [browserbase/mcp-server-browserbase](https://github.com/browserbase/mcp-server-browserbase) | 3,131 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 92 | 0 | **1** | 0 | 0 | 2 |
| 17 | [cloudflare/mcp-server-cloudflare](https://github.com/cloudflare/mcp-server-cloudflare) | 3,413 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 92 | 0 | **1** | 0 | 0 | 2 |
| 18 | [cyberagiinc/DevDocs](https://github.com/cyberagiinc/DevDocs) | 2,027 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 92 | 0 | **1** | 0 | 0 | 2 |
| 19 | [exa-labs/exa-mcp-server](https://github.com/exa-labs/exa-mcp-server) | 3,800 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 92 | 0 | **1** | 0 | 0 | 2 |
| 20 | [firecrawl/firecrawl-mcp-server](https://github.com/firecrawl/firecrawl-mcp-server) | 5,503 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 92 | 0 | **1** | 0 | 0 | 2 |
| 21 | [getsentry/XcodeBuildMCP](https://github.com/getsentry/XcodeBuildMCP) | 4,294 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 92 | 0 | **1** | 0 | 0 | 2 |
| 22 | [github/github-mcp-server](https://github.com/github/github-mcp-server) | 26,952 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 92 | 0 | **1** | 0 | 0 | 2 |
| 23 | [googleapis/genai-toolbox](https://github.com/googleapis/genai-toolbox) | 12,990 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 92 | 0 | **1** | 0 | 0 | 2 |
| 24 | [grafana/mcp-grafana](https://github.com/grafana/mcp-grafana) | 2,307 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 92 | 0 | **1** | 0 | 0 | 2 |
| 25 | [hangwin/mcp-chrome](https://github.com/hangwin/mcp-chrome) | 10,395 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 92 | 0 | **1** | 0 | 0 | 2 |
| 26 | [haris-musa/excel-mcp-server](https://github.com/haris-musa/excel-mcp-server) | 3,334 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 92 | 0 | **1** | 0 | 0 | 2 |
| 27 | [idosal/git-mcp](https://github.com/idosal/git-mcp) | 7,586 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 92 | 0 | **1** | 0 | 0 | 2 |
| 28 | [jamubc/gemini-mcp-tool](https://github.com/jamubc/gemini-mcp-tool) | 1,981 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 92 | 0 | **1** | 0 | 0 | 2 |
| 29 | [kreuzberg-dev/kreuzberg](https://github.com/kreuzberg-dev/kreuzberg) | 5,988 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 92 | 0 | **1** | 0 | 0 | 2 |
| 30 | [laravel/boost](https://github.com/laravel/boost) | 3,250 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 92 | 0 | **1** | 0 | 0 | 2 |
| 31 | [lharries/whatsapp-mcp](https://github.com/lharries/whatsapp-mcp) | 5,320 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 92 | 0 | **1** | 0 | 0 | 2 |
| 32 | [makenotion/notion-mcp-server](https://github.com/makenotion/notion-mcp-server) | 3,879 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 92 | 0 | **1** | 0 | 0 | 2 |
| 33 | [opensumi/core](https://github.com/opensumi/core) | 3,600 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 92 | 0 | **1** | 0 | 0 | 2 |
| 34 | [oraios/serena](https://github.com/oraios/serena) | 20,249 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 92 | 0 | **1** | 0 | 0 | 2 |
| 35 | [perplexityai/modelcontextprotocol](https://github.com/perplexityai/modelcontextprotocol) | 1,950 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 92 | 0 | **1** | 0 | 0 | 2 |
| 36 | [punkpeye/fastmcp](https://github.com/punkpeye/fastmcp) | 2,939 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 92 | 0 | **1** | 0 | 0 | 2 |
| 37 | [sooperset/mcp-atlassian](https://github.com/sooperset/mcp-atlassian) | 4,278 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 92 | 0 | **1** | 0 | 0 | 2 |
| 38 | [upstash/context7](https://github.com/upstash/context7) | 45,808 | ![A](https://img.shields.io/badge/A-brightgreen?style=flat-square) | 92 | 0 | **1** | 0 | 0 | 2 |
| 39 | [CursorTouch/Windows-MCP](https://github.com/CursorTouch/Windows-MCP) | 4,342 | ![B](https://img.shields.io/badge/B-green?style=flat-square) | 89 | 0 | **1** | 1 | 0 | 3 |
| 40 | [microsoft/playwright-mcp](https://github.com/microsoft/playwright-mcp) | 27,181 | ![B](https://img.shields.io/badge/B-green?style=flat-square) | 89 | 0 | **1** | 1 | 0 | 3 |
| 41 | [aipotheosis-labs/aci](https://github.com/aipotheosis-labs/aci) | 4,713 | ![B](https://img.shields.io/badge/B-green?style=flat-square) | 84 | 0 | **2** | 0 | 0 | 3 |
| 42 | [wonderwhy-er/DesktopCommanderMCP](https://github.com/wonderwhy-er/DesktopCommanderMCP) | 5,467 | ![B](https://img.shields.io/badge/B-green?style=flat-square) | 84 | 0 | **2** | 0 | 0 | 3 |
| 43 | [u14app/deep-research](https://github.com/u14app/deep-research) | 4,426 | ![B](https://img.shields.io/badge/B-green?style=flat-square) | 77 | **1** | **1** | 0 | 0 | 3 |
| 44 | [steipete/Peekaboo](https://github.com/steipete/Peekaboo) | 2,110 | ![C](https://img.shields.io/badge/C-yellow?style=flat-square) | 69 | **1** | **2** | 0 | 0 | 4 |
| 45 | [jlowin/fastmcp](https://github.com/jlowin/fastmcp) | 22,850 | ![C](https://img.shields.io/badge/C-yellow?style=flat-square) | 62 | **2** | **1** | 0 | 0 | 4 |
| 46 | [BeehiveInnovations/pal-mcp-server](https://github.com/BeehiveInnovations/pal-mcp-server) | 11,065 | ![F](https://img.shields.io/badge/F-red?style=flat-square) | 20 | **3** | **4** | 1 | 0 | 9 |
| 47 | [IBM/mcp-context-forge](https://github.com/IBM/mcp-context-forge) | 3,278 | ![F](https://img.shields.io/badge/F-red?style=flat-square) | 0 | **34** | **17** | 27 | 8 | 87 |
| 48 | [awslabs/mcp](https://github.com/awslabs/mcp) | 8,153 | ![F](https://img.shields.io/badge/F-red?style=flat-square) | 0 | **5** | **3** | 15 | 0 | 24 |
| 49 | [bytebase/dbhub](https://github.com/bytebase/dbhub) | 2,117 | ![F](https://img.shields.io/badge/F-red?style=flat-square) | 0 | **14** | **1** | 1 | 0 | 17 |
| 50 | [mindsdb/mindsdb](https://github.com/mindsdb/mindsdb) | 38,478 | ![F](https://img.shields.io/badge/F-red?style=flat-square) | 0 | **11** | **2** | 7 | 0 | 21 |

## Severity Breakdown

🔴 **Critical** (71): `███████████`
🟠 **High** (74): `███████████`
🟡 **Medium** (53): `████████`
🟢 **Low** (8): `█`
🔵 **Info** (49): `███████`

## Methodology

### Scoring Formula

```
Score = 100 - (Critical x 15) - (High x 8) - (Medium x 3) - (Low x 1)
Score is clamped to [0, 100]
```

Info-severity findings are tracked but do not affect the score.

### Grade Scale

| Grade | Score Range | Meaning |
|:-----:|:----------:|---------|
| ✅ A | 90 -- 100 | Excellent -- minimal risk |
| 🟢 B | 75 -- 89  | Good -- minor issues only |
| 🟡 C | 60 -- 74  | Fair -- some high-severity issues |
| 🟠 D | 40 -- 59  | Poor -- multiple high-severity issues |
| 🔴 F | 0 -- 39   | Critical -- immediate action required |

### Scanner Coverage

Each repository is scanned with [agentsec](https://pypi.org/project/agentsec-ai/) which runs 27 named security checks + dynamic credential detection across the OWASP Agentic Top 10 categories (ASI01 -- ASI10).

### Limitations

- Static analysis only; no runtime or dynamic testing
- Findings may include false positives that require manual triage
- Star count is a rough proxy for popularity and may bias the sample
- Some test fixtures may contain intentional dummy credentials

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

---

*Generated on 2026-02-15 by [agentsec](https://github.com/debu-sinha/agentsec) v0.4.1 | [Install](https://pypi.org/project/agentsec-ai/) | [Report an issue](https://github.com/debu-sinha/agentsec/issues)*
