# EB-1A Evidence Tracker (agentsec)

Use this file as an index to evidence artifacts. Keep links, dates, and independent sources.

## Criterion Map

| EB-1A Criterion | Current Strength | Evidence Links | Gaps |
|---|---|---|---|
| Original contributions of major significance | Medium | Benchmark report, checks catalog, OWASP scoring ADR | Independent adoption metrics, third-party validation |
| Authorship of scholarly/professional articles | Low | README, ADRs, checks catalog | Blog post, conference talk, whitepaper |
| Published material about you | Low | None yet | Media coverage, third-party blog mentions, security newsletter features |
| Judge of others' work | Low | None yet | Conference reviewing, open-source PR reviews on other projects |
| Critical/leading role | Medium | Sole author of agentsec, GitHub commit history | Adoption by organizations, contributor community |

## Product Impact Evidence

| Date | Artifact | Source Type | Why It Matters | Link/Path |
|---|---|---|---|---|
| 2026-02-15 | Benchmark report (v0.4.0) | Reproducible/public | Validates detection quality with precision/recall/F1 | [docs/benchmarks/results/2026-02-15-v0.4.0.md](../benchmarks/results/2026-02-15-v0.4.0.md) |
| 2026-02-15 | Case study: insecure workstation | Reproducible/public | Demonstrates real before/after risk reduction | [docs/case-studies/001-insecure-openclaw-workstation.md](../case-studies/001-insecure-openclaw-workstation.md) |
| 2026-02-15 | Formal checks catalog | Public reference | CIS Benchmark-style documentation of 26 checks | [docs/checks-catalog.md](../checks-catalog.md) |
| 2026-02-14 | OWASP scoring ADR | Public design record | Documents scoring methodology with OWASP Agentic Top 10 mapping | [docs/adr/ADR-0002-owasp-scoring-formula.md](../adr/ADR-0002-owasp-scoring-formula.md) |
| 2026-02-14 | Pre-install gate ADR | Public design record | Documents supply chain protection design | [docs/adr/ADR-0003-pre-install-gate.md](../adr/ADR-0003-pre-install-gate.md) |
| 2026-02-15 | 206 automated tests | CI/public | 14 integration + 192 unit tests, all passing | [tests/](../../tests/) |
| 2026-02-15 | GitHub Actions CI pipeline | Public | Lint, type-check, tests, self-scan on every push | [.github/workflows/ci.yml](../../.github/workflows/ci.yml) |

## Recognition Evidence

| Date | Mention/Interview/Talk | Third-Party Source | Audience Size | Link |
|---|---|---|---:|---|
| -- | No external mentions yet | -- | -- | -- |

**Gaps:** Need blog post on security engineering blog, conference CFP submission, security newsletter mention.

## Adoption Evidence

| Date | Metric | Value | Source | Link/Proof |
|---|---|---:|---|---|
| 2026-02-15 | GitHub stars | 0 | GitHub | https://github.com/debu-sinha/agentsec |
| 2026-02-15 | Repos using GitHub Action | 0 | GitHub code search | Not yet published to Marketplace |
| 2026-02-15 | PyPI downloads (monthly) | 0 | PyPI | Not yet published |
| 2026-02-15 | Test suite size | 206 | CI | pytest output |
| 2026-02-15 | Check coverage | 26 named checks + dynamic credential detection | Code | docs/checks-catalog.md |
| 2026-02-15 | OWASP categories covered | 7 of 10 (ASI01-03, ASI05, ASI07-08, ASI10) | Code | docs/checks-catalog.md |
| 2026-02-15 | CVE detections | 5 known CVEs | Code | docs/checks-catalog.md |

**Gaps:** PyPI publication, GitHub Marketplace listing, first external user, download metrics.

## Contribution Narrative Notes

- Problem scale addressed: OpenClaw (164K+ GitHub stars) and Claude Code have no dedicated security scanning tooling. MCP server ecosystem has no supply chain verification standard. Operators deploy agents with default configs that expose gateway to LAN, disable auth, and allow unrestricted tool execution.
- Why existing tools were insufficient: Generic SAST tools (Semgrep, CodeQL) don't understand agent-specific config semantics like DM policies, tool profiles, or MCP server trust. No tool maps findings to OWASP Agentic Top 10 (published 2025). No pre-install gate exists for npm/pip packages targeting agent ecosystems.
- What agentsec uniquely contributed: First open-source Agent Security Posture Management (ASPM) tool. 26 checks across 9 families with OWASP mapping. Automated hardening profiles. Pre-install supply chain gate. SARIF output for GitHub Code Scanning integration.
- Quantified outcomes: Benchmark precision/recall/F1 measured and published. Before/after score delta documented in case study. Sub-second scan runtime on typical configs.

## Identified Gaps (Priority Order)

1. **PyPI publication** - needed for adoption metrics and independent installability
2. **GitHub Action on Marketplace** - needed for CI adoption tracking
3. **Blog post** - technical deep-dive suitable for security engineering audience
4. **External user** - at least one documented adopter outside author
5. **Conference talk/CFP** - submit to BSides, DEF CON AI Village, or OWASP AppSec
6. **Expert letter** - CISO or security researcher endorsement letter
7. **Media mention** - coverage in security newsletter or blog

## Exhibit Folder Convention

Recommended structure:
- `evidence/exhibits/media/`
- `evidence/exhibits/benchmarks/`
- `evidence/exhibits/case-studies/`
- `evidence/exhibits/adoption/`
- `evidence/exhibits/speaking/`
- `evidence/exhibits/judging/`
- `evidence/exhibits/letters/`
