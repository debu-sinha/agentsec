# Changelog

All notable changes to agentsec are documented here.

## [0.4.3] - 2026-02-17

### Noise Reduction (Tier 2)

- Wire up Shannon entropy gate for KeywordDetector findings — values below
  entropy 3.0 are suppressed as false positives (eliminates ~287 findings from
  ecosystem scan, 27.6% total reduction)
- Cap LOW finding penalty at 15 points in OWASP scoring formula — prevents
  hundreds of test/doc context findings from producing automatic F grades
- Align dashboard `compute_score()` with updated OWASP scorer formula

### Expert Review Fixes (Tier 3)

- Fix HexHighEntropyString threshold from 4.5 to 3.5 — previous value exceeded
  theoretical maximum (log2(16)=4.0), effectively disabling the detector
- Add Pinecone (`pcsk_`), Cohere (`co-`), and Vercel (`vercel_`) API key
  detection patterns
- Add template syntax detection to placeholder filter (`{{ }}`, `<VAR>`, `%{var}`)
- Add `.sql`, `.ipynb`, `.csv`, `.jsonc` to scannable file extensions
- Add `__tests__`, `__mocks__`, `testdata`, `mocks`, `test_helpers` to
  low-confidence directory list for test-context severity downgrade
- Tighten reverse shell regex in skill scanner — require both socket.connect
  AND shell redirection (dup2/subprocess//bin/sh) to reduce FPs on legitimate
  networking code

### Stats

- 245 tests passing (9 new Tier 3 tests, 1 Windows-only symlink skip)
- Ecosystem scan: 1,038 → 751 findings (27.6% reduction from Tier 2)

## [0.4.2] - 2026-02-17

### Changed

- Migrate credential scanner to use Yelp's `detect-secrets` library as primary
  scanning engine for battle-tested false positive handling (23 detection plugins,
  11 heuristic filters including sequential string, UUID, and template detection)
- Add custom patterns for providers not covered by detect-secrets: OpenAI,
  Anthropic, Databricks, Hugging Face, Google API Key, connection strings
- Add connection string placeholder password detection (skips `changeme`,
  `password`, env var references `${...}`, and angle-bracket placeholders)
- Add file path context awareness: downgrade severity for findings in
  documentation files (all `.md`/`.rst`), test files (`*.test.ts`, `*.spec.js`,
  `test_*.py`, `*_test.go`), mock/fixture/stub files, docker-compose, and
  template config files (alembic.ini, `.env.example`)
- Downgrade all severity levels (critical/high/medium → low) in test/doc context,
  not just critical/high
- Add sequential pattern detection (`1234567890`, `abcdefghij`) to skip
  obviously fake credential values
- Skip lock files entirely (pnpm-lock.yaml, package-lock.json, yarn.lock, etc.)
- Expand placeholder password dictionary to 37 common values (postgres, mysql,
  redis, guest, foobar, hunter2, etc.)
- Fix connection string regex to match `postgresql://` (was only `postgres://`)
- Add placeholder detection to installation scanner's plaintext secret check
  with doc context severity downgrade

### Security Hardening (expert-reviewed)

- Fix OpenAI pattern collision with Anthropic keys by adding `(?!ant-)` negative
  lookahead; add support for `sk-proj-` and `sk-svcacct-` key formats with
  hyphens/underscores; add upper bound `{20,200}` to prevent greedy over-matching
- Fix `_is_placeholder()` false negative: remove `startswith(word)` check that
  suppressed real secrets whose post-prefix body began with "test", "example",
  etc.; replace with multi-word detection (2+ placeholder words = placeholder)
- Fix connection string regex ReDoS risk: exclude `:@` from username capture
  group to eliminate O(n^2) backtracking with multiple `:` before `@`
- Add `mongodb+srv`, `mssql`, `rediss`, `amqps` protocols to connection string
  detection
- Fix connection string `$` prefix check: require proper env var pattern
  (`${VAR}` or `$VAR_NAME`) instead of suppressing any password starting with `$`
- Fix fingerprint deduplication: include `line_number` in hash so distinct
  secrets of the same type in the same file are not collapsed into one finding
- Add Groq (`gsk_`) and Replicate (`r8_`) API key detection patterns
- Expand scannable file extensions: `.go`, `.rb`, `.java`, `.kt`, `.rs`, `.php`,
  `.tf`, `.tfvars`, `.hcl`, `.pem`, `.key`, `.gradle`, `.cs`, `.swift`, `.r`
- Scan all `.env.*` variants (was only 4 hardcoded names); add extensionless
  files: Dockerfile, .npmrc, .pypirc, .netrc, .pgpass, .bashrc, Makefile
- Increase `HexHighEntropyString` entropy threshold from 4.0 to 4.5 to reduce
  false positives on git SHAs and commit hashes
- Fix installation scanner `_is_plaintext_placeholder`: replace blanket
  `len < 40` check with word-dominance ratio (word must be >= 30% of value)
- Fix installation scanner `$` prefix check to match credential scanner fix

### Dependencies

- Add `detect-secrets>=1.4,<2` as a runtime dependency

### Stats

- 230 tests passing (14 new expert-review tests, 1 Windows-only symlink skip)

## [0.4.1] - 2026-02-17

### Fixes

- Make severity escalation idempotent (guard against double-scoring mutation)
- Add Python 3.10/3.11 fallback for tarfile `filter="data"` (3.12+ only feature)
- Validate `install` subcommand in gate CLI to prevent silent no-op
- Sanitize error messages to avoid leaking file system paths
- Harden tar extraction on pre-3.12 with path traversal and symlink checks
- Normalize severity display to uppercase in gate output
- Fix inconsistent "critical" vs "CRITICAL" casing in watch command
- Use em-dash consistently in gate command header
- Fix blog post check count from "35+" to accurate "27 named checks + dynamic credential detection"
- Use absolute GitHub URLs for images in README (fixes PyPI rendering)
- Fix zip extractall TOCTOU: extract members individually with per-file path traversal validation
- Fix summary severity counts computed before escalation (summary now reflects post-escalation severities)
- Sanitize gate error message to avoid leaking raw exception details
- Update CITATION.cff, launch docs to v0.4.1
- Skip CEX-001 (exec approvals missing) on non-OpenClaw targets to avoid false positives on MCP server repos
- Align dashboard scoring formula with OWASP scorer (HIGH*7, B>=80, floor=5)
- Fix action.yml shell injection by using proper arg array instead of unquoted string
- Add version pinning input to action.yml for reproducible CI runs
- Expand CI matrix to Python 3.10, 3.12, 3.13 (was 3.12 only)
- Add pip cache to CI for faster builds
- Replace static CI badge with live GitHub Actions status badge
- Fix exit code collision: 0=clean, 1=findings, 2=usage error, 3=runtime error
- Fix `_scan_exec_approvals` null check from `if not` to `if is None` for consistency
- Fix ADR-0004 "two reactive mechanisms" to "three" (matching listed items)
- Fix design doc `--fix` flag reference to `--apply` and stale credential provider count
- Fix CHANGELOG v0.3.0 check count from "35+" to accurate "27 named checks"
- Fix checks-catalog: add missing OWASP codes (CGW-002+ASI02, CID-003+ASI05)
- Fix checks-catalog ASI10 label to "Misaligned Behaviors" (was "Insufficient Monitoring")
- Update CLI reference exit codes documentation

### Stats

- 206 tests passing (1 Windows-only symlink skip)
- Benchmark P/R/F1 recomputed and verified against checked-in JSON artifacts

## [0.4.0] - 2026-02-15

### New Features

- `agentsec gate` - pre-install security gate that scans npm/pip packages BEFORE installation
  - Downloads package to temp dir, runs skill + MCP scanners on contents
  - Detects npm install hooks (preinstall/postinstall scripts)
  - Known-malicious package blocklist (extensible)
  - Supports --force, --dry-run, --fail-on flags
  - Blocks install if findings exceed severity threshold

### Documentation

- Added pre-install gate usage guide to README
- Added output format examples (JSON and SARIF) to README
- Added troubleshooting section covering common issues
- 3 new Architecture Decision Records (ADR-0002 through ADR-0004)

### Improvements

- Pinned dependency upper bounds to prevent future breakage
- Removed 3 unused dependencies (pyyaml, pathspec, jinja2)
- CI self-scan now fails on critical severity (was silently ignored)
- Added pip-audit to CI for dependency vulnerability scanning
- Separated test/dev optional dependency groups
- Fixed action.yml shell injection via env var indirection
- Exported SarifReporter from reporters package

### Bug Fixes

- Fixed watcher always reporting score=0.0 (wrong dict key)
- Fixed stale fallback version in SARIF output
- Fixed config docstring listing "html" instead of "sarif"
- Removed dead code (unused _findings attribute, empty hardeners package)

### Stats

- 206 tests across 17 test files
- 4 scanner modules (installation, skill, mcp, credential) + pre-install gate
- 4 ADRs documenting key architectural decisions

## [0.3.1] - 2026-02-15

### Scoring & Hardening

- Context-sensitive severity escalation (open group + disabled auth -> CRITICAL)
- Score floor of 5.0 to distinguish minimal controls from zero security
- Doom combo detection (open DM + full tools + no sandbox caps score at 20)
- Expanded workstation hardening profile with auth bypass flags and group policy

### Packaging & CI

- Fixed README content-type for PyPI rendering

### Stats

- 170 tests, 8 new OWASP scorer tests (doom combo, severity escalation, score caps)

## [0.3.0] - 2026-02-14

### Security Coverage

- Added 4 new CVE detections (CVE-2026-24763, 25157, 25593, 25475) -- total 5 known CVEs
- Added SSRF protection check (CGW-005) for agents with URL-capable tools
- Added safety scanner detection (CSF-001) for disabled built-in scanner on v2026.2.6+
- Added credential redaction check (CSF-002) for disabled redaction on v2026.2.6+
- Version-gated checks via `_version_gte()` helper

### New Commands

- `agentsec watch` -- filesystem watcher, auto-scans on skill install, config change, MCP update
- `agentsec hook` -- generates shell hooks (zsh/bash) for npm/pip auto-scanning

### Stats

- 27 named checks + dynamic credential detection across 7 OWASP Agentic categories
- 123 tests, all passing

## [0.2.0] - 2026-02-13

### Added

- Hardener module with 3 profiles (workstation, vps, public-bot)
- OpenClaw installation scanner with 30+ configuration checks
- MCP server scanner (tool poisoning, auth, schema validation)
- Skill analyzer (AST malware, instruction malware, prompt injection)
- Credential scanner (17 patterns + Shannon entropy)
- OWASP Agentic posture scoring (A-F grade, 0-100 score)
- SARIF, JSON, and terminal reporters
- Pre-commit hook support

### Stats

- 106 tests, all passing

## [0.1.0] - 2026-02-13

### Added

- Initial release
- 4 scanner modules (installation, skill, mcp, credential)
- CLI with scan, harden, list-scanners commands
- OWASP ASI01-ASI10 mapping
- 66 tests
