# Changelog

All notable changes to agentsec are documented here.

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

- 35+ security checks across 7 OWASP Agentic categories
- 123 tests, all passing

## [0.2.0] - 2026-02-13

### Added

- Hardener module with 3 profiles (workstation, vps, public-bot)
- OpenClaw installation scanner with 30+ configuration checks
- MCP server scanner (tool poisoning, auth, schema validation)
- Skill analyzer (AST malware, instruction malware, prompt injection)
- Credential scanner (16 providers + Shannon entropy)
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
