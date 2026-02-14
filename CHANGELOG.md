# Changelog

All notable changes to agentsec are documented here.

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

- 35+ security checks across 10 OWASP Agentic categories (ASI01-ASI10)
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
