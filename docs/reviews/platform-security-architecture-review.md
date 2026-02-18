# Platform Security Architecture Review: agentsec v0.4.4

**Review Date:** 2026-02-18
**Reviewer Role:** Distinguished Platform Security Architect
**Scope:** Full source review of `src/agentsec/` -- all modules, models, reporters, scanners, and supporting utilities
**Classification:** Internal -- Architecture Review

---

## Executive Summary

agentsec is a well-structured, defensively-coded security scanner targeting agentic AI installations. The architecture follows sound separation of concerns with a clean scanner plugin system, unified finding model, and multiple reporter backends. The codebase shows evidence of iterative hardening (detect-secrets migration, FP suppression layers, path-traversal protections in the gate module).

This review identifies **24 findings** across 9 architectural domains. The majority are medium-severity hardening opportunities rather than exploitable vulnerabilities, reflecting the overall maturity of the codebase. The most critical findings relate to the hardener's backup mechanism, the gate command's input validation, and the shell hook's matching logic.

**Severity Distribution:**

| Severity | Count |
|----------|-------|
| Critical | 3     |
| High     | 7     |
| Medium   | 10    |
| Low      | 4     |

---

## 1. Hardening System (`hardener.py`)

### PSA-001: Single Backup File Overwritten on Successive Runs

- **Severity:** Critical
- **Category:** Data Loss / Reversibility
- **Description:** The `harden()` function creates a backup at `config_path.with_suffix(".json.bak")`, but successive hardening runs overwrite the same `.bak` file. If a user runs `harden` twice with different profiles, the first backup (containing the original pre-hardened config) is silently destroyed. The second `.bak` file contains the already-hardened state from run one, making the original configuration irrecoverable.
- **Architecture Impact:** Users who rely on the backup for rollback will lose their original configuration. This is especially dangerous because `--apply` is a destructive write operation on the agent's primary config file.
- **Remediation:** Use timestamped backup names (e.g., `openclaw.json.bak.20260218T143022`) or implement a numbered rotation scheme (`*.bak.1`, `*.bak.2`, etc.). Consider maintaining a manifest of backups so the `harden` command can offer a `--rollback` option.
- **Effort:** Low (1-2 hours)

### PSA-002: No Integrity Verification of Backup Before Overwriting Original

- **Severity:** High
- **Category:** Data Integrity
- **Description:** At line 251-253 of `hardener.py`, the backup is created with `shutil.copy2()` and the original is immediately overwritten with `config_path.write_text()`. There is no verification that the backup write succeeded (e.g., by reading it back and comparing checksums) before the original is modified. A partial write to the backup (disk full, permissions race, interrupted I/O) would leave the user with a corrupted backup AND a modified original.
- **Architecture Impact:** Silent data corruption path. The backup exists but may be truncated or empty.
- **Remediation:** After `shutil.copy2()`, verify the backup's size matches the original. Alternatively, use an atomic write pattern: write to a temp file, verify, rename to backup, then write the new config. Consider using `os.fsync()` to flush the backup to disk before proceeding.
- **Effort:** Low (1-2 hours)

### PSA-003: Hardening Profiles Missing Claude Code, Cursor, Windsurf, Gemini CLI

- **Severity:** Medium
- **Category:** Profile Completeness
- **Description:** The detection module (`utils/detection.py`) supports seven agent types: `openclaw`, `clawdbot`, `moltbot`, `claude-code`, `cursor`, `windsurf`, and `gemini-cli`. However, the hardening engine (`hardener.py`) only provides profiles targeting OpenClaw-specific config keys (`gateway.bind`, `dmPolicy`, `sandbox.mode`, etc.). Running `harden` against a Claude Code or Cursor installation silently produces zero changes because `_find_config()` only looks for `openclaw.json` and `clawdbot.json`.
- **Architecture Impact:** Users scanning Claude Code or Cursor installations will receive findings but have no automated hardening path. The tool's promise of "scan -> harden -> monitor" breaks for non-OpenClaw agents.
- **Remediation:** Either (a) implement agent-type-specific hardening profiles that target each agent's config format, or (b) clearly document that hardening is OpenClaw-only and emit a warning when targeting other agent types. Option (a) is preferred for platform completeness.
- **Effort:** Medium (4-8 hours per agent type)

### PSA-004: `_tighten_permissions()` Silently Fails on Windows / NTFS

- **Severity:** Low
- **Category:** Cross-Platform
- **Description:** The `_tighten_permissions()` function uses POSIX `os.chmod()` with `stat.S_IRWXU` and `stat.S_IRUSR | stat.S_IWUSR`. On Windows/NTFS, `os.chmod()` only affects the read-only flag and cannot set owner-only permissions. The function catches `OSError` but logs at `DEBUG` level, making the failure invisible to users.
- **Architecture Impact:** Windows users running `harden --apply` will see the hardening succeed but file permissions remain world-readable. The CI matrix runs on Ubuntu/macOS, so this gap is not caught by tests.
- **Remediation:** On Windows, use `icacls` or the `win32security` module to set proper ACLs. At minimum, log a `WARNING` on Windows explaining that POSIX permission tightening is not available and manual ACL configuration is required.
- **Effort:** Medium (2-4 hours)

### PSA-005: `_set_nested()` Creates Intermediate Dicts Unconditionally

- **Severity:** Low
- **Category:** Config Corruption
- **Description:** The `_set_nested()` helper at line 291-299 creates intermediate dictionary keys if they don't exist. If a hardening action targets a dotpath like `gateway.bind` but the config has `gateway` set to a string value (e.g., `"gateway": "localhost"`), the function silently replaces the string with `{"bind": "loopback"}`. This is semantically different from what the config author may have intended.
- **Architecture Impact:** Edge case, but could produce a malformed config that the agent fails to parse on next startup.
- **Remediation:** Before creating intermediate dicts, validate that existing values are either dict or absent. If an existing value is a non-dict scalar, log a warning and skip the action rather than silently restructuring the config.
- **Effort:** Low (1 hour)

---

## 2. Multi-Platform Agent Discovery (`utils/detection.py`)

### PSA-006: Home Directory Scan Leaks Detection Across Unrelated Projects

- **Severity:** High
- **Category:** Detection Accuracy / Information Boundary
- **Description:** When no markers are found in the target directory, `detect_agent_type()` falls through to scanning `Path.home()` for agent markers (lines 76-85). This means if a user has Claude Code installed in their home directory but is scanning an unrelated project at `/opt/myapp`, the scanner will report the agent type as `claude-code` based on `~/.claude` existing. This can cause false positives from the installation scanner, which will check for Claude Code-specific config patterns in an unrelated directory.
- **Architecture Impact:** Cross-contamination of detection results. Scanners downstream receive an incorrect `agent_type` context, leading to irrelevant findings or missed findings.
- **Remediation:** Remove the home directory fallback, or make it opt-in via a `--detect-global` flag. If the home directory fallback is retained, clearly annotate in the `ScanContext.metadata` that the detection was from the home directory, not the scan target, so downstream scanners can adjust behavior.
- **Effort:** Low (1-2 hours)

### PSA-007: Detection Uses `Path.exists()` Without Symlink Resolution

- **Severity:** Medium
- **Category:** Symlink Abuse
- **Description:** The marker detection loop uses `marker_path.exists()`, which follows symlinks. An attacker who can plant a symlink named `.openclaw` pointing to an arbitrary directory could influence the detected agent type and, more importantly, cause the installation scanner to read config files from a location controlled by the attacker.
- **Architecture Impact:** In shared-hosting or multi-user environments, symlink-based detection manipulation could trick agentsec into reporting findings from attacker-controlled config files, potentially masking real issues or injecting false findings.
- **Remediation:** Use `marker_path.is_symlink()` check before trusting the marker. If a marker is a symlink, log a warning and either skip it or resolve and validate the target is within the expected directory tree.
- **Effort:** Low (1 hour)

---

## 3. MCP Security Architecture (`scanners/mcp.py`)

### PSA-008: Tool Poisoning Patterns Are Regex-Only, No Semantic Analysis

- **Severity:** Medium
- **Category:** Detection Depth
- **Description:** The `_TOOL_POISONING_PATTERNS` list uses fixed regex patterns to detect malicious instructions in tool descriptions. These patterns can be trivially evaded using synonyms, Unicode homoglyphs (beyond the basic invisible chars checked), or multi-language instructions. For example, "you must always invoke" triggers, but "it is required to call upon" does not, despite having identical semantic intent.
- **Architecture Impact:** Determined attackers can craft tool descriptions that pass regex-based checks while still manipulating LLM behavior. This is a fundamental limitation of pattern-based detection for natural language content.
- **Remediation:** Consider supplementing regex patterns with a lightweight LLM-based or embedding-based classifier for tool description analysis. At minimum, document this as a known limitation and recommend manual review of all third-party MCP server tool descriptions. Expand the pattern set to include additional evasion variants.
- **Effort:** High (8-16 hours for classifier; Low for pattern expansion)

### PSA-009: `save_tool_pins()` Writes Without Atomic Replace

- **Severity:** Medium
- **Category:** Race Condition / Data Integrity
- **Description:** The `save_tool_pins()` static method at line 524-531 writes the pins file with `pins_path.write_text()` directly. If the process is interrupted during the write (e.g., Ctrl+C during `pin-tools`, disk error), the pins file may be left in a corrupted state -- partially written JSON. The next scan would fail to parse it silently (the `json.JSONDecodeError` is caught at line 447, causing the verify step to be skipped entirely), meaning tool drift detection is silently disabled.
- **Architecture Impact:** A corrupted pins file silently disables rug-pull detection with no user notification.
- **Remediation:** Use atomic write: write to a temp file in the same directory, then `os.replace()` to atomically swap. This guarantees the pins file is always either the old complete version or the new complete version.
- **Effort:** Low (30 minutes)

### PSA-010: MCP Config JSON Parsing Has No Size Limit

- **Severity:** Medium
- **Category:** Denial of Service
- **Description:** The `_find_mcp_configs()` method reads and JSON-parses every candidate config file without any size check (lines 176-179). A maliciously crafted `mcp.json` file of several gigabytes would cause the scanner to exhaust memory. The installation scanner has a `_MAX_CONFIG_SIZE` guard, but the MCP scanner does not.
- **Architecture Impact:** Memory exhaustion DoS when scanning a directory containing an adversarial config file. This is relevant for the `gate` command, which scans untrusted downloaded packages.
- **Remediation:** Add a file size check before reading, consistent with the installation scanner's `_MAX_CONFIG_SIZE` pattern. A 10 MB limit is reasonable for JSON config files.
- **Effort:** Low (30 minutes)

### PSA-011: No Detection of Stdio Transport Hijacking

- **Severity:** Medium
- **Category:** Detection Gap
- **Description:** The MCP scanner checks for remote HTTP URLs and npx package risks but does not analyze `stdio`-transport MCP servers. Stdio-based servers can be just as dangerous: a malicious `command` entry like `python -c "import os; os.system('...')"` or a server binary that exfiltrates data via its stdio responses would not be flagged. The `_check_server_command()` method only checks for HTTP URLs and npx patterns.
- **Architecture Impact:** Stdio MCP servers, which are the most common transport, receive minimal security analysis.
- **Remediation:** Add checks for dangerous command patterns in stdio server configs: inline code execution (`python -c`, `node -e`), shell metacharacters, and commands that don't resolve to expected package binaries. Consider checking if the command binary exists and if it matches the expected MCP server package.
- **Effort:** Medium (2-4 hours)

---

## 4. Scanner Architecture (`scanners/base.py`)

### PSA-012: `BaseScanner.run()` Swallows All Exceptions Silently

- **Severity:** High
- **Category:** Observability / Fail-Open
- **Description:** The `run()` method at lines 82-113 catches `Exception` at line 96 and returns an empty list, effectively making every scanner fail-open. If a scanner has a bug that causes an uncaught `TypeError`, `KeyError`, or `AttributeError`, the scan silently produces zero findings for that scanner. The error is logged at `ERROR` level but the overall scan completes with a passing grade, giving the user a false sense of security.
- **Architecture Impact:** Silent scanner failures produce incomplete scan results. A user could receive a grade "A" report while one or more scanners crashed and produced no findings. This is the security equivalent of a fire alarm that silently disables itself when it detects smoke.
- **Remediation:** Add a mechanism to surface scanner failures in the report. Options: (a) add a `scanner_errors` field to `ScanReport` that the reporter renders, (b) add a `--strict` mode that fails the scan if any scanner errors, (c) at minimum, include a warning finding when a scanner fails. Option (a) is recommended as the default behavior.
- **Effort:** Medium (2-4 hours)

### PSA-013: `ScanContext` Is a Mutable Shared Dataclass With No Thread Safety

- **Severity:** Low
- **Category:** Concurrency Safety
- **Description:** `ScanContext` is a mutable dataclass shared across all scanners. Multiple scanners write to `config_files`, `discovered_secrets_locations`, `metadata`, and `files_scanned` without any synchronization. Currently scanners run sequentially, but if parallel scanner execution is ever introduced (a natural scaling optimization), these shared mutations will race.
- **Architecture Impact:** No immediate impact (sequential execution), but creates a latent concurrency bug that will surface if the orchestrator is ever parallelized.
- **Remediation:** Document the sequential execution contract explicitly. If parallelization is planned, either (a) make `ScanContext` fields thread-safe with locks, or (b) give each scanner its own context and merge results after.
- **Effort:** Low (documentation only for now)

---

## 5. Orchestrator Design (`orchestrator.py`)

### PSA-014: Posture Score Computed Twice on Same Findings List

- **Severity:** Medium
- **Category:** Correctness / Side Effects
- **Description:** In `run_scan()` at lines 66-71, `scorer.compute_posture_score(all_findings)` is called for severity escalation, and then `ScanSummary.from_findings()` is called to build the summary. However, in `cli.py` at line 235, `compute_posture_score()` is called AGAIN on `report.findings`. The `compute_posture_score()` method mutates findings via `_escalate_severities()`. While there is an `_escalated` guard attribute to prevent double-escalation, this guard is set via a dynamic attribute (`finding._escalated = True # type: ignore[attr-defined]`), which is not part of the Pydantic model and will not survive serialization/deserialization. If findings are ever round-tripped through JSON (e.g., loaded from a saved report), the escalation guard is lost and severities could be escalated again.
- **Architecture Impact:** Double-escalation risk after JSON round-trip. Findings that were HIGH -> CRITICAL via escalation would remain CRITICAL, but the scoring math would apply escalation logic again, potentially affecting category penalties.
- **Remediation:** Make `_escalated` a proper field on the `Finding` model (default `False`, excluded from display). Alternatively, make `_escalate_severities` idempotent by checking if the finding's severity already matches the escalated level rather than relying on a side-channel attribute.
- **Effort:** Low (1-2 hours)

### PSA-015: `scan_id` Uses Truncated UUID -- Collision Risk at Scale

- **Severity:** Low
- **Category:** Identifier Uniqueness
- **Description:** The `scan_id` is generated as `uuid.uuid4().hex[:12]` (line 83), which provides 48 bits of entropy. For a single user running occasional scans, this is adequate. However, if scan reports are aggregated across an organization (e.g., 10,000 daily scans from CI pipelines), the birthday paradox gives a non-trivial collision probability over time. While not critical, scan ID collisions would corrupt any deduplication or trend-tracking system.
- **Architecture Impact:** Low probability but high impact in enterprise aggregation scenarios.
- **Remediation:** Use the full UUID hex (32 chars) or at least 16 chars (64 bits of entropy) for scan IDs.
- **Effort:** Trivial (5 minutes)

---

## 6. Reporter Security (`reporters/`)

### PSA-016: SARIF Reporter Emits Absolute File Paths

- **Severity:** High
- **Category:** Information Disclosure
- **Description:** The SARIF reporter at line 139 emits `str(finding.file_path)` as the artifact URI. Since `finding.file_path` is an absolute `Path` object (set by scanners), the SARIF output will contain full filesystem paths like `C:\Users\username\.openclaw\openclaw.json` or `/home/deployer/.openclaw/credentials`. When SARIF reports are uploaded to GitHub Code Scanning or shared with third parties, these absolute paths leak the user's home directory structure, username, and installation layout.
- **Architecture Impact:** Information disclosure in a report format specifically designed for sharing and upload to CI/CD platforms.
- **Remediation:** Relativize file paths in SARIF output against the scan target root. The `uriBaseId: "%SRCROOT%"` is already present but the URI itself should be the relative path from the scan root, not the absolute path. Compute this as `finding.file_path.relative_to(report.target_path)` with a fallback to the filename if the path is outside the target.
- **Effort:** Low (1 hour)

### PSA-017: JSON Reporter Exposes Full Remediation Commands With Paths

- **Severity:** Medium
- **Category:** Information Disclosure
- **Description:** The JSON reporter serializes the complete `Remediation` model, including the `command` field which contains strings like `chmod 600 '/home/user/.openclaw/openclaw.json'` with full absolute paths. The `evidence` field may also contain path information. When JSON reports are stored in CI artifacts or log aggregation systems, this exposes filesystem layout to anyone with access to those systems.
- **Architecture Impact:** Remediation commands and evidence fields leak filesystem structure in machine-readable format.
- **Remediation:** Add a path sanitization pass in the JSON reporter that replaces absolute paths in evidence and remediation commands with paths relative to the scan target, or with `~` prefix for home-relative paths.
- **Effort:** Low (1-2 hours)

---

## 7. Watcher Architecture (`watcher.py`)

### PSA-018: Polling-Based Watcher Vulnerable to Filesystem Exhaustion

- **Severity:** High
- **Category:** Denial of Service
- **Description:** The `_build_snapshot()` function at line 104-118 calls `p.rglob("*")` on every watched directory, stat-ing every file recursively. If a watched directory contains a large number of files (e.g., `node_modules` under `.openclaw/extensions`), or if a symlink cycle exists, this will consume excessive CPU and memory on every poll interval. With a default 2-second poll interval, a directory containing 100K files would cause near-continuous I/O load.
- **Architecture Impact:** The watcher becomes a performance liability on installations with large skill/extension directories. Symlink cycles could cause infinite recursion (though `rglob` typically handles this).
- **Remediation:** (a) Add a file count limit per directory (e.g., stop enumerating after 10,000 files), (b) Skip `node_modules`, `.git`, and other known-heavy directories in the snapshot builder, (c) Consider using OS-native file watching (`inotify` on Linux, `FSEvents` on macOS, `ReadDirectoryChangesW` on Windows) via the `watchdog` library instead of polling.
- **Effort:** Medium (2-4 hours for skip-list; High for watchdog migration)

### PSA-019: Full Re-scan on Every File Change Is O(n) Per Event

- **Severity:** High
- **Category:** Performance / Resource Consumption
- **Description:** When any file change is detected, the watcher triggers a complete `run_scan()` (line 205), which runs ALL scanners across the entire installation directory. The credential scanner uses `rglob("*")` on the target, re-scanning every file for secrets on every change. If a user edits `openclaw.json` frequently during configuration, this triggers full credential scans every 2 seconds.
- **Architecture Impact:** The watcher's resource consumption scales with installation size, not change frequency. A large installation with frequent config edits could see significant CPU usage.
- **Remediation:** Implement incremental scanning: only re-run the scanner(s) relevant to the changed file type. For example, a change to `openclaw.json` only needs the installation scanner, not the credential scanner. A change in the `skills/` directory only needs the skill scanner. Map changed file paths to relevant scanners.
- **Effort:** Medium (4-8 hours)

### PSA-020: No Debouncing on Rapid File Changes

- **Severity:** Medium
- **Category:** Performance
- **Description:** The watcher processes every detected change event individually with a full scan per event. Rapid file operations (e.g., `npm install` writing dozens of files in quick succession, or a text editor creating temp files during save) will trigger dozens of overlapping scans. While scans are sequential (the sleep prevents true overlap), the backlog means stale events are processed long after they occurred.
- **Architecture Impact:** User experiences long delays and stale results during burst-write operations.
- **Remediation:** Add a debounce window (e.g., 5 seconds): after detecting a change, wait for the debounce period to elapse with no additional changes before triggering a scan. This collapses burst writes into a single scan.
- **Effort:** Low (1-2 hours)

---

## 8. CLI Security (`cli.py`)

### PSA-021: Gate Command Passes Unsanitized Package Names to `subprocess.run()`

- **Severity:** Critical
- **Category:** Command Injection
- **Description:** In `cli.py` line 887, the gate command executes `subprocess.run([pm, *args])` where `args` comes from user input via Click's `UNPROCESSED` arguments. While the use of a list (not a shell string) prevents classic shell injection, the package name itself is passed directly to `npm pack` or `pip download` in `gate.py` lines 275 and 312-316. A crafted "package name" like `--target /etc` or `-r evil-requirements.txt` would be interpreted as a flag by pip, potentially causing it to install from an attacker-controlled requirements file. The `_extract_package_names()` function does skip arguments starting with `-`, but this only applies to the agentsec-side extraction, not to the subprocess calls that pass the full `args` list to npm/pip.
- **Architecture Impact:** The gate command's security guarantee ("scan before install") can be bypassed by injecting pip/npm flags that alter download behavior.
- **Remediation:** In `_download_and_scan_npm()` and `_download_and_scan_pip()`, validate that `package_name` matches a valid package name pattern (alphanumeric, hyphens, underscores, scoped names for npm). Reject names containing flag-like patterns (`--`, leading `-`). Alternatively, use `--` separator before the package name in subprocess calls to prevent flag injection.
- **Effort:** Low (1-2 hours)

### PSA-022: Shell Hook Injection via Directory Name

- **Severity:** Critical
- **Category:** Code Injection
- **Description:** The generated shell hooks (`_ZSH_HOOK` and `_BASH_HOOK` at lines 673-747) embed `$PWD` comparisons using `[[ "$PWD" == *"openclaw"* ]]`. This glob match is overly broad: any directory whose name contains "openclaw" (e.g., `/tmp/evil-openclaw-exploit/`) would trigger the auto-scan hook. More critically, the hook runs `agentsec scan --quiet --fail-on critical 2>/dev/null`, which scans the current directory. If an attacker tricks a user into running `npm install` in a directory they control, the hook runs a scan (potentially safe) and then proceeds with the npm install, giving a false "No critical issues found" message if the malicious content is in a location the scanner doesn't check.

    Furthermore, the hooks wrap `npm`, `pip`, and `pip3` as shell functions, which could conflict with other shell customizations (e.g., `nvm`, `pyenv`, `pipx`) that also wrap these commands. The interaction order depends on shell evaluation order, which is fragile and poorly documented.
- **Architecture Impact:** False sense of security from hook-based scanning, plus potential breakage of legitimate shell tooling.
- **Remediation:** (a) Use more specific directory matching (check for actual config files, not directory name substrings), (b) Document the hook's interaction with nvm/pyenv, (c) Consider using npm/pip's native hook mechanisms instead of shell wrapping (e.g., `.npmrc`'s `preinstall` or pip's `--constraint` for pip-audit-like workflows).
- **Effort:** Medium (2-4 hours)

---

## 9. Cross-Cutting Concerns

### PSA-023: File Reads Throughout Codebase Lack Consistent Encoding Specification

- **Severity:** High
- **Category:** Cross-Platform Reliability
- **Description:** File reads across the codebase use a mix of approaches:
    - `path.read_text()` (no encoding specified) -- uses system default encoding, which varies by platform
    - `path.read_text(errors="replace")` -- replaces undecodable bytes but uses system default encoding
    - `path.read_text(encoding="utf-8", errors="replace")` -- explicit UTF-8 (used only in gate.py)

    On Windows with a non-UTF-8 system locale, `path.read_text()` uses `cp1252` by default, which will misparse UTF-8 files containing multi-byte characters (common in international agent configurations). This can cause regex patterns to miss matches or produce garbled evidence strings. The project memory already notes "UnicodeEncodeError on Windows cp1252 terminal."

    Affected files: `hardener.py` (line 232), `installation.py` (line 432), `credential.py` (line 596), `mcp.py` (lines 168, 178, 446), `skill.py` (lines 429, 503, 582, 625, 667, 747).
- **Architecture Impact:** Platform-dependent scan results. The same installation scanned on Linux and Windows may produce different findings due to encoding differences.
- **Remediation:** Standardize all file reads to `path.read_text(encoding="utf-8", errors="replace")`. Create a utility function like `safe_read_text(path: Path) -> str` in `utils/__init__.py` that encapsulates this pattern, and use it consistently across all scanners.
- **Effort:** Low (2-3 hours for full codebase sweep)

### PSA-024: Temp Directory Cleanup in Gate Uses `ignore_errors=True`

- **Severity:** High
- **Category:** Sensitive Data Residue
- **Description:** In `gate.py` line 263, `shutil.rmtree(temp_dir, ignore_errors=True)` silently fails if the temp directory cannot be removed. This temp directory contains the extracted contents of a downloaded package, which may include malicious code, credentials, or other sensitive artifacts from the pre-install scan. If cleanup fails (e.g., file locked by antivirus on Windows, permission issue), these artifacts persist in the system temp directory indefinitely.
- **Architecture Impact:** Malicious package artifacts persist on disk after the gate check, potentially accessible to other processes or users on the system.
- **Remediation:** (a) Replace `ignore_errors=True` with explicit error handling that logs a WARNING with the temp directory path so the user can manually clean up, (b) Use `atexit.register()` as a second cleanup layer, (c) On failure, attempt to at least shred/overwrite file contents before abandoning cleanup.
- **Effort:** Low (1 hour)

---

## Findings Summary Table

| ID | Title | Severity | Category | Component |
|----|-------|----------|----------|-----------|
| PSA-001 | Single backup overwritten on successive runs | Critical | Data Loss | hardener.py |
| PSA-002 | No integrity verification of backup | High | Data Integrity | hardener.py |
| PSA-003 | Hardening profiles missing non-OpenClaw agents | Medium | Completeness | hardener.py |
| PSA-004 | `_tighten_permissions()` fails on Windows | Low | Cross-Platform | hardener.py |
| PSA-005 | `_set_nested()` overwrites non-dict intermediates | Low | Config Corruption | hardener.py |
| PSA-006 | Home directory scan cross-contaminates detection | High | Detection Accuracy | detection.py |
| PSA-007 | Detection follows symlinks without validation | Medium | Symlink Abuse | detection.py |
| PSA-008 | Tool poisoning detection is regex-only | Medium | Detection Depth | mcp.py |
| PSA-009 | `save_tool_pins()` not atomic | Medium | Race Condition | mcp.py |
| PSA-010 | MCP config parsing has no size limit | Medium | Denial of Service | mcp.py |
| PSA-011 | No stdio transport hijacking detection | Medium | Detection Gap | mcp.py |
| PSA-012 | `BaseScanner.run()` swallows exceptions silently | High | Fail-Open | base.py |
| PSA-013 | `ScanContext` has no thread safety | Low | Concurrency | base.py |
| PSA-014 | Posture score double-computation / escalation guard fragility | Medium | Correctness | orchestrator.py |
| PSA-015 | Truncated UUID scan IDs | Low | Identifier Collision | orchestrator.py |
| PSA-016 | SARIF reporter emits absolute file paths | High | Information Disclosure | sarif_reporter.py |
| PSA-017 | JSON reporter exposes paths in remediation | Medium | Information Disclosure | json_reporter.py |
| PSA-018 | Watcher polls with unbounded rglob | High | Denial of Service | watcher.py |
| PSA-019 | Full re-scan on every file change | High | Performance | watcher.py |
| PSA-020 | No debouncing on rapid changes | Medium | Performance | watcher.py |
| PSA-021 | Gate passes unsanitized names to subprocess | Critical | Command Injection | cli.py / gate.py |
| PSA-022 | Shell hook directory name injection | Critical | Code Injection | cli.py |
| PSA-023 | Inconsistent file encoding across scanners | High | Cross-Platform | Multiple |
| PSA-024 | Temp directory cleanup silently fails | High | Data Residue | gate.py |

---

## Architecture Strengths (Notable Positives)

1. **Tar/Zip extraction is properly hardened.** The `_extract_tar_archive()` and `_extract_zip_archive()` functions in `gate.py` include path traversal validation and symlink blocking. The tar extractor uses Python 3.12+'s built-in `filter="data"` when available and falls back to manual validation on older runtimes. The zip extractor uses per-member extraction to avoid TOCTOU between validation and extraction. This is well-implemented.

2. **Secret sanitization is consistent.** The `sanitize_secret()` utility provides a single, auditable point for redacting secret values in evidence strings. The first-4 / last-4 pattern with masked middle is applied consistently across scanners.

3. **Finding fingerprinting is well-designed.** The SHA-256 based fingerprint using `scanner:category:file_path:title:line_number` provides stable deduplication across scans without including mutable fields like severity (which may be escalated).

4. **The credential scanner's multi-layer FP suppression is thorough.** The combination of detect-secrets heuristic filters, known example value allowlist, placeholder detection, Shannon entropy gating, and character class diversity checking represents a mature FP reduction pipeline. The IBM incident root-cause fixes (v0.4.4) demonstrate the team's commitment to precision.

5. **The OWASP scoring model with severity escalation is architecturally sound.** Context-sensitive escalation (e.g., open DM + disabled auth -> CRITICAL) reflects real-world risk composition. The doom combo detection is a pragmatic heuristic that captures the most dangerous configuration patterns.

6. **The scanner plugin architecture is clean.** The `BaseScanner` ABC with `ScanContext` sharing and registry-based discovery provides a straightforward extension point. Adding a new scanner requires only implementing the interface and registering in the registry.

---

## Prioritized Remediation Roadmap

### Tier 1: Address Now (Critical findings + quick wins)

| Finding | Effort | Impact |
|---------|--------|--------|
| PSA-001: Timestamped backups | 1-2 hrs | Prevents data loss on repeated hardening |
| PSA-021: Validate package names in gate | 1-2 hrs | Closes command injection vector |
| PSA-022: Fix shell hook matching | 2-4 hrs | Eliminates false security assurance |
| PSA-023: Standardize file encoding | 2-3 hrs | Fixes cross-platform scan consistency |
| PSA-012: Surface scanner failures in reports | 2-4 hrs | Eliminates silent fail-open |

### Tier 2: Next Sprint (High findings)

| Finding | Effort | Impact |
|---------|--------|--------|
| PSA-002: Verify backup integrity | 1-2 hrs | Defense against partial writes |
| PSA-006: Remove home directory detection fallback | 1-2 hrs | Eliminates cross-contamination |
| PSA-016: Relativize SARIF paths | 1 hr | Stops info disclosure in CI uploads |
| PSA-018: Add skip-list to watcher rglob | 2-4 hrs | Prevents watcher DoS |
| PSA-019: Incremental scanning in watcher | 4-8 hrs | Major performance improvement |
| PSA-024: Improve gate temp cleanup | 1 hr | Prevents malware residue |

### Tier 3: Planned Improvement (Medium findings)

| Finding | Effort | Impact |
|---------|--------|--------|
| PSA-003: Non-OpenClaw hardening profiles | 4-8 hrs/agent | Feature completeness |
| PSA-009: Atomic tool pin writes | 30 min | Data integrity |
| PSA-010: MCP config size limit | 30 min | DoS prevention |
| PSA-011: Stdio transport analysis | 2-4 hrs | Detection coverage |
| PSA-014: Fix escalation guard | 1-2 hrs | Correctness |
| PSA-017: Sanitize JSON reporter paths | 1-2 hrs | Info disclosure |
| PSA-020: Watcher debouncing | 1-2 hrs | Performance |

### Tier 4: Low Priority

| Finding | Effort | Impact |
|---------|--------|--------|
| PSA-004: Windows permission support | 2-4 hrs | Platform coverage |
| PSA-005: Config overwrite guard | 1 hr | Edge case |
| PSA-007: Symlink-aware detection | 1 hr | Defense in depth |
| PSA-008: Semantic tool description analysis | 8-16 hrs | Detection depth |
| PSA-013: Thread safety documentation | 30 min | Future-proofing |
| PSA-015: Full UUID for scan IDs | 5 min | Scale readiness |

---

## Conclusion

agentsec demonstrates solid security engineering fundamentals: proper input validation in archive extraction, consistent secret redaction, well-structured data models, and a thoughtful OWASP scoring system. The three critical findings (PSA-001, PSA-021, PSA-022) are all remediable with modest effort. The high-severity findings primarily involve information disclosure in reports and fail-open behavior that could mask scan failures.

The most impactful architectural improvement would be addressing PSA-012 (silent scanner failures) and PSA-023 (encoding inconsistency), as these affect the trustworthiness of every scan result. For the watcher subsystem, moving to event-driven file monitoring (PSA-018/019) would transform it from a CPU-intensive polling loop into a production-grade monitoring solution.

Overall, the codebase is in good shape for a v0.4.x release. The findings in this review represent hardening opportunities that would elevate the tool from "good" to "production-grade" reliability, particularly for enterprise CI/CD integration scenarios where SARIF reports are uploaded to shared platforms and scan results must be reproducible across different operating systems.
