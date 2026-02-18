# Supply Chain Security Review: agentsec v0.4.4

**Reviewer:** Distinguished Supply Chain Security Engineer
**Date:** 2026-02-18
**Scope:** Complete source tree (`src/agentsec/`), CI/CD pipelines (`.github/workflows/`), build configuration, dependency management
**Methodology:** Manual code review of all scanner modules, gate logic, CLI entry points, build/publish pipelines, and dependency specifications
**Severity Scale:** CRITICAL / HIGH / MEDIUM / LOW / INFO
**SLSA Framework:** SLSA v1.0 Build Levels 0-3

---

## Executive Summary

agentsec v0.4.4 demonstrates strong security awareness for a pre-1.0 tool. The pre-install gate correctly uses `npm pack` (not `npm install`) to avoid running install hooks, tar extraction has path traversal protections with version-gated `filter="data"` on Python 3.12+, and the tool-pinning mechanism provides meaningful defense against MCP rug-pull attacks. The CI pipeline uses signed tags, build provenance attestation via `actions/attest-build-provenance`, `pip-audit` for dependency vulnerability scanning, and PyPI trusted publisher (OIDC) for credential-free publishing.

However, this review identifies **23 findings** across the five focus areas. The most critical issues are:

1. **No package name validation before subprocess calls** (SCS-001) -- crafted names could exploit argument injection
2. **No integrity verification of downloaded packages** (SCS-002) -- MITM or registry compromise goes undetected
3. **The `--force` flag bypasses all gate protections** (SCS-003) -- with no persistent audit trail
4. **Pins file has no tamper detection** (SCS-008) -- an attacker with write access defeats rug-pull detection entirely
5. **All GitHub Actions use mutable tags** (SCS-020) -- vulnerable to tag mutation attacks
6. **`detect-secrets` missing from constraints file** (SCS-015) -- the security-critical runtime dependency is unpinned in CI

| Severity | Count |
|----------|-------|
| CRITICAL | 3     |
| HIGH     | 7     |
| MEDIUM   | 8     |
| LOW      | 3     |
| INFO     | 2     |

### SLSA Level Assessment

| Component | Current Level | Achievable | Blocker |
|-----------|--------------|------------|---------|
| Build (PyPI publish) | L1 | L2 | Need SHA-pinned actions, hermetic build |
| Gate (npm/pip download) | L0 | L1 | No integrity verification of downloads |
| Pins (tool hashing) | L0 | L1 | No tamper detection on pins file |

---

## 1. Pre-Install Gate (`src/agentsec/gate.py`)

### SCS-001: No Package Name Validation Before Subprocess Calls

**Severity:** CRITICAL
**Category:** CWE-88 (Improper Neutralization of Argument Delimiters in a Command)
**SLSA Impact:** Undermines L1 -- build inputs are not validated

**Attack Scenario:**
Package names are passed directly to `subprocess.run()` as list elements without validation. While list-form subprocess avoids shell injection, it does not prevent argument injection. A crafted package name like `--config=/tmp/evil.npmrc` could alter npm's behavior via argument confusion. On lines 274-276 and 312-320:

```python
# gate.py line 274
subprocess.run(
    ["npm", "pack", package_name, "--pack-destination", temp_dir],
    ...
)

# gate.py line 312
subprocess.run(
    ["pip", "download", "--no-deps", "--no-binary", ":all:", "-d", temp_dir, package_name],
    ...
)
```

The `_extract_package_names()` function strips version specifiers but does not validate that the remaining string is a legitimate package name. A name containing `--` prefixes would be interpreted as flags by npm/pip.

**Current Mitigation:** `subprocess.run()` uses list form (no `shell=True`). Package names are extracted by `_extract_package_names()` which strips version specifiers.

**Gap:** No input validation against package name format. No `--` argument separator before the package name to prevent flag injection. Names like `--config=/tmp/evil`, `--index-url=https://evil.com/simple`, or `--pre` would be interpreted as flags, not package names.

**Remediation:**
```python
import re

_NPM_PACKAGE_RE = re.compile(r"^(@[a-zA-Z0-9._-]+/)?[a-zA-Z0-9._-]+$")
_PIP_PACKAGE_RE = re.compile(r"^[a-zA-Z0-9._-]+$")

def _validate_package_name(pm: str, name: str) -> bool:
    """Validate package name against registry naming rules."""
    pattern = _NPM_PACKAGE_RE if pm == "npm" else _PIP_PACKAGE_RE
    return bool(pattern.match(name))
```

Additionally, insert `"--"` before the package name in both subprocess calls to separate flags from positional arguments.

---

### SCS-002: No Package Integrity Verification Before Extraction

**Severity:** HIGH
**Category:** CWE-494 (Download of Code Without Integrity Check)
**SLSA Impact:** Violates L1 source requirement -- no provenance verification of downloaded artifacts

**Attack Scenario:**
After `npm pack` or `pip download` completes, the downloaded archive is extracted and scanned without any integrity verification. If a MITM attack substitutes a different tarball (e.g., via compromised registry mirror, DNS hijack, or corporate proxy), the gate extracts and scans the wrong package. The scan would detect known-bad patterns but could miss novel malware not covered by the skill scanner's regex/AST patterns.

**Current Mitigation:** None. The gate trusts whatever `npm pack` and `pip download` produce.

**Gap:** No SHA-256/SHA-512 hash verification against the registry's published digests. `npm pack` does not verify signatures. `pip download` can verify hashes if `--require-hashes` is used, but agentsec does not enable it.

**Remediation:**
For npm: after `npm pack`, query the registry API (`https://registry.npmjs.org/{package}/{version}`) and compare the tarball's SHA-512 (shasum field) against the downloaded file.
For pip: use `pip download --require-hashes` when a hash is available, or verify the downloaded wheel/sdist SHA-256 against PyPI's JSON API (`https://pypi.org/pypi/{package}/json`).

---

### SCS-003: `--force` Flag Bypasses All Gate Protections Without Audit Trail

**Severity:** HIGH
**Category:** CWE-778 (Insufficient Logging)
**SLSA Impact:** N/A (operational control)

**Attack Scenario:**
The `--force` flag in `gate_check()` allows installation to proceed regardless of findings. In an automated CI/CD environment or when an attacker has terminal access, `--force` silently installs known-malicious packages with only a yellow warning printed to the terminal. There is no file-based audit log, and no way to detect post-facto that `--force` was used.

```python
# gate.py line 177
allowed = force or not has_blocking
```

In `cli.py` line 887, the actual install proceeds unconditionally when `force=True`:
```python
exit_code = subprocess.run([pm, *args]).returncode
```

**Current Mitigation:** A yellow warning is printed to the terminal when `--force` is active (cli.py lines 864-868).

**Gap:** No persistent audit trail. No way to detect that force was used in CI logs unless stdout is captured. No configuration option to disable `--force` for organizational use.

**Remediation:**
1. Write a structured JSON audit log entry to `~/.agentsec/gate-audit.jsonl` whenever `--force` is used, including timestamp, package name, finding count, and severity breakdown.
2. Add a configuration option `gate.allow_force = false` that organizations can set to hard-disable the `--force` flag.
3. Emit a distinct exit code (e.g., 4) when `--force` overrides a block, distinguishing it from "blocked" (1).

---

### SCS-004: Temp Directory Race Condition (Predictable Prefix)

**Severity:** MEDIUM
**Category:** CWE-377 (Insecure Temporary File)
**SLSA Impact:** L0 -- no isolation of build environment

**Attack Scenario:**
`_download_and_scan()` uses `tempfile.mkdtemp(prefix="agentsec_gate_")`. The fixed prefix makes the directory discoverable via `/tmp` enumeration. A local attacker could monitor for new directories matching the pattern and race to place symlinks inside before extraction begins. The window between directory creation (line 241) and tarball extraction is network-bound and non-trivial.

**Current Mitigation:** `mkdtemp()` returns a unique directory name with restrictive permissions (0700) on Unix. On Windows, temp directory ACLs vary.

**Gap:** Fixed `agentsec_gate_` prefix makes the directory discoverable. The zip extraction path (`_extract_zip_archive`) does not perform a post-extraction symlink sweep (tar path does via link blocking). `TemporaryDirectory` context manager is not used, risking cleanup failure on unhandled exceptions.

**Remediation:**
1. Remove the fixed prefix or replace with a cryptographically random one.
2. Add a post-extraction symlink sweep for the zip code path.
3. Use `tempfile.TemporaryDirectory()` context manager for automatic cleanup.

---

### SCS-005: Static Blocklist With No Update Mechanism

**Severity:** MEDIUM
**Category:** CWE-1059 (Insufficient Technical Documentation)
**SLSA Impact:** N/A (threat intelligence)

**Attack Scenario:**
The blocklists `_KNOWN_BAD_NPM` (22 entries) and `_KNOWN_BAD_PIP` (18 entries) are hardcoded. New malicious packages are published to npm and PyPI daily. Between agentsec releases, users have no protection against newly-discovered malicious packages. Some entries (`mcp-tool-exploit`, `claude-skill-helper`, `openclaw-utils-free`) appear to be hypothetical rather than observed in the wild.

**Current Mitigation:** The blocklist is updated with each agentsec release. The code comment notes "a future version could fetch from a remote feed."

**Gap:** No mechanism to update the blocklist between releases. No integration with existing threat feeds (Socket.dev, Phylum, Snyk, npm audit advisories). No user-extensible local blocklist.

**Remediation:**
1. Add support for a local blocklist file (`~/.agentsec/blocklist.json`) that users can update independently.
2. Add an `agentsec gate --update-blocklist` command that fetches from a curated feed.
3. Consider integrating with the Socket.dev or Phylum API for real-time package reputation checks.

---

### SCS-006: No Size Limits on Downloaded Packages (Zip Bomb / Resource Exhaustion)

**Severity:** MEDIUM
**Category:** CWE-400 (Uncontrolled Resource Consumption)
**SLSA Impact:** N/A (availability)

**Attack Scenario:**
A malicious package could contain a zip bomb or tar bomb that expands to gigabytes when extracted. The gate has no size limit on downloaded packages or extracted contents. While the `subprocess.run()` calls have timeouts (60s for npm, 120s for pip), the extraction itself (`_extract_tar_archive`, `_extract_zip_archive`) has no size limit, no file count limit, and no cumulative byte tracking.

**Current Mitigation:** Subprocess timeouts prevent infinite hangs. `shutil.rmtree()` in the finally block cleans up.

**Gap:** No check on archive size before extraction. No limit on total extracted size. No limit on number of files extracted. A 10MB archive could expand to 10GB+ via nested compression.

**Remediation:**
1. Check downloaded archive size before extraction (reject archives over a configurable threshold, e.g., 100MB).
2. Track cumulative extracted bytes during extraction and abort if a limit is exceeded (e.g., 1GB).
3. Limit the number of extracted files (e.g., 10,000) to prevent file-count bombs.

---

### SCS-007: TOCTOU Between Gate Scan and Actual Install

**Severity:** MEDIUM
**Category:** CWE-367 (TOCTOU Race Condition)
**SLSA Impact:** L0 -- scanned artifact is not the installed artifact

**Attack Scenario:**
After the gate scan passes, the CLI executes the actual install command (cli.py line 887):

```python
exit_code = subprocess.run([pm, *args]).returncode
```

The `args` list is the raw user-provided arguments. Between the gate scan (which downloads a specific version via `npm pack`) and the actual install (which may resolve a different version), a new malicious version could be published. The gate scanned version X but `npm install` installs version Y.

**Current Mitigation:** None. The gate and the install are two independent operations.

**Gap:** Classic TOCTOU: the version scanned is not necessarily the version installed. If the user does not specify an exact version pin (`package@1.2.3`), the gate scans the latest at scan time, but the install may resolve a newer version. Additionally, `args` are passed through unmodified -- the CLI does not inject `--ignore-scripts` for npm.

**Remediation:**
1. During the gate scan, record the exact resolved version and tarball hash.
2. Pass `package@<exact-version>` to the actual install command to ensure the installed version matches the scanned version.
3. For npm, additionally pass `--ignore-scripts` and only run scripts if the gate explicitly approved them.

---

## 2. Tool Pinning / Rug Pull Detection (`src/agentsec/scanners/mcp.py`)

### SCS-008: Pins File Has No Integrity Protection

**Severity:** HIGH
**Category:** CWE-353 (Missing Support for Integrity Check)
**SLSA Impact:** L0 -- attestation of pins is missing

**Attack Scenario:**
The `.agentsec-pins.json` file stores SHA-256 hashes of tool descriptions in plain JSON. An attacker who can write to the project directory (e.g., via a malicious MCP server, a compromised dependency, or local access) can silently update the pins file to match new malicious tool descriptions, defeating rug-pull detection entirely.

```python
# mcp.py line 519-531
def save_tool_pins(target: Path, tool_hashes: dict[str, str]) -> Path:
    pins_path = target / _PINS_FILENAME
    pins_data: dict[str, Any] = {"version": 1, "tools": {}}
    for tool_key, digest in sorted(tool_hashes.items()):
        pins_data["tools"][tool_key] = {"hash": digest}
    pins_path.write_text(json.dumps(pins_data, indent=2) + "\n")
    return pins_path
```

**Current Mitigation:** None. The file is plain JSON with no signature, HMAC, or permission enforcement.

**Gap:** No HMAC or digital signature on the pins file. No file permission enforcement after writing (the file is world-readable/writable based on umask). No detection of pins file modification outside of `agentsec pin-tools`. No `last_pinned_at` timestamp or `pinned_by` audit field.

**Remediation:**
1. Add an HMAC field computed over the sorted tool hashes using a machine-specific key derived from a stable machine identifier (e.g., `os.getlogin()` + hostname).
2. Verify the HMAC during `_verify_tool_pins()` and emit a CRITICAL finding if verification fails.
3. Set restrictive file permissions (0600) on the pins file after writing.
4. Add `last_pinned_at` and `pinned_by` fields for audit trail.

---

### SCS-009: Tool Description Hash Does Not Include Schema

**Severity:** MEDIUM
**Category:** CWE-345 (Insufficient Verification of Data Authenticity)
**SLSA Impact:** N/A (verification scope)

**Attack Scenario:**
The tool hash in `_collect_tool_hashes()` is computed only from the tool's `description` field (mcp.py line 430):

```python
digest = hashlib.sha256(description.encode()).hexdigest()
```

An attacker performing a rug-pull could leave the description unchanged but modify the tool's `inputSchema` to add a dangerous parameter (e.g., `shell_command`, `code`, `eval`) that would not be detected by pin verification. The schema change could turn a safe tool into an arbitrary command execution tool while keeping the same description.

**Current Mitigation:** The MCP scanner separately checks `inputSchema` for dangerous parameter names via `_DANGEROUS_SCHEMA_PATTERNS`, but this is pattern-based and can be evaded by using non-obvious parameter names.

**Gap:** The hash should cover the entire tool definition (name + description + inputSchema) to detect any form of tool mutation, not just description changes.

**Remediation:**
```python
# Hash the full tool definition, not just the description
tool_content = json.dumps({
    "name": tool.get("name", ""),
    "description": tool.get("description", ""),
    "inputSchema": tool.get("inputSchema", tool.get("input_schema", {})),
}, sort_keys=True)
digest = hashlib.sha256(tool_content.encode()).hexdigest()
```

---

### SCS-010: TOCTOU Between Pin Verification and Tool Execution

**Severity:** MEDIUM
**Category:** CWE-367 (Time-of-Check Time-of-Use)
**SLSA Impact:** N/A (runtime vs. static analysis gap)

**Attack Scenario:**
`_verify_tool_pins()` reads tool descriptions from the local MCP configuration files and compares hashes against the pins file. However, tools served by remote MCP servers can change their descriptions dynamically at runtime. The description served to the LLM during actual tool invocation may differ from what was in the config file at scan time. A remote server could serve a benign description during scanning but inject a malicious description when the LLM actually invokes the tool.

**Current Mitigation:** CMCP-002 flags remote MCP servers connecting to external URLs at HIGH severity. CMCP-003 flags unverified npx packages at MEDIUM severity.

**Gap:** The pin mechanism only verifies locally-configured tool descriptions. For remote MCP servers, the actual served description is not verified at runtime because agentsec operates as a static scanner, not a runtime proxy.

**Remediation:**
1. Document this limitation clearly in the `pin-tools` help text and README.
2. For remote MCP servers, recommend users deploy an MCP proxy that verifies tool descriptions at runtime against the pins file.
3. Consider adding a `--verify-remote` flag that fetches tool descriptions from running servers and compares against pins.

---

## 3. Skill Scanner Supply Chain (`src/agentsec/scanners/skill.py`)

### SCS-011: No Detection of Dependency Confusion Attacks

**Severity:** HIGH
**Category:** CWE-829 (Inclusion of Functionality from Untrusted Control Sphere)
**SLSA Impact:** L0 -- dependency provenance not verified

**Attack Scenario:**
The skill scanner's `_check_python_requirements()` checks whether dependencies are version-pinned but does not detect dependency confusion attacks. A skill's `requirements.txt` could reference a private package name (`internal-company-lib==1.0.0`) that an attacker has published on PyPI. When the skill is installed in a different environment, pip resolves to the attacker's public package.

Additionally, `_check_python_requirements()` does not scan for malicious directives in requirements files:

```python
# skill.py line 592
if "==" not in line and ">=" not in line and line.strip() not in (".", "-e ."):
```

This check only validates pinning. It does not flag `--extra-index-url`, `--index-url`, `--find-links`, or `-f` directives that could redirect resolution to attacker-controlled registries.

**Current Mitigation:** Unpinned dependencies are flagged as MEDIUM severity. Install hooks in `package.json` are flagged as HIGH.

**Gap:** No detection of:
- `--extra-index-url` or `--index-url` directives in requirements.txt (registry poisoning)
- `--find-links` pointing to attacker-controlled URLs
- `dependency_links` in `setup.py`/`setup.cfg`
- Private package names that shadow public PyPI packages

**Remediation:**
1. Flag `--extra-index-url`, `--index-url`, and `--find-links` directives in requirements.txt as HIGH severity.
2. Flag `dependency_links` in setup.py as HIGH severity.
3. Warn on `--trusted-host` directives (disables TLS verification).

---

### SCS-012: No Detection of `setup.py` Execution-at-Install Attacks

**Severity:** HIGH
**Category:** CWE-829 (Inclusion of Functionality from Untrusted Control Sphere)
**SLSA Impact:** L0 -- build-time code execution unverified

**Attack Scenario:**
The gate downloads sdists with `pip download --no-binary :all:` (gate.py line 317), which means the downloaded package contains a `setup.py`. While `pip download` does not execute `setup.py`, the skill scanner only runs general AST analysis on `.py` files found in the extracted contents. It does not specifically flag `setup.py` as a high-priority file or check for supply chain attack patterns unique to setup scripts:
- `cmdclass` overrides for `install`, `develop`, `egg_info`, `build_ext`
- Network imports (`requests`, `urllib`, `http.client`, `socket`) in a setup script
- Base64/encoded payloads that execute during `pip install`
- Data exfiltration in build commands

**Current Mitigation:** The skill scanner's regex patterns and AST analysis would catch some of these (base64 decode, subprocess, eval/exec) but `setup.py` is not given elevated severity.

**Gap:** `setup.py` should be treated as a high-priority file with elevated severity for any dangerous pattern. A `subprocess.call()` in `setup.py` is categorically more dangerous than in a regular module file.

**Remediation:**
1. In `_run_scanners_on_dir()`, detect `setup.py` files and apply an elevated severity multiplier.
2. Add AST patterns for `cmdclass` dictionary values that override `install`, `develop`, `egg_info`, or `build_ext`.
3. Flag any network imports (`requests`, `urllib`, `http.client`, `socket`) in `setup.py` as CRITICAL.

---

### SCS-013: JavaScript/TypeScript Code Analysis Is Regex-Only

**Severity:** MEDIUM
**Category:** CWE-1007 (Insufficient Visual Distinction of Homoglyphs)
**SLSA Impact:** N/A (detection coverage)

**Attack Scenario:**
The skill scanner runs full AST analysis on Python files but only regex-based scanning on JavaScript/TypeScript files (skill.py lines 313-315):

```python
if source_file.suffix == ".py":
    findings.extend(self._analyze_python_source(source_file, skill_name))
findings.extend(self._scan_regex_patterns(source_file, skill_name))
```

JavaScript is the primary language for MCP servers and npm-distributed skills. Without JS AST analysis, obfuscated malicious code can evade regex detection. For example, `eval(atob('...'))` split across multiple lines, `Function('return this')()` used to access globals, or computed property names like `process['e'+'n'+'v']` would be missed.

**Current Mitigation:** Regex patterns catch some constructs like `base64.b64decode`, but these are Python-centric patterns that do not map to JS idioms.

**Gap:** No detection of JS-specific supply chain patterns: `eval()`, `new Function(`, `require('child_process')`, `process.env` harvesting, dynamic `require()`, `vm.runInNewContext()`, `child_process.execSync`.

**Remediation:**
1. Add JS/TS-specific regex patterns for `eval(`, `new Function(`, `require('child_process')`, `process.env`, `vm.runIn`, `execSync`, `spawnSync`.
2. Consider integrating a lightweight JS parser (e.g., tree-sitter bindings) for AST-level analysis.
3. At minimum, add keyword-based detection for common npm malware patterns documented by Socket.dev and Phylum.

---

### SCS-014: No Cross-Reference Between Gate Blocklist and Skill Dependency Checker

**Severity:** LOW
**Category:** CWE-1059 (Insufficient Technical Documentation)
**SLSA Impact:** N/A (detection coverage)

**Attack Scenario:**
The gate maintains blocklists (`_KNOWN_BAD_NPM`, `_KNOWN_BAD_PIP`) but the skill scanner's `_check_npm_dependencies()` and `_check_python_requirements()` do not cross-reference these lists. A skill that declares `event-stream` or `colourama` as a dependency would not be flagged by the skill scanner -- only the gate would catch it during pre-install download. If a user installs a skill via a mechanism that bypasses the gate (e.g., `git clone`, manual copy), the blocklisted dependency goes undetected.

**Current Mitigation:** The gate catches blocklisted packages during `agentsec gate`. The skill scanner flags unpinned dependencies.

**Gap:** The skill scanner should cross-reference the gate's blocklists when checking dependencies in `requirements.txt` and `package.json`.

**Remediation:**
Extract the blocklists into a shared module (e.g., `agentsec.blocklists`) and check skill dependencies against them during `_check_python_requirements()` and `_check_npm_dependencies()`.

---

## 4. agentsec's Own Supply Chain

### SCS-015: `detect-secrets` Missing from Constraints File

**Severity:** HIGH
**Category:** CWE-1104 (Use of Unmaintained Third Party Components)
**SLSA Impact:** L0 -- security-critical dependency version not reproducible

**Attack Scenario:**
The `requirements/constraints-dev.txt` pins 11 packages but notably omits `detect-secrets`, which is agentsec's security-critical runtime dependency providing the credential scanning engine (23 plugins, 11 heuristic filters). In CI, the constraints file is used with `pip install -c requirements/constraints-dev.txt`, but since `detect-secrets` is not pinned, CI resolves it dynamically. A compromised minor/patch version of `detect-secrets` could disable or weaken credential scanning.

```
# constraints-dev.txt -- detect-secrets is MISSING
build==1.3.0
click==8.3.1
mypy==1.19.1
pip-audit==2.10.0
...
```

The `pyproject.toml` specifies `detect-secrets>=1.4,<2` -- a range spanning 6+ minor versions.

**Current Mitigation:** `pip-audit` runs in CI and would catch known CVEs. Constraints file pins other runtime dependencies.

**Gap:** `detect-secrets` is not pinned in the constraints file. No transitive dependency pinning. No hash verification for any dependency.

**Remediation:**
1. Add `detect-secrets==1.5.0` (or current known-good version) to `constraints-dev.txt`.
2. Use `pip-compile --generate-hashes` to produce a full constraints file with transitive dependencies and integrity hashes.
3. Install with `pip install --require-hashes -c requirements/constraints-dev.txt`.

---

### SCS-016: Runtime Dependencies Use Range Specifiers Without Lock File

**Severity:** MEDIUM
**Category:** CWE-494 (Download of Code Without Integrity Check)
**SLSA Impact:** L0 -- end-user install is not reproducible

**Attack Scenario:**
The `pyproject.toml` specifies runtime dependencies with broad range specifiers:

```toml
dependencies = [
    "click>=8.1,<9",
    "rich>=13.0,<14",
    "pydantic>=2.0,<3",
    "tomli>=2.0,<3; python_version < '3.11'",
    "detect-secrets>=1.4,<2",
]
```

There is no `uv.lock`, `requirements.lock`, or `pip-compile`-generated lock file in the repository. Users installing `agentsec-ai` from PyPI get whatever pip resolves at install time. For a security tool, this is particularly concerning because a compromised dependency could disable scanning.

**Current Mitigation:** CI uses `constraints-dev.txt` which pins some dependency versions. `pip-audit` runs in CI.

**Gap:** The constraints file does not cover transitive dependencies. Users installing agentsec get whatever pip resolves. `pydantic>=2.0,<3` spans 3+ major minor versions with breaking changes.

**Remediation:**
1. Add a `uv.lock` or `pip-compile`-generated lock file with hashes for all transitive dependencies.
2. Tighten `detect-secrets` range (it is security-critical).
3. Consider publishing with metadata that supports `--require-hashes`.

---

### SCS-017: Build Backend (`hatchling`) Is Not Version-Pinned

**Severity:** LOW
**Category:** CWE-1104 (Use of Unmaintained Third Party Components)
**SLSA Impact:** Undermines L2 -- build is not hermetic

**Attack Scenario:**
The `pyproject.toml` build-system section specifies:

```toml
[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"
```

`hatchling` has no version constraint. During `python -m build`, pip resolves and installs the latest version of hatchling and all its transitive dependencies. A compromised version of hatchling could inject code into the built wheel or sdist without detection.

**Current Mitigation:** The publish workflow uses constraints (`pip install --upgrade pip -c requirements/constraints-dev.txt build`), but `hatchling` is not in the constraints file. `build==1.3.0` is pinned, but `hatchling` (the actual backend) is not.

**Gap:** The build backend version is unconstrained in both `pyproject.toml` and `constraints-dev.txt`.

**Remediation:**
1. Pin hatchling in `pyproject.toml`: `requires = ["hatchling==1.25.0"]` (or current known-good version).
2. Add hatchling and its transitive dependencies to `constraints-dev.txt`.

---

### SCS-018: Weekly MCP Scan Workflow Pushes Directly to Main

**Severity:** MEDIUM
**Category:** CWE-269 (Improper Privilege Management)
**SLSA Impact:** N/A (CI/CD hygiene)

**Attack Scenario:**
The `weekly-mcp-scan.yml` workflow has `permissions: contents: write` and directly pushes to `main`:

```yaml
permissions:
  contents: write

# ...
git commit -m "Update MCP security dashboard..."
git pull --rebase origin main
git push
```

If the `generate_mcp_dashboard.py` script is compromised (or if the external repos it scans contain crafted content that triggers unexpected behavior in the dashboard generator), the workflow would push malicious content directly to main, bypassing PR review. The `git pull --rebase` could also merge concurrent changes.

**Current Mitigation:** The workflow runs on a schedule (Mondays) or manual dispatch only. The `git add` is scoped to `docs/mcp-security-grades.md docs/mcp-dashboard/`.

**Gap:** No branch protection enforcement in the workflow. No signed commits from the bot. The `git add` could match unexpected files if the script creates files outside expected paths.

**Remediation:**
1. Use a bot-authored PR instead of direct push to main, allowing branch protection rules to apply.
2. Add `git diff --cached --name-only` validation before committing to ensure only expected paths are staged.
3. Consider using `peter-evans/create-pull-request` action for automated PRs.

---

### SCS-019: Ruff Security Rule Suppressions May Hide Issues

**Severity:** INFO
**Category:** CWE-710 (Improper Adherence to Coding Standards)
**SLSA Impact:** N/A (code quality)

**Attack Scenario:**
The `pyproject.toml` ruff configuration suppresses several security rules globally:

```toml
ignore = ["S101", "S603", "S607", "S104", "S105", "TC001", "TC003"]
```

- `S603` (subprocess call without shell=True check) -- suppressed globally, but the gate and CLI both use `subprocess.run()` with user-controlled input
- `S607` (starting a process with a partial path) -- suppressed globally, meaning `npm`, `pip`, `pip3` are called without absolute paths
- `S105` (hardcoded password detection) -- suppressed globally, which could mask real credential leaks in source

**Current Mitigation:** These rules generate excessive false positives for a security tool that intentionally uses subprocess. The suppressions are documented via the ignore list.

**Gap:** `S603` and `S607` suppressions are appropriate for the gate module but may mask issues in other modules. `S105` suppression could hide real hardcoded secrets if they appear in source.

**Remediation:**
Move S603, S607, and S105 to per-file-ignores for the specific modules that need them (gate.py, cli.py, credential.py), rather than global suppression.

---

## 5. CI/CD Pipeline Supply Chain

### SCS-020: All GitHub Actions Use Mutable Tags (Not SHA-Pinned)

**Severity:** CRITICAL
**Category:** CWE-829 (Inclusion of Functionality from Untrusted Control Sphere)
**SLSA Impact:** Blocks L2 -- build pipeline is not hermetic or reproducible

**Attack Scenario:**
Every GitHub Actions workflow uses mutable version tags instead of SHA-pinned references:

```yaml
# ci.yml
- uses: actions/checkout@v4        # MUTABLE
- uses: actions/setup-python@v5    # MUTABLE
- uses: actions/upload-artifact@v4 # MUTABLE

# publish.yml
- uses: actions/attest-build-provenance@v1  # MUTABLE
- uses: pypa/gh-action-pypi-publish@release/v1  # MUTABLE

# claude-review.yml
- uses: anthropics/claude-code-action@v1  # MUTABLE
```

A compromised or hijacked action can be pushed to the same tag, causing all future workflow runs to execute malicious code. The `pypa/gh-action-pypi-publish` action in the publish workflow has access to PyPI OIDC credentials -- a compromised version could publish malicious packages. The `actions/attest-build-provenance` has `id-token: write` and `attestations: write` -- a compromised version could generate false attestations.

This is a well-documented attack vector. The `tj-actions/changed-files` compromise (CVE-2023-51664) demonstrated that mutable tags on popular actions can be silently replaced.

**Current Mitigation:** None. All actions use mutable tags.

**Gap:** No SHA pinning for any GitHub Action across all 7 workflows.

**Remediation:**
Pin all actions to their full SHA-256 commit hash:

```yaml
# Example for ci.yml
- uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11  # v4.1.1
- uses: actions/setup-python@0a5c61591373683505ea898e09a3ea4f39ef2b9c  # v5.0.0
```

Use Dependabot or Renovate to automatically propose updates when new versions are released.

---

### SCS-021: Publish Workflow Has No Reproducible Build Verification

**Severity:** MEDIUM
**Category:** CWE-693 (Protection Mechanism Failure)
**SLSA Impact:** Blocks L2 -- build is not reproducible or verifiable

**Attack Scenario:**
The publish workflow (publish.yml) builds the package and publishes it in a single step without verifying the build is reproducible:

```yaml
- name: Build package
  run: python -m build

- name: Attest build provenance
  uses: actions/attest-build-provenance@v1
  with:
    subject-path: "dist/*"

- name: Publish to PyPI
  uses: pypa/gh-action-pypi-publish@release/v1
```

There is no comparison between two independent builds to verify reproducibility. There is no Sigstore signing of the built artifacts. The build provenance attestation is generated but users have no documented way to verify it. The build environment is not hermetic -- `hatchling` is resolved dynamically.

**Current Mitigation:** Build provenance attestation is generated. PyPI trusted publisher (OIDC) is used. Signed tags are required by `tag-verify.yml`.

**Gap:** No Sigstore signing. No reproducible build verification. No documented verification instructions for users. Build backend version is unconstrained.

**Remediation:**
1. Add Sigstore signing: `python -m sigstore sign dist/*`
2. Add a reproducible build step that builds twice and compares hashes.
3. Document how users can verify the attestation: `gh attestation verify <artifact> --repo debu-sinha/agentsec`
4. Pin hatchling version for hermetic builds.

---

### SCS-022: Claude Review Workflow Has Broad Permissions

**Severity:** LOW
**Category:** CWE-200 (Exposure of Sensitive Information)
**SLSA Impact:** N/A (CI security)

**Attack Scenario:**
The `claude-review.yml` workflow has `id-token: write` permission (claude-review.yml line 13), which is typically needed for OIDC federation but is unusual for a code review action. The `issue_comment` trigger could allow `@claude` mentions in comments to trigger API calls without the comment author being a collaborator, enabling cost abuse.

```yaml
permissions:
  contents: read
  pull-requests: write
  issues: write
  id-token: write  # Why does a review action need this?
```

**Current Mitigation:** GitHub Actions secrets are not exposed to fork PRs by default in `pull_request` events. The workflow uses the standard `pull_request` trigger (not `pull_request_target`), which is safe for secrets.

**Gap:** `id-token: write` is unnecessarily broad for a review action. No collaborator check on `issue_comment` trigger. No rate limiting.

**Remediation:**
1. Remove `id-token: write` unless required by the Claude action.
2. Add a condition to check that the comment author is a collaborator before processing `@claude` mentions.
3. Consider adding a rate limit (e.g., max 3 review triggers per PR).

---

### SCS-023: No SBOM Generation in Build/Publish Pipeline

**Severity:** INFO
**Category:** CWE-1059 (Insufficient Technical Documentation)
**SLSA Impact:** Needed for L3 -- full provenance and dependency transparency

**Attack Scenario:**
The publish pipeline does not generate a Software Bill of Materials (SBOM). Users and organizations with compliance requirements cannot verify the full dependency tree of the installed package. Without an SBOM, it is difficult to perform transitive dependency analysis for newly-discovered CVEs.

**Current Mitigation:** `pip-audit` runs in CI to check for known vulnerabilities. Build provenance attestation provides some artifact metadata.

**Gap:** No SBOM in CycloneDX or SPDX format. No published dependency manifest for users.

**Remediation:**
1. Add SBOM generation to the publish workflow: `pip install cyclonedx-bom && cyclonedx-py --format json -o dist/sbom.json`
2. Publish the SBOM as a release artifact alongside the wheel and sdist.
3. Consider integrating with GitHub's dependency submission API.

---

## Summary of Remediation Priorities

### Phase 1: Immediate (before next release)

| ID | Title | Severity | Effort |
|----|-------|----------|--------|
| SCS-001 | Validate package names before subprocess | CRITICAL | Low |
| SCS-020 | SHA-pin all GitHub Actions | CRITICAL | Medium |
| SCS-015 | Pin detect-secrets in constraints file | HIGH | Low |
| SCS-003 | Add audit log for --force usage | HIGH | Low |

### Phase 2: Short-term (next 1-2 releases)

| ID | Title | Severity | Effort |
|----|-------|----------|--------|
| SCS-002 | Verify package integrity before extraction | HIGH | Medium |
| SCS-008 | Add HMAC/tamper detection to pins file | HIGH | Medium |
| SCS-011 | Detect dependency confusion patterns | HIGH | Medium |
| SCS-012 | Elevate setup.py analysis in gate scanner | HIGH | Low |
| SCS-009 | Hash full tool definition, not just description | MEDIUM | Low |
| SCS-007 | Pin exact version for actual install command | MEDIUM | Medium |
| SCS-016 | Add lock file with hashes for runtime deps | MEDIUM | Medium |

### Phase 3: Medium-term (roadmap)

| ID | Title | Severity | Effort |
|----|-------|----------|--------|
| SCS-005 | Local blocklist + threat feed integration | MEDIUM | High |
| SCS-006 | Size limits on archive extraction | MEDIUM | Medium |
| SCS-013 | JavaScript AST analysis | MEDIUM | High |
| SCS-018 | Use PR-based flow for weekly MCP scan | MEDIUM | Low |
| SCS-021 | Reproducible build + Sigstore signing | MEDIUM | Medium |
| SCS-004 | Randomize temp dir prefix | MEDIUM | Low |
| SCS-010 | Document remote MCP TOCTOU limitation | MEDIUM | Low |
| SCS-017 | Pin hatchling build backend version | LOW | Low |
| SCS-022 | Tighten Claude review workflow permissions | LOW | Low |
| SCS-014 | Cross-reference gate blocklist in skill scanner | LOW | Low |
| SCS-019 | Move ruff security suppressions to per-file | INFO | Low |
| SCS-023 | Add SBOM generation to publish pipeline | INFO | Medium |

---

## Positive Security Controls

The review also identified several areas where agentsec demonstrates strong supply chain security practices:

1. **Safe archive extraction:** `_extract_tar_archive()` correctly blocks path traversal and link entries on pre-3.12 Python, and uses the `filter="data"` parameter on 3.12+. `_extract_zip_archive()` validates each member individually to prevent TOCTOU between validation and extraction.

2. **npm pack over npm install:** The gate uses `npm pack` instead of `npm install`, which downloads the tarball without executing install hooks. This is the correct pattern and avoids the primary npm supply chain attack vector.

3. **Build provenance attestation:** The publish workflow uses `actions/attest-build-provenance@v1`, generating SLSA-compliant provenance for published artifacts.

4. **Signed tag enforcement:** The `tag-verify.yml` workflow requires signed annotated tags matching semver format for releases, preventing unauthorized tag pushes and version tampering.

5. **PyPI trusted publisher (OIDC):** The publish workflow uses `pypa/gh-action-pypi-publish` with OIDC, eliminating static PyPI API tokens from secrets and reducing credential exposure risk.

6. **pip-audit in CI:** Dependency vulnerability scanning is integrated into the CI pipeline, catching known CVEs in direct and transitive dependencies.

7. **Tool poisoning detection:** The MCP scanner's regex patterns for tool description manipulation (hidden instructions, data exfiltration, privilege escalation, invisible unicode, encoded content) are comprehensive and cover the known attack taxonomy from recent MCP security research.

8. **Install hook detection:** Both the gate (`_check_npm_install_hooks`) and skill scanner (`_check_npm_dependencies`) detect npm install lifecycle scripts (preinstall, postinstall, install, prepare), which are the primary vector for npm supply chain attacks.

9. **Credential sanitization:** Secrets in findings are consistently sanitized (first 4 + last 4 chars) across all output formats (terminal, JSON, SARIF), preventing accidental credential exposure in scan reports.

10. **Self-scan in CI:** agentsec runs `agentsec scan src/ --fail-on critical` against itself in the CI pipeline, practicing what it preaches.

---

*End of review.*
