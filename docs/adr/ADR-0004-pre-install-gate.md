# ADR-0004: Pre-Install Security Gate for Skills and MCP Servers

## Status
Accepted

## Context
agentsec currently offers three reactive mechanisms for detecting malicious skills and MCP servers:

1. **Post-install scanning** (`agentsec scan`): Detects issues after they're already on disk
2. **Shell hooks** (`agentsec hook`): Wraps npm/pip to scan after `install` completes
3. **Filesystem watcher** (`agentsec watch`): Polls for changes and scans when detected

All three share the same limitation: **the malicious code is already installed and potentially executed before agentsec sees it.** npm `postinstall` scripts run during `npm install`, meaning a malicious skill's install hook fires before agentsec's post-install scan. This is the difference between a smoke detector (reactive) and a firewall (preventive).

The agentic AI ecosystem has documented supply chain attacks:
- Published research has identified hundreds of malicious skills in public agent marketplaces, including data exfiltration and reverse shell payloads
- npm `preinstall`/`postinstall` hooks execute arbitrary code during installation
- pip `setup.py` can run arbitrary code during `pip install`

We need a preventive mechanism that evaluates packages BEFORE installation.

## Decision

Add `agentsec gate` -- a pre-install security gate that intercepts package installation, performs security checks on the package metadata and contents, and blocks installation if critical issues are found.

### Architecture

```
User runs: agentsec gate npm install cool-skill
                |
                v
    [1] Parse command (npm install cool-skill)
                |
                v
    [2] Download package to temp dir (npm pack / pip download)
                |
                v
    [3] Run skill + MCP scanners on temp contents
                |
                v
    [4] Check against known-bad registry (local blocklist)
                |
                v
    [5] PASS -> execute original install command
         FAIL -> block install, show findings, exit non-zero
```

### Key Design Choices

1. **Wrapper command, not a hook**: `agentsec gate npm install X` rather than replacing npm globally. This is explicit, auditable, and doesn't require system-level changes.

2. **Download-then-scan**: Use `npm pack` / `pip download --no-deps` to fetch the package without executing install scripts. Scan the tarball contents in a temp directory.

3. **Blocklist + heuristic**: Maintain a local blocklist of known-malicious packages (from Koi Security research, npm advisories). Also run the existing skill scanner on the downloaded contents.

4. **Fail-closed by default**: If scanning fails (network error, parse error), block the install. Users can `--force` to bypass.

5. **Shell hook integration**: The existing `agentsec hook` command will be updated to generate shell functions that use `agentsec gate` instead of post-install scanning.

### CLI Interface

```bash
# Gate a single install
agentsec gate npm install some-skill
agentsec gate pip install some-mcp-server

# Gate with custom threshold
agentsec gate --fail-on critical npm install some-skill

# Force install despite findings
agentsec gate --force npm install some-skill

# Check a package without installing
agentsec gate --dry-run npm install some-skill
```

### What Gets Scanned Pre-Install

| Check | Source | Feasible Pre-Install? |
|-------|--------|----------------------|
| Known-malicious package name | Local blocklist | Yes |
| npm install hooks (preinstall/postinstall) | package.json | Yes |
| Dangerous imports (eval, exec, subprocess) | AST analysis of source | Yes |
| Obfuscation patterns (base64, hex encoding) | Regex on source | Yes |
| Data exfiltration patterns | Regex on source | Yes |
| Prompt injection in tool descriptions | String analysis | Yes |
| Unpinned dependencies | package.json / requirements.txt | Yes |
| Typosquatting detection | Levenshtein distance vs popular packages | Yes (new) |
| Runtime behavior | Execution in sandbox | No (v0.5+ feature) |

## Alternatives Considered

### 1) npm/pip Wrapper Script (Replace Binary)
- Approach: Replace `npm` with a wrapper that always scans first
- Pros: Transparent, catches all installs
- Cons: Fragile (breaks on npm updates, path issues), intrusive, hard to maintain across platforms
- Rejected: Too invasive, users don't trust tools that replace system binaries

### 2) OS-Level File System Hook (inotify/FSEvents)
- Approach: Block file writes to skill directories until scan completes
- Pros: Catches ALL installation methods (manual copy, git clone, etc.)
- Cons: Requires root/admin, platform-specific, complex to implement correctly
- Rejected: Too complex, too platform-dependent, requires elevated privileges

### 3) Package Registry Proxy
- Approach: Run a local npm/pip registry proxy that scans packages in transit
- Pros: Transparent, catches all installs via that registry
- Cons: Requires registry configuration, TLS cert management, heavy infrastructure
- Rejected: Overkill for single-developer use case, doesn't fit CLI tool model

### 4) Git Pre-Commit Hook Only
- Approach: Scan on commit, not on install
- Pros: Simple, well-understood model
- Cons: Malicious code already executed during install, pre-commit is too late
- Rejected: Doesn't prevent the attack, only prevents committing evidence of it

## Consequences

### Positive
- **Prevents supply chain attacks before execution**: npm postinstall scripts never run
- **Reuses existing scanners**: skill.py and mcp.py analysis runs on downloaded contents
- **Explicit and auditable**: User sees exactly what was blocked and why
- **No system-level changes**: Wrapper command, not a binary replacement
- **Unique differentiator**: No other agentic security tool offers pre-install gating

### Negative
- **Extra step for users**: `agentsec gate npm install X` is longer than `npm install X`
- **Download overhead**: Package is downloaded twice (once to scan, once to install)
- **Cannot catch all vectors**: Manual file copies, git clones bypass the gate
- **Blocklist maintenance**: Known-bad list needs regular updates

### Neutral
- Shell hook integration means most users won't type the full command manually
- The gate command could eventually integrate with package manager plugin APIs (npm hooks, pip constraints) for tighter integration
