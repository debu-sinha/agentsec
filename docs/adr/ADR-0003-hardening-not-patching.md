# ADR-0003: Hardening via Config, Not Patching

## Status
Accepted

## Context
When agentsec detects a misconfiguration (e.g., gateway bound to LAN, DM policy set to "open"), the tool needs a remediation strategy. The fundamental question: should agentsec modify the agent's source code, binary, or runtime behavior -- or should it only modify the agent's configuration files?

This decision has major implications for:
- **Safety**: patching binaries or injecting code can break the agent
- **Maintainability**: patches break on upstream updates
- **Trust**: users need to understand exactly what changed
- **Reversibility**: users must be able to undo remediation
- **Scope**: config changes are bounded; code changes are unbounded

OpenClaw (and similar agents) store security-relevant settings in JSON config files (`openclaw.json`). Most security misconfigurations are config issues, not code bugs.

## Decision

**agentsec only modifies JSON configuration files. It never patches code, modifies binaries, injects runtime hooks, or changes the agent's source.**

The hardening engine (`hardener.py`) operates under these constraints:

1. **Config-only**: All changes are to JSON config files (openclaw.json, exec-approvals.json)
2. **Backup first**: A `.json.bak` copy is created before any write
3. **Dry-run by default**: `agentsec harden` previews changes; `--apply` is required to write
4. **Idempotent**: Running the same profile twice is safe (already-applied settings are skipped)
5. **Profile-based**: Changes are grouped into opinionated profiles (workstation, vps, public-bot) rather than individual toggles
6. **Transparent**: Every change includes a human-readable reason string
7. **Permission tightening**: File permissions (chmod 700/600) are applied as a safe side effect

What the hardener explicitly does NOT do:
- Modify OpenClaw source code or plugins
- Inject middleware or proxy layers
- Change systemd/docker/supervisor configurations
- Rotate credentials or generate new keys
- Modify firewall rules or network configuration
- Install additional software

## Alternatives Considered

### 1) Binary Patching / Monkey-Patching
- Approach: Modify OpenClaw's runtime to enforce security policies
- Pros: Can enforce policies that config alone cannot (e.g., runtime tool blocking)
- Cons: Breaks on upstream updates, fragile, hard to audit, version-specific
- Rejected: Too fragile, too risky, impossible to maintain across OpenClaw versions

### 2) Wrapper/Proxy Architecture
- Approach: Run a security proxy in front of OpenClaw's gateway
- Pros: Can inspect and block traffic in real-time, doesn't modify OpenClaw
- Cons: Adds operational complexity, latency, another failure point. Requires network-level integration.
- Rejected: Solves a different problem (runtime enforcement vs. posture hardening)

### 3) OpenClaw Plugin
- Approach: Build an OpenClaw skill that enforces security policies from inside
- Pros: Native integration, can leverage OpenClaw's API
- Cons: Requires OpenClaw to be running, chicken-and-egg problem (insecure agent loads security plugin), can be disabled by the agent itself
- Rejected: A security tool should not depend on the system it's securing

### 4) Individual Setting Commands
- Approach: `agentsec set gateway.bind loopback` for each setting
- Pros: Maximum granularity, user controls every change
- Cons: Requires security knowledge to know which settings matter. Users will miss critical combinations.
- Rejected: Profiles are better UX. Individual commands are too low-level for most users.

## Consequences

### Positive
- **Zero risk of breaking the agent**: Config changes are the intended customization mechanism
- **Fully reversible**: Restore from `.json.bak` or manually revert any setting
- **Auditable**: `git diff` on the config file shows exactly what changed
- **Survives upgrades**: Config files persist across OpenClaw version updates
- **No dependency on OpenClaw internals**: Works with any version that reads the config format
- **User trust**: Users can inspect the profile before applying (`show-profile`, dry-run)

### Negative
- **Limited scope**: Cannot remediate issues that require code changes (e.g., fixing a vulnerable dependency)
- **Cannot enforce runtime policies**: Config says "sandbox: all" but can't verify the sandbox actually works
- **Credential rotation is out of scope**: Detected plaintext secrets require manual rotation
- **Some findings are unfixable by config**: Malicious skill code, vulnerable npm packages

### Neutral
- Profiles are opinionated -- users may disagree with specific settings
- Config format changes in future OpenClaw versions would require hardener updates
- The "hardening gap" (findings that config can't fix) is clearly communicated in the delta report
