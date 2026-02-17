"""Profile-based hardening engine for OpenClaw installations.

Applies safe configuration changes without forking OpenClaw.
Changes are made to the JSON config file directly.

Profiles:
  workstation: single owner, loopback, pairing, minimal exposure
  vps:         remote hosting, strong auth, firewall posture, tool restrictions
  public-bot:  untrusted input, sandbox on, minimal tools, no exec
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class HardenAction:
    """A single config change to apply."""

    key: str
    value: object
    reason: str
    severity: str = "recommended"


@dataclass
class HardenResult:
    """Result of a hardening run."""

    profile: str
    applied: list[HardenAction] = field(default_factory=list)
    skipped: list[HardenAction] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    config_path: Path | None = None
    dry_run: bool = True


# Hardening profiles
_PROFILES: dict[str, list[HardenAction]] = {
    "workstation": [
        HardenAction(
            key="gateway.bind",
            value="loopback",
            reason="Bind to localhost only — single user workstation",
        ),
        HardenAction(
            key="dmPolicy",
            value="paired",
            reason="Only accept DMs from paired devices",
        ),
        HardenAction(
            key="discovery.mdns.mode",
            value="minimal",
            reason="Minimize mDNS broadcast information",
        ),
        HardenAction(
            key="tools.profile",
            value="messaging",
            reason="Restrict tool access; add specific tools via tools.allow",
            severity="recommended",
        ),
        HardenAction(
            key="session.dmScope",
            value="per-channel-peer",
            reason="Isolate DM sessions per channel peer",
        ),
        HardenAction(
            key="dangerouslyDisableDeviceAuth",
            value=False,
            reason="Never disable device auth, even on a workstation",
            severity="critical",
        ),
        HardenAction(
            key="dangerouslyDisableAuth",
            value=False,
            reason="Never disable auth — re-enable immediately",
            severity="critical",
        ),
        HardenAction(
            key="groupPolicy",
            value="allowlist",
            reason="Restrict to explicitly allowed groups only",
        ),
    ],
    "vps": [
        HardenAction(
            key="gateway.bind",
            value="loopback",
            reason="Bind to localhost; use reverse proxy with TLS for remote access",
        ),
        HardenAction(
            key="dmPolicy",
            value="paired",
            reason="Only accept DMs from authorized devices",
        ),
        HardenAction(
            key="groupPolicy",
            value="allowlist",
            reason="Only respond in explicitly allowed groups",
        ),
        HardenAction(
            key="discovery.mdns.mode",
            value="off",
            reason="Disable mDNS — VPS should not broadcast on LAN",
        ),
        HardenAction(
            key="tools.profile",
            value="messaging",
            reason="Restrict tools; enable only what's needed",
        ),
        HardenAction(
            key="session.dmScope",
            value="per-channel-peer",
            reason="Isolate per user for multi-tenant safety",
        ),
        HardenAction(
            key="dangerouslyDisableDeviceAuth",
            value=False,
            reason="Never disable device auth on remote systems",
            severity="critical",
        ),
    ],
    "public-bot": [
        HardenAction(
            key="gateway.bind",
            value="loopback",
            reason="Bind to localhost; front with authenticated reverse proxy",
        ),
        HardenAction(
            key="dmPolicy",
            value="allowlist",
            reason="Only respond to explicitly allowed users",
        ),
        HardenAction(
            key="groupPolicy",
            value="allowlist",
            reason="Only respond in explicitly allowed groups",
        ),
        HardenAction(
            key="discovery.mdns.mode",
            value="off",
            reason="Never broadcast public bot presence",
        ),
        HardenAction(
            key="tools.profile",
            value="minimal",
            reason="Minimal tools — untrusted input is constant",
        ),
        HardenAction(
            key="tools.deny",
            value=["exec", "browser", "web"],
            reason="Deny exec/browser/web for public-facing agents",
            severity="critical",
        ),
        HardenAction(
            key="sandbox.mode",
            value="all",
            reason="Sandbox all sessions — untrusted input everywhere",
            severity="critical",
        ),
        HardenAction(
            key="session.dmScope",
            value="per-channel-peer",
            reason="Strict session isolation for multi-user",
        ),
        HardenAction(
            key="dangerouslyDisableDeviceAuth",
            value=False,
            reason="Never disable device auth on public bots",
            severity="critical",
        ),
        HardenAction(
            key="dangerouslyDisableAuth",
            value=False,
            reason="Never disable auth on public bots",
            severity="critical",
        ),
    ],
}


def get_profiles() -> list[str]:
    """Return available hardening profile names."""
    return list(_PROFILES.keys())


def get_profile_actions(profile: str) -> list[HardenAction]:
    """Return the hardening actions for a profile."""
    if profile not in _PROFILES:
        raise ValueError(f"Unknown profile '{profile}'. Available: {', '.join(_PROFILES)}")
    return list(_PROFILES[profile])


def harden(
    target: Path,
    profile: str,
    dry_run: bool = True,
) -> HardenResult:
    """Apply a hardening profile to an OpenClaw installation.

    Args:
        target: Root directory of the agent installation
        profile: Hardening profile name (workstation, vps, public-bot)
        dry_run: If True, report what would change without writing
    """
    actions = get_profile_actions(profile)
    result = HardenResult(profile=profile, dry_run=dry_run)

    # Find config file
    config_path = _find_config(target)
    if not config_path:
        result.errors.append(
            f"No openclaw.json or clawdbot.json found in {target}. "
            f"Cannot apply hardening without a config file."
        )
        return result

    result.config_path = config_path

    # Load current config
    try:
        config_data = json.loads(config_path.read_text())
    except (json.JSONDecodeError, OSError) as e:
        result.errors.append(f"Failed to read config: {e}")
        return result

    # Apply each action
    for action in actions:
        current = _get_nested(config_data, action.key)
        if current == action.value:
            result.skipped.append(action)
        else:
            if not dry_run:
                _set_nested(config_data, action.key, action.value)
            result.applied.append(action)

    # Write updated config
    if not dry_run and result.applied:
        try:
            # Backup first
            backup = config_path.with_suffix(".json.bak")
            shutil.copy2(config_path, backup)
            config_path.write_text(json.dumps(config_data, indent=2) + "\n")
            logger.info("Config updated: %s (backup: %s)", config_path, backup)
        except OSError as e:
            result.errors.append(f"Failed to write config: {e}")

    # Tighten file permissions (always safe)
    if not dry_run:
        _tighten_permissions(target)

    return result


def _find_config(target: Path) -> Path | None:
    """Find the OpenClaw config file."""
    candidates = [
        target / "openclaw.json",
        target / ".openclaw" / "openclaw.json",
        target / "clawdbot.json",
        target / ".clawdbot" / "clawdbot.json",
    ]
    for c in candidates:
        if c.exists():
            return c
    return None


def _get_nested(data: dict, dotpath: str) -> object:
    """Get a value from a nested dict using dot notation."""
    keys = dotpath.split(".")
    current: Any = data
    for key in keys:
        if isinstance(current, dict):
            current = current.get(key)
        else:
            return None
    return current


def _set_nested(data: dict, dotpath: str, value: object) -> None:
    """Set a value in a nested dict using dot notation, creating parents as needed."""
    keys = dotpath.split(".")
    current = data
    for key in keys[:-1]:
        if key not in current or not isinstance(current[key], dict):
            current[key] = {}
        current = current[key]
    current[keys[-1]] = value


def _tighten_permissions(target: Path) -> None:
    """Tighten filesystem permissions on agent config directories and files."""
    for dir_name in [".openclaw", ".clawdbot", ".moltbot"]:
        dir_path = target / dir_name
        if dir_path.is_dir():
            try:
                os.chmod(dir_path, stat.S_IRWXU)  # 700
                logger.info("Set %s to 700", dir_path)
            except OSError:
                logger.debug("Could not chmod %s", dir_path)

    sensitive_files = [
        "openclaw.json",
        "clawdbot.json",
        ".env",
        ".env.local",
        "exec-approvals.json",
    ]
    for dir_name in [".openclaw", ".clawdbot", ""]:
        base = target / dir_name if dir_name else target
        for fname in sensitive_files:
            fpath = base / fname
            if fpath.is_file():
                try:
                    os.chmod(fpath, stat.S_IRUSR | stat.S_IWUSR)  # 600
                    logger.info("Set %s to 600", fpath)
                except OSError:
                    logger.debug("Could not chmod %s", fpath)
