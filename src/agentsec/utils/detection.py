"""Agent installation detection utilities.

Auto-detects the type of agent installation (OpenClaw, Claude Code, etc.)
based on filesystem markers. Supports legacy names (Clawdbot, Moltbot).
"""

from __future__ import annotations

import logging
from pathlib import Path

logger = logging.getLogger(__name__)

# Filesystem markers for agent type detection (ordered by specificity)
_AGENT_MARKERS: dict[str, list[str]] = {
    "openclaw": [
        "openclaw.json",
        ".openclaw",
        ".openclaw/openclaw.json",
        "SOUL.md",
        "node_modules/openclaw",
    ],
    "clawdbot": [
        "clawdbot.json",
        ".clawdbot",
        ".clawdbot/clawdbot.json",
        "node_modules/clawdbot",
    ],
    "moltbot": [
        ".moltbot",
        "moltbot.json",
        "node_modules/moltbot",
    ],
    "claude-code": [
        ".claude",
        "claude_desktop_config.json",
        ".claude/settings.json",
    ],
}

# Legacy agent types that map to their modern equivalents
_AGENT_TYPE_ALIASES: dict[str, str] = {
    "clawdbot": "openclaw",
    "moltbot": "openclaw",
}


def detect_agent_type(target: Path) -> str:
    """Detect the type of agent installation at the given path.

    Returns the agent type string or 'unknown' if no markers match.
    Normalizes legacy names (clawdbot, moltbot) to 'openclaw'.
    """
    for agent_type, markers in _AGENT_MARKERS.items():
        for marker in markers:
            marker_path = target / marker
            if marker_path.exists():
                logger.info("Detected agent type '%s' via marker: %s", agent_type, marker)
                return _AGENT_TYPE_ALIASES.get(agent_type, agent_type)

    # Check home directory patterns
    home = Path.home()
    for agent_type, markers in _AGENT_MARKERS.items():
        for marker in markers:
            if (home / marker).exists():
                logger.info(
                    "Detected agent type '%s' via home directory marker: %s",
                    agent_type,
                    marker,
                )
                return _AGENT_TYPE_ALIASES.get(agent_type, agent_type)

    logger.info("Could not auto-detect agent type at %s", target)
    return "unknown"


def find_agent_installations() -> list[tuple[Path, str]]:
    """Scan common locations for agent installations.

    Returns list of (path, agent_type) tuples.
    """
    installations: list[tuple[Path, str]] = []
    home = Path.home()

    # Common installation locations (including legacy paths)
    candidates = [
        home,
        home / ".openclaw",
        home / ".clawdbot",
        home / ".moltbot",
        home / ".claude",
        home / ".config" / "openclaw",
        home / ".config" / "clawdbot",
        # Legacy Moltbot/Clawdbot paths
        home / "clawd",
    ]

    # Also check if running inside an agent directory
    cwd = Path.cwd()
    if cwd not in candidates:
        candidates.insert(0, cwd)

    for candidate in candidates:
        if candidate.exists():
            agent_type = detect_agent_type(candidate)
            if agent_type != "unknown":
                installations.append((candidate, agent_type))

    # Deduplicate by resolved path
    seen: set[Path] = set()
    unique: list[tuple[Path, str]] = []
    for path, atype in installations:
        resolved = path.resolve()
        if resolved not in seen:
            seen.add(resolved)
            unique.append((path, atype))

    return unique
