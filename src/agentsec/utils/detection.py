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
    "cursor": [
        ".cursor",
        ".cursor/mcp.json",
        ".cursorrc",
    ],
    "windsurf": [
        ".windsurf",
        ".windsurf/mcp.json",
        ".codeium",
    ],
    "gemini-cli": [
        ".gemini",
        ".gemini/settings.json",
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
