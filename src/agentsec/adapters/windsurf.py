"""Windsurf adapter — parses Windsurf configuration into FrameworkConfig.

Reads Windsurf MCP server declarations from project and user-level configs,
.windsurfrules, and .windsurf/rules/*.md rule files.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from agentsec.adapters.base import (
    FrameworkAdapter,
    FrameworkConfig,
    McpServerConfig,
    RuleConfig,
)

logger = logging.getLogger(__name__)

# MCP config files (project-level, relative to target)
_PROJECT_MCP_CONFIGS = [
    ".windsurf/mcp.json",
]

# MCP config files (user-level, relative to home)
_USER_MCP_CONFIGS = [
    ".windsurf/mcp.json",
    ".codeium/windsurf/mcp_config.json",
]

# Rule sources (project-level)
_PROJECT_RULE_FILES = [
    ".windsurfrules",
]

# Rule directories (project-level)
_PROJECT_RULE_DIRS = [
    ".windsurf/rules",
]


def _read_json(path: Path) -> dict[str, Any] | None:
    """Read and parse a JSON file, returning None on any error."""
    try:
        data: dict[str, Any] = json.loads(path.read_text())
        return data
    except json.JSONDecodeError:
        logger.debug("Malformed JSON in %s", path)
        return None
    except OSError as e:
        logger.debug("Could not read %s: %s", path, e)
        return None
    except PermissionError:
        logger.debug("Permission denied reading %s", path)
        return None


def _read_text(path: Path) -> str | None:
    """Read a text file, returning None on any error."""
    try:
        return path.read_text(errors="replace")
    except OSError as e:
        logger.debug("Could not read %s: %s", path, e)
        return None
    except PermissionError:
        logger.debug("Permission denied reading %s", path)
        return None


class WindsurfAdapter(FrameworkAdapter):
    """Adapter for Windsurf editor configuration."""

    @property
    def name(self) -> str:
        return "windsurf"

    @property
    def display_name(self) -> str:
        return "Windsurf"

    @property
    def known_config_paths(self) -> list[str]:
        return [
            ".windsurf/mcp.json",
            "~/.windsurf/mcp.json",
            "~/.codeium/windsurf/mcp_config.json",
            ".windsurfrules",
            ".windsurf/rules/",
        ]

    def detect(self, target: Path) -> bool:
        """Check for Windsurf markers at the target or in the user home."""
        if (target / ".windsurf").is_dir():
            return True
        if (target / ".windsurfrules").is_file():
            return True

        home = Path.home()
        if (home / ".codeium" / "windsurf").is_dir():
            return True
        return bool((home / ".windsurf").is_dir())

    def discover_configs(self, target: Path) -> list[Path]:
        """Return all Windsurf config files found at project and user level."""
        found: list[Path] = []
        home = Path.home()

        # Project-level MCP configs
        for rel in _PROJECT_MCP_CONFIGS:
            path = target / rel
            if path.is_file():
                found.append(path)

        # User-level MCP configs
        for rel in _USER_MCP_CONFIGS:
            path = home / rel
            if path.is_file():
                found.append(path)

        # Project-level rule files
        for rel in _PROJECT_RULE_FILES:
            path = target / rel
            if path.is_file():
                found.append(path)

        # Project-level rule directories
        for rel in _PROJECT_RULE_DIRS:
            dir_path = target / rel
            if dir_path.is_dir():
                for child in dir_path.iterdir():
                    if child.is_file() and child.suffix == ".md":
                        found.append(child)

        return found

    def parse(self, target: Path) -> FrameworkConfig:
        """Parse all Windsurf configs into a normalized FrameworkConfig."""
        home = Path.home()
        config = FrameworkConfig(framework=self.name)
        raw: dict[str, Any] = {}

        # Parse project-level MCP configs
        for rel in _PROJECT_MCP_CONFIGS:
            path = target / rel
            if not path.is_file():
                continue
            data = _read_json(path)
            if data is None:
                continue
            config.config_paths.append(path)
            raw[rel] = data
            self._extract_mcp_servers(data, config)

        # Parse user-level MCP configs
        for rel in _USER_MCP_CONFIGS:
            path = home / rel
            if not path.is_file():
                continue
            data = _read_json(path)
            if data is None:
                continue
            config.config_paths.append(path)
            raw[f"~/{rel}"] = data
            self._extract_mcp_servers(data, config)

        # Parse rule files
        self._extract_rules(target, config)

        config.raw_configs = raw
        return config

    # ------------------------------------------------------------------
    # MCP server extraction
    # ------------------------------------------------------------------

    def _extract_mcp_servers(self, data: dict[str, Any], config: FrameworkConfig) -> None:
        """Parse MCP server declarations from Windsurf MCP config files.

        Windsurf uses the mcpServers key, same structure as Claude Code and Cursor.
        """
        servers = data.get("mcpServers", {})
        if not isinstance(servers, dict):
            return

        for server_name, server_data in servers.items():
            if not isinstance(server_data, dict):
                continue

            command = server_data.get("command", "")
            args = server_data.get("args", [])
            env = server_data.get("env", {})
            transport = server_data.get("transport", "stdio")

            if not isinstance(command, str):
                command = str(command)
            if not isinstance(args, list):
                args = []
            if not isinstance(env, dict):
                env = {}
            if not isinstance(transport, str):
                transport = "stdio"

            requires_auth = bool(server_data.get("auth") or server_data.get("headers"))

            config.mcp_servers.append(
                McpServerConfig(
                    name=server_name,
                    command=command,
                    args=[str(a) for a in args],
                    env={k: str(v) for k, v in env.items() if isinstance(v, str)},
                    transport=transport,
                    requires_auth=requires_auth,
                )
            )

    # ------------------------------------------------------------------
    # Rule extraction
    # ------------------------------------------------------------------

    def _extract_rules(self, target: Path, config: FrameworkConfig) -> None:
        """Collect rules from .windsurfrules and .windsurf/rules/*.md."""
        # .windsurfrules file
        for rel in _PROJECT_RULE_FILES:
            path = target / rel
            content = _read_text(path) if path.is_file() else None
            if content is not None:
                config.config_paths.append(path)
                config.rules.append(
                    RuleConfig(
                        name=path.name,
                        content=content,
                        source_file=str(path),
                        activation_mode="always",
                    )
                )

        # .windsurf/rules/*.md files
        for rel in _PROJECT_RULE_DIRS:
            dir_path = target / rel
            if not dir_path.is_dir():
                continue
            for child in sorted(dir_path.iterdir()):
                if not child.is_file() or child.suffix != ".md":
                    continue
                content = _read_text(child)
                if content is None:
                    continue

                config.rules.append(
                    RuleConfig(
                        name=child.stem,
                        content=content,
                        source_file=str(child),
                        activation_mode="always",
                    )
                )
