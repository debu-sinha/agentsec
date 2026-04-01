"""Cursor adapter — parses Cursor configuration into FrameworkConfig.

Reads Cursor MCP server declarations, .cursorrules, .cursor/rules/*.mdc
(MDC format with YAML frontmatter), and VS Code tasks with runOn triggers.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from agentsec.adapters.base import (
    FrameworkAdapter,
    FrameworkConfig,
    HookConfig,
    McpServerConfig,
    RuleConfig,
)

logger = logging.getLogger(__name__)

# MCP config files (project-level, relative to target)
_PROJECT_MCP_CONFIGS = [
    ".cursor/mcp.json",
]

# MCP config files (user-level, relative to home)
_USER_MCP_CONFIGS = [
    ".cursor/mcp.json",
]

# Rule sources (project-level)
_PROJECT_RULE_FILES = [
    ".cursorrules",
]

# Rule directories with MDC files (project-level)
_PROJECT_RULE_DIRS = [
    ".cursor/rules",
]

# VS Code tasks file (project-level, Cursor inherits VS Code task runner)
_PROJECT_TASKS = [
    ".vscode/tasks.json",
]


def _read_json(path: Path) -> dict[str, Any] | None:
    """Read and parse a JSON file, returning None on any error."""
    try:
        return json.loads(path.read_text())
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


def _parse_mdc(content: str, source_file: str) -> RuleConfig | None:
    """Parse an MDC file (YAML frontmatter between --- markers + markdown body).

    MDC format:
        ---
        description: Some description
        globs: "*.py"
        alwaysApply: false
        ---
        Body content here...

    Returns a RuleConfig with activation_mode and glob_pattern extracted
    from the frontmatter, and the markdown body as content.
    """
    stripped = content.strip()
    if not stripped.startswith("---"):
        # No frontmatter, treat entire file as content
        return RuleConfig(
            name=Path(source_file).stem,
            content=stripped,
            source_file=source_file,
            activation_mode="always",
        )

    # Find the closing --- delimiter
    rest = stripped[3:]
    end_idx = rest.find("---")
    if end_idx == -1:
        # Malformed frontmatter, treat entire file as content
        return RuleConfig(
            name=Path(source_file).stem,
            content=stripped,
            source_file=source_file,
            activation_mode="always",
        )

    frontmatter_text = rest[:end_idx].strip()
    body = rest[end_idx + 3 :].strip()

    # Parse frontmatter as simple key: value pairs (avoid yaml dependency)
    frontmatter: dict[str, str] = {}
    for line in frontmatter_text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        colon_idx = line.find(":")
        if colon_idx == -1:
            continue
        key = line[:colon_idx].strip()
        value = line[colon_idx + 1 :].strip().strip('"').strip("'")
        frontmatter[key] = value

    # Determine activation mode
    always_apply = frontmatter.get("alwaysApply", "false").lower() == "true"
    glob_pattern = frontmatter.get("globs", "")

    if always_apply:
        activation = "always"
    elif glob_pattern:
        activation = "glob"
    else:
        activation = "manual"

    return RuleConfig(
        name=Path(source_file).stem,
        content=body,
        source_file=source_file,
        activation_mode=activation,
        glob_pattern=glob_pattern,
    )


class CursorAdapter(FrameworkAdapter):
    """Adapter for Cursor editor configuration."""

    @property
    def name(self) -> str:
        return "cursor"

    @property
    def display_name(self) -> str:
        return "Cursor"

    @property
    def known_config_paths(self) -> list[str]:
        return [
            ".cursor/mcp.json",
            "~/.cursor/mcp.json",
            ".cursorrules",
            ".cursor/rules/",
            ".vscode/tasks.json",
        ]

    def detect(self, target: Path) -> bool:
        """Check for Cursor markers at the target or in the user home."""
        if (target / ".cursor").is_dir():
            return True
        if (target / ".cursorrules").is_file():
            return True

        home = Path.home()
        return bool((home / ".cursor").is_dir())

    def discover_configs(self, target: Path) -> list[Path]:
        """Return all Cursor config files found at project and user level."""
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

        # Project-level MDC rule directories
        for rel in _PROJECT_RULE_DIRS:
            dir_path = target / rel
            if dir_path.is_dir():
                for child in dir_path.iterdir():
                    if child.is_file() and child.suffix == ".mdc":
                        found.append(child)

        # VS Code tasks
        for rel in _PROJECT_TASKS:
            path = target / rel
            if path.is_file():
                found.append(path)

        return found

    def parse(self, target: Path) -> FrameworkConfig:
        """Parse all Cursor configs into a normalized FrameworkConfig."""
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

        # Parse VS Code tasks for hooks
        self._extract_tasks(target, config)

        config.raw_configs = raw
        return config

    # ------------------------------------------------------------------
    # MCP server extraction
    # ------------------------------------------------------------------

    def _extract_mcp_servers(self, data: dict[str, Any], config: FrameworkConfig) -> None:
        """Parse MCP server declarations from .cursor/mcp.json.

        Cursor uses the same mcpServers key format as Claude Code.
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
        """Collect rules from .cursorrules and .cursor/rules/*.mdc."""
        # .cursorrules file
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

        # .cursor/rules/*.mdc files
        for rel in _PROJECT_RULE_DIRS:
            dir_path = target / rel
            if not dir_path.is_dir():
                continue
            for child in sorted(dir_path.iterdir()):
                if not child.is_file() or child.suffix != ".mdc":
                    continue
                content = _read_text(child)
                if content is None:
                    continue

                rule = _parse_mdc(content, str(child))
                if rule is not None:
                    config.rules.append(rule)

    # ------------------------------------------------------------------
    # Task extraction (hooks)
    # ------------------------------------------------------------------

    def _extract_tasks(self, target: Path, config: FrameworkConfig) -> None:
        """Extract VS Code tasks with runOn: folderOpen as hooks.

        Cursor inherits the VS Code task runner. Tasks with
        "runOptions": {"runOn": "folderOpen"} execute automatically
        when the workspace opens.
        """
        for rel in _PROJECT_TASKS:
            path = target / rel
            if not path.is_file():
                continue
            data = _read_json(path)
            if data is None:
                continue

            tasks = data.get("tasks", [])
            if not isinstance(tasks, list):
                continue

            for task in tasks:
                if not isinstance(task, dict):
                    continue

                run_options = task.get("runOptions", {})
                if not isinstance(run_options, dict):
                    continue

                run_on = run_options.get("runOn", "")
                if run_on != "folderOpen":
                    continue

                task.get("label", "unnamed_task")
                command = task.get("command", "")
                task_type = task.get("type", "shell")

                if not command:
                    continue

                config.hooks.append(
                    HookConfig(
                        event="folderOpen",
                        hook_type=task_type,
                        command=command,
                        source_file=str(path),
                    )
                )
