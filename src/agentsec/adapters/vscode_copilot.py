"""VS Code Copilot adapter — parses GitHub Copilot configuration into FrameworkConfig.

Reads VS Code MCP server declarations (note: uses "servers" key, not "mcpServers"),
settings.json for auto-approve config, tasks.json for runOn hooks,
copilot-instructions.md, and AGENTS.md rule files.
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
    ".vscode/mcp.json",
]

# VS Code settings (project-level)
_PROJECT_SETTINGS = [
    ".vscode/settings.json",
]

# VS Code tasks (project-level)
_PROJECT_TASKS = [
    ".vscode/tasks.json",
]

# Copilot instruction files (project-level)
_PROJECT_RULE_FILES = [
    ".github/copilot-instructions.md",
    "AGENTS.md",
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


class VSCodeCopilotAdapter(FrameworkAdapter):
    """Adapter for VS Code with GitHub Copilot configuration."""

    @property
    def name(self) -> str:
        return "vscode_copilot"

    @property
    def display_name(self) -> str:
        return "VS Code Copilot"

    @property
    def known_config_paths(self) -> list[str]:
        return [
            ".vscode/mcp.json",
            ".vscode/settings.json",
            ".vscode/tasks.json",
            ".github/copilot-instructions.md",
            "AGENTS.md",
        ]

    def detect(self, target: Path) -> bool:
        """Check for VS Code Copilot markers at the target."""
        if (target / ".vscode" / "mcp.json").is_file():
            return True
        if (target / ".github" / "copilot-instructions.md").is_file():
            return True
        return bool((target / "AGENTS.md").is_file())

    def discover_configs(self, target: Path) -> list[Path]:
        """Return all VS Code Copilot config files found at project level."""
        found: list[Path] = []

        # MCP configs
        for rel in _PROJECT_MCP_CONFIGS:
            path = target / rel
            if path.is_file():
                found.append(path)

        # VS Code settings
        for rel in _PROJECT_SETTINGS:
            path = target / rel
            if path.is_file():
                found.append(path)

        # VS Code tasks
        for rel in _PROJECT_TASKS:
            path = target / rel
            if path.is_file():
                found.append(path)

        # Rule files
        for rel in _PROJECT_RULE_FILES:
            path = target / rel
            if path.is_file():
                found.append(path)

        return found

    def parse(self, target: Path) -> FrameworkConfig:
        """Parse all VS Code Copilot configs into a normalized FrameworkConfig."""
        config = FrameworkConfig(framework=self.name)
        raw: dict[str, Any] = {}

        # Parse MCP configs (uses "servers" key, not "mcpServers")
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

        # Parse VS Code settings for auto-approve config
        for rel in _PROJECT_SETTINGS:
            path = target / rel
            if not path.is_file():
                continue
            data = _read_json(path)
            if data is None:
                continue
            config.config_paths.append(path)
            raw[rel] = data
            self._extract_settings(data, config)

        # Parse VS Code tasks for hooks
        for rel in _PROJECT_TASKS:
            path = target / rel
            if not path.is_file():
                continue
            data = _read_json(path)
            if data is None:
                continue
            config.config_paths.append(path)
            raw[rel] = data
            self._extract_tasks(data, config, str(path))

        # Parse rule files
        self._extract_rules(target, config)

        config.raw_configs = raw
        return config

    # ------------------------------------------------------------------
    # MCP server extraction
    # ------------------------------------------------------------------

    def _extract_mcp_servers(self, data: dict[str, Any], config: FrameworkConfig) -> None:
        """Parse MCP server declarations from .vscode/mcp.json.

        VS Code uses the "servers" key, NOT "mcpServers" like Claude Code
        and Cursor. Each server entry has the same structure (command, args, env).
        """
        servers = data.get("servers", {})
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
    # Settings extraction
    # ------------------------------------------------------------------

    def _extract_settings(self, data: dict[str, Any], config: FrameworkConfig) -> None:
        """Extract Copilot auto-approve settings from .vscode/settings.json.

        Checks github.copilot.chat.agent.autoApprove which controls whether
        Copilot agent tool calls are auto-approved without user confirmation.
        """
        auto_approve = data.get("github.copilot.chat.agent.autoApprove")
        if auto_approve is None:
            return

        if isinstance(auto_approve, bool) and auto_approve:
            config.permissions.auto_approve_tools.append("*")
        elif isinstance(auto_approve, list):
            config.permissions.auto_approve_tools.extend(str(t) for t in auto_approve)

    # ------------------------------------------------------------------
    # Task extraction (hooks)
    # ------------------------------------------------------------------

    def _extract_tasks(
        self, data: dict[str, Any], config: FrameworkConfig, source_file: str
    ) -> None:
        """Extract VS Code tasks with runOn: folderOpen as hooks.

        Tasks with "runOptions": {"runOn": "folderOpen"} execute automatically
        when the workspace opens, which is a potential attack vector.
        """
        tasks = data.get("tasks", [])
        if not isinstance(tasks, list):
            return

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
                    source_file=source_file,
                )
            )

    # ------------------------------------------------------------------
    # Rule extraction
    # ------------------------------------------------------------------

    def _extract_rules(self, target: Path, config: FrameworkConfig) -> None:
        """Collect rules from copilot-instructions.md and AGENTS.md."""
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
