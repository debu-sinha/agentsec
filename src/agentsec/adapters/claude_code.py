"""Claude Code adapter — parses Claude Code configuration into FrameworkConfig.

Reads Claude Code project and user-level settings, MCP server declarations,
rules (CLAUDE.md, .claude/rules/, .claude/agents/, .claude/commands/),
hooks, permissions, sandbox config, and environment variables.
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
    PluginConfig,
    RuleConfig,
    SandboxConfig,
)

logger = logging.getLogger(__name__)

# Claude Code settings files (project-level, relative to target)
_PROJECT_SETTINGS = [
    ".claude/settings.json",
    ".claude/settings.local.json",
]

# Claude Code MCP config files (project-level)
_PROJECT_MCP_CONFIGS = [
    ".mcp.json",
]

# Rule sources (project-level)
_PROJECT_RULE_SOURCES = [
    "CLAUDE.md",
    ".claude/CLAUDE.md",
]

# Rule directories (project-level)
_PROJECT_RULE_DIRS = [
    ".claude/rules",
    ".claude/agents",
    ".claude/commands",
]

# User-level config paths (relative to home)
_USER_SETTINGS = [
    ".claude/settings.json",
]

_USER_MCP_CONFIGS = [
    ".claude.json",
]

_USER_RULE_SOURCES = [
    ".claude/CLAUDE.md",
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


class ClaudeCodeAdapter(FrameworkAdapter):
    """Adapter for Claude Code agent framework configuration."""

    @property
    def name(self) -> str:
        return "claude_code"

    @property
    def display_name(self) -> str:
        return "Claude Code"

    @property
    def known_config_paths(self) -> list[str]:
        return [
            ".claude/settings.json",
            ".claude/settings.local.json",
            ".mcp.json",
            "CLAUDE.md",
            ".claude/CLAUDE.md",
            "~/.claude/settings.json",
            "~/.claude.json",
            "~/.claude/CLAUDE.md",
        ]

    def detect(self, target: Path) -> bool:
        """Check for Claude Code markers at the target or in the user home."""
        # Project-level markers
        if (target / ".claude").is_dir():
            return True
        if (target / "CLAUDE.md").is_file():
            return True

        # User-global installation
        home = Path.home()
        return bool((home / ".claude").is_dir())

    def discover_configs(self, target: Path) -> list[Path]:
        """Return all Claude Code config files found at project and user level."""
        found: list[Path] = []
        home = Path.home()

        # Project-level settings
        for rel in _PROJECT_SETTINGS:
            path = target / rel
            if path.is_file():
                found.append(path)

        # Project-level MCP
        for rel in _PROJECT_MCP_CONFIGS:
            path = target / rel
            if path.is_file():
                found.append(path)

        # Project-level rule files
        for rel in _PROJECT_RULE_SOURCES:
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

        # User-level settings
        for rel in _USER_SETTINGS:
            path = home / rel
            if path.is_file():
                found.append(path)

        # User-level MCP
        for rel in _USER_MCP_CONFIGS:
            path = home / rel
            if path.is_file():
                found.append(path)

        # User-level rule files
        for rel in _USER_RULE_SOURCES:
            path = home / rel
            if path.is_file():
                found.append(path)

        return found

    def parse(self, target: Path) -> FrameworkConfig:
        """Parse all Claude Code configs into a normalized FrameworkConfig."""
        home = Path.home()
        config = FrameworkConfig(framework=self.name)
        raw: dict[str, Any] = {}

        # Parse project-level settings files
        for rel in _PROJECT_SETTINGS:
            path = target / rel
            if not path.is_file():
                continue
            data = _read_json(path)
            if data is None:
                continue
            config.config_paths.append(path)
            raw[rel] = data
            self._extract_settings(data, config, str(path))

        # Parse user-level settings
        for rel in _USER_SETTINGS:
            path = home / rel
            if not path.is_file():
                continue
            data = _read_json(path)
            if data is None:
                continue
            config.config_paths.append(path)
            raw[f"~/{rel}"] = data
            self._extract_settings(data, config, str(path))

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
        self._extract_rules(target, home, config)

        config.raw_configs = raw
        return config

    # ------------------------------------------------------------------
    # Settings extraction
    # ------------------------------------------------------------------

    def _extract_settings(
        self, data: dict[str, Any], config: FrameworkConfig, source_file: str
    ) -> None:
        """Extract hooks, permissions, env, sandbox, and plugins from a settings dict."""
        self._extract_hooks(data.get("hooks", {}), config, source_file)
        self._extract_permissions(data.get("permissions", {}), config)
        self._extract_env(data.get("env", {}), config)
        self._extract_sandbox(data, config)
        self._extract_plugins(data.get("enabledPlugins", []), config)

        # Track auto-approve MCP flag
        if data.get("enableAllProjectMcpServers"):
            config.permissions.auto_approve_mcp.append("*")

    def _extract_hooks(
        self, hooks: dict[str, Any], config: FrameworkConfig, source_file: str
    ) -> None:
        """Parse Claude Code hooks structure into HookConfig list.

        The hooks structure is:
        {
            "PreToolUse": [
                {
                    "matcher": "Bash",
                    "hooks": [
                        {"type": "command", "command": "...", "timeout": 30},
                        {"type": "prompt", "prompt": "..."}
                    ]
                }
            ]
        }
        """
        if not isinstance(hooks, dict):
            return

        for event_name, hook_groups in hooks.items():
            if not isinstance(hook_groups, list):
                continue
            for group in hook_groups:
                if not isinstance(group, dict):
                    continue
                for hook in group.get("hooks", []):
                    if not isinstance(hook, dict):
                        continue
                    hook_type = hook.get("type", "")
                    command = hook.get("command", "")
                    prompt = hook.get("prompt", "")
                    timeout = hook.get("timeout", 30)
                    if not isinstance(timeout, int):
                        timeout = 30

                    config.hooks.append(
                        HookConfig(
                            event=event_name,
                            hook_type=hook_type,
                            command=command,
                            prompt=prompt,
                            timeout=timeout,
                            source_file=source_file,
                        )
                    )

    def _extract_permissions(self, permissions: dict[str, Any], config: FrameworkConfig) -> None:
        """Parse Claude Code permissions into PermissionsConfig."""
        if not isinstance(permissions, dict):
            return

        allow = permissions.get("allow", [])
        deny = permissions.get("deny", [])
        default_mode = permissions.get("defaultMode", "ask")
        auto_approve = permissions.get("autoApprove", [])

        if isinstance(allow, list):
            config.permissions.allow_rules.extend(str(r) for r in allow)
        if isinstance(deny, list):
            config.permissions.deny_rules.extend(str(r) for r in deny)
        if isinstance(default_mode, str):
            config.permissions.default_mode = default_mode
        if isinstance(auto_approve, list):
            config.permissions.auto_approve_tools.extend(str(r) for r in auto_approve)

    def _extract_env(self, env: dict[str, Any], config: FrameworkConfig) -> None:
        """Extract environment variable declarations."""
        if not isinstance(env, dict):
            return
        for key, value in env.items():
            if isinstance(value, str):
                config.env_vars[key] = value

    def _extract_sandbox(self, data: dict[str, Any], config: FrameworkConfig) -> None:
        """Extract sandbox/network isolation settings."""
        sandbox_data = data.get("sandbox", {})
        if not isinstance(sandbox_data, dict):
            return

        enabled = sandbox_data.get("enabled", False)
        network_domains = sandbox_data.get("networkAllowedDomains", [])
        fs_deny_read = sandbox_data.get("filesystemDenyRead", [])
        fs_allow_write = sandbox_data.get("filesystemAllowWrite", [])

        if not isinstance(network_domains, list):
            network_domains = []
        if not isinstance(fs_deny_read, list):
            fs_deny_read = []
        if not isinstance(fs_allow_write, list):
            fs_allow_write = []

        config.sandbox = SandboxConfig(
            enabled=bool(enabled),
            network_allowed_domains=[str(d) for d in network_domains],
            filesystem_deny_read=[str(p) for p in fs_deny_read],
            filesystem_allow_write=[str(p) for p in fs_allow_write],
        )

    def _extract_plugins(self, plugins: list[Any], config: FrameworkConfig) -> None:
        """Extract enabled plugins/extensions."""
        if not isinstance(plugins, list):
            return
        for plugin in plugins:
            if isinstance(plugin, str):
                config.plugins.append(PluginConfig(name=plugin, enabled=True))
            elif isinstance(plugin, dict):
                config.plugins.append(
                    PluginConfig(
                        name=plugin.get("name", "unknown"),
                        source=plugin.get("source", ""),
                        enabled=plugin.get("enabled", True),
                        marketplace=plugin.get("marketplace", ""),
                    )
                )

    # ------------------------------------------------------------------
    # MCP server extraction
    # ------------------------------------------------------------------

    def _extract_mcp_servers(self, data: dict[str, Any], config: FrameworkConfig) -> None:
        """Parse MCP server declarations from .mcp.json or ~/.claude.json."""
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

    def _extract_rules(self, target: Path, home: Path, config: FrameworkConfig) -> None:
        """Collect rules from CLAUDE.md files, .claude/rules/, agents/, commands/."""
        # Project-level rule files
        for rel in _PROJECT_RULE_SOURCES:
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

        # Project-level rule directories
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

                # Determine activation mode from directory name
                parent_name = dir_path.name
                if parent_name == "rules":
                    activation = "always"
                elif parent_name == "agents":
                    activation = "agent"
                elif parent_name == "commands":
                    activation = "command"
                else:
                    activation = "always"

                config.rules.append(
                    RuleConfig(
                        name=child.stem,
                        content=content,
                        source_file=str(child),
                        activation_mode=activation,
                    )
                )

        # User-level rule files
        for rel in _USER_RULE_SOURCES:
            path = home / rel
            content = _read_text(path) if path.is_file() else None
            if content is not None:
                config.config_paths.append(path)
                config.rules.append(
                    RuleConfig(
                        name=f"user:{path.name}",
                        content=content,
                        source_file=str(path),
                        activation_mode="always",
                    )
                )
