"""Framework adapter interface and normalized config models.

Adapters translate framework-specific configuration files (Claude Code,
Cursor, Windsurf, etc.) into a common FrameworkConfig structure that
scanners can reason about uniformly.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Sub-config dataclasses
# ---------------------------------------------------------------------------


@dataclass
class McpServerConfig:
    """Normalized representation of a single MCP server declaration."""

    name: str
    command: str
    args: list[str] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)
    transport: str = "stdio"
    requires_auth: bool = False


@dataclass
class PermissionsConfig:
    """Normalized tool/resource permission rules."""

    allow_rules: list[str] = field(default_factory=list)
    deny_rules: list[str] = field(default_factory=list)
    default_mode: str = "ask"
    auto_approve_tools: list[str] = field(default_factory=list)
    auto_approve_mcp: list[str] = field(default_factory=list)


@dataclass
class HookConfig:
    """Normalized lifecycle hook (pre/post tool use, etc.)."""

    event: str
    hook_type: str
    command: str
    prompt: str = ""
    timeout: int = 30
    source_file: str = ""


@dataclass
class RuleConfig:
    """Normalized instruction rule (CLAUDE.md, .cursorrules, etc.)."""

    name: str
    content: str
    source_file: str = ""
    activation_mode: str = "always"
    glob_pattern: str = ""


@dataclass
class SandboxConfig:
    """Normalized sandbox / network isolation settings."""

    enabled: bool = False
    network_allowed_domains: list[str] = field(default_factory=list)
    filesystem_deny_read: list[str] = field(default_factory=list)
    filesystem_allow_write: list[str] = field(default_factory=list)


@dataclass
class PluginConfig:
    """Normalized plugin / extension declaration."""

    name: str
    source: str = ""
    enabled: bool = True
    marketplace: str = ""


# ---------------------------------------------------------------------------
# Top-level normalized config
# ---------------------------------------------------------------------------


@dataclass
class FrameworkConfig:
    """Unified configuration extracted from any agent framework.

    Scanners operate on this structure instead of parsing raw JSON/YAML
    from each framework individually.
    """

    framework: str
    config_paths: list[Path] = field(default_factory=list)
    mcp_servers: list[McpServerConfig] = field(default_factory=list)
    permissions: PermissionsConfig = field(default_factory=PermissionsConfig)
    hooks: list[HookConfig] = field(default_factory=list)
    rules: list[RuleConfig] = field(default_factory=list)
    sandbox: SandboxConfig | None = None
    plugins: list[PluginConfig] = field(default_factory=list)
    env_vars: dict[str, str] = field(default_factory=dict)
    raw_configs: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Abstract adapter
# ---------------------------------------------------------------------------


class FrameworkAdapter(ABC):
    """Abstract base for framework-specific config adapters.

    Each supported agent framework (Claude Code, Cursor, Windsurf, etc.)
    gets a concrete subclass that knows how to locate, read, and normalize
    that framework's configuration into a FrameworkConfig.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Machine-readable adapter identifier (e.g. 'claude_code')."""

    @property
    @abstractmethod
    def display_name(self) -> str:
        """Human-readable name shown in reports (e.g. 'Claude Code')."""

    @abstractmethod
    def detect(self, target: Path) -> bool:
        """Return True if the target directory contains this framework's artifacts."""

    @abstractmethod
    def discover_configs(self, target: Path) -> list[Path]:
        """Return paths to all config files found under *target* for this framework."""

    @abstractmethod
    def parse(self, target: Path) -> FrameworkConfig:
        """Parse all discovered configs into a normalized FrameworkConfig."""

    @property
    @abstractmethod
    def known_config_paths(self) -> list[str]:
        """Relative paths this framework is known to use for configuration.

        Used for quick existence checks before full parsing. Paths may
        contain ``~`` for user-home expansion.
        """
