"""Agent definitions for auto-discovery and multi-framework scanning.

Single source of truth for AI agent installation paths, marker files,
and config locations across macOS, Linux, and Windows.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class AgentDefinition:
    """Definition of a known AI agent for discovery and scanning."""

    name: str
    display_name: str
    agent_type: str
    marker_paths: dict[str, list[str]] = field(default_factory=dict)
    config_paths: dict[str, list[str]] = field(default_factory=dict)
    mcp_config_paths: dict[str, list[str]] = field(default_factory=dict)
    binary_names: list[str] = field(default_factory=list)
    env_overrides: list[str] = field(default_factory=list)
    supported: bool = False


AGENT_REGISTRY: dict[str, AgentDefinition] = {
    "claude_code": AgentDefinition(
        name="claude_code",
        display_name="Claude Code",
        agent_type="claude-code",
        marker_paths={
            "darwin": ["~/.claude/"],
            "linux": ["~/.claude/"],
            "windows": ["%USERPROFILE%\\.claude\\"],
        },
        config_paths={
            "darwin": [
                "~/.claude/settings.json",
                ".claude/settings.json",
                ".claude/settings.local.json",
            ],
            "linux": [
                "~/.claude/settings.json",
                ".claude/settings.json",
                ".claude/settings.local.json",
            ],
            "windows": [
                "%USERPROFILE%\\.claude\\settings.json",
                ".claude\\settings.json",
                ".claude\\settings.local.json",
            ],
        },
        mcp_config_paths={
            "darwin": ["~/.claude.json", ".mcp.json"],
            "linux": ["~/.claude.json", ".mcp.json"],
            "windows": ["%USERPROFILE%\\.claude.json", ".mcp.json"],
        },
        binary_names=["claude"],
        supported=True,
    ),
    "claude_desktop": AgentDefinition(
        name="claude_desktop",
        display_name="Claude Desktop",
        agent_type="claude-desktop",
        marker_paths={
            "darwin": ["~/Library/Application Support/Claude/"],
            "linux": ["~/.config/claude-desktop/"],
            "windows": ["%APPDATA%\\Claude\\"],
        },
        config_paths={
            "darwin": [
                "~/Library/Application Support/Claude/claude_desktop_config.json",
            ],
            "linux": ["~/.config/claude-desktop/claude_desktop_config.json"],
            "windows": ["%APPDATA%\\Claude\\claude_desktop_config.json"],
        },
        mcp_config_paths={
            "darwin": [
                "~/Library/Application Support/Claude/claude_desktop_config.json",
            ],
            "linux": ["~/.config/claude-desktop/claude_desktop_config.json"],
            "windows": ["%APPDATA%\\Claude\\claude_desktop_config.json"],
        },
        supported=False,
    ),
    "cursor": AgentDefinition(
        name="cursor",
        display_name="Cursor",
        agent_type="cursor",
        marker_paths={
            "darwin": ["~/.cursor/"],
            "linux": ["~/.cursor/"],
            "windows": ["%USERPROFILE%\\.cursor\\"],
        },
        config_paths={
            "darwin": [
                "~/.cursor/mcp.json",
                ".cursor/mcp.json",
                ".cursorrules",
            ],
            "linux": [
                "~/.cursor/mcp.json",
                ".cursor/mcp.json",
                ".cursorrules",
            ],
            "windows": [
                "%USERPROFILE%\\.cursor\\mcp.json",
                ".cursor\\mcp.json",
                ".cursorrules",
            ],
        },
        mcp_config_paths={
            "darwin": ["~/.cursor/mcp.json", ".cursor/mcp.json"],
            "linux": ["~/.cursor/mcp.json", ".cursor/mcp.json"],
            "windows": [
                "%USERPROFILE%\\.cursor\\mcp.json",
                ".cursor\\mcp.json",
            ],
        },
        binary_names=["cursor"],
        supported=True,
    ),
    "windsurf": AgentDefinition(
        name="windsurf",
        display_name="Windsurf",
        agent_type="windsurf",
        marker_paths={
            "darwin": ["~/.codeium/windsurf/", "~/.windsurf/"],
            "linux": ["~/.codeium/windsurf/", "~/.windsurf/"],
            "windows": [
                "%USERPROFILE%\\.codeium\\windsurf\\",
                "%USERPROFILE%\\.windsurf\\",
            ],
        },
        config_paths={
            "darwin": [
                "~/.codeium/windsurf/mcp_config.json",
                ".windsurf/mcp.json",
                ".windsurfrules",
            ],
            "linux": [
                "~/.codeium/windsurf/mcp_config.json",
                ".windsurf/mcp.json",
                ".windsurfrules",
            ],
            "windows": [
                "%USERPROFILE%\\.codeium\\windsurf\\mcp_config.json",
                ".windsurf\\mcp.json",
                ".windsurfrules",
            ],
        },
        mcp_config_paths={
            "darwin": [
                "~/.codeium/windsurf/mcp_config.json",
                ".windsurf/mcp.json",
            ],
            "linux": [
                "~/.codeium/windsurf/mcp_config.json",
                ".windsurf/mcp.json",
            ],
            "windows": [
                "%USERPROFILE%\\.codeium\\windsurf\\mcp_config.json",
                ".windsurf\\mcp.json",
            ],
        },
        supported=True,
    ),
    "vscode_copilot": AgentDefinition(
        name="vscode_copilot",
        display_name="VS Code Copilot",
        agent_type="vscode-copilot",
        marker_paths={
            "darwin": ["~/.vscode/extensions/github.copilot-*"],
            "linux": ["~/.vscode/extensions/github.copilot-*"],
            "windows": ["%USERPROFILE%\\.vscode\\extensions\\github.copilot-*"],
        },
        config_paths={
            "darwin": [
                ".vscode/mcp.json",
                ".vscode/settings.json",
                ".vscode/tasks.json",
                ".github/copilot-instructions.md",
            ],
            "linux": [
                ".vscode/mcp.json",
                ".vscode/settings.json",
                ".vscode/tasks.json",
                ".github/copilot-instructions.md",
            ],
            "windows": [
                ".vscode\\mcp.json",
                ".vscode\\settings.json",
                ".vscode\\tasks.json",
                ".github\\copilot-instructions.md",
            ],
        },
        mcp_config_paths={
            "darwin": [".vscode/mcp.json"],
            "linux": [".vscode/mcp.json"],
            "windows": [".vscode\\mcp.json"],
        },
        binary_names=["code"],
        supported=True,
    ),
    "gemini_cli": AgentDefinition(
        name="gemini_cli",
        display_name="Gemini CLI",
        agent_type="gemini-cli",
        marker_paths={
            "darwin": ["~/.gemini/"],
            "linux": ["~/.gemini/"],
            "windows": ["%USERPROFILE%\\.gemini\\"],
        },
        config_paths={
            "darwin": ["~/.gemini/settings.json", ".gemini/settings.json"],
            "linux": ["~/.gemini/settings.json", ".gemini/settings.json"],
            "windows": [
                "%USERPROFILE%\\.gemini\\settings.json",
                ".gemini\\settings.json",
            ],
        },
        mcp_config_paths={
            "darwin": ["~/.gemini/settings.json"],
            "linux": ["~/.gemini/settings.json"],
            "windows": ["%USERPROFILE%\\.gemini\\settings.json"],
        },
        binary_names=["gemini"],
        env_overrides=["GEMINI_CLI_HOME"],
        supported=False,
    ),
    "codex": AgentDefinition(
        name="codex",
        display_name="OpenAI Codex CLI",
        agent_type="codex",
        marker_paths={
            "darwin": ["~/.codex/"],
            "linux": ["~/.codex/"],
            "windows": ["%USERPROFILE%\\.codex\\"],
        },
        config_paths={
            "darwin": ["~/.codex/config.toml", ".codex/config.toml"],
            "linux": ["~/.codex/config.toml", ".codex/config.toml"],
            "windows": [
                "%USERPROFILE%\\.codex\\config.toml",
                ".codex\\config.toml",
            ],
        },
        mcp_config_paths={
            "darwin": ["~/.codex/config.toml"],
            "linux": ["~/.codex/config.toml"],
            "windows": ["%USERPROFILE%\\.codex\\config.toml"],
        },
        binary_names=["codex"],
        env_overrides=["CODEX_HOME"],
        supported=False,
    ),
    "openclaw": AgentDefinition(
        name="openclaw",
        display_name="OpenClaw",
        agent_type="openclaw",
        marker_paths={
            "darwin": ["~/.openclaw/", "~/.clawdbot/"],
            "linux": ["~/.openclaw/", "~/.clawdbot/"],
            "windows": [
                "%USERPROFILE%\\.openclaw\\",
                "%USERPROFILE%\\.clawdbot\\",
            ],
        },
        config_paths={
            "darwin": ["~/.openclaw/openclaw.json"],
            "linux": ["~/.openclaw/openclaw.json"],
            "windows": ["%USERPROFILE%\\.openclaw\\openclaw.json"],
        },
        mcp_config_paths={
            "darwin": ["~/.openclaw/openclaw.json"],
            "linux": ["~/.openclaw/openclaw.json"],
            "windows": ["%USERPROFILE%\\.openclaw\\openclaw.json"],
        },
        env_overrides=["OPENCLAW_HOME"],
        supported=True,
    ),
    "amazon_q": AgentDefinition(
        name="amazon_q",
        display_name="Amazon Q Developer",
        agent_type="amazon-q",
        marker_paths={
            "darwin": ["~/.aws/amazonq/"],
            "linux": ["~/.aws/amazonq/"],
            "windows": ["%USERPROFILE%\\.aws\\amazonq\\"],
        },
        config_paths={
            "darwin": ["~/.aws/amazonq/mcp.json", ".amazonq/default.json"],
            "linux": ["~/.aws/amazonq/mcp.json", ".amazonq/default.json"],
            "windows": [
                "%USERPROFILE%\\.aws\\amazonq\\mcp.json",
                ".amazonq\\default.json",
            ],
        },
        mcp_config_paths={
            "darwin": ["~/.aws/amazonq/mcp.json", ".amazonq/default.json"],
            "linux": ["~/.aws/amazonq/mcp.json", ".amazonq/default.json"],
            "windows": [
                "%USERPROFILE%\\.aws\\amazonq\\mcp.json",
                ".amazonq\\default.json",
            ],
        },
        binary_names=["q"],
        supported=False,
    ),
    "kiro": AgentDefinition(
        name="kiro",
        display_name="Kiro",
        agent_type="kiro",
        marker_paths={
            "darwin": ["~/.kiro/"],
            "linux": ["~/.kiro/"],
            "windows": ["%USERPROFILE%\\.kiro\\"],
        },
        config_paths={
            "darwin": ["~/.kiro/settings/mcp.json", ".kiro/mcp.json"],
            "linux": ["~/.kiro/settings/mcp.json", ".kiro/mcp.json"],
            "windows": [
                "%USERPROFILE%\\.kiro\\settings\\mcp.json",
                ".kiro\\mcp.json",
            ],
        },
        mcp_config_paths={
            "darwin": ["~/.kiro/settings/mcp.json", ".kiro/mcp.json"],
            "linux": ["~/.kiro/settings/mcp.json", ".kiro/mcp.json"],
            "windows": [
                "%USERPROFILE%\\.kiro\\settings\\mcp.json",
                ".kiro\\mcp.json",
            ],
        },
        supported=False,
    ),
    "continue_dev": AgentDefinition(
        name="continue_dev",
        display_name="Continue",
        agent_type="continue",
        marker_paths={
            "darwin": ["~/.continue/"],
            "linux": ["~/.continue/"],
            "windows": ["%USERPROFILE%\\.continue\\"],
        },
        config_paths={
            "darwin": ["~/.continue/config.yaml", "~/.continue/config.json"],
            "linux": ["~/.continue/config.yaml", "~/.continue/config.json"],
            "windows": [
                "%USERPROFILE%\\.continue\\config.yaml",
                "%USERPROFILE%\\.continue\\config.json",
            ],
        },
        mcp_config_paths={
            "darwin": [".continue/mcpServers/mcp.json"],
            "linux": [".continue/mcpServers/mcp.json"],
            "windows": [".continue\\mcpServers\\mcp.json"],
        },
        supported=False,
    ),
    "roo_code": AgentDefinition(
        name="roo_code",
        display_name="Roo Code",
        agent_type="roo-code",
        marker_paths={
            "darwin": [
                "~/Library/Application Support/Code/User/globalStorage/rooveterinaryinc.roo-cline/",
            ],
            "linux": [
                "~/.config/Code/User/globalStorage/rooveterinaryinc.roo-cline/",
            ],
            "windows": [
                "%APPDATA%\\Code\\User\\globalStorage\\rooveterinaryinc.roo-cline\\",
            ],
        },
        config_paths={
            "darwin": [".roo/mcp.json"],
            "linux": [".roo/mcp.json"],
            "windows": [".roo\\mcp.json"],
        },
        mcp_config_paths={
            "darwin": [".roo/mcp.json"],
            "linux": [".roo/mcp.json"],
            "windows": [".roo\\mcp.json"],
        },
        supported=False,
    ),
}


def get_agent(name: str) -> AgentDefinition | None:
    return AGENT_REGISTRY.get(name)


def get_supported_agents() -> list[AgentDefinition]:
    return [a for a in AGENT_REGISTRY.values() if a.supported]


def get_all_agents() -> list[AgentDefinition]:
    return list(AGENT_REGISTRY.values())
