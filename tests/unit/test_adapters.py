"""Tests for framework adapters (Claude Code, Cursor, Windsurf, VS Code Copilot)."""

import json

import pytest

from agentsec.adapters.base import (
    FrameworkConfig,
    PermissionsConfig,
)
from agentsec.adapters.claude_code import ClaudeCodeAdapter
from agentsec.adapters.cursor import CursorAdapter, _parse_mdc
from agentsec.adapters.vscode_copilot import VSCodeCopilotAdapter
from agentsec.adapters.windsurf import WindsurfAdapter

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def claude_adapter():
    return ClaudeCodeAdapter()


@pytest.fixture
def cursor_adapter():
    return CursorAdapter()


@pytest.fixture
def windsurf_adapter():
    return WindsurfAdapter()


@pytest.fixture
def vscode_adapter():
    return VSCodeCopilotAdapter()


# ---------------------------------------------------------------------------
# Claude Code: detect()
# ---------------------------------------------------------------------------


def test_claude_detect_with_dot_claude_dir(claude_adapter, tmp_path):
    (tmp_path / ".claude").mkdir()
    assert claude_adapter.detect(tmp_path) is True


def test_claude_detect_with_claude_md(claude_adapter, tmp_path):
    (tmp_path / "CLAUDE.md").write_text("# Instructions")
    assert claude_adapter.detect(tmp_path) is True


def test_claude_detect_empty_dir(claude_adapter, tmp_path, monkeypatch):
    fake_home = tmp_path / "_fake_home"
    fake_home.mkdir()
    monkeypatch.setattr("agentsec.adapters.claude_code.Path.home", lambda: fake_home)
    assert claude_adapter.detect(tmp_path) is False


# ---------------------------------------------------------------------------
# Claude Code: discover_configs()
# ---------------------------------------------------------------------------


def test_claude_discover_settings(claude_adapter, tmp_path, monkeypatch):
    fake_home = tmp_path / "_fake_home"
    fake_home.mkdir()
    monkeypatch.setattr("agentsec.adapters.claude_code.Path.home", lambda: fake_home)

    claude_dir = tmp_path / ".claude"
    claude_dir.mkdir()
    settings = claude_dir / "settings.json"
    settings.write_text("{}")
    local_settings = claude_dir / "settings.local.json"
    local_settings.write_text("{}")

    found = claude_adapter.discover_configs(tmp_path)
    assert settings in found
    assert local_settings in found


def test_claude_discover_mcp_json(claude_adapter, tmp_path, monkeypatch):
    fake_home = tmp_path / "_fake_home"
    fake_home.mkdir()
    monkeypatch.setattr("agentsec.adapters.claude_code.Path.home", lambda: fake_home)

    mcp = tmp_path / ".mcp.json"
    mcp.write_text("{}")

    found = claude_adapter.discover_configs(tmp_path)
    assert mcp in found


def test_claude_discover_rule_files(claude_adapter, tmp_path, monkeypatch):
    fake_home = tmp_path / "_fake_home"
    fake_home.mkdir()
    monkeypatch.setattr("agentsec.adapters.claude_code.Path.home", lambda: fake_home)

    (tmp_path / "CLAUDE.md").write_text("# Rules")
    rules_dir = tmp_path / ".claude" / "rules"
    rules_dir.mkdir(parents=True)
    (rules_dir / "style.md").write_text("# Style")
    (rules_dir / "not_md.txt").write_text("ignored")

    found = claude_adapter.discover_configs(tmp_path)
    assert tmp_path / "CLAUDE.md" in found
    assert rules_dir / "style.md" in found
    assert rules_dir / "not_md.txt" not in found


def test_claude_discover_empty_project(claude_adapter, tmp_path, monkeypatch):
    fake_home = tmp_path / "_fake_home"
    fake_home.mkdir()
    monkeypatch.setattr("agentsec.adapters.claude_code.Path.home", lambda: fake_home)

    found = claude_adapter.discover_configs(tmp_path)
    assert found == []


# ---------------------------------------------------------------------------
# Claude Code: parse() - hooks
# ---------------------------------------------------------------------------


def test_claude_parse_hooks(claude_adapter, tmp_path, monkeypatch):
    fake_home = tmp_path / "_fake_home"
    fake_home.mkdir()
    monkeypatch.setattr("agentsec.adapters.claude_code.Path.home", lambda: fake_home)

    claude_dir = tmp_path / ".claude"
    claude_dir.mkdir()
    settings = {
        "hooks": {
            "PreToolUse": [
                {
                    "matcher": "Bash",
                    "hooks": [
                        {"type": "command", "command": "echo safety check", "timeout": 15},
                        {"type": "prompt", "prompt": "Review this tool call"},
                    ],
                }
            ]
        }
    }
    (claude_dir / "settings.json").write_text(json.dumps(settings))

    config = claude_adapter.parse(tmp_path)
    assert len(config.hooks) == 2
    assert config.hooks[0].event == "PreToolUse"
    assert config.hooks[0].hook_type == "command"
    assert config.hooks[0].command == "echo safety check"
    assert config.hooks[0].timeout == 15
    assert config.hooks[1].hook_type == "prompt"
    assert config.hooks[1].prompt == "Review this tool call"


# ---------------------------------------------------------------------------
# Claude Code: parse() - permissions
# ---------------------------------------------------------------------------


def test_claude_parse_permissions(claude_adapter, tmp_path, monkeypatch):
    fake_home = tmp_path / "_fake_home"
    fake_home.mkdir()
    monkeypatch.setattr("agentsec.adapters.claude_code.Path.home", lambda: fake_home)

    claude_dir = tmp_path / ".claude"
    claude_dir.mkdir()
    settings = {
        "permissions": {
            "allow": ["Bash(git *)", "Read"],
            "deny": ["Write(/etc/*)"],
            "defaultMode": "allow",
            "autoApprove": ["Read", "Glob"],
        },
        "enableAllProjectMcpServers": True,
    }
    (claude_dir / "settings.json").write_text(json.dumps(settings))

    config = claude_adapter.parse(tmp_path)
    assert "Bash(git *)" in config.permissions.allow_rules
    assert "Read" in config.permissions.allow_rules
    assert "Write(/etc/*)" in config.permissions.deny_rules
    assert config.permissions.default_mode == "allow"
    assert "Read" in config.permissions.auto_approve_tools
    assert "*" in config.permissions.auto_approve_mcp


# ---------------------------------------------------------------------------
# Claude Code: parse() - MCP servers
# ---------------------------------------------------------------------------


def test_claude_parse_mcp_servers(claude_adapter, tmp_path, monkeypatch):
    fake_home = tmp_path / "_fake_home"
    fake_home.mkdir()
    monkeypatch.setattr("agentsec.adapters.claude_code.Path.home", lambda: fake_home)

    mcp_data = {
        "mcpServers": {
            "filesystem": {
                "command": "npx",
                "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"],
                "env": {"NODE_ENV": "production"},
            },
            "remote-server": {
                "command": "mcp-client",
                "transport": "sse",
                "auth": True,
            },
        }
    }
    (tmp_path / ".mcp.json").write_text(json.dumps(mcp_data))

    config = claude_adapter.parse(tmp_path)
    assert len(config.mcp_servers) == 2

    fs_server = next(s for s in config.mcp_servers if s.name == "filesystem")
    assert fs_server.command == "npx"
    assert fs_server.args == ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]
    assert fs_server.env == {"NODE_ENV": "production"}
    assert fs_server.transport == "stdio"
    assert fs_server.requires_auth is False

    remote = next(s for s in config.mcp_servers if s.name == "remote-server")
    assert remote.transport == "sse"
    assert remote.requires_auth is True


# ---------------------------------------------------------------------------
# Claude Code: parse() - rules
# ---------------------------------------------------------------------------


def test_claude_parse_rules(claude_adapter, tmp_path, monkeypatch):
    fake_home = tmp_path / "_fake_home"
    fake_home.mkdir()
    monkeypatch.setattr("agentsec.adapters.claude_code.Path.home", lambda: fake_home)

    (tmp_path / "CLAUDE.md").write_text("Top-level rules")
    claude_dir = tmp_path / ".claude"
    claude_dir.mkdir()
    (claude_dir / "CLAUDE.md").write_text("Nested rules")

    rules_dir = claude_dir / "rules"
    rules_dir.mkdir()
    (rules_dir / "testing.md").write_text("Test rules")

    agents_dir = claude_dir / "agents"
    agents_dir.mkdir()
    (agents_dir / "reviewer.md").write_text("Agent config")

    commands_dir = claude_dir / "commands"
    commands_dir.mkdir()
    (commands_dir / "deploy.md").write_text("Deploy command")

    config = claude_adapter.parse(tmp_path)

    rule_names = [r.name for r in config.rules]
    assert "CLAUDE.md" in rule_names
    assert "testing" in rule_names
    assert "reviewer" in rule_names
    assert "deploy" in rule_names

    testing_rule = next(r for r in config.rules if r.name == "testing")
    assert testing_rule.activation_mode == "always"
    assert testing_rule.content == "Test rules"

    agent_rule = next(r for r in config.rules if r.name == "reviewer")
    assert agent_rule.activation_mode == "agent"

    cmd_rule = next(r for r in config.rules if r.name == "deploy")
    assert cmd_rule.activation_mode == "command"


# ---------------------------------------------------------------------------
# Claude Code: parse() - sandbox
# ---------------------------------------------------------------------------


def test_claude_parse_sandbox(claude_adapter, tmp_path, monkeypatch):
    fake_home = tmp_path / "_fake_home"
    fake_home.mkdir()
    monkeypatch.setattr("agentsec.adapters.claude_code.Path.home", lambda: fake_home)

    claude_dir = tmp_path / ".claude"
    claude_dir.mkdir()
    settings = {
        "sandbox": {
            "enabled": True,
            "networkAllowedDomains": ["api.example.com"],
            "filesystemDenyRead": ["/etc/passwd"],
            "filesystemAllowWrite": ["/tmp"],
        }
    }
    (claude_dir / "settings.json").write_text(json.dumps(settings))

    config = claude_adapter.parse(tmp_path)
    assert config.sandbox is not None
    assert config.sandbox.enabled is True
    assert "api.example.com" in config.sandbox.network_allowed_domains
    assert "/etc/passwd" in config.sandbox.filesystem_deny_read
    assert "/tmp" in config.sandbox.filesystem_allow_write


# ---------------------------------------------------------------------------
# Claude Code: parse() - env vars and plugins
# ---------------------------------------------------------------------------


def test_claude_parse_env_and_plugins(claude_adapter, tmp_path, monkeypatch):
    fake_home = tmp_path / "_fake_home"
    fake_home.mkdir()
    monkeypatch.setattr("agentsec.adapters.claude_code.Path.home", lambda: fake_home)

    claude_dir = tmp_path / ".claude"
    claude_dir.mkdir()
    settings = {
        "env": {"OPENAI_API_KEY": "sk-test123"},
        "enabledPlugins": ["todo-manager", {"name": "custom-tool", "source": "github"}],
    }
    (claude_dir / "settings.json").write_text(json.dumps(settings))

    config = claude_adapter.parse(tmp_path)
    assert config.env_vars["OPENAI_API_KEY"] == "sk-test123"
    assert len(config.plugins) == 2
    assert config.plugins[0].name == "todo-manager"
    assert config.plugins[1].name == "custom-tool"
    assert config.plugins[1].source == "github"


# ---------------------------------------------------------------------------
# Claude Code: adapter properties
# ---------------------------------------------------------------------------


def test_claude_adapter_name(claude_adapter):
    assert claude_adapter.name == "claude_code"
    assert claude_adapter.display_name == "Claude Code"


def test_claude_known_config_paths(claude_adapter):
    paths = claude_adapter.known_config_paths
    assert ".claude/settings.json" in paths
    assert "CLAUDE.md" in paths
    assert "~/.claude.json" in paths


# ---------------------------------------------------------------------------
# Cursor: detect()
# ---------------------------------------------------------------------------


def test_cursor_detect_with_dot_cursor_dir(cursor_adapter, tmp_path):
    (tmp_path / ".cursor").mkdir()
    assert cursor_adapter.detect(tmp_path) is True


def test_cursor_detect_with_cursorrules(cursor_adapter, tmp_path):
    (tmp_path / ".cursorrules").write_text("rules here")
    assert cursor_adapter.detect(tmp_path) is True


def test_cursor_detect_empty_dir(cursor_adapter, tmp_path, monkeypatch):
    fake_home = tmp_path / "_fake_home"
    fake_home.mkdir()
    monkeypatch.setattr("agentsec.adapters.cursor.Path.home", lambda: fake_home)
    assert cursor_adapter.detect(tmp_path) is False


# ---------------------------------------------------------------------------
# Cursor: discover_configs()
# ---------------------------------------------------------------------------


def test_cursor_discover_mcp_and_rules(cursor_adapter, tmp_path, monkeypatch):
    fake_home = tmp_path / "_fake_home"
    fake_home.mkdir()
    monkeypatch.setattr("agentsec.adapters.cursor.Path.home", lambda: fake_home)

    cursor_dir = tmp_path / ".cursor"
    cursor_dir.mkdir()
    mcp = cursor_dir / "mcp.json"
    mcp.write_text("{}")

    (tmp_path / ".cursorrules").write_text("rules")

    rules_dir = cursor_dir / "rules"
    rules_dir.mkdir()
    (rules_dir / "style.mdc").write_text("---\nalwaysApply: true\n---\nBody")
    (rules_dir / "readme.txt").write_text("ignored")

    vscode_dir = tmp_path / ".vscode"
    vscode_dir.mkdir()
    tasks = vscode_dir / "tasks.json"
    tasks.write_text("{}")

    found = cursor_adapter.discover_configs(tmp_path)
    assert mcp in found
    assert tmp_path / ".cursorrules" in found
    assert rules_dir / "style.mdc" in found
    assert rules_dir / "readme.txt" not in found
    assert tasks in found


# ---------------------------------------------------------------------------
# Cursor: _parse_mdc()
# ---------------------------------------------------------------------------


def test_parse_mdc_with_frontmatter():
    content = '---\ndescription: Check style\nglobs: "*.py"\nalwaysApply: false\n---\nBody content'
    rule = _parse_mdc(content, "/fake/style.mdc")
    assert rule is not None
    assert rule.name == "style"
    assert rule.content == "Body content"
    assert rule.activation_mode == "glob"
    assert rule.glob_pattern == "*.py"


def test_parse_mdc_always_apply():
    content = "---\nalwaysApply: true\n---\nAlways active"
    rule = _parse_mdc(content, "/fake/always.mdc")
    assert rule is not None
    assert rule.activation_mode == "always"
    assert rule.content == "Always active"


def test_parse_mdc_no_frontmatter():
    content = "Plain markdown content"
    rule = _parse_mdc(content, "/fake/plain.mdc")
    assert rule is not None
    assert rule.activation_mode == "always"
    assert rule.content == "Plain markdown content"


def test_parse_mdc_malformed_frontmatter():
    content = "---\nkey: value\nNo closing delimiter"
    rule = _parse_mdc(content, "/fake/bad.mdc")
    assert rule is not None
    assert rule.activation_mode == "always"


def test_parse_mdc_manual_mode():
    content = "---\ndescription: Manual rule\nalwaysApply: false\n---\nManual content"
    rule = _parse_mdc(content, "/fake/manual.mdc")
    assert rule is not None
    assert rule.activation_mode == "manual"
    assert rule.glob_pattern == ""


# ---------------------------------------------------------------------------
# Cursor: parse() - MCP servers
# ---------------------------------------------------------------------------


def test_cursor_parse_mcp_servers(cursor_adapter, tmp_path, monkeypatch):
    fake_home = tmp_path / "_fake_home"
    fake_home.mkdir()
    monkeypatch.setattr("agentsec.adapters.cursor.Path.home", lambda: fake_home)

    cursor_dir = tmp_path / ".cursor"
    cursor_dir.mkdir()
    mcp_data = {
        "mcpServers": {
            "db-server": {
                "command": "node",
                "args": ["server.js"],
                "env": {"DB_HOST": "localhost"},
                "transport": "sse",
            }
        }
    }
    (cursor_dir / "mcp.json").write_text(json.dumps(mcp_data))

    config = cursor_adapter.parse(tmp_path)
    assert len(config.mcp_servers) == 1
    assert config.mcp_servers[0].name == "db-server"
    assert config.mcp_servers[0].command == "node"
    assert config.mcp_servers[0].args == ["server.js"]
    assert config.mcp_servers[0].env == {"DB_HOST": "localhost"}
    assert config.mcp_servers[0].transport == "sse"


# ---------------------------------------------------------------------------
# Cursor: parse() - tasks.json auto-run detection
# ---------------------------------------------------------------------------


def test_cursor_parse_tasks_folder_open(cursor_adapter, tmp_path, monkeypatch):
    fake_home = tmp_path / "_fake_home"
    fake_home.mkdir()
    monkeypatch.setattr("agentsec.adapters.cursor.Path.home", lambda: fake_home)

    vscode_dir = tmp_path / ".vscode"
    vscode_dir.mkdir()
    tasks = {
        "tasks": [
            {
                "label": "startup",
                "type": "shell",
                "command": "echo hello",
                "runOptions": {"runOn": "folderOpen"},
            },
            {
                "label": "manual-task",
                "type": "shell",
                "command": "npm test",
                "runOptions": {"runOn": "default"},
            },
        ]
    }
    (vscode_dir / "tasks.json").write_text(json.dumps(tasks))

    # Also need .cursor dir for detect to work during parse
    (tmp_path / ".cursor").mkdir()

    config = cursor_adapter.parse(tmp_path)
    assert len(config.hooks) == 1
    assert config.hooks[0].event == "folderOpen"
    assert config.hooks[0].command == "echo hello"
    assert config.hooks[0].hook_type == "shell"


# ---------------------------------------------------------------------------
# Cursor: parse() - rules
# ---------------------------------------------------------------------------


def test_cursor_parse_rules(cursor_adapter, tmp_path, monkeypatch):
    fake_home = tmp_path / "_fake_home"
    fake_home.mkdir()
    monkeypatch.setattr("agentsec.adapters.cursor.Path.home", lambda: fake_home)

    (tmp_path / ".cursorrules").write_text("Global cursor rules")

    rules_dir = tmp_path / ".cursor" / "rules"
    rules_dir.mkdir(parents=True)
    (rules_dir / "python.mdc").write_text(
        '---\ndescription: Python rules\nglobs: "*.py"\nalwaysApply: false\n---\nUse type hints'
    )

    config = cursor_adapter.parse(tmp_path)
    assert len(config.rules) == 2

    cursorrules = next(r for r in config.rules if r.name == ".cursorrules")
    assert cursorrules.content == "Global cursor rules"
    assert cursorrules.activation_mode == "always"

    python_rule = next(r for r in config.rules if r.name == "python")
    assert python_rule.content == "Use type hints"
    assert python_rule.activation_mode == "glob"
    assert python_rule.glob_pattern == "*.py"


# ---------------------------------------------------------------------------
# Cursor: adapter properties
# ---------------------------------------------------------------------------


def test_cursor_adapter_name(cursor_adapter):
    assert cursor_adapter.name == "cursor"
    assert cursor_adapter.display_name == "Cursor"


# ---------------------------------------------------------------------------
# Windsurf: detect()
# ---------------------------------------------------------------------------


def test_windsurf_detect_with_dot_windsurf_dir(windsurf_adapter, tmp_path):
    (tmp_path / ".windsurf").mkdir()
    assert windsurf_adapter.detect(tmp_path) is True


def test_windsurf_detect_with_windsurfrules(windsurf_adapter, tmp_path):
    (tmp_path / ".windsurfrules").write_text("rules")
    assert windsurf_adapter.detect(tmp_path) is True


def test_windsurf_detect_via_codeium_path(windsurf_adapter, tmp_path, monkeypatch):
    fake_home = tmp_path / "_fake_home"
    fake_home.mkdir()
    (fake_home / ".codeium" / "windsurf").mkdir(parents=True)
    monkeypatch.setattr("agentsec.adapters.windsurf.Path.home", lambda: fake_home)
    assert windsurf_adapter.detect(tmp_path) is True


def test_windsurf_detect_via_home_windsurf(windsurf_adapter, tmp_path, monkeypatch):
    fake_home = tmp_path / "_fake_home"
    fake_home.mkdir()
    (fake_home / ".windsurf").mkdir()
    monkeypatch.setattr("agentsec.adapters.windsurf.Path.home", lambda: fake_home)
    assert windsurf_adapter.detect(tmp_path) is True


def test_windsurf_detect_empty_dir(windsurf_adapter, tmp_path, monkeypatch):
    fake_home = tmp_path / "_fake_home"
    fake_home.mkdir()
    monkeypatch.setattr("agentsec.adapters.windsurf.Path.home", lambda: fake_home)
    assert windsurf_adapter.detect(tmp_path) is False


# ---------------------------------------------------------------------------
# Windsurf: discover_configs()
# ---------------------------------------------------------------------------


def test_windsurf_discover_project_configs(windsurf_adapter, tmp_path, monkeypatch):
    fake_home = tmp_path / "_fake_home"
    fake_home.mkdir()
    monkeypatch.setattr("agentsec.adapters.windsurf.Path.home", lambda: fake_home)

    ws_dir = tmp_path / ".windsurf"
    ws_dir.mkdir()
    mcp = ws_dir / "mcp.json"
    mcp.write_text("{}")

    (tmp_path / ".windsurfrules").write_text("rules")

    rules_dir = ws_dir / "rules"
    rules_dir.mkdir()
    (rules_dir / "coding.md").write_text("Coding standards")

    found = windsurf_adapter.discover_configs(tmp_path)
    assert mcp in found
    assert tmp_path / ".windsurfrules" in found
    assert rules_dir / "coding.md" in found


# ---------------------------------------------------------------------------
# Windsurf: parse() - MCP servers
# ---------------------------------------------------------------------------


def test_windsurf_parse_mcp_servers(windsurf_adapter, tmp_path, monkeypatch):
    fake_home = tmp_path / "_fake_home"
    fake_home.mkdir()
    monkeypatch.setattr("agentsec.adapters.windsurf.Path.home", lambda: fake_home)

    ws_dir = tmp_path / ".windsurf"
    ws_dir.mkdir()
    mcp_data = {
        "mcpServers": {
            "search": {
                "command": "npx",
                "args": ["-y", "mcp-search"],
                "headers": {"Authorization": "Bearer token"},
            }
        }
    }
    (ws_dir / "mcp.json").write_text(json.dumps(mcp_data))

    config = windsurf_adapter.parse(tmp_path)
    assert len(config.mcp_servers) == 1
    assert config.mcp_servers[0].name == "search"
    assert config.mcp_servers[0].requires_auth is True


# ---------------------------------------------------------------------------
# Windsurf: parse() - rules
# ---------------------------------------------------------------------------


def test_windsurf_parse_rules(windsurf_adapter, tmp_path, monkeypatch):
    fake_home = tmp_path / "_fake_home"
    fake_home.mkdir()
    monkeypatch.setattr("agentsec.adapters.windsurf.Path.home", lambda: fake_home)

    (tmp_path / ".windsurfrules").write_text("Global windsurf rules")

    rules_dir = tmp_path / ".windsurf" / "rules"
    rules_dir.mkdir(parents=True)
    (rules_dir / "format.md").write_text("Formatting rules")

    config = windsurf_adapter.parse(tmp_path)
    assert len(config.rules) == 2

    ws_rule = next(r for r in config.rules if r.name == ".windsurfrules")
    assert ws_rule.content == "Global windsurf rules"

    fmt_rule = next(r for r in config.rules if r.name == "format")
    assert fmt_rule.content == "Formatting rules"
    assert fmt_rule.activation_mode == "always"


# ---------------------------------------------------------------------------
# Windsurf: adapter properties
# ---------------------------------------------------------------------------


def test_windsurf_adapter_name(windsurf_adapter):
    assert windsurf_adapter.name == "windsurf"
    assert windsurf_adapter.display_name == "Windsurf"


# ---------------------------------------------------------------------------
# VS Code Copilot: detect()
# ---------------------------------------------------------------------------


def test_vscode_detect_with_mcp_json(vscode_adapter, tmp_path):
    vscode_dir = tmp_path / ".vscode"
    vscode_dir.mkdir()
    (vscode_dir / "mcp.json").write_text("{}")
    assert vscode_adapter.detect(tmp_path) is True


def test_vscode_detect_with_copilot_instructions(vscode_adapter, tmp_path):
    gh_dir = tmp_path / ".github"
    gh_dir.mkdir()
    (gh_dir / "copilot-instructions.md").write_text("# Instructions")
    assert vscode_adapter.detect(tmp_path) is True


def test_vscode_detect_with_agents_md(vscode_adapter, tmp_path):
    (tmp_path / "AGENTS.md").write_text("# Agents")
    assert vscode_adapter.detect(tmp_path) is True


def test_vscode_detect_empty_dir(vscode_adapter, tmp_path):
    assert vscode_adapter.detect(tmp_path) is False


# ---------------------------------------------------------------------------
# VS Code Copilot: discover_configs()
# ---------------------------------------------------------------------------


def test_vscode_discover_all_configs(vscode_adapter, tmp_path):
    vscode_dir = tmp_path / ".vscode"
    vscode_dir.mkdir()
    mcp = vscode_dir / "mcp.json"
    mcp.write_text("{}")
    settings = vscode_dir / "settings.json"
    settings.write_text("{}")
    tasks = vscode_dir / "tasks.json"
    tasks.write_text("{}")

    gh_dir = tmp_path / ".github"
    gh_dir.mkdir()
    instructions = gh_dir / "copilot-instructions.md"
    instructions.write_text("# Instructions")

    (tmp_path / "AGENTS.md").write_text("# Agents")

    found = vscode_adapter.discover_configs(tmp_path)
    assert mcp in found
    assert settings in found
    assert tasks in found
    assert instructions in found
    assert tmp_path / "AGENTS.md" in found


def test_vscode_discover_empty_project(vscode_adapter, tmp_path):
    found = vscode_adapter.discover_configs(tmp_path)
    assert found == []


# ---------------------------------------------------------------------------
# VS Code Copilot: parse() - "servers" key (not "mcpServers")
# ---------------------------------------------------------------------------


def test_vscode_parse_mcp_uses_servers_key(vscode_adapter, tmp_path):
    vscode_dir = tmp_path / ".vscode"
    vscode_dir.mkdir()
    mcp_data = {
        "servers": {
            "my-server": {
                "command": "node",
                "args": ["index.js"],
                "env": {"PORT": "3000"},
            }
        }
    }
    (vscode_dir / "mcp.json").write_text(json.dumps(mcp_data))

    config = vscode_adapter.parse(tmp_path)
    assert len(config.mcp_servers) == 1
    assert config.mcp_servers[0].name == "my-server"
    assert config.mcp_servers[0].command == "node"
    assert config.mcp_servers[0].args == ["index.js"]
    assert config.mcp_servers[0].env == {"PORT": "3000"}


def test_vscode_parse_ignores_mcpservers_key(vscode_adapter, tmp_path):
    """VS Code uses 'servers' not 'mcpServers'. Verify mcpServers is ignored."""
    vscode_dir = tmp_path / ".vscode"
    vscode_dir.mkdir()
    mcp_data = {
        "mcpServers": {
            "wrong-key": {
                "command": "node",
                "args": ["wrong.js"],
            }
        }
    }
    (vscode_dir / "mcp.json").write_text(json.dumps(mcp_data))

    config = vscode_adapter.parse(tmp_path)
    assert len(config.mcp_servers) == 0


# ---------------------------------------------------------------------------
# VS Code Copilot: parse() - autoApprove detection
# ---------------------------------------------------------------------------


def test_vscode_parse_auto_approve_bool(vscode_adapter, tmp_path):
    vscode_dir = tmp_path / ".vscode"
    vscode_dir.mkdir()
    settings = {"github.copilot.chat.agent.autoApprove": True}
    (vscode_dir / "settings.json").write_text(json.dumps(settings))

    config = vscode_adapter.parse(tmp_path)
    assert "*" in config.permissions.auto_approve_tools


def test_vscode_parse_auto_approve_list(vscode_adapter, tmp_path):
    vscode_dir = tmp_path / ".vscode"
    vscode_dir.mkdir()
    settings = {"github.copilot.chat.agent.autoApprove": ["terminal", "editFile"]}
    (vscode_dir / "settings.json").write_text(json.dumps(settings))

    config = vscode_adapter.parse(tmp_path)
    assert "terminal" in config.permissions.auto_approve_tools
    assert "editFile" in config.permissions.auto_approve_tools


def test_vscode_parse_auto_approve_false(vscode_adapter, tmp_path):
    vscode_dir = tmp_path / ".vscode"
    vscode_dir.mkdir()
    settings = {"github.copilot.chat.agent.autoApprove": False}
    (vscode_dir / "settings.json").write_text(json.dumps(settings))

    config = vscode_adapter.parse(tmp_path)
    assert config.permissions.auto_approve_tools == []


# ---------------------------------------------------------------------------
# VS Code Copilot: parse() - tasks.json
# ---------------------------------------------------------------------------


def test_vscode_parse_tasks(vscode_adapter, tmp_path):
    vscode_dir = tmp_path / ".vscode"
    vscode_dir.mkdir()
    tasks = {
        "tasks": [
            {
                "label": "auto-lint",
                "type": "shell",
                "command": "npm run lint",
                "runOptions": {"runOn": "folderOpen"},
            },
            {
                "label": "build",
                "type": "shell",
                "command": "npm run build",
            },
        ]
    }
    (vscode_dir / "tasks.json").write_text(json.dumps(tasks))

    config = vscode_adapter.parse(tmp_path)
    assert len(config.hooks) == 1
    assert config.hooks[0].event == "folderOpen"
    assert config.hooks[0].command == "npm run lint"


# ---------------------------------------------------------------------------
# VS Code Copilot: parse() - rules
# ---------------------------------------------------------------------------


def test_vscode_parse_rules(vscode_adapter, tmp_path):
    gh_dir = tmp_path / ".github"
    gh_dir.mkdir()
    (gh_dir / "copilot-instructions.md").write_text("Use TypeScript")

    (tmp_path / "AGENTS.md").write_text("Agent instructions")

    config = vscode_adapter.parse(tmp_path)
    assert len(config.rules) == 2

    copilot_rule = next(r for r in config.rules if r.name == "copilot-instructions.md")
    assert copilot_rule.content == "Use TypeScript"
    assert copilot_rule.activation_mode == "always"

    agents_rule = next(r for r in config.rules if r.name == "AGENTS.md")
    assert agents_rule.content == "Agent instructions"


# ---------------------------------------------------------------------------
# VS Code Copilot: adapter properties
# ---------------------------------------------------------------------------


def test_vscode_adapter_name(vscode_adapter):
    assert vscode_adapter.name == "vscode_copilot"
    assert vscode_adapter.display_name == "VS Code Copilot"


# ---------------------------------------------------------------------------
# Cross-adapter: FrameworkConfig output structure
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "adapter_cls",
    [ClaudeCodeAdapter, CursorAdapter, WindsurfAdapter, VSCodeCopilotAdapter],
    ids=["claude", "cursor", "windsurf", "vscode"],
)
def test_parse_empty_dir_returns_valid_config(adapter_cls, tmp_path, monkeypatch):
    """All adapters return a valid FrameworkConfig on an empty directory."""
    fake_home = tmp_path / "_fake_home"
    fake_home.mkdir()

    for module in [
        "agentsec.adapters.claude_code",
        "agentsec.adapters.cursor",
        "agentsec.adapters.windsurf",
    ]:
        monkeypatch.setattr(f"{module}.Path.home", lambda: fake_home)

    adapter = adapter_cls()
    config = adapter.parse(tmp_path)

    assert isinstance(config, FrameworkConfig)
    assert config.framework == adapter.name
    assert isinstance(config.mcp_servers, list)
    assert isinstance(config.hooks, list)
    assert isinstance(config.rules, list)
    assert isinstance(config.permissions, PermissionsConfig)


@pytest.mark.parametrize(
    ("adapter_cls", "marker_setup"),
    [
        (ClaudeCodeAdapter, lambda p: (p / ".claude").mkdir()),
        (CursorAdapter, lambda p: (p / ".cursor").mkdir()),
        (WindsurfAdapter, lambda p: (p / ".windsurf").mkdir()),
        (
            VSCodeCopilotAdapter,
            lambda p: (p / ".vscode").mkdir() or (p / ".vscode" / "mcp.json").write_text("{}"),
        ),
    ],
    ids=["claude", "cursor", "windsurf", "vscode"],
)
def test_detect_true_with_markers(adapter_cls, marker_setup, tmp_path):
    marker_setup(tmp_path)
    adapter = adapter_cls()
    assert adapter.detect(tmp_path) is True


# ---------------------------------------------------------------------------
# Edge cases: malformed JSON
# ---------------------------------------------------------------------------


def test_claude_parse_malformed_json(claude_adapter, tmp_path, monkeypatch):
    fake_home = tmp_path / "_fake_home"
    fake_home.mkdir()
    monkeypatch.setattr("agentsec.adapters.claude_code.Path.home", lambda: fake_home)

    claude_dir = tmp_path / ".claude"
    claude_dir.mkdir()
    (claude_dir / "settings.json").write_text("not valid json {{{")

    config = claude_adapter.parse(tmp_path)
    assert isinstance(config, FrameworkConfig)
    assert len(config.hooks) == 0


def test_cursor_parse_malformed_mcp_json(cursor_adapter, tmp_path, monkeypatch):
    fake_home = tmp_path / "_fake_home"
    fake_home.mkdir()
    monkeypatch.setattr("agentsec.adapters.cursor.Path.home", lambda: fake_home)

    cursor_dir = tmp_path / ".cursor"
    cursor_dir.mkdir()
    (cursor_dir / "mcp.json").write_text("broken json")

    config = cursor_adapter.parse(tmp_path)
    assert isinstance(config, FrameworkConfig)
    assert len(config.mcp_servers) == 0


# ---------------------------------------------------------------------------
# Edge cases: MCP server with auth headers
# ---------------------------------------------------------------------------


def test_mcp_server_auth_via_headers(claude_adapter, tmp_path, monkeypatch):
    fake_home = tmp_path / "_fake_home"
    fake_home.mkdir()
    monkeypatch.setattr("agentsec.adapters.claude_code.Path.home", lambda: fake_home)

    mcp_data = {
        "mcpServers": {
            "auth-server": {
                "command": "mcp-remote",
                "headers": {"Authorization": "Bearer secret"},
            }
        }
    }
    (tmp_path / ".mcp.json").write_text(json.dumps(mcp_data))

    config = claude_adapter.parse(tmp_path)
    assert config.mcp_servers[0].requires_auth is True


# ---------------------------------------------------------------------------
# Edge cases: non-string env values filtered
# ---------------------------------------------------------------------------


def test_mcp_server_filters_non_string_env(claude_adapter, tmp_path, monkeypatch):
    fake_home = tmp_path / "_fake_home"
    fake_home.mkdir()
    monkeypatch.setattr("agentsec.adapters.claude_code.Path.home", lambda: fake_home)

    mcp_data = {
        "mcpServers": {
            "test": {
                "command": "node",
                "env": {"GOOD": "value", "BAD": 12345},
            }
        }
    }
    (tmp_path / ".mcp.json").write_text(json.dumps(mcp_data))

    config = claude_adapter.parse(tmp_path)
    assert config.mcp_servers[0].env == {"GOOD": "value"}
