"""Tests for the agent discovery engine."""

import pytest

from agentsec.discovery import (
    DiscoveredAgent,
    _expand_path,
    _resolve_paths,
    _resolve_project_paths,
    discover_agents,
)
from agentsec.models.agents import AGENT_REGISTRY


@pytest.fixture
def mock_home_with_claude(tmp_path, monkeypatch):
    """Create a fake home directory with Claude Code markers."""
    fake_home = tmp_path / "fake_home"
    fake_home.mkdir()
    (fake_home / ".claude").mkdir()
    (fake_home / ".claude" / "settings.json").write_text("{}")
    monkeypatch.setenv("HOME", str(fake_home))
    monkeypatch.setenv("USERPROFILE", str(fake_home))
    monkeypatch.setattr("pathlib.Path.home", lambda: fake_home)
    monkeypatch.setattr("os.path.expanduser", lambda p: p.replace("~", str(fake_home)))
    return fake_home


@pytest.fixture
def mock_home_empty(tmp_path, monkeypatch):
    """Create a fake home directory with no agent markers."""
    fake_home = tmp_path / "fake_home"
    fake_home.mkdir()
    monkeypatch.setenv("HOME", str(fake_home))
    monkeypatch.setenv("USERPROFILE", str(fake_home))
    monkeypatch.setattr("pathlib.Path.home", lambda: fake_home)
    monkeypatch.setattr("os.path.expanduser", lambda p: p.replace("~", str(fake_home)))
    return fake_home


# ---------------------------------------------------------------------------
# discover_agents() - global detection
# ---------------------------------------------------------------------------


def test_discover_finds_claude_code(mock_home_with_claude):
    agents = discover_agents()
    names = [a.name for a in agents]
    assert "claude_code" in names


def test_discover_empty_home_returns_empty(mock_home_empty):
    agents = discover_agents()
    assert agents == []


def test_discover_returns_discovered_agent_type(mock_home_with_claude):
    agents = discover_agents()
    for agent in agents:
        assert isinstance(agent, DiscoveredAgent)


def test_discover_agent_fields(mock_home_with_claude):
    agents = discover_agents()
    claude = next(a for a in agents if a.name == "claude_code")
    assert claude.display_name == "Claude Code"
    assert claude.agent_type == "claude-code"
    assert claude.supported is True
    assert claude.scope == "global"
    assert claude.version is None  # detect_versions defaults to False


# ---------------------------------------------------------------------------
# discover_agents() - project-level detection
# ---------------------------------------------------------------------------


def test_discover_project_level_cursor(mock_home_empty, tmp_path):
    cursor_dir = tmp_path / ".cursor"
    cursor_dir.mkdir()
    (cursor_dir / "mcp.json").write_text("{}")

    agents = discover_agents(target=tmp_path)
    names = [a.name for a in agents]
    assert "cursor" in names


def test_discover_project_level_vscode(mock_home_empty, tmp_path):
    vscode_dir = tmp_path / ".vscode"
    vscode_dir.mkdir()
    (vscode_dir / "mcp.json").write_text("{}")

    agents = discover_agents(target=tmp_path)
    names = [a.name for a in agents]
    assert "vscode_copilot" in names


def test_discover_project_only_scope(mock_home_empty, tmp_path):
    """When an agent is only found at project level, scope should be 'project'."""
    cursor_dir = tmp_path / ".cursor"
    cursor_dir.mkdir()
    (cursor_dir / "mcp.json").write_text("{}")

    agents = discover_agents(target=tmp_path)
    cursor = next(a for a in agents if a.name == "cursor")
    assert cursor.scope == "project"


# ---------------------------------------------------------------------------
# discover_agents() - version detection disabled
# ---------------------------------------------------------------------------


def test_discover_version_detection_off_by_default(mock_home_with_claude):
    agents = discover_agents()
    for agent in agents:
        assert agent.version is None


# ---------------------------------------------------------------------------
# discover_agents() - sorted by display_name
# ---------------------------------------------------------------------------


def test_discover_results_sorted(mock_home_with_claude, tmp_path, monkeypatch):
    """Results should be sorted alphabetically by display_name."""
    # Add cursor markers too
    list(AGENT_REGISTRY.values())[0]  # just check sorting
    agents = discover_agents()
    display_names = [a.display_name for a in agents]
    assert display_names == sorted(display_names)


# ---------------------------------------------------------------------------
# _expand_path()
# ---------------------------------------------------------------------------


def test_expand_path_tilde(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    monkeypatch.setattr("os.path.expanduser", lambda p: p.replace("~", str(tmp_path)))
    result = _expand_path("~/test")
    assert str(tmp_path) in result


# ---------------------------------------------------------------------------
# _resolve_paths()
# ---------------------------------------------------------------------------


def test_resolve_paths_finds_existing(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    (tmp_path / "test_file").write_text("content")
    found = _resolve_paths([str(tmp_path / "test_file")])
    assert len(found) == 1


def test_resolve_paths_skips_missing():
    found = _resolve_paths(["/nonexistent/path/that/does/not/exist"])
    assert found == []


# ---------------------------------------------------------------------------
# _resolve_project_paths()
# ---------------------------------------------------------------------------


def test_resolve_project_paths_finds_relative(tmp_path):
    (tmp_path / ".cursor").mkdir()
    (tmp_path / ".cursor" / "mcp.json").write_text("{}")

    found = _resolve_project_paths([".cursor/mcp.json"], tmp_path)
    assert len(found) == 1
    assert found[0] == tmp_path / ".cursor" / "mcp.json"


def test_resolve_project_paths_ignores_home_relative(tmp_path):
    found = _resolve_project_paths(["~/.cursor/mcp.json"], tmp_path)
    assert found == []


def test_resolve_project_paths_ignores_env_var_paths(tmp_path):
    found = _resolve_project_paths(["%USERPROFILE%\\.cursor\\mcp.json"], tmp_path)
    assert found == []
