"""Tests for the agent definitions registry."""

import pytest

from agentsec.models.agents import (
    AGENT_REGISTRY,
    AgentDefinition,
    get_agent,
    get_all_agents,
    get_supported_agents,
)

_EXPECTED_AGENTS = [
    "claude_code",
    "claude_desktop",
    "cursor",
    "windsurf",
    "vscode_copilot",
    "gemini_cli",
    "codex",
    "openclaw",
    "amazon_q",
    "kiro",
    "continue_dev",
    "roo_code",
]

_SUPPORTED_AGENTS = [
    "claude_code",
    "cursor",
    "windsurf",
    "vscode_copilot",
    "openclaw",
]

_OS_KEYS = ["darwin", "linux", "windows"]


# ---------------------------------------------------------------------------
# Registry completeness
# ---------------------------------------------------------------------------


def test_registry_has_all_expected_agents():
    assert len(AGENT_REGISTRY) == 12
    for name in _EXPECTED_AGENTS:
        assert name in AGENT_REGISTRY


def test_registry_values_are_agent_definitions():
    for agent in AGENT_REGISTRY.values():
        assert isinstance(agent, AgentDefinition)


# ---------------------------------------------------------------------------
# get_agent()
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name", _EXPECTED_AGENTS)
def test_get_agent_returns_correct_definition(name):
    agent = get_agent(name)
    assert agent is not None
    assert agent.name == name


def test_get_agent_returns_none_for_unknown():
    assert get_agent("nonexistent_agent") is None


# ---------------------------------------------------------------------------
# get_supported_agents()
# ---------------------------------------------------------------------------


def test_get_supported_agents_returns_only_supported():
    supported = get_supported_agents()
    for agent in supported:
        assert agent.supported is True


def test_get_supported_agents_count():
    supported = get_supported_agents()
    assert len(supported) == len(_SUPPORTED_AGENTS)


def test_get_supported_agents_names():
    supported = get_supported_agents()
    names = {a.name for a in supported}
    assert names == set(_SUPPORTED_AGENTS)


# ---------------------------------------------------------------------------
# get_all_agents()
# ---------------------------------------------------------------------------


def test_get_all_agents_returns_all():
    all_agents = get_all_agents()
    assert len(all_agents) == 12


# ---------------------------------------------------------------------------
# Required fields on every agent
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name", _EXPECTED_AGENTS)
def test_agent_has_marker_paths_for_all_os(name):
    agent = get_agent(name)
    assert agent is not None
    for os_key in _OS_KEYS:
        assert os_key in agent.marker_paths, f"{name} missing marker_paths for {os_key}"
        assert isinstance(agent.marker_paths[os_key], list)
        assert len(agent.marker_paths[os_key]) > 0


@pytest.mark.parametrize("name", _EXPECTED_AGENTS)
def test_agent_has_config_paths_for_all_os(name):
    agent = get_agent(name)
    assert agent is not None
    for os_key in _OS_KEYS:
        assert os_key in agent.config_paths, f"{name} missing config_paths for {os_key}"
        assert isinstance(agent.config_paths[os_key], list)
        assert len(agent.config_paths[os_key]) > 0


@pytest.mark.parametrize("name", _EXPECTED_AGENTS)
def test_agent_has_display_name(name):
    agent = get_agent(name)
    assert agent is not None
    assert len(agent.display_name) > 0


@pytest.mark.parametrize("name", _EXPECTED_AGENTS)
def test_agent_has_agent_type(name):
    agent = get_agent(name)
    assert agent is not None
    assert len(agent.agent_type) > 0


@pytest.mark.parametrize("name", _EXPECTED_AGENTS)
def test_agent_has_mcp_config_paths_for_all_os(name):
    agent = get_agent(name)
    assert agent is not None
    for os_key in _OS_KEYS:
        assert os_key in agent.mcp_config_paths, f"{name} missing mcp_config_paths for {os_key}"
        assert isinstance(agent.mcp_config_paths[os_key], list)


# ---------------------------------------------------------------------------
# Frozen dataclass
# ---------------------------------------------------------------------------


def test_agent_definition_is_frozen():
    agent = get_agent("claude_code")
    assert agent is not None
    with pytest.raises(AttributeError):
        agent.name = "modified"


# ---------------------------------------------------------------------------
# Specific agent properties
# ---------------------------------------------------------------------------


def test_claude_code_has_binary():
    agent = get_agent("claude_code")
    assert agent is not None
    assert "claude" in agent.binary_names


def test_cursor_has_binary():
    agent = get_agent("cursor")
    assert agent is not None
    assert "cursor" in agent.binary_names


def test_windsurf_has_no_binary():
    agent = get_agent("windsurf")
    assert agent is not None
    assert agent.binary_names == []


def test_openclaw_has_env_overrides():
    agent = get_agent("openclaw")
    assert agent is not None
    assert "OPENCLAW_HOME" in agent.env_overrides
