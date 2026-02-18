"""Tests for agent installation auto-detection."""

from agentsec.utils.detection import detect_agent_type


def test_detects_openclaw_by_config(tmp_path):
    (tmp_path / "openclaw.json").write_text("{}")
    assert detect_agent_type(tmp_path) == "openclaw"


def test_detects_openclaw_by_directory(tmp_path):
    (tmp_path / ".openclaw").mkdir()
    assert detect_agent_type(tmp_path) == "openclaw"


def test_detects_claude_code(tmp_path):
    (tmp_path / ".claude").mkdir()
    assert detect_agent_type(tmp_path) == "claude-code"


def test_detects_cursor(tmp_path):
    (tmp_path / ".cursor").mkdir()
    assert detect_agent_type(tmp_path) == "cursor"


def test_detects_cursor_by_mcp_json(tmp_path):
    cursor_dir = tmp_path / ".cursor"
    cursor_dir.mkdir()
    (cursor_dir / "mcp.json").write_text("{}")
    assert detect_agent_type(tmp_path) == "cursor"


def test_detects_windsurf(tmp_path):
    (tmp_path / ".windsurf").mkdir()
    assert detect_agent_type(tmp_path) == "windsurf"


def test_detects_windsurf_by_codeium(tmp_path):
    (tmp_path / ".codeium").mkdir()
    assert detect_agent_type(tmp_path) == "windsurf"


def test_detects_gemini_cli(tmp_path):
    (tmp_path / ".gemini").mkdir()
    assert detect_agent_type(tmp_path) == "gemini-cli"


def test_normalizes_clawdbot_to_openclaw(tmp_path):
    (tmp_path / "clawdbot.json").write_text("{}")
    assert detect_agent_type(tmp_path) == "openclaw"


def test_normalizes_moltbot_to_openclaw(tmp_path):
    (tmp_path / ".moltbot").mkdir()
    assert detect_agent_type(tmp_path) == "openclaw"


def test_returns_unknown_for_empty_dir(tmp_path, monkeypatch):
    """Empty dir with no home directory markers should return 'unknown'."""
    # Patch Path.home() to avoid detecting markers on the developer's machine
    monkeypatch.setattr("agentsec.utils.detection.Path.home", lambda: tmp_path / "_fake_home")
    assert detect_agent_type(tmp_path) == "unknown"
