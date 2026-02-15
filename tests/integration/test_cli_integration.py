"""Integration tests for the agentsec CLI.

These tests run the full CLI pipeline end-to-end against mock agent
directories, verifying that scan -> score -> report works correctly.
"""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from agentsec.cli import main


def _create_openclaw_dir(tmp_path: Path) -> Path:
    """Create a minimal OpenClaw installation directory."""
    oc_dir = tmp_path / ".openclaw"
    oc_dir.mkdir()

    config = {
        "gatewayHostname": "127.0.0.1",
        "gatewayPort": 40000,
        "authRequired": True,
        "dmPolicy": "paired",
        "groupPolicy": "invite-only",
        "toolProfile": "default",
    }
    (oc_dir / "openclaw.json").write_text(json.dumps(config))

    # Add exec-approvals so CEX-001 doesn't fire
    approvals = {"defaultApproval": "ask", "rules": []}
    (oc_dir / "exec-approvals.json").write_text(json.dumps(approvals))
    return tmp_path


def _create_insecure_openclaw_dir(tmp_path: Path) -> Path:
    """Create an OpenClaw dir with multiple misconfigurations."""
    oc_dir = tmp_path / ".openclaw"
    oc_dir.mkdir()

    config = {
        "gatewayHostname": "0.0.0.0",
        "gatewayPort": 40000,
        "authRequired": False,
        "dmPolicy": "open",
        "groupPolicy": "open",
        "toolProfile": "full",
    }
    (oc_dir / "openclaw.json").write_text(json.dumps(config))
    return tmp_path


def _create_mcp_config(tmp_path: Path) -> Path:
    """Create a directory with MCP server config."""
    oc_dir = tmp_path / ".openclaw"
    oc_dir.mkdir()
    (oc_dir / "openclaw.json").write_text(json.dumps({"gatewayHostname": "127.0.0.1"}))
    approvals = {"defaultApproval": "ask", "rules": []}
    (oc_dir / "exec-approvals.json").write_text(json.dumps(approvals))

    mcp_config = {
        "mcpServers": {
            "safe-server": {
                "command": "node",
                "args": ["server.js"],
            },
        }
    }
    (oc_dir / "mcp.json").write_text(json.dumps(mcp_config))
    return tmp_path


def _scan_to_json(tmp_path: Path, target: Path, extra_args: list[str] | None = None):
    """Run scan with JSON file output and return parsed data."""
    out_file = tmp_path / "report.json"
    args = ["scan", str(target), "-o", "json", "-f", str(out_file), "--fail-on", "none"]
    if extra_args:
        args.extend(extra_args)
    runner = CliRunner()
    result = runner.invoke(main, args)
    assert result.exit_code == 0, f"CLI failed: {result.output}"
    return json.loads(out_file.read_text())


# -----------------------------------------------------------------------
# Full scan pipeline
# -----------------------------------------------------------------------


def test_scan_clean_config_json_output(tmp_path):
    """A secure config should produce few or no critical findings."""
    target = _create_openclaw_dir(tmp_path)
    data = _scan_to_json(tmp_path, target)

    assert "findings" in data
    assert "summary" in data
    assert data["summary"]["critical"] == 0


def test_scan_insecure_config_finds_criticals(tmp_path):
    """An insecure config should flag critical findings."""
    target = _create_insecure_openclaw_dir(tmp_path)
    data = _scan_to_json(tmp_path, target)

    assert data["summary"]["critical"] > 0
    assert data["summary"]["total_findings"] > 0

    titles = [f["title"] for f in data["findings"]]
    assert any("open" in t.lower() or "full tool" in t.lower() for t in titles)


def test_scan_insecure_fail_on_critical(tmp_path):
    """--fail-on critical should exit nonzero when criticals exist."""
    target = _create_insecure_openclaw_dir(tmp_path)
    runner = CliRunner()
    result = runner.invoke(main, ["scan", str(target), "--fail-on", "critical", "-q"])

    assert result.exit_code != 0


def test_scan_clean_fail_on_critical(tmp_path):
    """--fail-on critical should exit zero on a clean config."""
    target = _create_openclaw_dir(tmp_path)
    runner = CliRunner()
    result = runner.invoke(main, ["scan", str(target), "--fail-on", "critical", "-q"])

    assert result.exit_code == 0


# -----------------------------------------------------------------------
# Output formats
# -----------------------------------------------------------------------


def test_scan_sarif_output_valid(tmp_path):
    """SARIF output should be valid JSON with required schema fields."""
    target = _create_insecure_openclaw_dir(tmp_path)
    out_file = tmp_path / "results.sarif"
    runner = CliRunner()
    runner.invoke(
        main,
        ["scan", str(target), "-o", "sarif", "-f", str(out_file), "--fail-on", "none"],
    )

    assert out_file.exists()
    sarif = json.loads(out_file.read_text())
    assert sarif["$schema"] == "https://json.schemastore.org/sarif-2.1.0.json"
    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"]) == 1
    assert "results" in sarif["runs"][0]
    assert "tool" in sarif["runs"][0]


def test_scan_json_to_file(tmp_path):
    """JSON output to file should be parseable and contain report fields."""
    target = _create_openclaw_dir(tmp_path)
    data = _scan_to_json(tmp_path, target)

    assert "version" in data
    assert "scan_id" in data
    assert "findings" in data
    assert "summary" in data


# -----------------------------------------------------------------------
# Scanner selection
# -----------------------------------------------------------------------


def test_scan_specific_scanner_only(tmp_path):
    """Running with -s installation should only run that scanner."""
    target = _create_openclaw_dir(tmp_path)
    data = _scan_to_json(tmp_path, target, extra_args=["-s", "installation"])

    assert data["summary"]["scanners_run"] == ["installation"]


def test_scan_multiple_scanners(tmp_path):
    """Running with multiple scanners should run all specified."""
    target = _create_openclaw_dir(tmp_path)
    data = _scan_to_json(tmp_path, target, extra_args=["-s", "installation,credential"])

    assert "installation" in data["summary"]["scanners_run"]
    assert "credential" in data["summary"]["scanners_run"]


# -----------------------------------------------------------------------
# OWASP scoring integration
# -----------------------------------------------------------------------


def test_insecure_config_has_multiple_criticals(tmp_path):
    """A badly misconfigured installation should produce many critical findings."""
    target = _create_insecure_openclaw_dir(tmp_path)
    data = _scan_to_json(tmp_path, target)

    assert data["summary"]["critical"] >= 2


def test_scan_with_mcp_config(tmp_path):
    """Scanning a dir with MCP config should include MCP scanner results."""
    target = _create_mcp_config(tmp_path)
    data = _scan_to_json(tmp_path, target)

    assert "mcp" in data["summary"]["scanners_run"]


def test_owasp_ids_present_in_findings(tmp_path):
    """Every finding should have at least one OWASP category mapped."""
    target = _create_insecure_openclaw_dir(tmp_path)
    data = _scan_to_json(tmp_path, target)

    for finding in data["findings"]:
        assert len(finding["owasp_ids"]) > 0, f"Finding '{finding['title']}' has no OWASP IDs"


# -----------------------------------------------------------------------
# CLI commands
# -----------------------------------------------------------------------


def test_list_scanners_output():
    """list-scanners should return all available scanner names."""
    runner = CliRunner()
    result = runner.invoke(main, ["list-scanners"])

    assert result.exit_code == 0
    assert "installation" in result.output
    assert "skill" in result.output
    assert "mcp" in result.output
    assert "credential" in result.output


def test_version_output():
    """--version should print the current version."""
    runner = CliRunner()
    result = runner.invoke(main, ["--version"])

    assert result.exit_code == 0
    assert "0.4.0" in result.output


def test_harden_dry_run(tmp_path):
    """harden --dry-run should not modify files."""
    target = _create_openclaw_dir(tmp_path)
    config_file = target / ".openclaw" / "openclaw.json"
    original_content = config_file.read_text()

    runner = CliRunner()
    result = runner.invoke(main, ["harden", str(target), "-p", "workstation", "--dry-run"])

    assert result.exit_code == 0
    assert config_file.read_text() == original_content
