"""Tests for the CLI module."""

import json
from pathlib import Path

from click.testing import CliRunner

from agentsec.cli import main


def _make_openclaw(tmp_path: Path, version: str = "2026.2.12") -> Path:
    config = {"version": version}
    (tmp_path / "openclaw.json").write_text(json.dumps(config))
    return tmp_path


def test_scan_default_terminal_output(tmp_path):
    _make_openclaw(tmp_path)
    runner = CliRunner()
    result = runner.invoke(main, ["scan", str(tmp_path), "--fail-on", "none"])
    assert result.exit_code == 0
    assert "agentsec" in result.output


def test_scan_json_output(tmp_path):
    _make_openclaw(tmp_path)
    runner = CliRunner()
    result = runner.invoke(main, ["scan", str(tmp_path), "-o", "json", "--fail-on", "none"])
    assert result.exit_code == 0


def test_scan_sarif_output(tmp_path):
    _make_openclaw(tmp_path)
    runner = CliRunner()
    result = runner.invoke(main, ["scan", str(tmp_path), "-o", "sarif", "--fail-on", "none"])
    assert result.exit_code == 0


def test_scan_json_to_file(tmp_path):
    _make_openclaw(tmp_path)
    output_file = tmp_path / "report.json"
    runner = CliRunner()
    result = runner.invoke(
        main,
        ["scan", str(tmp_path), "-o", "json", "-f", str(output_file), "--fail-on", "none"],
    )
    assert result.exit_code == 0
    assert output_file.exists()
    data = json.loads(output_file.read_text())
    assert "findings" in data


def test_scan_quiet_mode(tmp_path):
    _make_openclaw(tmp_path)
    runner = CliRunner()
    result = runner.invoke(main, ["scan", str(tmp_path), "-q", "--fail-on", "none"])
    assert result.exit_code == 0
    assert result.output.strip() == ""


def test_scan_specific_scanners(tmp_path):
    _make_openclaw(tmp_path)
    runner = CliRunner()
    result = runner.invoke(main, ["scan", str(tmp_path), "-s", "installation", "--fail-on", "none"])
    assert result.exit_code == 0


def test_scan_fail_on_critical_exits_nonzero(tmp_path):
    """Scan with a vulnerable version should exit nonzero on critical findings."""
    _make_openclaw(tmp_path, version="2026.1.20")
    runner = CliRunner()
    result = runner.invoke(main, ["scan", str(tmp_path), "--fail-on", "critical"])
    # Old version has critical CVEs, should fail
    assert result.exit_code != 0


def test_scan_fail_on_none_always_zero(tmp_path):
    _make_openclaw(tmp_path, version="2026.1.20")
    runner = CliRunner()
    result = runner.invoke(main, ["scan", str(tmp_path), "--fail-on", "none"])
    assert result.exit_code == 0


def test_list_scanners():
    runner = CliRunner()
    result = runner.invoke(main, ["list-scanners"])
    assert result.exit_code == 0
    assert "installation" in result.output
    assert "skill" in result.output
    assert "mcp" in result.output
    assert "credential" in result.output


def test_version_flag():
    runner = CliRunner()
    result = runner.invoke(main, ["--version"])
    assert result.exit_code == 0
    assert "0.4.0" in result.output


def test_hook_zsh():
    runner = CliRunner()
    result = runner.invoke(main, ["hook", "--shell", "zsh"])
    assert result.exit_code == 0
    assert "_agentsec_post_install" in result.output
    assert "npm" in result.output


def test_hook_bash():
    runner = CliRunner()
    result = runner.invoke(main, ["hook", "--shell", "bash"])
    assert result.exit_code == 0
    assert "_agentsec_post_install" in result.output
    assert "echo -e" in result.output


def test_harden_dry_run(tmp_path):
    _make_openclaw(tmp_path)
    runner = CliRunner()
    result = runner.invoke(main, ["harden", str(tmp_path), "-p", "workstation"])
    assert result.exit_code == 0
    assert "DRY RUN" in result.output


def test_harden_apply(tmp_path):
    _make_openclaw(tmp_path)
    runner = CliRunner()
    result = runner.invoke(main, ["harden", str(tmp_path), "-p", "workstation", "--apply"])
    assert result.exit_code == 0
    # Config should be updated
    config = json.loads((tmp_path / "openclaw.json").read_text())
    assert config.get("gateway", {}).get("bind") == "loopback"


def test_harden_no_config(tmp_path):
    runner = CliRunner()
    result = runner.invoke(main, ["harden", str(tmp_path), "-p", "workstation"])
    assert result.exit_code == 1
