"""Tests for the scan orchestrator."""

import json
from pathlib import Path

from agentsec.models.config import AgentsecConfig, ScannerConfig, ScanTarget
from agentsec.models.report import ScanReport
from agentsec.orchestrator import run_scan


def _make_target(tmp_path: Path, version: str = "2026.2.12") -> Path:
    config = {"version": version}
    (tmp_path / "openclaw.json").write_text(json.dumps(config))
    return tmp_path


def test_run_scan_returns_report(tmp_path):
    target = _make_target(tmp_path)
    config = AgentsecConfig(targets=[ScanTarget(path=target)])
    report = run_scan(config)
    assert isinstance(report, ScanReport)
    assert report.scan_id
    assert report.agent_type


def test_run_scan_includes_findings(tmp_path):
    target = _make_target(tmp_path, version="2026.1.20")
    config = AgentsecConfig(targets=[ScanTarget(path=target)])
    report = run_scan(config)
    assert len(report.findings) > 0


def test_run_scan_safe_version_fewer_findings(tmp_path):
    target = _make_target(tmp_path, version="2026.2.12")
    config = AgentsecConfig(targets=[ScanTarget(path=target)])
    report = run_scan(config)
    # Safe version should have no CVE findings
    cve_findings = [f for f in report.findings if "CVE" in f.title]
    assert len(cve_findings) == 0


def test_run_scan_with_specific_scanners(tmp_path):
    target = _make_target(tmp_path)
    config = AgentsecConfig(
        targets=[ScanTarget(path=target)],
        scanners={
            "installation": ScannerConfig(enabled=True),
            "skill": ScannerConfig(enabled=False),
            "mcp": ScannerConfig(enabled=False),
            "credential": ScannerConfig(enabled=False),
        },
    )
    report = run_scan(config)
    assert isinstance(report, ScanReport)


def test_run_scan_has_owasp_mappings(tmp_path):
    target = _make_target(tmp_path, version="2026.1.20")
    config = AgentsecConfig(targets=[ScanTarget(path=target)])
    report = run_scan(config)
    assert report.owasp_mappings is not None


def test_run_scan_has_summary(tmp_path):
    target = _make_target(tmp_path)
    config = AgentsecConfig(targets=[ScanTarget(path=target)])
    report = run_scan(config)
    assert report.summary is not None
    assert report.summary.duration_seconds >= 0


def test_run_scan_defaults_to_cwd_when_no_targets():
    config = AgentsecConfig(targets=[])
    report = run_scan(config)
    assert isinstance(report, ScanReport)


def test_run_scan_all_scanners_disabled(tmp_path):
    target = _make_target(tmp_path)
    config = AgentsecConfig(
        targets=[ScanTarget(path=target)],
        scanners={
            "installation": ScannerConfig(enabled=False),
            "skill": ScannerConfig(enabled=False),
            "mcp": ScannerConfig(enabled=False),
            "credential": ScannerConfig(enabled=False),
        },
    )
    report = run_scan(config)
    assert len(report.findings) == 0
