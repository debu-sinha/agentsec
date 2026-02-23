"""Tests for baseline file support."""

from __future__ import annotations

import json

from agentsec.models.findings import (
    Finding,
    FindingCategory,
    FindingSeverity,
)
from agentsec.utils.baseline import apply_baseline, create_baseline, load_baseline


def _make_finding(title: str = "Test finding", severity: FindingSeverity = FindingSeverity.HIGH):
    return Finding(
        scanner="test",
        category=FindingCategory.INSECURE_CONFIG,
        severity=severity,
        title=title,
        description="A test finding",
    )


def test_create_baseline_writes_file(tmp_path):
    findings = [_make_finding("Finding 1"), _make_finding("Finding 2")]
    path = tmp_path / ".agentsec-baseline.json"
    result = create_baseline(findings, path)

    assert result == path
    assert path.exists()

    data = json.loads(path.read_text())
    assert data["version"] == 1
    assert "created" in data
    assert len(data["findings"]) == 2


def test_create_baseline_captures_fingerprints(tmp_path):
    findings = [_make_finding("Finding 1")]
    path = tmp_path / "baseline.json"
    create_baseline(findings, path)

    data = json.loads(path.read_text())
    fingerprint = findings[0].fingerprint
    assert fingerprint in data["findings"]
    entry = data["findings"][fingerprint]
    assert entry["status"] == "accepted"
    assert entry["title"] == "Finding 1"
    assert entry["severity"] == "high"
    assert entry["scanner"] == "test"


def test_load_baseline_returns_entries(tmp_path):
    findings = [_make_finding("Existing")]
    path = tmp_path / "baseline.json"
    create_baseline(findings, path)

    baseline = load_baseline(path)
    assert len(baseline) == 1
    fingerprint = findings[0].fingerprint
    assert fingerprint in baseline


def test_load_baseline_missing_file(tmp_path):
    baseline = load_baseline(tmp_path / "nonexistent.json")
    assert baseline == {}


def test_load_baseline_malformed_json(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text("not json at all")
    baseline = load_baseline(path)
    assert baseline == {}


def test_apply_baseline_splits_findings(tmp_path):
    old_finding = _make_finding("Known issue")

    path = tmp_path / "baseline.json"
    create_baseline([old_finding], path)
    baseline = load_baseline(path)

    # Create fresh findings with same fingerprints
    old_copy = _make_finding("Known issue")
    new_copy = _make_finding("New issue")

    new_findings, baselined = apply_baseline([old_copy, new_copy], baseline)

    assert len(new_findings) == 1
    assert new_findings[0].title == "New issue"
    assert new_findings[0].metadata.get("baseline") is False

    assert len(baselined) == 1
    assert baselined[0].title == "Known issue"
    assert baselined[0].metadata.get("baseline") is True
    assert baselined[0].metadata.get("baseline_status") == "accepted"


def test_apply_baseline_empty_baseline():
    findings = [_make_finding("Some finding")]
    new, baselined = apply_baseline(findings, {})

    assert len(new) == 1
    assert len(baselined) == 0


def test_apply_baseline_all_baselined(tmp_path):
    f1 = _make_finding("A")
    f2 = _make_finding("B")

    path = tmp_path / "baseline.json"
    create_baseline([f1, f2], path)
    baseline = load_baseline(path)

    f1_copy = _make_finding("A")
    f2_copy = _make_finding("B")

    new, baselined = apply_baseline([f1_copy, f2_copy], baseline)

    assert len(new) == 0
    assert len(baselined) == 2


def test_create_baseline_default_path(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    findings = [_make_finding()]
    path = create_baseline(findings)
    assert path.name == ".agentsec-baseline.json"
    assert path.exists()
