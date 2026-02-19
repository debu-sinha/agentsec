"""Tests for the SARIF 2.1.0 reporter."""

import json
from pathlib import Path

import pytest

from agentsec.models.findings import (
    Finding,
    FindingCategory,
    FindingConfidence,
    FindingSeverity,
    Remediation,
)
from agentsec.models.report import ScanReport, ScanSummary
from agentsec.reporters.sarif_reporter import SarifReporter


@pytest.fixture
def reporter():
    return SarifReporter()


def _make_report(findings: list[Finding] | None = None) -> ScanReport:
    findings = findings or []
    return ScanReport(
        scan_id="test-001",
        target_path="/tmp/test",
        agent_type="openclaw",
        findings=findings,
        summary=ScanSummary.from_findings(
            findings=findings,
            scanners_run=["installation"],
            files_scanned=5,
            duration_seconds=0.5,
        ),
    )


def test_empty_report_produces_valid_sarif(reporter):
    report = _make_report()
    result = json.loads(reporter.render(report))

    assert result["version"] == "2.1.0"
    assert len(result["runs"]) == 1
    assert result["runs"][0]["tool"]["driver"]["name"] == "agentsec"
    assert result["runs"][0]["results"] == []


def test_finding_maps_to_sarif_result(reporter):
    finding = Finding(
        scanner="credential",
        category=FindingCategory.EXPOSED_TOKEN,
        severity=FindingSeverity.CRITICAL,
        title="OpenAI API Key found",
        description="An OpenAI API key was detected in config.py",
        file_path=Path("/tmp/test/config.py"),
        line_number=42,
        owasp_ids=["ASI05"],
    )
    report = _make_report([finding])
    result = json.loads(reporter.render(report))

    sarif_results = result["runs"][0]["results"]
    assert len(sarif_results) == 1

    sr = sarif_results[0]
    assert sr["level"] == "error"
    assert sr["ruleId"] == "agentsec/credential/exposed_token"
    assert sr["fingerprints"]["agentsec/v1"] == finding.fingerprint
    assert sr["locations"][0]["physicalLocation"]["region"]["startLine"] == 42


def test_severity_mapping(reporter):
    severities = {
        FindingSeverity.CRITICAL: "error",
        FindingSeverity.HIGH: "error",
        FindingSeverity.MEDIUM: "warning",
        FindingSeverity.LOW: "note",
        FindingSeverity.INFO: "note",
    }

    for severity, expected_level in severities.items():
        finding = Finding(
            scanner="test",
            category=FindingCategory.INSECURE_CONFIG,
            severity=severity,
            title=f"Test {severity.value}",
            description="Test finding",
        )
        report = _make_report([finding])
        result = json.loads(reporter.render(report))
        assert result["runs"][0]["results"][0]["level"] == expected_level


def test_rules_are_deduplicated(reporter):
    findings = [
        Finding(
            scanner="credential",
            category=FindingCategory.EXPOSED_TOKEN,
            severity=FindingSeverity.CRITICAL,
            title="Key 1",
            description="First key",
        ),
        Finding(
            scanner="credential",
            category=FindingCategory.EXPOSED_TOKEN,
            severity=FindingSeverity.CRITICAL,
            title="Key 2",
            description="Second key",
        ),
    ]
    report = _make_report(findings)
    result = json.loads(reporter.render(report))

    rules = result["runs"][0]["tool"]["driver"]["rules"]
    assert len(rules) == 1
    assert rules[0]["id"] == "agentsec/credential/exposed_token"


def test_remediation_included_in_rules(reporter):
    finding = Finding(
        scanner="credential",
        category=FindingCategory.EXPOSED_TOKEN,
        severity=FindingSeverity.CRITICAL,
        title="API Key found",
        description="Key detected",
        remediation=Remediation(
            summary="Rotate the key",
            steps=["Go to dashboard", "Regenerate key", "Update config"],
            automated=True,
            command="agentsec harden --vault",
        ),
    )
    report = _make_report([finding])
    result = json.loads(reporter.render(report))

    rule = result["runs"][0]["tool"]["driver"]["rules"][0]
    assert "help" in rule
    assert "Rotate the key" in rule["help"]["text"]
    assert "agentsec harden --vault" in rule["help"]["markdown"]


def test_owasp_tags_in_rules(reporter):
    finding = Finding(
        scanner="installation",
        category=FindingCategory.MISSING_AUTH,
        severity=FindingSeverity.HIGH,
        title="No auth",
        description="Auth disabled",
        owasp_ids=["ASI05", "ASI09"],
    )
    report = _make_report([finding])
    result = json.loads(reporter.render(report))

    rule = result["runs"][0]["tool"]["driver"]["rules"][0]
    tags = rule["properties"]["tags"]
    assert "ASI05" in tags
    assert "ASI09" in tags


def test_write_to_file(reporter, tmp_path):
    report = _make_report()
    output_path = tmp_path / "results.sarif"
    reporter.render(report, output_path=output_path)

    assert output_path.exists()
    content = json.loads(output_path.read_text())
    assert content["version"] == "2.1.0"


def test_precision_from_confidence(reporter):
    """SARIF precision field should map from Finding confidence."""
    confidences = {
        FindingConfidence.HIGH: "very-high",
        FindingConfidence.MEDIUM: "high",
        FindingConfidence.LOW: "medium",
    }

    for confidence, expected_precision in confidences.items():
        finding = Finding(
            scanner="credential",
            category=FindingCategory.EXPOSED_TOKEN,
            severity=FindingSeverity.CRITICAL,
            confidence=confidence,
            title=f"Test {confidence.value}",
            description="Test finding",
        )
        report = _make_report([finding])
        result = json.loads(reporter.render(report))

        rule = result["runs"][0]["tool"]["driver"]["rules"][0]
        assert rule["properties"]["precision"] == expected_precision


def test_file_paths_are_relative(reporter):
    """SARIF output should use relative paths, not absolute."""
    finding = Finding(
        scanner="credential",
        category=FindingCategory.EXPOSED_TOKEN,
        severity=FindingSeverity.CRITICAL,
        title="Key found",
        description="Key detected",
        file_path=Path("/tmp/test/src/config.py"),
        line_number=10,
    )
    report = _make_report([finding])
    result = json.loads(reporter.render(report))

    uri = result["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"][
        "uri"
    ]
    # Should be relative to /tmp/test (the target_path)
    assert not uri.startswith("/tmp/test")
    assert "src/config.py" in uri
