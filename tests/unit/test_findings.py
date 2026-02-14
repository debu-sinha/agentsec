"""Tests for the Finding model and related data structures."""

from pathlib import Path

import pytest

from agentsec.models.findings import (
    Finding,
    FindingCategory,
    FindingSeverity,
    Remediation,
)


def test_finding_creation():
    finding = Finding(
        scanner="installation",
        category=FindingCategory.PLAINTEXT_SECRET,
        severity=FindingSeverity.CRITICAL,
        title="OpenAI key in config.json",
        description="A plaintext OpenAI API key was found.",
    )
    assert finding.scanner == "installation"
    assert finding.severity == FindingSeverity.CRITICAL
    assert finding.id is not None
    assert len(finding.id) == 12


def test_finding_fingerprint_is_stable():
    f1 = Finding(
        scanner="installation",
        category=FindingCategory.PLAINTEXT_SECRET,
        severity=FindingSeverity.CRITICAL,
        title="OpenAI key in config.json",
        description="desc",
        file_path=Path("/home/user/.openclaw/config.json"),
    )
    f2 = Finding(
        scanner="installation",
        category=FindingCategory.PLAINTEXT_SECRET,
        severity=FindingSeverity.CRITICAL,
        title="OpenAI key in config.json",
        description="different description",
        file_path=Path("/home/user/.openclaw/config.json"),
    )
    assert f1.fingerprint == f2.fingerprint


def test_finding_fingerprint_changes_with_scanner():
    f1 = Finding(
        scanner="installation",
        category=FindingCategory.PLAINTEXT_SECRET,
        severity=FindingSeverity.CRITICAL,
        title="Key found",
        description="desc",
    )
    f2 = Finding(
        scanner="credential",
        category=FindingCategory.PLAINTEXT_SECRET,
        severity=FindingSeverity.CRITICAL,
        title="Key found",
        description="desc",
    )
    assert f1.fingerprint != f2.fingerprint


def test_severity_rank_ordering():
    assert FindingSeverity.CRITICAL.value == "critical"
    critical = Finding(
        scanner="test",
        category=FindingCategory.PLAINTEXT_SECRET,
        severity=FindingSeverity.CRITICAL,
        title="critical",
        description="desc",
    )
    info = Finding(
        scanner="test",
        category=FindingCategory.PLAINTEXT_SECRET,
        severity=FindingSeverity.INFO,
        title="info",
        description="desc",
    )
    assert critical.severity_rank < info.severity_rank


def test_remediation_model():
    r = Remediation(
        summary="Fix the issue",
        steps=["Step 1", "Step 2"],
        automated=True,
        command="agentsec harden --vault",
        references=["https://example.com"],
    )
    assert r.automated
    assert len(r.steps) == 2


@pytest.mark.parametrize(
    ("severity", "expected_rank"),
    [
        (FindingSeverity.CRITICAL, 0),
        (FindingSeverity.HIGH, 1),
        (FindingSeverity.MEDIUM, 2),
        (FindingSeverity.LOW, 3),
        (FindingSeverity.INFO, 4),
    ],
)
def test_severity_ranks(severity, expected_rank):
    f = Finding(
        scanner="test",
        category=FindingCategory.INSECURE_CONFIG,
        severity=severity,
        title="test",
        description="test",
    )
    assert f.severity_rank == expected_rank
