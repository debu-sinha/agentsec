"""Tests for the OWASP Agentic Top 10 scorer."""

import pytest

from agentsec.analyzers.owasp_scorer import OwaspScorer
from agentsec.models.findings import Finding, FindingCategory, FindingSeverity
from agentsec.models.owasp import OwaspAgenticCategory


@pytest.fixture
def scorer():
    return OwaspScorer()


def _make_finding(
    category: FindingCategory,
    severity: FindingSeverity,
    owasp_ids: list[str] | None = None,
) -> Finding:
    return Finding(
        scanner="test",
        category=category,
        severity=severity,
        title=f"Test {category.value}",
        description="Test finding",
        owasp_ids=owasp_ids or [],
    )


def test_maps_plaintext_secret_to_asi05(scorer):
    finding = _make_finding(FindingCategory.PLAINTEXT_SECRET, FindingSeverity.CRITICAL)
    mappings = scorer.score([finding])
    assert len(mappings) == 1
    assert OwaspAgenticCategory.ASI05_PRIVILEGE_COMPROMISE in mappings[0].categories


def test_maps_prompt_injection_to_asi01(scorer):
    finding = _make_finding(
        FindingCategory.PROMPT_INJECTION_VECTOR,
        FindingSeverity.HIGH,
    )
    mappings = scorer.score([finding])
    assert len(mappings) == 1
    assert OwaspAgenticCategory.ASI01_AGENT_GOAL_HIJACK in mappings[0].categories


def test_maps_supply_chain_to_asi03(scorer):
    finding = _make_finding(FindingCategory.SUPPLY_CHAIN, FindingSeverity.HIGH)
    mappings = scorer.score([finding])
    assert len(mappings) == 1
    assert OwaspAgenticCategory.ASI03_SUPPLY_CHAIN_VULNERABILITIES in mappings[0].categories


def test_respects_explicit_owasp_ids(scorer):
    finding = _make_finding(
        FindingCategory.INSECURE_CONFIG,
        FindingSeverity.MEDIUM,
        owasp_ids=["ASI08"],
    )
    mappings = scorer.score([finding])
    assert len(mappings) == 1
    assert OwaspAgenticCategory.ASI08_UNCONTROLLED_CASCADING in mappings[0].categories


def test_risk_score_scales_with_severity(scorer):
    critical = _make_finding(FindingCategory.PLAINTEXT_SECRET, FindingSeverity.CRITICAL)
    low = _make_finding(FindingCategory.PLAINTEXT_SECRET, FindingSeverity.LOW)

    crit_mappings = scorer.score([critical])
    low_mappings = scorer.score([low])

    assert crit_mappings[0].risk_score > low_mappings[0].risk_score


def test_posture_score_perfect_when_no_findings(scorer):
    posture = scorer.compute_posture_score([])
    assert posture["overall_score"] == 100.0
    assert posture["grade"] == "A"


def test_posture_score_degrades_with_findings(scorer):
    findings = [
        _make_finding(FindingCategory.PLAINTEXT_SECRET, FindingSeverity.CRITICAL),
        _make_finding(FindingCategory.NETWORK_EXPOSURE, FindingSeverity.CRITICAL),
        _make_finding(FindingCategory.MISSING_AUTH, FindingSeverity.HIGH),
    ]
    posture = scorer.compute_posture_score(findings)
    assert posture["overall_score"] < 100.0
    assert posture["grade"] in ("C", "D", "F")


def test_multiple_findings_produce_multiple_mappings(scorer):
    findings = [
        _make_finding(FindingCategory.PLAINTEXT_SECRET, FindingSeverity.CRITICAL),
        _make_finding(FindingCategory.PROMPT_INJECTION_VECTOR, FindingSeverity.HIGH),
        _make_finding(FindingCategory.SUPPLY_CHAIN, FindingSeverity.MEDIUM),
    ]
    mappings = scorer.score(findings)
    assert len(mappings) == 3


def test_score_floor_never_below_five(scorer):
    """Many findings should still produce a minimum score of 5."""
    findings = [
        _make_finding(FindingCategory.PLAINTEXT_SECRET, FindingSeverity.CRITICAL)
        for _ in range(20)
    ]
    posture = scorer.compute_posture_score(findings)
    assert posture["overall_score"] == 5.0
    assert posture["grade"] == "F"


def test_doom_combo_caps_at_20(scorer):
    """Open DM + full tools + sandbox disabled = doom combo, max score 20."""
    findings = [
        Finding(
            scanner="test",
            category=FindingCategory.INSECURE_DEFAULT,
            severity=FindingSeverity.CRITICAL,
            title="DM policy open",
            description="t",
        ),
        Finding(
            scanner="test",
            category=FindingCategory.INSECURE_DEFAULT,
            severity=FindingSeverity.CRITICAL,
            title="Full tool profile with open access",
            description="t",
        ),
        Finding(
            scanner="test",
            category=FindingCategory.INSECURE_DEFAULT,
            severity=FindingSeverity.MEDIUM,
            title="Sandboxing disabled with exposure",
            description="t",
        ),
    ]
    posture = scorer.compute_posture_score(findings)
    assert posture["overall_score"] <= 20.0


def test_doom_combo_not_triggered_without_all_three(scorer):
    """Two of three doom elements should not trigger the cap."""
    findings = [
        Finding(
            scanner="test",
            category=FindingCategory.INSECURE_DEFAULT,
            severity=FindingSeverity.CRITICAL,
            title="DM policy open",
            description="t",
        ),
        Finding(
            scanner="test",
            category=FindingCategory.INSECURE_DEFAULT,
            severity=FindingSeverity.CRITICAL,
            title="Full tool profile with open access",
            description="t",
        ),
    ]
    posture = scorer.compute_posture_score(findings)
    # 2 criticals but no doom combo, capped at 55 not 20
    assert posture["overall_score"] <= 55.0
    assert posture["overall_score"] > 20.0


def test_severity_escalation_open_group_with_disabled_auth(scorer):
    """Open group policy + missing auth should escalate HIGH -> CRITICAL."""
    findings = [
        Finding(
            scanner="test",
            category=FindingCategory.MISSING_AUTH,
            severity=FindingSeverity.CRITICAL,
            title="Dangerous auth bypass flag set",
            description="t",
        ),
        Finding(
            scanner="test",
            category=FindingCategory.INSECURE_DEFAULT,
            severity=FindingSeverity.HIGH,
            title="Group policy open to all",
            description="t",
        ),
    ]
    scorer.compute_posture_score(findings)
    group_finding = findings[1]
    assert group_finding.severity == FindingSeverity.CRITICAL


def test_severity_escalation_not_triggered_without_auth_issue(scorer):
    """Open group policy alone should stay HIGH, not escalate."""
    findings = [
        Finding(
            scanner="test",
            category=FindingCategory.INSECURE_DEFAULT,
            severity=FindingSeverity.HIGH,
            title="Group policy open to all",
            description="t",
        ),
    ]
    scorer.compute_posture_score(findings)
    assert findings[0].severity == FindingSeverity.HIGH


def test_single_critical_caps_at_55(scorer):
    """One critical finding should cap the score at 55."""
    findings = [
        _make_finding(FindingCategory.PLAINTEXT_SECRET, FindingSeverity.CRITICAL),
    ]
    posture = scorer.compute_posture_score(findings)
    assert posture["overall_score"] <= 55.0


def test_three_criticals_caps_at_20(scorer):
    """Three or more critical findings cap score at 20."""
    findings = [
        _make_finding(FindingCategory.PLAINTEXT_SECRET, FindingSeverity.CRITICAL),
        _make_finding(FindingCategory.NETWORK_EXPOSURE, FindingSeverity.CRITICAL),
        _make_finding(FindingCategory.MISSING_AUTH, FindingSeverity.CRITICAL),
    ]
    posture = scorer.compute_posture_score(findings)
    assert posture["overall_score"] <= 20.0


def test_owasp_category_metadata():
    cat = OwaspAgenticCategory.ASI01_AGENT_GOAL_HIJACK
    assert cat.value == "ASI01"
    assert "hijack" in cat.title.lower() or "injection" in cat.title.lower()
    assert len(cat.attack_scenarios) > 0
    assert len(cat.controls) > 0
