"""Tests for the policy-as-code engine."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from agentsec.models.findings import (
    Finding,
    FindingCategory,
    FindingConfidence,
    FindingSeverity,
)
from agentsec.policy import PolicyEvaluator, PolicyRule, PolicyViolation


@pytest.fixture
def sample_findings() -> list[Finding]:
    return [
        Finding(
            scanner="credential",
            category=FindingCategory.PLAINTEXT_SECRET,
            severity=FindingSeverity.CRITICAL,
            confidence=FindingConfidence.HIGH,
            title="Hardcoded OpenAI API key",
            description="API key found in config.py",
            file_path=Path("config.py"),
        ),
        Finding(
            scanner="credential",
            category=FindingCategory.EXPOSED_TOKEN,
            severity=FindingSeverity.HIGH,
            confidence=FindingConfidence.MEDIUM,
            title="GitHub token in .env",
            description="Token found in .env file",
            file_path=Path(".env"),
        ),
        Finding(
            scanner="installation",
            category=FindingCategory.INSECURE_DEFAULT,
            severity=FindingSeverity.MEDIUM,
            confidence=FindingConfidence.HIGH,
            title="DM policy set to open",
            description="Open DM policy allows unsolicited messages",
        ),
        Finding(
            scanner="mcp",
            category=FindingCategory.MCP_TOOL_POISONING,
            severity=FindingSeverity.HIGH,
            confidence=FindingConfidence.HIGH,
            title="Hidden directive in tool description",
            description="Tool description contains behavioral instruction",
        ),
    ]


@pytest.fixture
def sample_posture() -> dict:
    return {
        "grade": "D",
        "overall_score": 62.0,
        "raw_score": 62.0,
    }


class TestPolicyRule:
    def test_severity_match(self, sample_findings: list[Finding]) -> None:
        rule = PolicyRule(
            {
                "id": "T-001",
                "name": "No criticals",
                "condition": {"severity": "critical", "max_count": 0},
                "action": "fail",
            }
        )
        violation = rule.evaluate(sample_findings)
        assert violation is not None
        assert violation.matched_count == 1
        assert violation.action == "fail"

    def test_severity_under_threshold(self, sample_findings: list[Finding]) -> None:
        rule = PolicyRule(
            {
                "id": "T-002",
                "name": "Max 5 criticals",
                "condition": {"severity": "critical", "max_count": 5},
                "action": "fail",
            }
        )
        violation = rule.evaluate(sample_findings)
        assert violation is None

    def test_category_match(self, sample_findings: list[Finding]) -> None:
        rule = PolicyRule(
            {
                "id": "T-003",
                "name": "No plaintext secrets",
                "condition": {"category": "plaintext_secret", "max_count": 0},
                "action": "fail",
            }
        )
        violation = rule.evaluate(sample_findings)
        assert violation is not None
        assert violation.matched_count == 1

    def test_owasp_match(self, sample_findings: list[Finding]) -> None:
        # Manually set owasp_ids
        sample_findings[0].owasp_ids = ["ASI05"]
        sample_findings[1].owasp_ids = ["ASI05"]
        rule = PolicyRule(
            {
                "id": "T-004",
                "name": "No ASI05",
                "condition": {"owasp_id": "ASI05", "max_count": 0},
                "action": "fail",
            }
        )
        violation = rule.evaluate(sample_findings)
        assert violation is not None
        assert violation.matched_count == 2

    def test_scanner_match(self, sample_findings: list[Finding]) -> None:
        rule = PolicyRule(
            {
                "id": "T-005",
                "name": "No MCP findings",
                "condition": {"scanner": "mcp", "max_count": 0},
                "action": "fail",
            }
        )
        violation = rule.evaluate(sample_findings)
        assert violation is not None
        assert violation.matched_count == 1

    def test_title_regex_match(self, sample_findings: list[Finding]) -> None:
        rule = PolicyRule(
            {
                "id": "T-006",
                "name": "No hardcoded keys",
                "condition": {"title_regex": "hardcoded", "max_count": 0},
                "action": "fail",
            }
        )
        violation = rule.evaluate(sample_findings)
        assert violation is not None
        assert violation.matched_count == 1

    def test_severity_min_match(self, sample_findings: list[Finding]) -> None:
        rule = PolicyRule(
            {
                "id": "T-007",
                "name": "Max 2 high or above",
                "condition": {"severity_min": "high", "max_count": 2},
                "action": "fail",
            }
        )
        violation = rule.evaluate(sample_findings)
        assert violation is not None
        # CRITICAL + 2 HIGH = 3, exceeds max_count=2
        assert violation.matched_count == 3

    def test_posture_grade_pass(self, sample_posture: dict) -> None:
        rule = PolicyRule(
            {
                "id": "T-008",
                "name": "Min grade F",
                "condition": {"type": "posture_grade", "min_grade": "F"},
                "action": "fail",
            }
        )
        violation = rule.evaluate([], sample_posture)
        assert violation is None

    def test_posture_grade_fail(self, sample_posture: dict) -> None:
        rule = PolicyRule(
            {
                "id": "T-009",
                "name": "Min grade B",
                "condition": {"type": "posture_grade", "min_grade": "B"},
                "action": "fail",
            }
        )
        violation = rule.evaluate([], sample_posture)
        assert violation is not None
        assert "D" in violation.message
        assert "B" in violation.message

    def test_posture_score_pass(self, sample_posture: dict) -> None:
        rule = PolicyRule(
            {
                "id": "T-010",
                "name": "Min score 60",
                "condition": {"type": "posture_score", "min_score": 60},
                "action": "fail",
            }
        )
        violation = rule.evaluate([], sample_posture)
        assert violation is None

    def test_posture_score_fail(self, sample_posture: dict) -> None:
        rule = PolicyRule(
            {
                "id": "T-011",
                "name": "Min score 80",
                "condition": {"type": "posture_score", "min_score": 80},
                "action": "fail",
            }
        )
        violation = rule.evaluate([], sample_posture)
        assert violation is not None
        assert "62.0" in violation.message

    def test_warn_action(self, sample_findings: list[Finding]) -> None:
        rule = PolicyRule(
            {
                "id": "T-012",
                "name": "Warn on MCP poisoning",
                "condition": {"category": "mcp_tool_poisoning", "max_count": 0},
                "action": "warn",
            }
        )
        violation = rule.evaluate(sample_findings)
        assert violation is not None
        assert violation.action == "warn"


class TestPolicyViolation:
    def test_to_finding(self) -> None:
        v = PolicyViolation(
            rule_id="POL-001",
            rule_name="Zero criticals",
            action="fail",
            message="Found 2 critical findings",
            matched_count=2,
        )
        f = v.to_finding()
        assert f.scanner == "policy"
        assert f.severity == FindingSeverity.HIGH
        assert "POL-001" in f.evidence
        assert f.metadata["policy_rule_id"] == "POL-001"
        assert f.metadata["policy_action"] == "fail"

    def test_warn_to_finding_medium_severity(self) -> None:
        v = PolicyViolation(
            rule_id="POL-002",
            rule_name="Watch for MCP",
            action="warn",
            message="Found MCP issues",
            matched_count=1,
        )
        f = v.to_finding()
        assert f.severity == FindingSeverity.MEDIUM


class TestPolicyEvaluator:
    def test_load_from_yaml(self, tmp_path: Path) -> None:
        policy_file = tmp_path / "policy.yaml"
        policy_file.write_text(
            yaml.dump(
                {
                    "name": "test-policy",
                    "version": "1.0",
                    "rules": [
                        {
                            "id": "T-001",
                            "name": "No criticals",
                            "condition": {"severity": "critical", "max_count": 0},
                            "action": "fail",
                        }
                    ],
                }
            )
        )
        evaluator = PolicyEvaluator.load(policy_file)
        assert evaluator.name == "test-policy"
        assert len(evaluator.rules) == 1

    def test_evaluate_returns_violations(
        self, sample_findings: list[Finding], sample_posture: dict
    ) -> None:
        evaluator = PolicyEvaluator(
            {
                "name": "test",
                "rules": [
                    {
                        "id": "T-001",
                        "name": "No criticals",
                        "condition": {"severity": "critical", "max_count": 0},
                        "action": "fail",
                    },
                    {
                        "id": "T-002",
                        "name": "Min grade B",
                        "condition": {"type": "posture_grade", "min_grade": "B"},
                        "action": "fail",
                    },
                ],
            }
        )
        violations = evaluator.evaluate(sample_findings, sample_posture)
        assert len(violations) == 2

    def test_should_fail_with_fail_action(self, sample_findings: list[Finding]) -> None:
        evaluator = PolicyEvaluator(
            {
                "name": "test",
                "rules": [
                    {
                        "id": "T-001",
                        "name": "No criticals",
                        "condition": {"severity": "critical", "max_count": 0},
                        "action": "fail",
                    }
                ],
            }
        )
        violations = evaluator.evaluate(sample_findings)
        assert evaluator.should_fail(violations)

    def test_should_not_fail_with_warn_only(self, sample_findings: list[Finding]) -> None:
        evaluator = PolicyEvaluator(
            {
                "name": "test",
                "rules": [
                    {
                        "id": "T-001",
                        "name": "Warn on criticals",
                        "condition": {"severity": "critical", "max_count": 0},
                        "action": "warn",
                    }
                ],
            }
        )
        violations = evaluator.evaluate(sample_findings)
        assert not evaluator.should_fail(violations)

    def test_exemption_removes_finding(self, sample_findings: list[Finding]) -> None:
        # Get the fingerprint of the first finding
        fp = sample_findings[0].fingerprint
        evaluator = PolicyEvaluator(
            {
                "name": "test",
                "rules": [
                    {
                        "id": "T-001",
                        "name": "No criticals",
                        "condition": {"severity": "critical", "max_count": 0},
                        "action": "fail",
                    }
                ],
                "exemptions": [
                    {
                        "finding_id": fp,
                        "rule_id": "T-001",
                        "reason": "Accepted risk",
                        "expires": "2099-12-31",
                    }
                ],
            }
        )
        violations = evaluator.evaluate(sample_findings)
        # The critical finding should be exempted, so no violation
        assert len(violations) == 0

    def test_expired_exemption_does_not_suppress(self, sample_findings: list[Finding]) -> None:
        fp = sample_findings[0].fingerprint
        evaluator = PolicyEvaluator(
            {
                "name": "test",
                "rules": [
                    {
                        "id": "T-001",
                        "name": "No criticals",
                        "condition": {"severity": "critical", "max_count": 0},
                        "action": "fail",
                    }
                ],
                "exemptions": [
                    {
                        "finding_id": fp,
                        "rule_id": "T-001",
                        "reason": "Was accepted",
                        "expires": "2020-01-01",
                    }
                ],
            }
        )
        violations = evaluator.evaluate(sample_findings)
        assert len(violations) == 1

    def test_no_rules_no_violations(self, sample_findings: list[Finding]) -> None:
        evaluator = PolicyEvaluator({"name": "empty", "rules": []})
        violations = evaluator.evaluate(sample_findings)
        assert len(violations) == 0

    def test_clean_scan_no_violations(self) -> None:
        evaluator = PolicyEvaluator(
            {
                "name": "strict",
                "rules": [
                    {
                        "id": "T-001",
                        "name": "No criticals",
                        "condition": {"severity": "critical", "max_count": 0},
                        "action": "fail",
                    }
                ],
            }
        )
        violations = evaluator.evaluate([])
        assert len(violations) == 0

    def test_combined_conditions(self, sample_findings: list[Finding]) -> None:
        rule = PolicyRule(
            {
                "id": "T-013",
                "name": "No high credential findings",
                "condition": {
                    "severity": "high",
                    "scanner": "credential",
                    "max_count": 0,
                },
                "action": "fail",
            }
        )
        violation = rule.evaluate(sample_findings)
        assert violation is not None
        # Only the HIGH credential finding should match (not the HIGH MCP finding)
        assert violation.matched_count == 1
