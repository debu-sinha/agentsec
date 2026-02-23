"""Policy-as-code engine for agentsec.

Evaluates scan findings against organizational security policies defined in YAML.
Policies let teams enforce rules like "zero critical findings" or "minimum grade B"
in CI/CD pipelines without modifying scanner configuration.

Usage:
    agentsec scan --policy .agentsec-policy.yaml
"""

from __future__ import annotations

import logging
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from agentsec.models.findings import (
    Finding,
    FindingCategory,
    FindingConfidence,
    FindingSeverity,
    Remediation,
)

logger = logging.getLogger(__name__)


class PolicyViolation:
    """Result of a policy rule evaluation."""

    def __init__(
        self,
        rule_id: str,
        rule_name: str,
        action: str,
        message: str,
        matched_count: int = 0,
    ):
        self.rule_id = rule_id
        self.rule_name = rule_name
        self.action = action
        self.message = message
        self.matched_count = matched_count

    def to_finding(self) -> Finding:
        severity_map = {
            "fail": FindingSeverity.HIGH,
            "warn": FindingSeverity.MEDIUM,
            "info": FindingSeverity.INFO,
        }
        return Finding(
            scanner="policy",
            category=FindingCategory.INSECURE_CONFIG,
            severity=severity_map.get(self.action, FindingSeverity.MEDIUM),
            confidence=FindingConfidence.HIGH,
            title=f"Policy violation: {self.rule_name}",
            description=self.message,
            evidence=f"Rule {self.rule_id}: {self.matched_count} findings matched condition",
            remediation=Remediation(
                summary=f"Fix findings to satisfy policy rule {self.rule_id}",
                steps=[self.message],
            ),
            owasp_ids=["ASI10"],
            metadata={"policy_rule_id": self.rule_id, "policy_action": self.action},
        )


class PolicyRule:
    """Single rule in a security policy."""

    def __init__(self, rule_dict: dict[str, Any]):
        self.id: str = rule_dict["id"]
        self.name: str = rule_dict["name"]
        self.description: str = rule_dict.get("description", "")
        self.condition: dict[str, Any] = rule_dict.get("condition", {})
        self.action: str = rule_dict.get("action", "fail").lower()

    def evaluate(
        self,
        findings: list[Finding],
        posture: dict[str, Any] | None = None,
    ) -> PolicyViolation | None:
        """Evaluate this rule against findings and posture. Returns violation or None."""
        condition_type = self.condition.get("type", "finding_match")

        if condition_type == "posture_grade":
            return self._check_posture_grade(posture)
        if condition_type == "posture_score":
            return self._check_posture_score(posture)
        return self._check_finding_match(findings)

    def _check_finding_match(self, findings: list[Finding]) -> PolicyViolation | None:
        max_count = self.condition.get("max_count", 0)
        matched = self._match_findings(findings)
        if len(matched) > max_count:
            return PolicyViolation(
                rule_id=self.id,
                rule_name=self.name,
                action=self.action,
                message=(
                    f"Found {len(matched)} findings matching rule '{self.name}' "
                    f"(max allowed: {max_count})"
                ),
                matched_count=len(matched),
            )
        return None

    def _match_findings(self, findings: list[Finding]) -> list[Finding]:
        matched = findings

        severity = self.condition.get("severity")
        if severity:
            sev = FindingSeverity(severity.lower())
            matched = [f for f in matched if f.severity == sev]

        severity_min = self.condition.get("severity_min")
        if severity_min:
            sev_min = FindingSeverity(severity_min.lower())
            rank_map = {
                FindingSeverity.CRITICAL: 0,
                FindingSeverity.HIGH: 1,
                FindingSeverity.MEDIUM: 2,
                FindingSeverity.LOW: 3,
                FindingSeverity.INFO: 4,
            }
            max_rank = rank_map[sev_min]
            matched = [f for f in matched if f.severity_rank <= max_rank]

        category = self.condition.get("category")
        if category:
            cat = FindingCategory(category.lower())
            matched = [f for f in matched if f.category == cat]

        owasp_id = self.condition.get("owasp_id")
        if owasp_id:
            matched = [f for f in matched if owasp_id in f.owasp_ids]

        scanner = self.condition.get("scanner")
        if scanner:
            matched = [f for f in matched if f.scanner == scanner]

        title_regex = self.condition.get("title_regex")
        if title_regex:
            pattern = re.compile(title_regex, re.IGNORECASE)
            matched = [f for f in matched if pattern.search(f.title)]

        return matched

    def _check_posture_grade(self, posture: dict[str, Any] | None) -> PolicyViolation | None:
        if not posture:
            return None
        min_grade = self.condition.get("min_grade", "F")
        grade_order = {"A": 0, "B": 1, "C": 2, "D": 3, "F": 4}
        actual_grade = posture.get("grade", "F")
        if grade_order.get(actual_grade, 4) > grade_order.get(min_grade, 4):
            return PolicyViolation(
                rule_id=self.id,
                rule_name=self.name,
                action=self.action,
                message=(
                    f"Posture grade {actual_grade} is below minimum required grade {min_grade}"
                ),
            )
        return None

    def _check_posture_score(self, posture: dict[str, Any] | None) -> PolicyViolation | None:
        if not posture:
            return None
        min_score = self.condition.get("min_score", 0)
        actual_score = posture.get("overall_score", 0)
        if actual_score < min_score:
            return PolicyViolation(
                rule_id=self.id,
                rule_name=self.name,
                action=self.action,
                message=(f"Posture score {actual_score:.1f} is below minimum required {min_score}"),
            )
        return None


class PolicyEvaluator:
    """Evaluates scan results against a YAML security policy."""

    def __init__(self, policy_dict: dict[str, Any]):
        self.name: str = policy_dict.get("name", "unnamed-policy")
        self.version: str = str(policy_dict.get("version", "1.0"))
        self.description: str = policy_dict.get("description", "")
        self.rules: list[PolicyRule] = [PolicyRule(r) for r in policy_dict.get("rules", [])]
        self._exemptions: list[dict[str, Any]] = policy_dict.get("exemptions", [])

    @staticmethod
    def load(path: Path) -> PolicyEvaluator:
        """Load a policy from a YAML file."""
        with open(path) as f:
            policy_dict = yaml.safe_load(f)
        if not isinstance(policy_dict, dict):
            raise ValueError(f"Policy file {path} must contain a YAML mapping")
        return PolicyEvaluator(policy_dict)

    def evaluate(
        self,
        findings: list[Finding],
        posture: dict[str, Any] | None = None,
    ) -> list[PolicyViolation]:
        """Evaluate all rules and return violations."""
        filtered = self._apply_exemptions(findings)
        violations = []
        for rule in self.rules:
            violation = rule.evaluate(filtered, posture)
            if violation:
                violations.append(violation)
        return violations

    def should_fail(self, violations: list[PolicyViolation]) -> bool:
        """Return True if any violation has action=fail."""
        return any(v.action == "fail" for v in violations)

    def _apply_exemptions(self, findings: list[Finding]) -> list[Finding]:
        """Remove findings that have active exemptions."""
        if not self._exemptions:
            return findings

        now = datetime.now(timezone.utc)
        active_exemptions: set[str] = set()
        for ex in self._exemptions:
            expires = ex.get("expires")
            if expires:
                try:
                    exp_dt = datetime.fromisoformat(expires)
                    if exp_dt.tzinfo is None:
                        exp_dt = exp_dt.replace(tzinfo=timezone.utc)
                    if exp_dt < now:
                        continue
                except (ValueError, TypeError):
                    continue
            finding_id = ex.get("finding_id", "")
            if finding_id:
                active_exemptions.add(finding_id)

        if not active_exemptions:
            return findings
        return [f for f in findings if f.fingerprint not in active_exemptions]
