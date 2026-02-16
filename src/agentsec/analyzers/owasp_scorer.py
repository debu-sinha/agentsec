"""OWASP Agentic Top 10 scorer — maps findings to OWASP categories and computes risk.

Takes raw findings from all scanners and produces:
- Category-level risk scores (0-10)
- Finding-to-category mappings with rationale
- Aggregate posture score
- Compliance-ready output for security reports
"""

from __future__ import annotations

import logging
from typing import Any

from agentsec.models.findings import Finding, FindingCategory, FindingSeverity
from agentsec.models.owasp import OwaspAgenticCategory, OwaspMapping

logger = logging.getLogger(__name__)

# Maps FindingCategory -> list of applicable OWASP Agentic categories
_CATEGORY_TO_OWASP: dict[FindingCategory, list[OwaspAgenticCategory]] = {
    # Installation findings
    FindingCategory.EXPOSED_CREDENTIALS: [
        OwaspAgenticCategory.ASI05_PRIVILEGE_COMPROMISE,
    ],
    FindingCategory.INSECURE_PERMISSIONS: [
        OwaspAgenticCategory.ASI05_PRIVILEGE_COMPROMISE,
    ],
    FindingCategory.NETWORK_EXPOSURE: [
        OwaspAgenticCategory.ASI05_PRIVILEGE_COMPROMISE,
        OwaspAgenticCategory.ASI02_EXCESSIVE_AGENCY,
    ],
    FindingCategory.MISSING_AUTH: [
        OwaspAgenticCategory.ASI05_PRIVILEGE_COMPROMISE,
        OwaspAgenticCategory.ASI02_EXCESSIVE_AGENCY,
    ],
    FindingCategory.OUTDATED_VERSION: [
        OwaspAgenticCategory.ASI03_SUPPLY_CHAIN_VULNERABILITIES,
    ],
    FindingCategory.INSECURE_DEFAULT: [
        OwaspAgenticCategory.ASI02_EXCESSIVE_AGENCY,
        OwaspAgenticCategory.ASI10_MISALIGNED_BEHAVIORS,
    ],
    # Skill findings
    FindingCategory.MALICIOUS_SKILL: [
        OwaspAgenticCategory.ASI03_SUPPLY_CHAIN_VULNERABILITIES,
    ],
    FindingCategory.DANGEROUS_PATTERN: [
        OwaspAgenticCategory.ASI02_EXCESSIVE_AGENCY,
        OwaspAgenticCategory.ASI03_SUPPLY_CHAIN_VULNERABILITIES,
    ],
    FindingCategory.DEPENDENCY_RISK: [
        OwaspAgenticCategory.ASI03_SUPPLY_CHAIN_VULNERABILITIES,
    ],
    FindingCategory.PROMPT_INJECTION_VECTOR: [
        OwaspAgenticCategory.ASI01_AGENT_GOAL_HIJACK,
        OwaspAgenticCategory.ASI03_SUPPLY_CHAIN_VULNERABILITIES,
    ],
    FindingCategory.DATA_EXFILTRATION_RISK: [
        OwaspAgenticCategory.ASI05_PRIVILEGE_COMPROMISE,
        OwaspAgenticCategory.ASI03_SUPPLY_CHAIN_VULNERABILITIES,
    ],
    FindingCategory.SKILL_INTEGRITY: [
        OwaspAgenticCategory.ASI03_SUPPLY_CHAIN_VULNERABILITIES,
        OwaspAgenticCategory.ASI04_KNOWLEDGE_POISONING,
    ],
    # MCP findings
    FindingCategory.MCP_TOOL_POISONING: [
        OwaspAgenticCategory.ASI01_AGENT_GOAL_HIJACK,
        OwaspAgenticCategory.ASI03_SUPPLY_CHAIN_VULNERABILITIES,
    ],
    FindingCategory.MCP_NO_AUTH: [
        OwaspAgenticCategory.ASI05_PRIVILEGE_COMPROMISE,
    ],
    FindingCategory.MCP_SCHEMA_VIOLATION: [
        OwaspAgenticCategory.ASI02_EXCESSIVE_AGENCY,
    ],
    FindingCategory.MCP_CROSS_ORIGIN: [
        OwaspAgenticCategory.ASI03_SUPPLY_CHAIN_VULNERABILITIES,
        OwaspAgenticCategory.ASI05_PRIVILEGE_COMPROMISE,
    ],
    FindingCategory.MCP_EXCESSIVE_PERMISSIONS: [
        OwaspAgenticCategory.ASI02_EXCESSIVE_AGENCY,
    ],
    # Credential findings
    FindingCategory.PLAINTEXT_SECRET: [
        OwaspAgenticCategory.ASI05_PRIVILEGE_COMPROMISE,
    ],
    FindingCategory.WEAK_ENCRYPTION: [
        OwaspAgenticCategory.ASI05_PRIVILEGE_COMPROMISE,
    ],
    FindingCategory.EXPOSED_TOKEN: [
        OwaspAgenticCategory.ASI05_PRIVILEGE_COMPROMISE,
    ],
    FindingCategory.HARDCODED_CREDENTIAL: [
        OwaspAgenticCategory.ASI05_PRIVILEGE_COMPROMISE,
        OwaspAgenticCategory.ASI03_SUPPLY_CHAIN_VULNERABILITIES,
    ],
    # Configuration findings
    FindingCategory.CONFIG_DRIFT: [
        OwaspAgenticCategory.ASI04_KNOWLEDGE_POISONING,
        OwaspAgenticCategory.ASI06_MEMORY_MANIPULATION,
    ],
    FindingCategory.INSECURE_CONFIG: [
        OwaspAgenticCategory.ASI02_EXCESSIVE_AGENCY,
        OwaspAgenticCategory.ASI10_MISALIGNED_BEHAVIORS,
    ],
    # General
    FindingCategory.CVE_MATCH: [
        OwaspAgenticCategory.ASI03_SUPPLY_CHAIN_VULNERABILITIES,
    ],
    FindingCategory.SUPPLY_CHAIN: [
        OwaspAgenticCategory.ASI03_SUPPLY_CHAIN_VULNERABILITIES,
    ],
}

# Severity-to-score multiplier
_SEVERITY_WEIGHT: dict[FindingSeverity, float] = {
    FindingSeverity.CRITICAL: 10.0,
    FindingSeverity.HIGH: 7.5,
    FindingSeverity.MEDIUM: 5.0,
    FindingSeverity.LOW: 2.5,
    FindingSeverity.INFO: 1.0,
}


class OwaspScorer:
    """Maps findings to OWASP Agentic Top 10 categories and computes risk scores."""

    def score(self, findings: list[Finding]) -> list[OwaspMapping]:
        """Score all findings against OWASP Agentic Top 10.

        Returns a list of OwaspMapping objects, one per finding that
        maps to at least one OWASP category.
        """
        mappings: list[OwaspMapping] = []

        for finding in findings:
            owasp_cats = self._map_finding(finding)
            if not owasp_cats:
                continue

            risk_score = self._compute_risk_score(finding, owasp_cats)
            rationale = self._generate_rationale(finding, owasp_cats)

            # Also annotate the finding with OWASP IDs
            finding.owasp_ids = [cat.value for cat in owasp_cats]

            mappings.append(
                OwaspMapping(
                    finding_id=finding.id,
                    categories=owasp_cats,
                    risk_score=risk_score,
                    rationale=rationale,
                )
            )

        return mappings

    def compute_posture_score(self, findings: list[Finding]) -> dict[str, Any]:
        """Compute an aggregate security posture score.

        Returns a dict with:
        - overall_score: 0-100 (higher = more secure)
        - category_scores: per-OWASP-category breakdown
        - grade: A-F letter grade

        Scoring uses fixed penalty thresholds so that adding low-severity
        findings never inflates the score. Critical findings cap the
        maximum achievable grade.
        """
        if not findings:
            return {
                "overall_score": 100.0,
                "category_scores": {},
                "grade": "A",
            }

        # Apply context-sensitive severity escalation before scoring.
        # Guard against double-escalation if called more than once on same findings.
        unescalated = [f for f in findings if not getattr(f, "_escalated", False)]
        self._escalate_severities(unescalated)

        # Count by severity
        severity_counts = dict.fromkeys(FindingSeverity, 0)
        for f in findings:
            severity_counts[f.severity] += 1

        critical = severity_counts[FindingSeverity.CRITICAL]
        high = severity_counts[FindingSeverity.HIGH]
        medium = severity_counts[FindingSeverity.MEDIUM]
        low = severity_counts[FindingSeverity.LOW]

        # Compute per-category penalty
        category_penalties: dict[OwaspAgenticCategory, float] = dict.fromkeys(
            OwaspAgenticCategory, 0.0
        )

        for finding in findings:
            cats = self._map_finding(finding)
            weight = _SEVERITY_WEIGHT.get(finding.severity, 1.0)
            for cat in cats:
                category_penalties[cat] += weight

        # Normalize penalties to 0-10 scale per category
        max_penalty_per_cat = max(category_penalties.values()) if category_penalties else 1.0
        category_scores: dict[str, float] = {}
        for cat, penalty in category_penalties.items():
            # Score is 10 - normalized penalty (clamped to 0-10)
            normalized = min(penalty / max(max_penalty_per_cat, 1.0) * 10.0, 10.0)
            score = max(10.0 - normalized, 0.0)
            category_scores[f"{cat.value}: {cat.title}"] = round(score, 1)

        # Doom combo: open DM + full tools + no sandbox = catastrophic
        doom_combo = self._check_doom_combo(findings)

        # Fixed-threshold scoring: critical findings cap the max grade.
        # Each severity level subtracts fixed points from 100.
        overall = 100.0
        overall -= critical * 15.0
        overall -= high * 7.0
        overall -= medium * 3.0
        overall -= low * 1.0

        # Clamp to 5-100. Floor of 5 distinguishes "has some controls"
        # from a hypothetical system with zero security whatsoever.
        overall = max(min(overall, 100.0), 5.0)

        # Critical findings cap the maximum achievable score
        if critical >= 3 or doom_combo:
            overall = min(overall, 20.0)
        elif critical >= 1:
            overall = min(overall, 55.0)
        elif high >= 5:
            overall = min(overall, 65.0)

        grade = self._score_to_grade(overall)

        return {
            "overall_score": round(overall, 1),
            "category_scores": category_scores,
            "grade": grade,
        }

    def _map_finding(self, finding: Finding) -> list[OwaspAgenticCategory]:
        """Map a single finding to its OWASP categories."""
        # Use explicit OWASP IDs if already set on the finding
        if finding.owasp_ids:
            cats = []
            for owasp_id in finding.owasp_ids:
                for cat in OwaspAgenticCategory:
                    if cat.value == owasp_id:
                        cats.append(cat)
                        break
            if cats:
                return cats

        # Fall back to category-based mapping
        return list(_CATEGORY_TO_OWASP.get(finding.category, []))

    def _compute_risk_score(
        self,
        finding: Finding,
        categories: list[OwaspAgenticCategory],
    ) -> float:
        """Compute a composite risk score for a finding (0-10)."""
        base = _SEVERITY_WEIGHT.get(finding.severity, 1.0)
        # Boost if finding maps to multiple categories (wider impact)
        breadth_multiplier = min(1.0 + (len(categories) - 1) * 0.1, 1.5)
        return min(round(base * breadth_multiplier, 1), 10.0)

    def _generate_rationale(
        self,
        finding: Finding,
        categories: list[OwaspAgenticCategory],
    ) -> str:
        """Generate human-readable rationale for the OWASP mapping."""
        cat_names = ", ".join(f"{c.value} ({c.title})" for c in categories)
        return (
            f"Finding '{finding.title}' ({finding.severity.value}) maps to "
            f"{cat_names}. Category: {finding.category.value}."
        )

    @staticmethod
    def _check_doom_combo(findings: list[Finding]) -> bool:
        """Detect catastrophic finding combinations.

        When open DM policy + full tool access + no sandbox are all present,
        any message can execute arbitrary code -- equivalent to unauthenticated RCE.
        """
        titles_lower = {f.title.lower() for f in findings}
        categories = {f.category for f in findings}

        has_open_dm = any("dm" in t and ("open" in t or "unrestricted" in t) for t in titles_lower)
        has_full_tools = any(
            "tool" in t and ("full" in t or "unrestricted" in t) for t in titles_lower
        )
        has_no_sandbox = any(
            "sandbox" in t and ("disabled" in t or "missing" in t or "off" in t)
            for t in titles_lower
        )

        # Also check by finding category for broader matching
        has_excessive_agency = (
            FindingCategory.INSECURE_DEFAULT in categories
            and FindingCategory.MISSING_AUTH in categories
        )

        return (has_open_dm and has_full_tools and has_no_sandbox) or (
            has_open_dm and has_full_tools and has_excessive_agency
        )

    @staticmethod
    def _escalate_severities(findings: list[Finding]) -> None:
        """Apply context-sensitive severity escalation.

        Some findings are HIGH in isolation but become CRITICAL when
        combined with other findings. For example, open group policy is
        HIGH alone but CRITICAL when auth is also disabled -- together
        they allow unauthenticated prompt injection into any group.
        """
        categories = {f.category for f in findings}
        titles_lower = {f.title.lower() for f in findings}

        auth_disabled = FindingCategory.MISSING_AUTH in categories
        open_inbound = any(
            ("dm" in t or "group" in t) and ("open" in t or "unrestricted" in t)
            for t in titles_lower
        )

        if not (auth_disabled or open_inbound):
            return

        for finding in findings:
            if finding.severity != FindingSeverity.HIGH:
                continue

            title_lower = finding.title.lower()

            # Open group/DM policy + disabled auth = unauthenticated access
            if (
                ("group" in title_lower or "dm" in title_lower)
                and ("open" in title_lower or "wildcard" in title_lower)
                and auth_disabled
            ):
                finding.severity = FindingSeverity.CRITICAL
                finding._escalated = True  # type: ignore[attr-defined]

            # Risky tool groups + open inbound = unauthenticated code exec
            if "tool group" in title_lower and "open access" in title_lower and open_inbound:
                finding.severity = FindingSeverity.CRITICAL
                finding._escalated = True  # type: ignore[attr-defined]

    @staticmethod
    def _score_to_grade(score: float) -> str:
        """Convert numeric score to letter grade."""
        if score >= 90:
            return "A"
        if score >= 80:
            return "B"
        if score >= 70:
            return "C"
        if score >= 60:
            return "D"
        return "F"
