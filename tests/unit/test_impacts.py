"""Tests for impact descriptions and UX improvements."""

import io
import json

import pytest

from agentsec.impacts import OWASP_LABELS, apply_impacts
from agentsec.models.findings import (
    Finding,
    FindingCategory,
    FindingSeverity,
    Remediation,
)
from agentsec.models.report import ScanReport, ScanSummary
from agentsec.reporters.terminal import TerminalReporter


def _make_finding(
    title: str,
    severity: FindingSeverity = FindingSeverity.CRITICAL,
    category: FindingCategory = FindingCategory.INSECURE_CONFIG,
    automated: bool = False,
    owasp_ids: list[str] | None = None,
) -> Finding:
    remediation = None
    if automated:
        remediation = Remediation(
            summary="Auto-fix available",
            steps=["Run agentsec harden"],
            automated=True,
            command="agentsec harden -p workstation --apply",
        )
    return Finding(
        scanner="test",
        category=category,
        severity=severity,
        title=title,
        description="Test finding",
        remediation=remediation,
        owasp_ids=owasp_ids or [],
    )


# ── Impact mapping tests ──────────────────────────────────────────


class TestApplyImpacts:
    def test_gateway_binding(self):
        findings = [_make_finding("Gateway bound to non-loopback address")]
        apply_impacts(findings)
        assert findings[0].impact == "Anyone on the network can reach this agent"

    def test_gateway_auth_missing(self):
        findings = [_make_finding("Gateway auth missing")]
        apply_impacts(findings)
        assert findings[0].impact is not None
        assert "control" in findings[0].impact

    def test_sandbox_disabled(self):
        findings = [_make_finding("Sandbox disabled")]
        apply_impacts(findings)
        assert findings[0].impact is not None
        assert "unrestricted" in findings[0].impact

    def test_exec_approvals_missing(self):
        findings = [_make_finding("Exec approvals missing")]
        apply_impacts(findings)
        assert findings[0].impact is not None
        assert "command" in findings[0].impact

    def test_reverse_shell(self):
        findings = [_make_finding("Reverse shell pattern detected")]
        apply_impacts(findings)
        assert findings[0].impact == "This skill opens a backdoor to your machine"

    def test_data_exfiltration(self):
        findings = [_make_finding("Data exfiltration risk detected")]
        apply_impacts(findings)
        assert findings[0].impact is not None
        assert "data" in findings[0].impact.lower()

    def test_openai_key(self):
        findings = [_make_finding("OpenAI API Key found")]
        apply_impacts(findings)
        assert findings[0].impact == "Any app on this machine can use your OpenAI key"

    def test_aws_key(self):
        findings = [_make_finding("AWS Access Key found")]
        apply_impacts(findings)
        assert "AWS account" in findings[0].impact

    def test_private_key(self):
        findings = [_make_finding("Private key block found")]
        apply_impacts(findings)
        assert findings[0].impact is not None
        assert "impersonate" in findings[0].impact

    def test_cve_detected(self):
        findings = [_make_finding("Known CVE detected: CVE-2024-1234")]
        apply_impacts(findings)
        assert findings[0].impact is not None
        assert "exploit" in findings[0].impact.lower()

    def test_mcp_tool_poisoning(self):
        findings = [_make_finding("Tool description changed (rug pull)")]
        apply_impacts(findings)
        assert findings[0].impact is not None

    def test_unpinned_deps(self):
        findings = [_make_finding("Unpinned dependency: requests")]
        apply_impacts(findings)
        assert "malware" in findings[0].impact

    def test_does_not_overwrite_existing_impact(self):
        finding = _make_finding("OpenAI API Key found")
        finding.impact = "Custom impact"
        apply_impacts([finding])
        assert finding.impact == "Custom impact"

    def test_unmatched_title_gets_no_impact(self):
        findings = [_make_finding("Totally unique finding with no pattern match xyz")]
        apply_impacts(findings)
        assert findings[0].impact is None

    def test_all_impacts_under_65_chars(self):
        """Every impact string must fit within the 65-char limit."""
        from agentsec.impacts import _IMPACT_MAP

        for _pattern, impact in _IMPACT_MAP:
            assert len(impact) <= 65, f"Impact too long ({len(impact)} chars): {impact}"

    def test_multiple_findings_all_get_impacts(self):
        findings = [
            _make_finding("Gateway bound to non-loopback address"),
            _make_finding("Sandbox disabled"),
            _make_finding("OpenAI API Key found"),
        ]
        apply_impacts(findings)
        for f in findings:
            assert f.impact is not None

    def test_case_insensitive_matching(self):
        findings = [_make_finding("GATEWAY AUTH MISSING")]
        apply_impacts(findings)
        assert findings[0].impact is not None


# ── OWASP labels tests ────────────────────────────────────────────


class TestOwaspLabels:
    def test_all_ten_categories_have_labels(self):
        for i in range(1, 11):
            code = f"ASI{i:02d}"
            assert code in OWASP_LABELS, f"Missing label for {code}"

    def test_labels_are_short(self):
        for code, label in OWASP_LABELS.items():
            assert len(label) <= 8, f"Label too long for {code}: {label}"


# ── Terminal reporter UX tests ────────────────────────────────────


def _make_report(findings: list[Finding]) -> ScanReport:
    summary = ScanSummary(
        total_findings=len(findings),
        critical=sum(1 for f in findings if f.severity == FindingSeverity.CRITICAL),
        high=sum(1 for f in findings if f.severity == FindingSeverity.HIGH),
        medium=sum(1 for f in findings if f.severity == FindingSeverity.MEDIUM),
        low=sum(1 for f in findings if f.severity == FindingSeverity.LOW),
        scanners_run=["test"],
        files_scanned=1,
        duration_seconds=0.1,
        pass_fail="FAIL",
    )
    return ScanReport(
        version="0.4.4",
        scan_id="test-scan-001",
        target_path="/tmp/test",
        agent_type="test",
        findings=findings,
        summary=summary,
    )


def _render_to_string(
    findings: list[Finding],
    posture: dict,
    verbose: bool = False,
) -> str:
    """Render report to a plain string for testing."""
    from rich.console import Console

    buf = io.StringIO()
    console = Console(file=buf, force_terminal=False, width=120)
    reporter = TerminalReporter(console=console, verbose=verbose)
    report = _make_report(findings)
    reporter.render(report, posture=posture)
    return buf.getvalue()


class TestTerminalReporterUX:
    def test_impact_subline_shown(self):
        finding = _make_finding(
            "Gateway bound to non-loopback address",
            owasp_ids=["ASI05"],
        )
        finding.impact = "Anyone on the network can reach this agent"

        output = _render_to_string(
            [finding],
            {"grade": "F", "overall_score": 5.0, "category_scores": {}},
        )
        assert "-> Anyone on the network can reach this agent" in output

    def test_owasp_label_shown_instead_of_code(self):
        finding = _make_finding(
            "Gateway auth missing",
            owasp_ids=["ASI05"],
        )
        output = _render_to_string(
            [finding],
            {"grade": "F", "overall_score": 5.0, "category_scores": {}},
        )
        assert "Secrets" in output

    def test_table_capped_at_10_in_default_mode(self):
        findings = [
            _make_finding(
                f"Finding number {i}",
                severity=FindingSeverity.CRITICAL,
                owasp_ids=["ASI05"],
            )
            for i in range(15)
        ]
        output = _render_to_string(
            findings,
            {"grade": "F", "overall_score": 5.0, "category_scores": {}},
        )
        assert "and 5 more" in output

    def test_verbose_shows_all_findings(self):
        findings = [
            _make_finding(
                f"Finding number {i}",
                severity=FindingSeverity.CRITICAL,
                owasp_ids=["ASI05"],
            )
            for i in range(15)
        ]
        output = _render_to_string(
            findings,
            {"grade": "F", "overall_score": 5.0, "category_scores": {}},
            verbose=True,
        )
        assert "and 5 more" not in output
        assert "Finding number 14" in output

    def test_low_info_hidden_in_default_mode(self):
        findings = [
            _make_finding("Critical issue", severity=FindingSeverity.CRITICAL),
            _make_finding("Low issue", severity=FindingSeverity.LOW),
            _make_finding("Info issue", severity=FindingSeverity.INFO),
        ]
        output = _render_to_string(
            findings,
            {"grade": "F", "overall_score": 5.0, "category_scores": {}},
        )
        assert "Critical issue" in output
        assert "and 2 more" in output

    def test_top_risk_callout_for_critical(self):
        finding = _make_finding(
            "Gateway auth missing",
            severity=FindingSeverity.CRITICAL,
        )
        finding.impact = "Any device on the network can control this agent"
        output = _render_to_string(
            [finding],
            {"grade": "F", "overall_score": 5.0, "category_scores": {}},
        )
        assert "Top Risk" in output

    def test_no_top_risk_when_no_critical(self):
        finding = _make_finding(
            "Some medium issue",
            severity=FindingSeverity.MEDIUM,
        )
        output = _render_to_string(
            [finding],
            {"grade": "C", "overall_score": 70.0, "category_scores": {}},
        )
        assert "Top Risk" not in output

    def test_projected_grade_shown(self):
        findings = [
            _make_finding(
                "DM policy set to open",
                severity=FindingSeverity.MEDIUM,
                automated=True,
            ),
            _make_finding(
                "Group policy open",
                severity=FindingSeverity.MEDIUM,
                automated=True,
            ),
        ]
        output = _render_to_string(
            findings,
            {"grade": "D", "overall_score": 60.0, "category_scores": {}},
        )
        assert "After auto-fix" in output


# ── SARIF impact tests ────────────────────────────────────────────


class TestSarifImpact:
    def test_impact_in_sarif_message(self):
        from agentsec.reporters.sarif_reporter import SarifReporter

        finding = _make_finding(
            "OpenAI API Key found",
            category=FindingCategory.EXPOSED_TOKEN,
            owasp_ids=["ASI05"],
        )
        finding.impact = "Any app on this machine can use your OpenAI key"
        report = _make_report([finding])

        reporter = SarifReporter()
        sarif_str = reporter.render(report)
        sarif = json.loads(sarif_str)

        results = sarif["runs"][0]["results"]
        assert len(results) == 1
        assert results[0]["message"]["text"].startswith(
            "Any app on this machine can use your OpenAI key"
        )

    def test_no_impact_uses_description_only(self):
        from agentsec.reporters.sarif_reporter import SarifReporter

        finding = _make_finding(
            "Some unique finding",
            category=FindingCategory.INSECURE_CONFIG,
        )
        assert finding.impact is None
        report = _make_report([finding])

        reporter = SarifReporter()
        sarif_str = reporter.render(report)
        sarif = json.loads(sarif_str)

        results = sarif["runs"][0]["results"]
        assert results[0]["message"]["text"] == "Test finding"


# ── Finding model impact field tests ──────────────────────────────


class TestFindingImpactField:
    def test_impact_field_default_none(self):
        f = _make_finding("test")
        assert f.impact is None

    def test_impact_field_set(self):
        f = _make_finding("test")
        f.impact = "Short impact description"
        assert f.impact == "Short impact description"

    def test_impact_max_length_enforced(self):
        with pytest.raises(ValueError):
            Finding(
                scanner="test",
                category=FindingCategory.INSECURE_CONFIG,
                severity=FindingSeverity.MEDIUM,
                title="test",
                description="test",
                impact="x" * 66,
            )

    def test_impact_at_max_length_ok(self):
        f = Finding(
            scanner="test",
            category=FindingCategory.INSECURE_CONFIG,
            severity=FindingSeverity.MEDIUM,
            title="test",
            description="test",
            impact="x" * 65,
        )
        assert len(f.impact) == 65
