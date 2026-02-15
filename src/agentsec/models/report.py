"""Report models for agentsec scan output."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field

from agentsec.models.findings import Finding, FindingSeverity
from agentsec.models.owasp import OwaspMapping


def _get_version() -> str:
    """Get package version without circular import."""
    try:
        from importlib.metadata import version

        return version("agentsec")
    except Exception:
        return "0.3.1"


class ScanSummary(BaseModel):
    """Aggregate statistics for a scan run."""

    total_findings: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0
    scanners_run: list[str] = Field(default_factory=list)
    files_scanned: int = 0
    duration_seconds: float = 0.0
    owasp_categories_hit: list[str] = Field(default_factory=list)

    @property
    def pass_fail(self) -> str:
        """Simple pass/fail based on presence of critical or high findings."""
        if self.critical > 0 or self.high > 0:
            return "FAIL"
        return "PASS"

    @classmethod
    def from_findings(
        cls,
        findings: list[Finding],
        scanners_run: list[str],
        files_scanned: int,
        duration_seconds: float,
    ) -> ScanSummary:
        severity_counts = dict.fromkeys(FindingSeverity, 0)
        owasp_ids: set[str] = set()
        for f in findings:
            severity_counts[f.severity] += 1
            owasp_ids.update(f.owasp_ids)

        return cls(
            total_findings=len(findings),
            critical=severity_counts[FindingSeverity.CRITICAL],
            high=severity_counts[FindingSeverity.HIGH],
            medium=severity_counts[FindingSeverity.MEDIUM],
            low=severity_counts[FindingSeverity.LOW],
            info=severity_counts[FindingSeverity.INFO],
            scanners_run=scanners_run,
            files_scanned=files_scanned,
            duration_seconds=duration_seconds,
            owasp_categories_hit=sorted(owasp_ids),
        )


class ScanReport(BaseModel):
    """Complete scan report with findings, OWASP mappings, and summary."""

    version: str = Field(default_factory=_get_version)
    scan_id: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    target_path: str
    agent_type: str
    findings: list[Finding] = Field(default_factory=list)
    owasp_mappings: list[OwaspMapping] = Field(default_factory=list)
    summary: ScanSummary = Field(default_factory=ScanSummary)
    metadata: dict[str, Any] = Field(default_factory=dict)

    def findings_by_severity(self) -> dict[FindingSeverity, list[Finding]]:
        """Group findings by severity for reporting."""
        grouped: dict[FindingSeverity, list[Finding]] = {s: [] for s in FindingSeverity}
        for f in self.findings:
            grouped[f.severity].append(f)
        return grouped

    def findings_by_scanner(self) -> dict[str, list[Finding]]:
        """Group findings by scanner module for reporting."""
        grouped: dict[str, list[Finding]] = {}
        for f in self.findings:
            grouped.setdefault(f.scanner, []).append(f)
        return grouped
