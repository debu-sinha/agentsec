"""agentsec - Security scanner and hardener for agentic AI installations.

Quickstart::

    from agentsec import run_scan, AgentsecConfig, ScanTarget

    config = AgentsecConfig(
        targets=[ScanTarget(path=Path.home() / ".openclaw")],
    )
    report = run_scan(config)

    for finding in report.findings:
        print(f"{finding.severity.value}: {finding.title}")
"""

__version__ = "0.4.1"

from agentsec.models.config import AgentsecConfig, ScannerConfig, ScanTarget
from agentsec.models.findings import Finding, FindingCategory, FindingSeverity, Remediation
from agentsec.models.report import ScanReport, ScanSummary
from agentsec.orchestrator import run_scan

__all__ = [
    "run_scan",
    "AgentsecConfig",
    "ScanTarget",
    "ScannerConfig",
    "ScanReport",
    "ScanSummary",
    "Finding",
    "FindingCategory",
    "FindingSeverity",
    "Remediation",
    "__version__",
]
