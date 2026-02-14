"""Scan orchestrator — coordinates scanner execution and report generation.

This is the core engine that:
1. Detects the agent type at the target path
2. Runs all enabled scanners
3. Scores findings against OWASP Agentic Top 10
4. Generates the final report
"""

from __future__ import annotations

import logging
import time
import uuid
from pathlib import Path

from agentsec.analyzers.owasp_scorer import OwaspScorer
from agentsec.models.config import AgentsecConfig, ScanTarget
from agentsec.models.report import ScanReport, ScanSummary
from agentsec.scanners.base import ScanContext
from agentsec.scanners.registry import get_all_scanners
from agentsec.utils.detection import detect_agent_type

logger = logging.getLogger(__name__)


def run_scan(config: AgentsecConfig) -> ScanReport:
    """Execute a full scan against all configured targets.

    Uses the first target in config.targets (or CWD if none specified).
    """
    # Resolve target
    if config.targets:
        target = config.targets[0]
    else:
        target = ScanTarget(path=Path.cwd())

    target_path = target.path.expanduser().resolve()

    # Detect agent type
    agent_type = target.agent_type
    if agent_type == "auto":
        agent_type = detect_agent_type(target_path)

    logger.info("Scanning target: %s (agent type: %s)", target_path, agent_type)

    # Build scan context
    context = ScanContext(target_path=target_path, agent_type=agent_type)

    # Run all enabled scanners
    all_findings = []
    scanners_run = []
    start_time = time.monotonic()

    scanner_classes = get_all_scanners()
    for scanner_name, scanner_cls in scanner_classes.items():
        scanner_config = config.scanners.get(scanner_name)
        if scanner_config and not scanner_config.enabled:
            continue

        scanner = scanner_cls(config=scanner_config)
        findings = scanner.run(context)
        all_findings.extend(findings)
        scanners_run.append(scanner_name)

    elapsed = time.monotonic() - start_time

    # Score findings against OWASP
    scorer = OwaspScorer()
    owasp_mappings = scorer.score(all_findings)

    # Build summary
    summary = ScanSummary.from_findings(
        findings=all_findings,
        scanners_run=scanners_run,
        files_scanned=context.files_scanned,
        duration_seconds=elapsed,
    )

    # Build report
    report = ScanReport(
        scan_id=uuid.uuid4().hex[:12],
        target_path=str(target_path),
        agent_type=agent_type,
        findings=all_findings,
        owasp_mappings=owasp_mappings,
        summary=summary,
        metadata={
            "config_files_found": {name: str(path) for name, path in context.config_files.items()},
            "secrets_locations": [str(p) for p in context.discovered_secrets_locations],
        },
    )

    return report
