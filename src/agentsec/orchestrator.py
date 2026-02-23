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

_SUPPRESS_MARKER = "agentsec:ignore"


def _filter_inline_suppressed(findings: list) -> list:
    """Remove findings where the source line contains ``# agentsec:ignore``.

    Only applies to findings that have both a file_path and line_number.
    Uses a cache to avoid re-reading the same file multiple times.
    """
    file_cache: dict[Path, list[str]] = {}
    kept: list = []

    for finding in findings:
        if finding.file_path and finding.line_number:
            fpath = Path(finding.file_path)
            if fpath not in file_cache:
                try:
                    file_cache[fpath] = fpath.read_text(errors="replace").splitlines()
                except OSError:
                    file_cache[fpath] = []
            lines = file_cache[fpath]
            line_idx = finding.line_number - 1
            if 0 <= line_idx < len(lines) and _SUPPRESS_MARKER in lines[line_idx]:
                logger.debug(
                    "Suppressed finding '%s' at %s:%d (inline marker)",
                    finding.title,
                    fpath,
                    finding.line_number,
                )
                continue
        kept.append(finding)
    return kept


def run_scan(config: AgentsecConfig) -> ScanReport:
    """Execute a full scan against all configured targets.

    Uses the first target in config.targets (or CWD if none specified).
    """
    # Resolve target
    target = config.targets[0] if config.targets else ScanTarget(path=Path.cwd())

    target_path = target.path.expanduser().resolve()

    # Detect agent type
    agent_type = target.agent_type
    if agent_type == "auto":
        agent_type = detect_agent_type(target_path)

    logger.info("Scanning target: %s (agent type: %s)", target_path, agent_type)

    # Build scan context
    context = ScanContext(
        target_path=target_path,
        agent_type=agent_type,
        scan_history=config.scan_history,
        history_depth=config.history_depth,
    )

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

    # Filter out inline-suppressed findings (# agentsec:ignore on the finding line)
    all_findings = _filter_inline_suppressed(all_findings)

    # Score findings against OWASP
    scorer = OwaspScorer()
    owasp_mappings = scorer.score(all_findings)

    # Run posture scoring first so context-sensitive severity escalation
    # happens BEFORE the summary counts severities.
    scorer.compute_posture_score(all_findings)

    # Build summary (now reflects post-escalation severities)
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
