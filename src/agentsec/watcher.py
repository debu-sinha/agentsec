"""Filesystem watcher for continuous security monitoring.

Watches OpenClaw config directories, skill directories, and MCP server
configs for changes. Triggers an automatic scan when files are added,
modified, or deleted.

Usage:
    agentsec watch                    # Watch default paths
    agentsec watch ~/.openclaw        # Watch specific path
    agentsec watch --on-change notify # Desktop notification on findings
"""

from __future__ import annotations

import contextlib
import logging
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from agentsec.analyzers.owasp_scorer import OwaspScorer
from agentsec.models.config import AgentsecConfig, ScanTarget
from agentsec.models.findings import FindingSeverity
from agentsec.orchestrator import run_scan

logger = logging.getLogger(__name__)

# Directories and file patterns to watch
_WATCH_PATTERNS: list[str] = [
    "openclaw.json",
    "clawdbot.json",
    ".env",
    ".env.local",
    "exec-approvals.json",
    "SOUL.md",
    "AGENTS.md",
    "TOOLS.md",
    "USER.md",
]

_WATCH_DIRS: list[str] = [
    "extensions",
    "skills",
    "plugins",
    "mcp-servers",
    "agents",
]


@dataclass
class WatchEvent:
    """A filesystem change that triggered a scan."""

    path: Path
    event_type: str  # created, modified, deleted
    timestamp: float = field(default_factory=time.time)


@dataclass
class WatchResult:
    """Result of a watch-triggered scan."""

    event: WatchEvent
    finding_count: int = 0
    critical_count: int = 0
    high_count: int = 0
    grade: str = "?"
    score: float = 100.0


def _get_watch_paths(target: Path) -> list[Path]:
    """Build the list of paths to monitor for changes."""
    paths: list[Path] = []

    # Direct config files
    for pattern in _WATCH_PATTERNS:
        config_path = target / pattern
        if config_path.exists():
            paths.append(config_path)

    # Config subdirectories
    for subdir in [".openclaw", ".clawdbot", ".moltbot"]:
        sub_path = target / subdir
        if sub_path.is_dir():
            paths.append(sub_path)
            # Watch config files inside
            for pattern in _WATCH_PATTERNS:
                inner = sub_path / pattern
                if inner.exists():
                    paths.append(inner)

    # Skill/plugin directories
    for subdir in [".openclaw", ".clawdbot", ""]:
        base = target / subdir if subdir else target
        for watch_dir in _WATCH_DIRS:
            dir_path = base / watch_dir
            if dir_path.is_dir():
                paths.append(dir_path)

    return paths


def _build_snapshot(paths: list[Path]) -> dict[Path, float]:
    """Build a snapshot of file modification times for change detection."""
    snapshot: dict[Path, float] = {}
    for p in paths:
        if p.is_file():
            with contextlib.suppress(OSError):
                snapshot[p] = p.stat().st_mtime
        elif p.is_dir():
            try:
                for child in p.rglob("*"):
                    if child.is_file():
                        snapshot[child] = child.stat().st_mtime
            except OSError:
                continue  # Skip directories we cannot read
    return snapshot


def _diff_snapshots(
    old: dict[Path, float],
    new: dict[Path, float],
) -> list[WatchEvent]:
    """Compare two snapshots and return change events."""
    events: list[WatchEvent] = []

    # New or modified files
    for path, mtime in new.items():
        if path not in old:
            events.append(WatchEvent(path=path, event_type="created"))
        elif old[path] < mtime:
            events.append(WatchEvent(path=path, event_type="modified"))

    # Deleted files
    for path in old:
        if path not in new:
            events.append(WatchEvent(path=path, event_type="deleted"))

    return events


def watch_and_scan(
    target: Path,
    interval: float = 2.0,
    on_result: Callable[[WatchResult], None] | None = None,
    max_iterations: int | None = None,
) -> None:
    """Watch filesystem for changes and trigger scans.

    Args:
        target: Root directory of the agent installation
        interval: Seconds between filesystem polls
        on_result: Callback for each scan result (for CLI rendering)
        max_iterations: Stop after N iterations (for testing; None = forever)
    """
    watch_paths = _get_watch_paths(target)
    if not watch_paths:
        logger.warning("No watchable paths found at %s", target)
        raise FileNotFoundError(f"No watchable agent files found at {target}")

    logger.info("Watching %d paths at %s (poll every %.1fs)", len(watch_paths), target, interval)

    # Initial snapshot
    snapshot = _build_snapshot(watch_paths)

    # Initial scan to establish baseline
    config = AgentsecConfig(targets=[ScanTarget(path=target)])
    report = run_scan(config)
    scorer = OwaspScorer()
    posture = scorer.compute_posture_score(report.findings)

    if on_result:
        on_result(
            WatchResult(
                event=WatchEvent(path=target, event_type="initial_scan"),
                finding_count=len(report.findings),
                critical_count=sum(
                    1 for f in report.findings if f.severity == FindingSeverity.CRITICAL
                ),
                high_count=sum(1 for f in report.findings if f.severity == FindingSeverity.HIGH),
                grade=posture.get("grade", "?"),
                score=posture.get("overall_score", 0.0),
            )
        )

    iterations = 0
    while max_iterations is None or iterations < max_iterations:
        time.sleep(interval)
        iterations += 1

        # Rebuild watch paths (new dirs may have appeared)
        watch_paths = _get_watch_paths(target)
        new_snapshot = _build_snapshot(watch_paths)

        events = _diff_snapshots(snapshot, new_snapshot)
        if not events:
            continue

        logger.info("Detected %d change(s), triggering scan...", len(events))
        for event in events:
            logger.info("  %s: %s", event.event_type, event.path)

        # Re-scan
        report = run_scan(config)
        posture = scorer.compute_posture_score(report.findings)

        for event in events:
            result = WatchResult(
                event=event,
                finding_count=len(report.findings),
                critical_count=sum(
                    1 for f in report.findings if f.severity == FindingSeverity.CRITICAL
                ),
                high_count=sum(1 for f in report.findings if f.severity == FindingSeverity.HIGH),
                grade=posture.get("grade", "?"),
                score=posture.get("overall_score", 0.0),
            )
            if on_result:
                on_result(result)

        snapshot = new_snapshot
