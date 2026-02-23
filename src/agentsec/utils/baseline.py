"""Baseline file support for tracking known vs new findings.

A baseline captures finding fingerprints at a point in time so that CI
pipelines can distinguish new findings (fail) from known technical debt
(report but don't fail).
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from agentsec.models.findings import Finding

DEFAULT_BASELINE_PATH = ".agentsec-baseline.json"
_BASELINE_VERSION = 1


def create_baseline(findings: list[Finding], path: Path | None = None) -> Path:
    """Write a baseline file from a list of findings.

    Each finding is keyed by its fingerprint so future scans can match.
    """
    if path is None:
        path = Path(DEFAULT_BASELINE_PATH)

    entries: dict[str, dict[str, str]] = {}
    for f in findings:
        entries[f.fingerprint] = {
            "status": "accepted",
            "title": f.title,
            "severity": f.severity.value,
            "scanner": f.scanner,
        }

    baseline: dict[str, Any] = {
        "version": _BASELINE_VERSION,
        "created": datetime.now(timezone.utc).isoformat(),
        "findings": entries,
    }

    path.write_text(json.dumps(baseline, indent=2) + "\n")
    return path


def load_baseline(path: Path) -> dict[str, dict[str, str]]:
    """Load a baseline file and return the fingerprint -> entry map.

    Returns an empty dict if the file doesn't exist or is malformed.
    """
    if not path.exists():
        return {}

    try:
        data = json.loads(path.read_text())
        if not isinstance(data, dict):
            return {}
        return data.get("findings", {})
    except (json.JSONDecodeError, OSError):
        return {}


def apply_baseline(
    findings: list[Finding],
    baseline: dict[str, dict[str, str]],
) -> tuple[list[Finding], list[Finding]]:
    """Split findings into new and baselined.

    Returns (new_findings, baselined_findings). Baselined findings
    have ``metadata["baseline"] = True`` set.
    """
    new: list[Finding] = []
    baselined: list[Finding] = []

    for f in findings:
        if f.fingerprint in baseline:
            f.metadata["baseline"] = True
            f.metadata["baseline_status"] = baseline[f.fingerprint].get("status", "accepted")
            baselined.append(f)
        else:
            f.metadata["baseline"] = False
            new.append(f)

    return new, baselined
