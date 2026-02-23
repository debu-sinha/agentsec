"""Base scanner interface.

All scanner modules (installation, skill, MCP, credential) implement
this interface so the orchestrator can run them uniformly.
"""

from __future__ import annotations

import fnmatch
import json
import logging
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from agentsec.models.config import ScannerConfig
from agentsec.models.findings import (
    Finding,
    FindingCategory,
    FindingSeverity,
    Remediation,
)

logger = logging.getLogger(__name__)

_IGNOREFILE_NAME = ".agentsecignore"


def _load_ignore_patterns(target: Path) -> list[str]:
    """Load glob patterns from .agentsecignore file.

    Format (same conventions as .gitignore):
    - One pattern per line
    - Lines starting with # are comments
    - Empty lines are skipped
    - Patterns are matched with fnmatch against relative paths
    """
    ignore_file = target / _IGNOREFILE_NAME
    if not ignore_file.exists():
        return []
    try:
        lines = ignore_file.read_text().splitlines()
    except OSError:
        return []
    patterns: list[str] = []
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        patterns.append(stripped)
    return patterns


@dataclass
class ScanContext:
    """Shared context passed to every scanner during a scan run.

    Contains the target path, detected agent type, and any state
    that scanners need to share (e.g., discovered config file locations).
    """

    target_path: Path
    agent_type: str = "auto"
    config_files: dict[str, Path] = field(default_factory=dict)
    discovered_secrets_locations: list[Path] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    files_scanned: int = 0
    _ignore_patterns: list[str] | None = field(default=None, repr=False)

    def register_config_file(self, name: str, path: Path) -> None:
        """Register a discovered config file for other scanners to use."""
        self.config_files[name] = path

    def register_secrets_location(self, path: Path) -> None:
        """Register a path known to contain secrets."""
        if path not in self.discovered_secrets_locations:
            self.discovered_secrets_locations.append(path)

    @property
    def ignore_patterns(self) -> list[str]:
        """Lazily load .agentsecignore patterns from the target directory."""
        if self._ignore_patterns is None:
            self._ignore_patterns = _load_ignore_patterns(self.target_path)
        return self._ignore_patterns

    def is_ignored(self, path: Path) -> bool:
        """Check if a path should be ignored based on .agentsecignore."""
        if not self.ignore_patterns:
            return False
        try:
            rel = path.relative_to(self.target_path)
        except ValueError:
            return False
        rel_posix = rel.as_posix()
        return any(fnmatch.fnmatch(rel_posix, p) for p in self.ignore_patterns)


class BaseScanner(ABC):
    """Abstract base for all scanner modules.

    Subclasses implement `scan()` to produce findings and declare
    their `name` for registry and reporting purposes.
    """

    def __init__(self, config: ScannerConfig | None = None):
        self.config = config or ScannerConfig()

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique scanner identifier used in reports and config."""

    @property
    @abstractmethod
    def description(self) -> str:
        """Human-readable description of what this scanner checks."""

    @abstractmethod
    def scan(self, context: ScanContext) -> list[Finding]:
        """Execute the scan and return findings.

        Args:
            context: Shared scan context with target info and cross-scanner state.

        Returns:
            List of Finding objects discovered by this scanner.
        """

    def run(self, context: ScanContext) -> list[Finding]:
        """Execute scan with timing and error handling."""
        if not self.config.enabled:
            logger.info("Scanner '%s' is disabled, skipping", self.name)
            return []

        logger.info("Running scanner: %s", self.name)
        start = time.monotonic()

        try:
            findings = self.scan(context)
        except (OSError, PermissionError, ValueError, json.JSONDecodeError) as e:
            logger.warning("Scanner '%s' skipped: %s: %s", self.name, type(e).__name__, e)
            return [
                Finding(
                    scanner=self.name,
                    category=FindingCategory.INSECURE_CONFIG,
                    severity=FindingSeverity.LOW,
                    title=f"Scanner '{self.name}' skipped due to error",
                    description=(
                        f"The {self.name} scanner could not complete: {type(e).__name__}: {e}"
                    ),
                    remediation=Remediation(
                        summary="Investigate the error and re-run the scan",
                    ),
                )
            ]
        except Exception as e:
            logger.error(
                "Scanner '%s' failed unexpectedly: %s: %s",
                self.name,
                type(e).__name__,
                e,
            )
            logger.debug("Scanner '%s' traceback:", self.name, exc_info=True)
            return [
                Finding(
                    scanner=self.name,
                    category=FindingCategory.INSECURE_CONFIG,
                    severity=FindingSeverity.MEDIUM,
                    title=f"Scanner '{self.name}' failed unexpectedly",
                    description=(
                        f"The {self.name} scanner encountered an unexpected error: "
                        f"{type(e).__name__}: {e}. Results may be incomplete."
                    ),
                    remediation=Remediation(
                        summary="Check scanner logs and report the issue",
                    ),
                )
            ]

        elapsed = time.monotonic() - start
        logger.info(
            "Scanner '%s' completed in %.2fs — %d findings",
            self.name,
            elapsed,
            len(findings),
        )
        return findings
