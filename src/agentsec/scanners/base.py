"""Base scanner interface.

All scanner modules (installation, skill, MCP, credential) implement
this interface so the orchestrator can run them uniformly.
"""

from __future__ import annotations

import logging
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from agentsec.models.config import ScannerConfig
from agentsec.models.findings import Finding

logger = logging.getLogger(__name__)


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

    def register_config_file(self, name: str, path: Path) -> None:
        """Register a discovered config file for other scanners to use."""
        self.config_files[name] = path

    def register_secrets_location(self, path: Path) -> None:
        """Register a path known to contain secrets."""
        if path not in self.discovered_secrets_locations:
            self.discovered_secrets_locations.append(path)


class BaseScanner(ABC):
    """Abstract base for all scanner modules.

    Subclasses implement `scan()` to produce findings and declare
    their `name` for registry and reporting purposes.
    """

    def __init__(self, config: ScannerConfig | None = None):
        self.config = config or ScannerConfig()
        self._findings: list[Finding] = []

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique scanner identifier used in reports and config."""
        ...

    @property
    @abstractmethod
    def description(self) -> str:
        """Human-readable description of what this scanner checks."""
        ...

    @abstractmethod
    def scan(self, context: ScanContext) -> list[Finding]:
        """Execute the scan and return findings.

        Args:
            context: Shared scan context with target info and cross-scanner state.

        Returns:
            List of Finding objects discovered by this scanner.
        """
        ...

    def run(self, context: ScanContext) -> list[Finding]:
        """Execute scan with timing and error handling."""
        if not self.config.enabled:
            logger.info("Scanner '%s' is disabled, skipping", self.name)
            return []

        logger.info("Running scanner: %s", self.name)
        start = time.monotonic()

        try:
            findings = self.scan(context)
        except Exception as e:
            logger.error("Scanner '%s' failed: %s", self.name, type(e).__name__)
            logger.debug("Scanner '%s' traceback:", self.name, exc_info=True)
            return []

        elapsed = time.monotonic() - start
        logger.info(
            "Scanner '%s' completed in %.2fs — %d findings",
            self.name,
            elapsed,
            len(findings),
        )
        return findings
