"""Configuration model for agentsec scans."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field


class ScanTarget(BaseModel):
    """Describes a target installation to scan."""

    path: Path = Field(description="Root directory of the agent installation")
    agent_type: str = Field(
        default="auto",
        description="Agent type: 'openclaw', 'claude-code', 'auto' (detect automatically)",
    )


class ScannerConfig(BaseModel):
    """Per-scanner configuration knobs."""

    enabled: bool = True
    severity_threshold: str = Field(
        default="info",
        description="Minimum severity to report: critical, high, medium, low, info",
    )
    extra: dict[str, Any] = Field(default_factory=dict)


class AgentsecConfig(BaseModel):
    """Top-level configuration for an agentsec scan run."""

    targets: list[ScanTarget] = Field(default_factory=list)
    scanners: dict[str, ScannerConfig] = Field(
        default_factory=lambda: {
            "installation": ScannerConfig(),
            "skill": ScannerConfig(),
            "mcp": ScannerConfig(),
            "credential": ScannerConfig(),
        }
    )
    output_format: str = Field(
        default="terminal",
        description="Output format: terminal, json, html",
    )
    output_path: Path | None = Field(
        default=None,
        description="File path for report output (None = stdout)",
    )
    fail_on_severity: str | None = Field(
        default="high",
        description="Exit non-zero if findings at this severity or above exist (CI mode)",
    )
    max_file_size_mb: int = Field(
        default=50,
        description="Skip files larger than this (avoids OOM on huge binaries)",
    )
