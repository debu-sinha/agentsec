"""Core finding models for agentsec scan results.

Every scanner module produces Finding objects that flow through the reporting
pipeline and OWASP scoring engine.
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field, computed_field


class FindingSeverity(str, Enum):
    """CVSS-aligned severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingConfidence(str, Enum):
    """Confidence that a finding is a true positive (not a false alarm)."""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class FindingCategory(str, Enum):
    """Top-level finding categories aligned with scanner modules."""

    # Installation scanner
    EXPOSED_CREDENTIALS = "exposed_credentials"
    INSECURE_PERMISSIONS = "insecure_permissions"
    NETWORK_EXPOSURE = "network_exposure"
    MISSING_AUTH = "missing_auth"
    OUTDATED_VERSION = "outdated_version"
    INSECURE_DEFAULT = "insecure_default"

    # Skill analyzer
    MALICIOUS_SKILL = "malicious_skill"
    DANGEROUS_PATTERN = "dangerous_pattern"
    DEPENDENCY_RISK = "dependency_risk"
    PROMPT_INJECTION_VECTOR = "prompt_injection_vector"
    DATA_EXFILTRATION_RISK = "data_exfiltration_risk"
    SKILL_INTEGRITY = "skill_integrity"

    # MCP scanner
    MCP_TOOL_POISONING = "mcp_tool_poisoning"
    MCP_NO_AUTH = "mcp_no_auth"
    MCP_SCHEMA_VIOLATION = "mcp_schema_violation"
    MCP_CROSS_ORIGIN = "mcp_cross_origin"
    MCP_EXCESSIVE_PERMISSIONS = "mcp_excessive_permissions"
    MCP_TOOL_DRIFT = "mcp_tool_drift"

    # Credential vault
    PLAINTEXT_SECRET = "plaintext_secret"
    WEAK_ENCRYPTION = "weak_encryption"
    EXPOSED_TOKEN = "exposed_token"
    HARDCODED_CREDENTIAL = "hardcoded_credential"

    # Configuration
    CONFIG_DRIFT = "config_drift"
    INSECURE_CONFIG = "insecure_config"

    # General
    CVE_MATCH = "cve_match"
    SUPPLY_CHAIN = "supply_chain"


class Remediation(BaseModel):
    """Actionable remediation guidance for a finding."""

    summary: str = Field(description="One-line fix description")
    steps: list[str] = Field(default_factory=list, description="Step-by-step remediation")
    automated: bool = Field(
        default=False,
        description="Whether agentsec can auto-remediate this finding",
    )
    command: str | None = Field(
        default=None,
        description="CLI command to auto-remediate (if automated=True)",
    )
    references: list[str] = Field(
        default_factory=list,
        description="URLs to relevant documentation or advisories",
    )


class Finding(BaseModel):
    """A single security finding from any scanner module.

    Findings are the universal currency of agentsec. Every scanner produces
    them, the OWASP scorer categorizes them, and the reporter renders them.
    """

    id: str = Field(default_factory=lambda: uuid.uuid4().hex[:12])
    scanner: str = Field(description="Scanner module that produced this finding")
    category: FindingCategory
    severity: FindingSeverity
    confidence: FindingConfidence = Field(
        default=FindingConfidence.HIGH,
        description="Confidence this is a true positive (high/medium/low)",
    )
    title: str = Field(description="Short description of the finding", max_length=200)
    description: str = Field(description="Detailed explanation of the risk")
    evidence: str | None = Field(
        default=None,
        description="Concrete evidence (sanitized — no raw secrets)",
    )
    file_path: Path | None = Field(
        default=None,
        description="File where the issue was found",
    )
    line_number: int | None = Field(default=None, description="Line number if applicable")
    remediation: Remediation | None = Field(default=None)
    owasp_ids: list[str] = Field(
        default_factory=list,
        description="OWASP Agentic Top 10 category IDs (e.g., ['ASI01', 'ASI03'])",
    )
    cve_ids: list[str] = Field(
        default_factory=list,
        description="Related CVE identifiers",
    )
    metadata: dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @computed_field  # type: ignore[prop-decorator]
    @property
    def fingerprint(self) -> str:
        """Stable hash for deduplication across scans.

        Based on scanner + category + file + title + line so distinct secrets
        in the same file are not collapsed.
        """
        content = (
            f"{self.scanner}:{self.category.value}:{self.file_path}:{self.title}:{self.line_number}"
        )
        return hashlib.sha256(content.encode()).hexdigest()[:16]

    @property
    def severity_rank(self) -> int:
        """Numeric rank for sorting (lower = more severe)."""
        ranks = {
            FindingSeverity.CRITICAL: 0,
            FindingSeverity.HIGH: 1,
            FindingSeverity.MEDIUM: 2,
            FindingSeverity.LOW: 3,
            FindingSeverity.INFO: 4,
        }
        return ranks[self.severity]
