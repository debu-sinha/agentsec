"""SARIF 2.1.0 reporter — outputs scan results in GitHub Code Scanning format.

SARIF (Static Analysis Results Interchange Format) is the standard format
consumed by GitHub Advanced Security, VS Code, and most CI/CD platforms.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from agentsec.models.findings import FindingConfidence, FindingSeverity
from agentsec.models.report import ScanReport

_CONFIDENCE_TO_SARIF_PRECISION = {
    FindingConfidence.HIGH: "very-high",
    FindingConfidence.MEDIUM: "high",
    FindingConfidence.LOW: "medium",
}

_SEVERITY_TO_SARIF_LEVEL = {
    FindingSeverity.CRITICAL: "error",
    FindingSeverity.HIGH: "error",
    FindingSeverity.MEDIUM: "warning",
    FindingSeverity.LOW: "note",
    FindingSeverity.INFO: "note",
}

_SEVERITY_TO_SARIF_RANK = {
    FindingSeverity.CRITICAL: 9.5,
    FindingSeverity.HIGH: 8.0,
    FindingSeverity.MEDIUM: 5.0,
    FindingSeverity.LOW: 3.0,
    FindingSeverity.INFO: 1.0,
}


class SarifReporter:
    """Renders scan reports as SARIF 2.1.0 for GitHub Code Scanning and IDE integration."""

    def render(
        self,
        report: ScanReport,
        posture: dict[str, Any] | None = None,
        output_path: Path | None = None,
    ) -> str:
        """Render the report as a SARIF JSON string."""
        self._source_root = Path(report.target_path).resolve()
        rules = self._build_rules(report)
        rule_index = {rule["id"]: i for i, rule in enumerate(rules)}

        sarif = {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "agentsec",
                            "version": report.version,
                            "semanticVersion": report.version,
                            "informationUri": "https://github.com/debu-sinha/agentsec",
                            "rules": rules,
                        }
                    },
                    "results": [self._finding_to_result(f, rule_index) for f in report.findings],
                    "invocations": [
                        {
                            "executionSuccessful": True,
                            "toolExecutionNotifications": [],
                        }
                    ],
                }
            ],
        }

        json_str = json.dumps(sarif, indent=2, default=str)

        if output_path:
            output_path.write_text(json_str)

        return json_str

    def _build_rules(self, report: ScanReport) -> list[dict[str, Any]]:
        """Build unique SARIF rule definitions from findings."""
        seen: dict[str, dict[str, Any]] = {}

        for finding in report.findings:
            rule_id = f"agentsec/{finding.scanner}/{finding.category.value}"
            if rule_id in seen:
                continue

            tags = [finding.scanner, finding.category.value]
            tags.extend(finding.owasp_ids)

            rule: dict[str, Any] = {
                "id": rule_id,
                "name": finding.category.value,
                "shortDescription": {"text": finding.title},
                "fullDescription": {"text": finding.description},
                "defaultConfiguration": {
                    "level": _SEVERITY_TO_SARIF_LEVEL[finding.severity],
                },
                "properties": {
                    "tags": tags,
                    "security-severity": str(_SEVERITY_TO_SARIF_RANK[finding.severity]),
                    "precision": _CONFIDENCE_TO_SARIF_PRECISION.get(finding.confidence, "high"),
                },
            }

            if finding.remediation:
                rule["help"] = {
                    "text": finding.remediation.summary,
                    "markdown": self._remediation_markdown(finding),
                }

            seen[rule_id] = rule

        return list(seen.values())

    def _finding_to_result(self, finding: Any, rule_index: dict[str, int]) -> dict[str, Any]:
        """Convert a Finding to a SARIF result."""
        rule_id = f"agentsec/{finding.scanner}/{finding.category.value}"

        message_text = finding.description
        if finding.impact:
            message_text = f"{finding.impact}. {message_text}"

        result: dict[str, Any] = {
            "ruleId": rule_id,
            "ruleIndex": rule_index.get(rule_id, 0),
            "level": _SEVERITY_TO_SARIF_LEVEL[finding.severity],
            "message": {"text": message_text},
            "fingerprints": {
                "agentsec/v1": finding.fingerprint,
            },
        }

        if finding.file_path:
            file_uri = self._to_relative_uri(finding.file_path)
            location: dict[str, Any] = {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": file_uri,
                        "uriBaseId": "%SRCROOT%",
                    }
                }
            }
            if finding.line_number:
                location["physicalLocation"]["region"] = {
                    "startLine": finding.line_number,
                }
            result["locations"] = [location]

        if finding.remediation:
            result["fixes"] = [
                {
                    "description": {"text": finding.remediation.summary},
                }
            ]

        return result

    def _to_relative_uri(self, file_path: str) -> str:
        """Convert a file path to a URI relative to the source root.

        Prevents leaking absolute paths (usernames, directory structure)
        in SARIF output shared with CI/CD or external tools.
        """
        try:
            rel = Path(file_path).resolve().relative_to(self._source_root)
            return str(rel).replace("\\", "/")
        except (ValueError, TypeError):
            # Path not under source root — use filename only as safe fallback
            return Path(file_path).name

    @staticmethod
    def _remediation_markdown(finding: Any) -> str:
        """Build a markdown help string from remediation steps."""
        parts = [f"## {finding.remediation.summary}\n"]
        for i, step in enumerate(finding.remediation.steps, 1):
            parts.append(f"{i}. {step}")
        if finding.remediation.automated and finding.remediation.command:
            parts.append(f"\n**Auto-fix:** `{finding.remediation.command}`")
        return "\n".join(parts)
