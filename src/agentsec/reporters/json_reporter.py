"""JSON reporter — outputs scan results as structured JSON."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from agentsec.models.report import ScanReport


class JsonReporter:
    """Renders scan reports as JSON for programmatic consumption and CI pipelines."""

    def render(
        self,
        report: ScanReport,
        posture: dict[str, Any] | None = None,
        output_path: Path | None = None,
    ) -> str:
        """Render the report as a JSON string.

        If output_path is provided, also writes to that file.
        """
        data = json.loads(report.model_dump_json())

        if posture:
            data["posture"] = posture

        json_str = json.dumps(data, indent=2, default=str)

        if output_path:
            output_path.write_text(json_str)

        return json_str
