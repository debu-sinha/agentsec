"""Generate deterministic, colored UI captures for README/docs.

Outputs:
  docs/demo/screenshots/ui-insecure.{html,svg}
  docs/demo/screenshots/ui-clean.{html,svg}
"""

from __future__ import annotations

import io
import json
from pathlib import Path

from rich.console import Console

from agentsec.analyzers.owasp_scorer import OwaspScorer
from agentsec.models.config import AgentsecConfig, ScanTarget
from agentsec.orchestrator import run_scan
from agentsec.reporters.terminal import TerminalReporter


def _write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def _create_fixtures(base: Path) -> tuple[Path, Path]:
    insecure = base / "insecure"
    clean = base / "clean"

    _write_json(
        insecure / ".openclaw" / "openclaw.json",
        {
            "version": "2026.1.0",
            "gateway": {"bind": "lan"},
            "dmPolicy": "open",
            "groupPolicy": "open",
            "tools": {"profile": "full"},
            "sandbox": {"mode": "off"},
        },
    )

    _write_json(
        clean / ".openclaw" / "openclaw.json",
        {
            "version": "2026.2.12",
            "gateway": {"bind": "loopback", "auth": {"token": "redacted-token"}},
            "dmPolicy": "paired",
            "groupPolicy": "allowlist",
            "tools": {"profile": "messaging"},
            "sandbox": {"mode": "all"},
            "session": {"dmScope": "per-channel-peer"},
        },
    )

    _write_json(
        clean / ".openclaw" / "exec-approvals.json",
        {"defaults": {"security": "allowlist", "askFallback": "deny"}},
    )

    return insecure, clean


def _render_capture(target: Path, output_prefix: Path) -> None:
    # Use an in-memory sink to avoid Windows codepage rendering issues.
    sink = io.StringIO()
    console = Console(
        record=True,
        width=120,
        force_terminal=True,
        file=sink,
        legacy_windows=False,
    )
    reporter = TerminalReporter(console=console, verbose=False)

    config = AgentsecConfig(targets=[ScanTarget(path=target)])
    report = run_scan(config)
    posture = OwaspScorer().compute_posture_score(report.findings)
    reporter.render(report, posture)

    output_prefix.parent.mkdir(parents=True, exist_ok=True)
    console.save_html(str(output_prefix.with_suffix(".html")), inline_styles=True)
    console.save_svg(str(output_prefix.with_suffix(".svg")), title=f"agentsec-ui-{target.name}")


def main() -> None:
    root = Path("docs") / "demo" / "screenshots"
    fixtures_root = root / "fixtures"

    insecure, clean = _create_fixtures(fixtures_root)
    _render_capture(insecure, root / "ui-insecure")
    _render_capture(clean, root / "ui-clean")

    print("Generated UI captures:")
    print((root / "ui-insecure.html").as_posix())
    print((root / "ui-insecure.svg").as_posix())
    print((root / "ui-clean.html").as_posix())
    print((root / "ui-clean.svg").as_posix())


if __name__ == "__main__":
    main()
