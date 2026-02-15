"""Terminal (Rich) reporter — renders scan results to the console.

Designed to produce screenshot-worthy, single-screen security posture reports.
Default output is compact (~20 lines). Use --verbose for full details.
"""

from __future__ import annotations

from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from agentsec import __version__
from agentsec.models.findings import FindingSeverity
from agentsec.models.report import ScanReport

# Brand colors
_BRAND = "deep_sky_blue1"
_ACCENT = "medium_purple1"
_DIM = "grey70"

# Severity colors
_SEVERITY_COLORS = {
    FindingSeverity.CRITICAL: "bold red",
    FindingSeverity.HIGH: "dark_orange",
    FindingSeverity.MEDIUM: "yellow",
    FindingSeverity.LOW: "cyan",
    FindingSeverity.INFO: "dim",
}

_SEVERITY_LABELS = {
    FindingSeverity.CRITICAL: "CRIT",
    FindingSeverity.HIGH: "HIGH",
    FindingSeverity.MEDIUM: "MED ",
    FindingSeverity.LOW: "LOW ",
    FindingSeverity.INFO: "INFO",
}

_GRADE_COLORS = {
    "A": "bold green",
    "B": "bold cyan",
    "C": "bold yellow",
    "D": "bold dark_orange",
    "F": "bold red",
}


class TerminalReporter:
    """Renders scan reports to the terminal using Rich."""

    def __init__(self, console: Console | None = None, verbose: bool = False):
        self.console = console or Console()
        self.verbose = verbose

    def render(self, report: ScanReport, posture: dict[str, Any] | None = None) -> None:
        """Render the full scan report to the terminal."""
        self.console.print()

        # 1. Banner
        self._render_banner(report)

        # 2. Grade hero (top of output — the screenshot moment)
        self._render_grade(report, posture)

        if report.findings:
            # 3. Severity spectrum bar
            self._render_severity_bar(report)

            # 4. Findings table
            self._render_findings_table(report)

            # 5. Verbose: detailed findings + OWASP posture
            if self.verbose:
                self._render_details(report)
                if posture:
                    self._render_posture(posture)

            # 6. Fix First — prioritized action list
            self._render_fix_first(report)
        else:
            self._render_clean_scan()

        # 7. Footer
        self._render_footer(report)

    def _render_banner(self, report: ScanReport) -> None:
        self.console.print(
            f"[{_BRAND}]agentsec[/{_BRAND}] [{_ACCENT}]v{__version__}[/{_ACCENT}]"
            f" [{_DIM}]— AI Agent Security Scanner[/{_DIM}]"
        )
        self.console.print(
            f"[{_DIM}]Target: {report.target_path} · "
            f"Agent: {report.agent_type}[/{_DIM}]"
        )
        self.console.print()

    def _render_grade(self, report: ScanReport, posture: dict[str, Any] | None) -> None:
        """Grade + score bar at the top — the screenshot moment."""
        grade = posture.get("grade", "?") if posture else "?"
        score = posture.get("overall_score", 0) if posture else 0
        grade_color = _GRADE_COLORS.get(grade, "white")
        summary = report.summary

        # Grade line
        grade_text = Text()
        grade_text.append("Security Grade: ", style=_DIM)
        grade_text.append(f" {grade} ", style=grade_color)
        self.console.print(grade_text)

        # Score bar
        bar_width = 50
        filled = int(bar_width * score / 100) if score else 0
        unfilled = bar_width - filled
        bar_color = grade_color.replace("bold ", "")
        bar = Text()
        bar.append("\u2501" * filled, style=bar_color)
        bar.append("\u2501" * unfilled, style="dim")
        bar.append(f" {score}/100", style=grade_color)
        self.console.print(bar)

        # Severity counts on one line
        parts = []
        for sev_name, count, color in [
            ("critical", summary.critical, "bold red"),
            ("high", summary.high, "dark_orange"),
            ("medium", summary.medium, "yellow"),
            ("low", summary.low, "cyan"),
        ]:
            style = color if count > 0 else "dim"
            parts.append(f"[{style}]{count} {sev_name}[/{style}]")

        self.console.print(" \u00b7 ".join(parts))

        # Pass/fail
        result_style = "bold green" if summary.pass_fail == "PASS" else "bold red"
        self.console.print(f"[{result_style}]{summary.pass_fail}[/{result_style}]")
        self.console.print()

    def _render_severity_bar(self, report: ScanReport) -> None:
        """Proportional severity distribution bar."""
        summary = report.summary
        segments = [
            (summary.critical, "red", "CRIT"),
            (summary.high, "dark_orange", "HIGH"),
            (summary.medium, "yellow", "MED"),
            (summary.low, "cyan", "LOW"),
        ]

        total = sum(s[0] for s in segments)
        if total == 0:
            return

        bar_width = 50
        bar = Text()
        for count, color, _label in segments:
            if count == 0:
                continue
            segment_width = max(1, int(bar_width * count / total))
            bar.append("\u2588" * segment_width, style=color)

        self.console.print(bar)

        legend_parts = []
        for count, color, label in segments:
            if count > 0:
                legend_parts.append(f"[{color}]\u2588 {label}:{count}[/{color}]")
        self.console.print("  ".join(legend_parts))
        self.console.print()

    def _render_findings_table(self, report: ScanReport) -> None:
        """Compact findings table with OWASP tags."""
        sorted_findings = sorted(report.findings, key=lambda f: f.severity_rank)

        table = Table(show_lines=False, pad_edge=True, box=None, show_header=True)
        table.add_column("Sev", width=4)
        table.add_column("Finding", min_width=40, no_wrap=False)
        table.add_column("OWASP", width=6, justify="right")

        for finding in sorted_findings:
            sev_color = _SEVERITY_COLORS[finding.severity]
            sev_text = Text(_SEVERITY_LABELS[finding.severity], style=sev_color)

            title = finding.title
            if finding.file_path:
                loc = str(finding.file_path.name)
                if finding.line_number:
                    loc += f":{finding.line_number}"
                title += f" [dim]({loc})[/dim]"

            owasp = ""
            if finding.owasp_ids:
                owasp = f"[bold white on dark_red] {finding.owasp_ids[0]} [/bold white on dark_red]"

            table.add_row(sev_text, title, owasp)

        self.console.print(table)

    def _render_fix_first(self, report: ScanReport) -> None:
        """Prioritized action list — what to fix first."""
        urgent = sorted(
            [
                f
                for f in report.findings
                if f.severity in (FindingSeverity.CRITICAL, FindingSeverity.HIGH)
            ],
            key=lambda f: f.severity_rank,
        )

        if not urgent:
            return

        self.console.print()
        lines = []
        for i, finding in enumerate(urgent[:3], 1):
            sev_color = _SEVERITY_COLORS[finding.severity]
            sev_label = _SEVERITY_LABELS[finding.severity].strip()
            fix_text = ""
            if finding.remediation:
                if finding.remediation.automated and finding.remediation.command:
                    fix_text = f" \u2192 [cyan]{finding.remediation.command}[/cyan]"
                else:
                    fix_text = f" \u2192 {finding.remediation.summary}"
            lines.append(
                f"  [{sev_color}]{i}. [{sev_label}][/{sev_color}] {finding.title}{fix_text}"
            )

        remaining = len(urgent) - 3
        if remaining > 0:
            lines.append(f"  [{_DIM}]... and {remaining} more[/{_DIM}]")

        self.console.print(
            Panel(
                "\n".join(lines),
                title="[bold yellow]Fix First[/bold yellow]",
                border_style="yellow",
                padding=(0, 1),
            )
        )

    def _render_details(self, report: ScanReport) -> None:
        """Verbose: full finding details with remediation steps."""
        sorted_findings = sorted(report.findings, key=lambda f: f.severity_rank)

        self.console.print(f"\n[bold]Detailed Findings[/bold]\n")
        for i, finding in enumerate(sorted_findings, 1):
            sev_color = _SEVERITY_COLORS[finding.severity]
            self.console.print(
                f"[{sev_color}]{i}. [{finding.severity.value.upper()}] "
                f"{finding.title}[/{sev_color}]"
            )
            self.console.print(f"   {finding.description}")
            if finding.evidence:
                self.console.print(f"   Evidence: {finding.evidence}")
            if finding.owasp_ids:
                tags = " ".join(
                    f"[bold white on dark_red] {oid} [/bold white on dark_red]"
                    for oid in finding.owasp_ids
                )
                self.console.print(f"   OWASP: {tags}")
            if finding.remediation:
                self.console.print(f"   [bold]Fix:[/bold] {finding.remediation.summary}")
                for step in finding.remediation.steps[:3]:
                    self.console.print(f"     - {step}")
                if finding.remediation.automated:
                    self.console.print(
                        f"   Auto-fix: [cyan]{finding.remediation.command}[/cyan]"
                    )
            self.console.print()

    def _render_posture(self, posture: dict[str, Any]) -> None:
        """OWASP posture table (verbose mode only)."""
        cat_scores = posture.get("category_scores", {})
        if not cat_scores:
            return

        table = Table(title="OWASP Agentic Top 10 Posture", show_lines=False)
        table.add_column("Category", min_width=35)
        table.add_column("Score", width=8, justify="right")
        table.add_column("", width=6)

        for category, score in sorted(cat_scores.items()):
            if score >= 9.0:
                status = Text("PASS", style="green")
            elif score >= 7.0:
                status = Text("WARN", style="yellow")
            else:
                status = Text("FAIL", style="red")

            score_style = "green" if score >= 8 else ("yellow" if score >= 6 else "red")
            table.add_row(category, Text(f"{score}/10", style=score_style), status)

        self.console.print(table)

    def _render_clean_scan(self) -> None:
        """Positive message when no findings are detected."""
        self.console.print(
            Panel(
                "[bold green]No vulnerabilities detected[/bold green]\n"
                f"[{_DIM}]All checks passed. Run scans regularly to catch regressions.[/{_DIM}]",
                border_style="green",
                padding=(0, 1),
            )
        )

    def _render_footer(self, report: ScanReport) -> None:
        """Compact footer with scan stats."""
        summary = report.summary
        self.console.print(
            f"\n[{_DIM}]{summary.total_findings} findings \u00b7 "
            f"{len(summary.scanners_run)} scanners \u00b7 "
            f"{summary.duration_seconds:.2f}s \u00b7 "
            f"{summary.files_scanned} files[/{_DIM}]"
        )

        if summary.critical > 0:
            self.console.print(
                f"[bold red]Fix critical issues now.[/bold red] "
                f"Re-run: [cyan]agentsec scan[/cyan]"
            )
        elif summary.high > 0:
            self.console.print(
                f"[dark_orange]Address high-severity issues before deploying.[/dark_orange]"
            )
        self.console.print()
