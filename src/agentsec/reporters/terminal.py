"""Terminal (Rich) reporter — renders scan results to the console."""

from __future__ import annotations

from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from agentsec.models.findings import FindingSeverity
from agentsec.models.report import ScanReport

_SEVERITY_COLORS = {
    FindingSeverity.CRITICAL: "bold red",
    FindingSeverity.HIGH: "red",
    FindingSeverity.MEDIUM: "yellow",
    FindingSeverity.LOW: "cyan",
    FindingSeverity.INFO: "dim",
}

_SEVERITY_ICONS = {
    FindingSeverity.CRITICAL: "CRIT",
    FindingSeverity.HIGH: "HIGH",
    FindingSeverity.MEDIUM: "MED ",
    FindingSeverity.LOW: "LOW ",
    FindingSeverity.INFO: "INFO",
}


class TerminalReporter:
    """Renders scan reports to the terminal using Rich."""

    def __init__(self, console: Console | None = None):
        self.console = console or Console()

    def render(self, report: ScanReport, posture: dict[str, Any] | None = None) -> None:
        """Render the full scan report to the terminal."""
        self._render_header(report)

        if report.findings:
            self._render_critical_actions(report)
            self._render_summary(report, posture)
            self._render_findings_table(report)
            self._render_details(report)
            if posture:
                self._render_posture(posture)
            self._render_next_steps(report)
        else:
            self._render_summary(report, posture)
            self._render_clean_scan()

    def _render_header(self, report: ScanReport) -> None:
        self.console.print()
        self.console.print(
            Panel(
                f"[bold]agentsec scan report[/bold]\n"
                f"Target: {report.target_path}\n"
                f"Agent type: {report.agent_type}\n"
                f"Scan ID: {report.scan_id}\n"
                f"Time: {report.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}",
                title="agentsec",
                border_style="blue",
            )
        )

    def _render_critical_actions(self, report: ScanReport) -> None:
        """Show a prominent panel for critical/high findings that need immediate action."""
        critical = [f for f in report.findings if f.severity == FindingSeverity.CRITICAL]
        high = [f for f in report.findings if f.severity == FindingSeverity.HIGH]

        if not critical and not high:
            return

        lines: list[str] = []
        if critical:
            lines.append(
                f"[bold red]CRITICAL: {len(critical)} "
                f"finding{'s' if len(critical) != 1 else ''} "
                f"require immediate action[/bold red]"
            )
        if high:
            lines.append(
                f"[red]HIGH: {len(high)} "
                f"finding{'s' if len(high) != 1 else ''} "
                f"should be fixed soon[/red]"
            )

        lines.append("")

        # Show top actions (up to 5)
        urgent = sorted(critical + high, key=lambda f: f.severity_rank)
        for finding in urgent[:5]:
            icon = (
                "[bold red]*[/bold red]"
                if finding.severity == FindingSeverity.CRITICAL
                else "[red]*[/red]"
            )
            loc = ""
            if finding.file_path:
                loc = f" ({finding.file_path.name}"
                if finding.line_number:
                    loc += f":{finding.line_number}"
                loc += ")"
            lines.append(f"  {icon} {finding.title}{loc}")

        if len(urgent) > 5:
            lines.append(f"  ... and {len(urgent) - 5} more")

        self.console.print(
            Panel(
                "\n".join(lines),
                title="[bold red]Action Required[/bold red]",
                border_style="red",
            )
        )

    def _render_summary(self, report: ScanReport, posture: dict[str, Any] | None = None) -> None:
        summary = report.summary
        grade = posture.get("grade", "?") if posture else "?"
        score = posture.get("overall_score", "?") if posture else "?"

        grade_color = {
            "A": "green",
            "B": "cyan",
            "C": "yellow",
            "D": "red",
            "F": "bold red",
        }.get(grade, "white")

        table = Table(show_header=False, box=None, padding=(0, 2))
        table.add_column("metric", style="bold")
        table.add_column("value")

        table.add_row("Total findings", str(summary.total_findings))
        table.add_row(
            "Critical",
            Text(str(summary.critical), style="bold red" if summary.critical else "dim"),
        )
        table.add_row(
            "High",
            Text(str(summary.high), style="red" if summary.high else "dim"),
        )
        table.add_row(
            "Medium",
            Text(str(summary.medium), style="yellow" if summary.medium else "dim"),
        )
        table.add_row("Low", str(summary.low))
        table.add_row("Info", str(summary.info))
        table.add_row("Files scanned", str(summary.files_scanned))
        table.add_row("Scanners run", ", ".join(summary.scanners_run))
        table.add_row("Duration", f"{summary.duration_seconds:.2f}s")
        table.add_row(
            "Security grade",
            Text(f"{grade} ({score}/100)", style=grade_color),
        )
        table.add_row(
            "Result",
            Text(
                summary.pass_fail,
                style="bold green" if summary.pass_fail == "PASS" else "bold red",
            ),
        )

        self.console.print(Panel(table, title="Summary", border_style="blue"))

    def _render_findings_table(self, report: ScanReport) -> None:
        """Compact findings table with severity, scanner, and title."""
        sorted_findings = sorted(report.findings, key=lambda f: f.severity_rank)

        table = Table(title="Findings", show_lines=True)
        table.add_column("Severity", width=8)
        table.add_column("Scanner", width=12)
        table.add_column("Finding", min_width=40)

        for finding in sorted_findings:
            sev_color = _SEVERITY_COLORS[finding.severity]
            sev_text = Text(
                _SEVERITY_ICONS[finding.severity],
                style=sev_color,
            )

            title_parts = [finding.title]
            if finding.file_path:
                loc = str(finding.file_path.name)
                if finding.line_number:
                    loc += f":{finding.line_number}"
                title_parts.append(f"[dim]{loc}[/dim]")

            table.add_row(
                sev_text,
                finding.scanner,
                "\n".join(title_parts),
            )

        self.console.print(table)

    def _render_details(self, report: ScanReport) -> None:
        """Show detailed findings for CRITICAL and HIGH only by default."""
        critical_high = [
            f
            for f in report.findings
            if f.severity in (FindingSeverity.CRITICAL, FindingSeverity.HIGH)
        ]

        if not critical_high:
            return

        sorted_findings = sorted(critical_high, key=lambda f: f.severity_rank)

        self.console.print("\n[bold]Detailed Findings (Critical + High)[/bold]\n")
        for i, finding in enumerate(sorted_findings, 1):
            sev_color = _SEVERITY_COLORS[finding.severity]
            self.console.print(
                f"[{sev_color}]{i}. [{finding.severity.value.upper()}] "
                f"{finding.title}[/{sev_color}]"
            )
            self.console.print(f"   {finding.description}")
            if finding.evidence:
                self.console.print(f"   Evidence: {finding.evidence}")
            if finding.remediation:
                self.console.print(f"   [bold]Fix:[/bold] {finding.remediation.summary}")
                for step in finding.remediation.steps[:3]:
                    self.console.print(f"     - {step}")
                if finding.remediation.automated:
                    self.console.print(f"   Auto-fix: [cyan]{finding.remediation.command}[/cyan]")
            self.console.print()

    def _render_posture(self, posture: dict[str, Any]) -> None:
        cat_scores = posture.get("category_scores", {})
        if not cat_scores:
            return

        table = Table(title="OWASP Agentic Top 10 Posture")
        table.add_column("Category", min_width=40)
        table.add_column("Score", width=10, justify="right")
        table.add_column("Status", width=10)

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
        """Render a positive message when no findings are detected."""
        self.console.print(
            Panel(
                "[bold green]Security scan passed[/bold green]\n\n"
                "Your agent installation has no detected vulnerabilities.\n\n"
                "[dim]Run scans regularly to catch regressions.\n"
                "Use --scanners to target specific areas.[/dim]",
                border_style="green",
            )
        )

    def _render_next_steps(self, report: ScanReport) -> None:
        """Render actionable next steps based on findings."""
        summary = report.summary

        self.console.print(
            f"\n[dim]Scan complete. {summary.total_findings} findings "
            f"from {len(summary.scanners_run)} scanners in "
            f"{summary.duration_seconds:.2f}s.[/dim]"
        )

        if summary.critical > 0:
            self.console.print("\n[bold red]Next steps:[/bold red]")
            self.console.print("  1. Fix critical findings immediately (see details above)")
            self.console.print("  2. Re-run: [cyan]agentsec scan[/cyan]")
            self.console.print(
                "  3. For CI pipelines: [cyan]agentsec scan -o json -f report.json "
                "--fail-on critical[/cyan]"
            )
        elif summary.high > 0:
            self.console.print("\n[yellow]Next steps:[/yellow]")
            self.console.print("  1. Address high-severity findings before deployment")
            self.console.print("  2. To pass CI now: [cyan]agentsec scan --fail-on critical[/cyan]")
        else:
            self.console.print(
                "\n[dim]Tip: Use [cyan]agentsec scan -o json[/cyan] for CI pipelines "
                "or [cyan]agentsec scan -s credential[/cyan] for targeted scans[/dim]"
            )
        self.console.print()
