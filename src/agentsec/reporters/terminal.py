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
from agentsec.impacts import OWASP_LABELS
from agentsec.models.findings import FindingConfidence, FindingSeverity
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

            # 4. Top Risk callout (worst finding)
            self._render_top_risk(report)

            # 5. Findings table
            self._render_findings_table(report)

            # 6. Verbose: detailed findings + OWASP posture
            if self.verbose:
                self._render_details(report)
                if posture:
                    self._render_posture(posture)

            # 7. Next Steps — actionable remediation
            self._render_next_steps(report)
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
            f"[{_DIM}]Target: {report.target_path} · Agent: {report.agent_type}[/{_DIM}]"
        )
        self.console.print()

    def _render_grade(self, report: ScanReport, posture: dict[str, Any] | None) -> None:
        """Grade + score bar at the top — the screenshot moment."""
        grade = posture.get("grade", "?") if posture else "?"
        score = posture.get("overall_score", 0) if posture else 0
        grade_color = _GRADE_COLORS.get(grade, "white")
        summary = report.summary

        # Grade line with projected improvement
        grade_text = Text()
        grade_text.append("Security Grade: ", style=_DIM)
        grade_text.append(f" {grade} ", style=grade_color)

        # Show projected grade after auto-fix if there are fixable findings
        auto_fixable = [f for f in report.findings if f.remediation and f.remediation.automated]
        if auto_fixable and grade != "A":
            projected = self._compute_projected_grade(report, posture)
            if projected and projected["grade"] != grade:
                proj_color = _GRADE_COLORS.get(projected["grade"], "white")
                grade_text.append(" -> After auto-fix: ", style=_DIM)
                grade_text.append(
                    f" {projected['grade']} ",
                    style=proj_color,
                )
                grade_text.append(
                    f" ({projected['overall_score']}/100)",
                    style=proj_color,
                )
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

    def _render_top_risk(self, report: ScanReport) -> None:
        """Highlight the single worst finding in a prominent callout."""
        critical_findings = [f for f in report.findings if f.severity == FindingSeverity.CRITICAL]
        if not critical_findings:
            return

        worst = critical_findings[0]
        msg = worst.title
        if worst.impact:
            msg += f"\n[{_DIM}]{worst.impact}[/{_DIM}]"

        self.console.print(
            Panel(
                f"[bold red]{msg}[/bold red]",
                title="[bold red]Top Risk[/bold red]",
                border_style="red",
                padding=(0, 1),
            )
        )

    def _compute_projected_grade(
        self, report: ScanReport, posture: dict[str, Any] | None
    ) -> dict[str, Any] | None:
        """Compute what the grade would be after running auto-fix."""
        if not posture:
            return None

        remaining = [f for f in report.findings if not (f.remediation and f.remediation.automated)]
        if not remaining:
            return {"grade": "A", "overall_score": 100.0}

        try:
            from agentsec.analyzers.owasp_scorer import OwaspScorer

            scorer = OwaspScorer()
            return scorer.compute_posture_score(remaining)
        except Exception:
            return None

    def _render_findings_table(self, report: ScanReport) -> None:
        """Compact findings table with impact sub-lines, OWASP labels, and overflow cap."""
        sorted_findings = sorted(report.findings, key=lambda f: f.severity_rank)

        # In default mode, hide LOW/INFO and cap at 10 rows
        max_rows = 10
        if not self.verbose:
            visible = [
                f
                for f in sorted_findings
                if f.severity not in (FindingSeverity.LOW, FindingSeverity.INFO)
            ]
            overflow = len(sorted_findings) - len(visible)
            if len(visible) > max_rows:
                overflow += len(visible) - max_rows
                visible = visible[:max_rows]
        else:
            visible = sorted_findings
            overflow = 0

        table = Table(show_lines=False, pad_edge=True, box=None, show_header=True)
        table.add_column("Sev", width=4)
        table.add_column("Finding", min_width=40, no_wrap=False)
        table.add_column("Fix", width=4, justify="center")
        table.add_column("OWASP", width=8, justify="right")

        for finding in visible:
            sev_color = _SEVERITY_COLORS[finding.severity]
            sev_text = Text(_SEVERITY_LABELS[finding.severity], style=sev_color)

            title = finding.title
            if finding.file_path:
                loc = str(finding.file_path.name)
                if finding.line_number:
                    loc += f":{finding.line_number}"
                title += f" [dim]({loc})[/dim]"

            # Auto-fix indicator
            fix_tag = ""
            if finding.remediation and finding.remediation.automated:
                fix_tag = "[green]AUTO[/green]"

            # OWASP label instead of bare code
            owasp = ""
            if finding.owasp_ids:
                code = finding.owasp_ids[0]
                label = OWASP_LABELS.get(code, code)
                owasp = f"[bold white on dark_red] {label} [/bold white on dark_red]"

            table.add_row(sev_text, title, fix_tag, owasp)

            # Impact sub-line
            if finding.impact:
                table.add_row("", f"[{_DIM}]-> {finding.impact}[/{_DIM}]", "", "")

        self.console.print(table)

        if overflow > 0:
            self.console.print(
                f"  [{_DIM}]... and {overflow} more. Use --verbose to see all.[/{_DIM}]"
            )

    def _render_next_steps(self, report: ScanReport) -> None:
        """Actionable next steps — split into auto-fixable and manual."""
        from agentsec.models.findings import FindingCategory

        auto_fixable = [f for f in report.findings if f.remediation and f.remediation.automated]
        manual = [f for f in report.findings if not (f.remediation and f.remediation.automated)]

        self.console.print()
        lines: list[str] = []

        # Auto-fix section with summary of what gets fixed
        if auto_fixable:
            lines.append(
                f"  [bold green]\u25b8 Auto-fix available[/bold green] "
                f"[{_DIM}]({len(auto_fixable)} findings):[/{_DIM}]"
            )
            lines.append("  [cyan]agentsec harden ~ -p workstation --apply[/cyan]")
            # Show compact list of what gets fixed
            auto_titles = [f.title for f in sorted(auto_fixable, key=lambda f: f.severity_rank)]
            for title in auto_titles[:6]:
                lines.append(f"     [{_DIM}]\u2713 {title}[/{_DIM}]")
            if len(auto_titles) > 6:
                lines.append(f"     [{_DIM}]\u2713 ...and {len(auto_titles) - 6} more[/{_DIM}]")
            lines.append("")

        # Manual section — group credential findings to avoid repetition
        manual_urgent = sorted(
            [f for f in manual if f.severity in (FindingSeverity.CRITICAL, FindingSeverity.HIGH)],
            key=lambda f: f.severity_rank,
        )

        if manual_urgent:
            # Separate credential-type findings from others
            cred_categories = {
                FindingCategory.PLAINTEXT_SECRET,
                FindingCategory.EXPOSED_TOKEN,
                FindingCategory.HARDCODED_CREDENTIAL,
                FindingCategory.EXPOSED_CREDENTIALS,
            }
            cred_findings = [f for f in manual_urgent if f.category in cred_categories]
            other_findings = [f for f in manual_urgent if f.category not in cred_categories]

            lines.append(
                f"  [bold yellow]\u25b8 Manual action required[/bold yellow] "
                f"[{_DIM}]({len(manual_urgent)} findings):[/{_DIM}]"
            )

            item_num = 1

            # Group credential findings by file
            if cred_findings:
                file_groups: dict[str, list] = {}
                for f in cred_findings:
                    key = str(f.file_path.name) if f.file_path else "unknown"
                    file_groups.setdefault(key, []).append(f)

                for file_name, group in file_groups.items():
                    worst = min(group, key=lambda f: f.severity_rank)
                    sev_color = _SEVERITY_COLORS[worst.severity]
                    sev_label = _SEVERITY_LABELS[worst.severity].strip()

                    lines.append(
                        f"  [{sev_color}]{item_num}. [{sev_label}][/{sev_color}] "
                        f"{len(group)} plaintext credential{'s' if len(group) != 1 else ''}"
                        f" in {file_name}"
                    )

                    # List individual credential types compactly
                    cred_types = []
                    for f in group:
                        name = f.title
                        # Strip common prefixes and suffixes to get the credential type
                        for prefix in ("Plaintext ", "plaintext "):
                            if name.startswith(prefix):
                                name = name[len(prefix) :]
                        for suffix in (
                            f" found in {file_name}",
                            f" in {file_name}",
                        ):
                            if name.endswith(suffix):
                                name = name[: -len(suffix)]
                        # Remove trailing " (possible secret)" for entropy findings
                        name = name.replace(" (possible secret)", "")
                        cred_types.append(name)

                    # Deduplicate while preserving order
                    seen: set[str] = set()
                    unique_types = []
                    for ct in cred_types:
                        if ct not in seen:
                            seen.add(ct)
                            unique_types.append(ct)

                    lines.append(f"     [{_DIM}]{', '.join(unique_types)}[/{_DIM}]")

                    # Show remediation steps once for the group
                    representative = next((f for f in group if f.remediation), None)
                    if representative and representative.remediation:
                        for step in representative.remediation.steps:
                            lines.append(f"     [{_DIM}]- {step}[/{_DIM}]")

                    item_num += 1

            # Individual non-credential findings
            for finding in other_findings:
                sev_color = _SEVERITY_COLORS[finding.severity]
                sev_label = _SEVERITY_LABELS[finding.severity].strip()
                lines.append(
                    f"  [{sev_color}]{item_num}. [{sev_label}][/{sev_color}] {finding.title}"
                )
                if finding.remediation:
                    for step in finding.remediation.steps:
                        lines.append(f"     [{_DIM}]- {step}[/{_DIM}]")
                item_num += 1

        if lines:
            self.console.print(
                Panel(
                    "\n".join(lines),
                    title="[bold yellow]Next Steps[/bold yellow]",
                    border_style="yellow",
                    padding=(0, 1),
                )
            )

    def _render_details(self, report: ScanReport) -> None:
        """Verbose: full finding details with remediation steps."""
        sorted_findings = sorted(report.findings, key=lambda f: f.severity_rank)

        self.console.print("\n[bold]Detailed Findings[/bold]\n")
        for i, finding in enumerate(sorted_findings, 1):
            sev_color = _SEVERITY_COLORS[finding.severity]
            self.console.print(
                f"[{sev_color}]{i}. [{finding.severity.value.upper()}] "
                f"{finding.title}[/{sev_color}]"
            )
            self.console.print(f"   {finding.description}")
            if finding.confidence != FindingConfidence.HIGH:
                conf_style = "yellow" if finding.confidence == FindingConfidence.MEDIUM else "dim"
                self.console.print(
                    f"   Confidence: [{conf_style}]{finding.confidence.value}[/{conf_style}]"
                )
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
                    self.console.print(f"   Auto-fix: [cyan]{finding.remediation.command}[/cyan]")
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
        """Compact footer with scan stats and command hints."""
        summary = report.summary
        self.console.print(
            f"\n[{_DIM}]{summary.total_findings} findings \u00b7 "
            f"{len(summary.scanners_run)} scanners \u00b7 "
            f"{summary.duration_seconds:.2f}s \u00b7 "
            f"{summary.files_scanned} files[/{_DIM}]"
        )

        if summary.critical > 0:
            self.console.print(
                "[bold red]Fix critical issues now.[/bold red] Re-run: [cyan]agentsec scan[/cyan]"
            )
        elif summary.high > 0:
            self.console.print(
                "[dark_orange]Address high-severity issues before deploying.[/dark_orange]"
            )

        # Command hints for discoverability
        self.console.print(
            f"[{_DIM}]More: [cyan]agentsec harden[/cyan] \u00b7 "
            f"[cyan]agentsec gate[/cyan] npm install <pkg> \u00b7 "
            f"[cyan]agentsec watch[/cyan] \u00b7 "
            f"[cyan]agentsec --help[/cyan][/{_DIM}]"
        )
        self.console.print()
