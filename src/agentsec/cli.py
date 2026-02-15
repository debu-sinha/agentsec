"""CLI entry point for agentsec.

Usage:
    agentsec scan [TARGET_PATH] [OPTIONS]
    agentsec scan --output json --fail-on high
    agentsec scan ~/.openclaw --scanners installation,credential
"""

from __future__ import annotations

import logging
import subprocess
import sys
import time
from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn
from rich.table import Table

from agentsec import __version__
from agentsec.analyzers.owasp_scorer import OwaspScorer
from agentsec.models.config import AgentsecConfig, ScannerConfig, ScanTarget
from agentsec.models.findings import FindingSeverity
from agentsec.orchestrator import run_scan
from agentsec.reporters.json_reporter import JsonReporter
from agentsec.reporters.sarif_reporter import SarifReporter
from agentsec.reporters.terminal import TerminalReporter
from agentsec.scanners.registry import get_all_scanners

logger = logging.getLogger(__name__)
console = Console()


def _configure_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )


@click.group(
    epilog="""Examples:

  Quick scan of current directory:
    $ agentsec scan

  CI/CD pipeline (fail on critical, JSON output):
    $ agentsec scan -o json -f report.json --fail-on critical

  GitHub Code Scanning integration:
    $ agentsec scan -o sarif -f results.sarif

  Deep credential scan only:
    $ agentsec scan -s credential -v

  Scan a specific agent installation:
    $ agentsec scan ~/.openclaw

Learn more: https://github.com/debu-sinha/agentsec
"""
)
@click.version_option(version=__version__, prog_name="agentsec")
def main() -> None:
    """agentsec -- Security scanner for agentic AI installations.

    Scans OpenClaw, Claude Code, and other AI agent installations for
    security vulnerabilities, credential exposure, malicious skills,
    and MCP server misconfigurations. Maps findings to the OWASP
    Agentic Top 10 (2026).
    """


@main.command()
@click.argument("target", default=".", type=click.Path(exists=True))
@click.option(
    "--output",
    "-o",
    type=click.Choice(["terminal", "json", "sarif"]),
    default="terminal",
    help="Output format (terminal, json, or sarif for GitHub Code Scanning)",
)
@click.option(
    "--output-file",
    "-f",
    type=click.Path(),
    default=None,
    help="Write report to file (default: stdout)",
)
@click.option(
    "--scanners",
    "-s",
    type=str,
    default=None,
    help="Comma-separated list of scanners to run (default: all)",
)
@click.option(
    "--fail-on",
    type=click.Choice(["critical", "high", "medium", "low", "info", "none"]),
    default="high",
    help="Exit non-zero if findings at this severity or above (default: high)",
)
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose logging")
@click.option("--quiet", "-q", is_flag=True, help="Suppress terminal output, exit code only")
def scan(
    target: str,
    output: str,
    output_file: str | None,
    scanners: str | None,
    fail_on: str,
    verbose: bool,
    quiet: bool,
) -> None:
    """Scan an agent installation for security vulnerabilities.

    TARGET is the path to the agent installation directory (default: current directory).

    \b
    Examples:
        agentsec scan                            # scan current directory
        agentsec scan ~/.openclaw                # scan specific path
        agentsec scan -o json -f report.json     # JSON output to file
        agentsec scan -o sarif -f results.sarif  # SARIF for GitHub
        agentsec scan --fail-on critical         # only fail on critical
        agentsec scan -s installation,mcp        # run specific scanners
    """
    _configure_logging(verbose)

    target_path = Path(target).expanduser().resolve()

    # Build config
    scanner_configs: dict[str, ScannerConfig] = {}
    if scanners:
        enabled_names = {s.strip() for s in scanners.split(",")}
        for name in ["installation", "skill", "mcp", "credential"]:
            scanner_configs[name] = ScannerConfig(enabled=(name in enabled_names))
    else:
        for name in ["installation", "skill", "mcp", "credential"]:
            scanner_configs[name] = ScannerConfig()

    config = AgentsecConfig(
        targets=[ScanTarget(path=target_path)],
        scanners=scanner_configs,
        output_format=output,
        output_path=Path(output_file) if output_file else None,
        fail_on_severity=fail_on if fail_on != "none" else None,
    )

    # Run the scan with progress animation
    is_tty = console.is_terminal and not quiet and output == "terminal"

    if is_tty:
        with Progress(
            SpinnerColumn("dots"),
            TextColumn("[deep_sky_blue1]{task.description}[/deep_sky_blue1]"),
            BarColumn(bar_width=30),
            TextColumn("[grey70]{task.fields[status]}[/grey70]"),
            console=console,
            transient=True,
        ) as progress:
            scan_task = progress.add_task("Scanning...", total=4, status="starting")
            for i, phase in enumerate(["configuration", "skills", "MCP servers", "credentials"]):
                progress.update(scan_task, description=f"Scanning {phase}...", status=phase)
                if i == 0:
                    report = run_scan(config)
                progress.update(scan_task, advance=1)
            progress.update(scan_task, description="Calculating posture...", status="scoring")
    else:
        report = run_scan(config)

    # Score posture
    scorer = OwaspScorer()
    posture = scorer.compute_posture_score(report.findings)

    # Render output (skip if quiet mode unless writing to file)
    if not quiet or config.output_path:
        if output == "json":
            json_reporter = JsonReporter()
            json_str = json_reporter.render(
                report,
                posture=posture,
                output_path=config.output_path,
            )
            if not config.output_path and not quiet:
                console.print(json_str)
            elif config.output_path and not quiet:
                console.print(f"[green]Report written to {config.output_path}[/green]")
        elif output == "sarif":
            sarif_reporter = SarifReporter()
            sarif_str = sarif_reporter.render(
                report,
                posture=posture,
                output_path=config.output_path,
            )
            if not config.output_path and not quiet:
                console.print(sarif_str)
            elif config.output_path and not quiet:
                console.print(f"[green]SARIF report written to {config.output_path}[/green]")
        else:
            if not quiet:
                terminal_reporter = TerminalReporter(console=console, verbose=verbose)
                terminal_reporter.render(report, posture=posture)

    # Exit code based on fail_on threshold
    if config.fail_on_severity:
        threshold_map = {
            "critical": FindingSeverity.CRITICAL,
            "high": FindingSeverity.HIGH,
            "medium": FindingSeverity.MEDIUM,
            "low": FindingSeverity.LOW,
            "info": FindingSeverity.INFO,
        }
        threshold = threshold_map.get(config.fail_on_severity)
        if threshold:
            threshold_rank = {
                FindingSeverity.CRITICAL: 0,
                FindingSeverity.HIGH: 1,
                FindingSeverity.MEDIUM: 2,
                FindingSeverity.LOW: 3,
                FindingSeverity.INFO: 4,
            }[threshold]

            failing_count = sum(1 for f in report.findings if f.severity_rank <= threshold_rank)
            if failing_count > 0:
                if not quiet:
                    console.print(
                        f"\n[bold red]FAIL[/bold red]: {failing_count} findings at "
                        f"severity '{config.fail_on_severity}' or above.\n"
                    )
                # Exit code = min(failing count, 127) for shell compatibility
                sys.exit(min(failing_count, 127))


@main.command("list-scanners")
def list_scanners() -> None:
    """List all available scanner modules.

    Shows each scanner's name and description to help you choose
    which scanners to run with the --scanners flag.
    """
    all_scanners = get_all_scanners()

    table = Table(title="Available Scanners", show_lines=True)
    table.add_column("Name", style="bold cyan", width=16)
    table.add_column("Description", min_width=40)

    for name, scanner_cls in all_scanners.items():
        scanner = scanner_cls()
        table.add_row(name, scanner.description)

    console.print(table)
    console.print(
        "\n[dim]Use [cyan]agentsec scan -s <name>[/cyan] to run specific scanners only.[/dim]\n"
    )


@main.command()
@click.argument("target", default=".", type=click.Path(exists=True))
@click.option(
    "--profile",
    "-p",
    type=click.Choice(["workstation", "vps", "public-bot"]),
    required=True,
    help="Hardening profile to apply",
)
@click.option(
    "--apply",
    "do_apply",
    is_flag=True,
    default=False,
    help="Actually write changes (default is dry-run)",
)
@click.option(
    "--dry-run",
    is_flag=True,
    default=True,
    help="Show what would change without writing (default)",
)
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose logging")
def harden(target: str, profile: str, do_apply: bool, dry_run: bool, verbose: bool) -> None:
    """Apply a hardening profile to an agent installation.

    Profiles:
      workstation  — single owner, loopback, minimal exposure
      vps          — remote hosting, strong auth + tool restrictions
      public-bot   — untrusted input, sandbox on, minimal tools

    \b
    Examples:
        agentsec harden -p workstation --dry-run   # preview changes
        agentsec harden -p vps --apply             # apply VPS hardening
        agentsec harden -p public-bot --apply      # lock down public bot
    """
    from agentsec.hardener import harden as do_harden

    _configure_logging(verbose)
    target_path = Path(target).expanduser().resolve()

    is_dry_run = not do_apply
    console.print(
        f"\n[bold]agentsec harden[/bold] — profile: [cyan]{profile}[/cyan], "
        f"target: {target_path}, "
        f"{'[yellow]DRY RUN[/yellow]' if is_dry_run else '[bold green]APPLYING[/bold green]'}\n"
    )

    # Run a pre-hardening scan to show impact preview
    pre_report = None
    pre_posture = None
    try:
        pre_config = AgentsecConfig(
            targets=[ScanTarget(path=target_path)],
            scanners={n: ScannerConfig() for n in ["installation", "skill", "mcp", "credential"]},
        )
        pre_report = run_scan(pre_config)
        scorer = OwaspScorer()
        pre_posture = scorer.compute_posture_score(pre_report.findings)
    except Exception:
        logger.debug("Pre-hardening scan failed, skipping preview")

    result = do_harden(target_path, profile, dry_run=is_dry_run)

    if result.errors:
        for err in result.errors:
            console.print(f"[bold red]Error:[/bold red] {err}")
        sys.exit(1)

    if result.applied:
        table = Table(title="Changes" + (" (would apply)" if is_dry_run else " (applied)"))
        table.add_column("Setting", style="cyan")
        table.add_column("New Value")
        table.add_column("Reason")
        for action in result.applied:
            table.add_row(action.key, str(action.value), action.reason)
        console.print(table)
    else:
        console.print("[green]No changes needed — installation already matches profile.[/green]")

    if result.skipped:
        console.print(f"\n[dim]{len(result.skipped)} settings already at target value.[/dim]")

    if is_dry_run and result.applied:
        # Show impact preview
        if pre_posture:
            _render_harden_preview(pre_report, pre_posture, result)
        console.print(
            f"\n[yellow]Dry run complete.[/yellow] "
            f"Use [cyan]agentsec harden -p {profile} --apply[/cyan] to write changes.\n"
        )
    elif not is_dry_run and result.applied:
        console.print(
            f"\n[green]Hardening applied.[/green] Config: {result.config_path}\n"
            f"[dim]Backup saved as {result.config_path}.bak[/dim]\n"
        )

        # Auto-rescan after apply and show delta
        try:
            post_config = AgentsecConfig(
                targets=[ScanTarget(path=target_path)],
                scanners={
                    n: ScannerConfig() for n in ["installation", "skill", "mcp", "credential"]
                },
            )
            post_report = run_scan(post_config)
            scorer = OwaspScorer()
            post_posture = scorer.compute_posture_score(post_report.findings)

            if pre_posture and pre_report:
                _render_harden_delta(pre_report, pre_posture, post_report, post_posture)
            else:
                console.print(
                    f"  Post-hardening: grade [bold]{post_posture['grade']}[/bold] "
                    f"({post_posture['overall_score']}/100), "
                    f"{len(post_report.findings)} findings\n"
                )
        except Exception:
            console.print("[dim]Re-scan after hardening skipped.[/dim]\n")


def _render_harden_preview(
    pre_report: object,
    pre_posture: dict,
    result: object,
) -> None:
    """Show projected impact of hardening before applying."""
    pre_grade = pre_posture.get("grade", "?")
    pre_score = pre_posture.get("overall_score", 0)
    pre_summary = pre_report.summary

    config_fixable = len(result.applied)

    console.print()
    console.print(
        Panel(
            f"  [bold]Current:[/bold]  grade [bold]{pre_grade}[/bold] ({pre_score}/100) "
            f"- {pre_summary.critical} critical, {pre_summary.high} high, "
            f"{pre_summary.medium} medium\n"
            f"  [bold]Will fix:[/bold] {config_fixable} config settings "
            f"({len(result.skipped)} already at target)\n"
            "  [bold yellow]Note:[/bold yellow]  Hardening fixes configuration only. "
            "Credentials, CVEs, and\n"
            "          malicious skills require separate remediation.",
            title="[bold]Impact Preview[/bold]",
            border_style="blue",
            padding=(0, 1),
        )
    )


def _render_harden_delta(
    pre_report: object,
    pre_posture: dict,
    post_report: object,
    post_posture: dict,
) -> None:
    """Show before/after delta after hardening is applied."""
    pre_grade = pre_posture.get("grade", "?")
    pre_score = pre_posture.get("overall_score", 0)
    post_grade = post_posture.get("grade", "?")
    post_score = post_posture.get("overall_score", 0)

    pre_s = pre_report.summary
    post_s = post_report.summary

    score_delta = post_score - pre_score
    delta_str = f"+{score_delta:.1f}" if score_delta > 0 else f"{score_delta:.1f}"
    delta_style = "green" if score_delta > 0 else ("red" if score_delta < 0 else "dim")

    fixed_count = pre_s.total_findings - post_s.total_findings
    fixed_str = f"-{fixed_count} fixed" if fixed_count > 0 else "no change"

    lines = [
        f"  [bold]Before:[/bold]  {pre_grade} ({pre_score}/100) "
        f"- {pre_s.critical} crit, {pre_s.high} high, {pre_s.medium} med",
        f"  [bold]After:[/bold]   {post_grade} ({post_score}/100) "
        f"- {post_s.critical} crit, {post_s.high} high, {post_s.medium} med"
        f"  [{delta_style}]({delta_str} pts, {fixed_str})[/{delta_style}]",
    ]

    # Show remaining critical/high as next steps
    if post_s.critical > 0:
        lines.append("")
        lines.append(
            f"  [bold red]{post_s.critical} critical[/bold red] "
            f"and [dark_orange]{post_s.high} high[/dark_orange] findings remain."
        )
        lines.append(
            "  [dim]Run [cyan]agentsec scan -v[/cyan] to see details and next steps.[/dim]"
        )

    console.print(
        Panel(
            "\n".join(lines),
            title="[bold]Hardening Results[/bold]",
            border_style="green" if score_delta > 0 else "yellow",
            padding=(0, 1),
        )
    )
    console.print()


@main.command("show-profile")
@click.argument("profile", type=click.Choice(["workstation", "vps", "public-bot"]))
def show_profile(profile: str) -> None:
    """Show what a hardening profile will change.

    Displays each setting, its target value, and the security rationale
    without modifying anything.
    """
    from agentsec.hardener import get_profile_actions

    actions = get_profile_actions(profile)

    table = Table(title=f"Hardening Profile: {profile}", show_lines=True)
    table.add_column("Setting", style="cyan", width=30)
    table.add_column("New Value", width=16)
    table.add_column("Reason", min_width=40)

    for action in actions:
        sev_style = "bold red" if action.severity == "critical" else ""
        table.add_row(
            action.key,
            f"[{sev_style}]{action.value}[/{sev_style}]" if sev_style else str(action.value),
            action.reason,
        )

    console.print("\n")
    console.print(table)
    console.print(
        "\n[dim]This profile modifies configuration only. "
        "Credentials, CVEs, and skills require separate fixes.[/dim]\n"
    )


@main.command()
@click.argument("target", default=".", type=click.Path(exists=True))
@click.option(
    "--interval",
    "-i",
    type=float,
    default=2.0,
    help="Seconds between filesystem polls (default: 2.0)",
)
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose logging")
def watch(target: str, interval: float, verbose: bool) -> None:
    """Watch for changes and auto-scan on skill install, config change, or MCP update.

    Monitors your OpenClaw installation directory for filesystem changes.
    When a new skill is installed, MCP server config changes, or any
    security-relevant file is modified, agentsec automatically re-scans
    and reports new findings.

    \b
    Examples:
        agentsec watch                   # watch current directory
        agentsec watch ~/.openclaw       # watch specific installation
        agentsec watch -i 5              # poll every 5 seconds
    """
    from agentsec.watcher import WatchResult, watch_and_scan

    _configure_logging(verbose)
    target_path = Path(target).expanduser().resolve()

    console.print(
        f"\n[bold]agentsec watch[/bold] v{__version__} — monitoring {target_path}\n"
        f"[dim]Press Ctrl+C to stop.[/dim]\n"
    )

    def on_result(result: WatchResult) -> None:
        event = result.event
        if event.event_type == "initial_scan":
            console.print(
                f"[bold]Baseline scan:[/bold] {result.finding_count} findings, "
                f"grade [bold]{result.grade}[/bold] ({result.score:.0f}/100)"
            )
            if result.critical_count > 0:
                console.print(f"  [bold red]{result.critical_count} critical[/bold red] findings")
            if result.high_count > 0:
                console.print(f"  [bold yellow]{result.high_count} high[/bold yellow] findings")
            console.print("[dim]Watching for changes...[/dim]\n")
        else:
            timestamp = time.strftime("%H:%M:%S")
            icon = {
                "created": "[green]+[/green]",
                "modified": "[yellow]~[/yellow]",
                "deleted": "[red]-[/red]",
            }.get(event.event_type, "?")

            console.print(
                f"[dim]{timestamp}[/dim] {icon} {event.event_type}: [cyan]{event.path.name}[/cyan]"
            )
            console.print(
                f"  Re-scan: {result.finding_count} findings, "
                f"grade [bold]{result.grade}[/bold] ({result.score:.0f}/100)"
            )
            if result.critical_count > 0:
                console.print(
                    f"  [bold red]{result.critical_count} CRITICAL[/bold red] — action required"
                )
            console.print()

    try:
        watch_and_scan(target_path, interval=interval, on_result=on_result)
    except KeyboardInterrupt:
        console.print("\n[dim]Stopped watching.[/dim]")


@main.command()
@click.option(
    "--shell",
    "-s",
    type=click.Choice(["zsh", "bash"]),
    default="zsh",
    help="Shell to generate hook for (default: zsh)",
)
def hook(shell: str) -> None:
    """Generate a shell hook that auto-scans after npm/pip install in agent directories.

    Add to your shell profile (~/.zshrc or ~/.bashrc):

    \b
        eval "$(agentsec hook --shell zsh)"

    This wraps npm and pip commands to automatically trigger an agentsec
    scan when packages are installed in OpenClaw-related directories.
    """
    if shell == "zsh":
        click.echo(_ZSH_HOOK)
    else:
        click.echo(_BASH_HOOK)


_ZSH_HOOK = r"""# agentsec auto-scan hook for zsh
# Wraps npm/pip to auto-scan after installs in agent directories

_agentsec_post_install() {
    local cmd="$1"
    shift
    command "$cmd" "$@"
    local exit_code=$?

    # Only scan after install/add commands
    case "$1" in
        install|add|i)
            # Check if we're in or near an OpenClaw directory
            if [ -f "openclaw.json" ] || [ -d ".openclaw" ] || \
               [ -f "clawdbot.json" ] || [ -d ".clawdbot" ] || \
               [[ "$PWD" == *"openclaw"* ]] || [[ "$PWD" == *"extensions"* ]] || \
               [[ "$PWD" == *"skills"* ]] || [[ "$PWD" == *"mcp"* ]]; then
                echo ""
                echo "\033[1magentsec\033[0m: New package detected, scanning..."
                agentsec scan --quiet --fail-on critical 2>/dev/null
                local scan_exit=$?
                if [ $scan_exit -ne 0 ]; then
                    echo "\033[1;31magentsec: CRITICAL!\033[0m Run 'agentsec scan' for details."
                else
                    echo "\033[32magentsec: No critical issues found.\033[0m"
                fi
            fi
            ;;
    esac

    return $exit_code
}

npm() { _agentsec_post_install npm "$@"; }
pip() { _agentsec_post_install pip "$@"; }
pip3() { _agentsec_post_install pip3 "$@"; }
"""

_BASH_HOOK = r"""# agentsec auto-scan hook for bash
# Wraps npm/pip to auto-scan after installs in agent directories

_agentsec_post_install() {
    local cmd="$1"
    shift
    command "$cmd" "$@"
    local exit_code=$?

    # Only scan after install/add commands
    case "$1" in
        install|add|i)
            # Check if we're in or near an OpenClaw directory
            if [ -f "openclaw.json" ] || [ -d ".openclaw" ] || \
               [ -f "clawdbot.json" ] || [ -d ".clawdbot" ] || \
               [[ "$PWD" == *"openclaw"* ]] || [[ "$PWD" == *"extensions"* ]] || \
               [[ "$PWD" == *"skills"* ]] || [[ "$PWD" == *"mcp"* ]]; then
                echo ""
                echo -e "\033[1magentsec\033[0m: New package detected, scanning..."
                agentsec scan --quiet --fail-on critical 2>/dev/null
                local scan_exit=$?
                if [ $scan_exit -ne 0 ]; then
                    echo -e "\033[1;31magentsec: CRITICAL!\033[0m Run 'agentsec scan' for details."
                else
                    echo -e "\033[32magentsec: No critical issues found.\033[0m"
                fi
            fi
            ;;
    esac

    return $exit_code
}

npm() { _agentsec_post_install npm "$@"; }
pip() { _agentsec_post_install pip "$@"; }
pip3() { _agentsec_post_install pip3 "$@"; }
"""


@main.command(context_settings={"ignore_unknown_options": True, "allow_extra_args": True})
@click.argument("command", nargs=-1, type=click.UNPROCESSED)
@click.option(
    "--fail-on",
    type=click.Choice(["critical", "high", "medium", "low", "info"]),
    default="critical",
    help="Block install at this severity or above (default: critical)",
)
@click.option("--force", is_flag=True, help="Allow install despite findings")
@click.option("--dry-run", is_flag=True, help="Scan only, don't run install")
@click.pass_context
def gate(
    ctx: click.Context,
    command: tuple[str, ...],
    fail_on: str,
    force: bool,
    dry_run: bool,
) -> None:
    """Pre-install security gate. Scans packages BEFORE installation.

    Downloads the package, runs security checks, and blocks install
    if critical issues are found. Only proceeds with the real install
    after the package passes.

    \b
    Examples:
        agentsec gate npm install some-skill
        agentsec gate pip install some-mcp-server
        agentsec gate --fail-on high npm install risky-package
        agentsec gate --dry-run npm install untrusted-package
    """
    from agentsec.gate import gate_check

    if not command:
        console.print("[red]Usage: agentsec gate <npm|pip> install <package>[/red]")
        raise SystemExit(1)

    pm = command[0]
    if pm not in ("npm", "pip", "pip3"):
        console.print(f"[red]Unsupported package manager: {pm}[/red]")
        console.print("Supported: npm, pip, pip3")
        raise SystemExit(1)

    args = list(command[1:])
    pkg_manager = "pip" if pm in ("pip", "pip3") else "npm"

    console.print()
    console.print("[bold]agentsec gate[/bold] - pre-install security check")
    console.print(f"  Package manager: [cyan]{pm}[/cyan]")
    console.print(f"  Command: [dim]{pm} {' '.join(args)}[/dim]")
    console.print(f"  Fail threshold: [yellow]{fail_on}[/yellow]")
    console.print()

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Downloading and scanning...", total=None)
        result = gate_check(pkg_manager, args, fail_on=fail_on, force=force)
        progress.update(task, completed=True)

    if result.findings:
        # Show findings
        severity_colors = {
            "CRITICAL": "red bold",
            "HIGH": "red",
            "MEDIUM": "yellow",
            "LOW": "blue",
            "INFO": "dim",
        }
        console.print(f"[bold]Found {len(result.findings)} issue(s):[/bold]")
        console.print()
        for f in result.findings:
            color = severity_colors.get(f.severity.value, "white")
            console.print(f"  [{color}]{f.severity.value:>8}[/{color}]  {f.title}")
            if f.evidence:
                console.print(f"           [dim]{f.evidence[:120]}[/dim]")
        console.print()

    if result.blocklist_hit:
        console.print(
            Panel(
                "[red bold]BLOCKED[/red bold]: Package is on the agentsec blocklist of "
                "known-malicious packages. Installation prevented.",
                border_style="red",
            )
        )
        raise SystemExit(1)

    if not result.allowed:
        console.print(
            Panel(
                f"[red bold]BLOCKED[/red bold]: Pre-install scan found issues at "
                f"[bold]{fail_on}[/bold] severity or above.\n\n"
                f"Use [cyan]--force[/cyan] to install anyway, or "
                f"[cyan]--dry-run[/cyan] to inspect without installing.",
                border_style="red",
            )
        )
        raise SystemExit(1)

    if result.findings and result.allowed:
        console.print(
            "[yellow]Findings detected but below threshold. Proceeding with install.[/yellow]"
        )
        console.print()

    if not result.findings:
        console.print("[green]No issues found. Package looks clean.[/green]")
        console.print()

    if dry_run:
        console.print("[dim]Dry run - skipping actual installation.[/dim]")
        return

    # Run the actual install command
    console.print(f"[bold]Running:[/bold] {pm} {' '.join(args)}")
    console.print()
    exit_code = subprocess.run([pm, *args]).returncode
    raise SystemExit(exit_code)


if __name__ == "__main__":
    main()
