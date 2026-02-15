"""CLI entry point for agentsec.

Usage:
    agentsec scan [TARGET_PATH] [OPTIONS]
    agentsec scan --output json --fail-on high
    agentsec scan ~/.openclaw --scanners installation,credential
"""

from __future__ import annotations

import logging
import sys
import time
from pathlib import Path

import click
from rich.console import Console
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
        console.print(
            f"\n[yellow]Dry run complete.[/yellow] "
            f"Use [cyan]agentsec harden -p {profile} --apply[/cyan] to write changes.\n"
        )
    elif not is_dry_run and result.applied:
        console.print(
            f"\n[green]Hardening applied.[/green] Config: {result.config_path}\n"
            f"[dim]Backup saved as {result.config_path}.bak[/dim]\n"
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


if __name__ == "__main__":
    main()
