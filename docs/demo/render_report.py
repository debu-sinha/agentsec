"""Generate a Rich HTML report showing before/after hardening."""

from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from agentsec.analyzers.owasp_scorer import OwaspScorer
from agentsec.hardener import get_profile_actions, harden
from agentsec.models.config import AgentsecConfig, ScanTarget
from agentsec.orchestrator import run_scan
from agentsec.reporters.terminal import TerminalReporter

console = Console(record=True, width=110, force_terminal=True)
reporter = TerminalReporter(console=console)
scorer = OwaspScorer()

target = Path.home()
config = AgentsecConfig(targets=[ScanTarget(path=target)])


def do_scan():
    report = run_scan(config)
    posture = scorer.compute_posture_score(report.findings)
    return report, posture


# === BEFORE ===
console.print()
console.print("[bold white on red]  BEFORE HARDENING -- Vulnerable OpenClaw  [/]")
console.print()
report1, posture1 = do_scan()
reporter.render(report1, posture=posture1)

# === SHOW PROFILE ===
console.print()
console.print("[bold white on blue]  agentsec show-profile workstation  [/]")
console.print()
actions = get_profile_actions("workstation")
table = Table(title="Hardening Profile: workstation", show_lines=True)
table.add_column("Setting", style="cyan", width=30)
table.add_column("New Value", width=16)
table.add_column("Reason", min_width=40)
for a in actions:
    table.add_row(a.key, str(a.value), a.reason)
console.print(table)
console.print()
console.print(
    "[dim]This profile modifies configuration only. "
    "Credentials, CVEs, and skills require separate fixes.[/dim]"
)

# === APPLY ===
console.print()
console.print("[bold white on green]  HARDENING APPLIED  [/]")
console.print()
result = harden(target, "workstation", dry_run=False)
for a in result.applied:
    console.print(
        f"  [green]\u2713[/green] {a.key} = [cyan]{a.value}[/cyan]  [dim]({a.reason})[/dim]"
    )

# === AFTER ===
console.print()
console.print("[bold white on green]  AFTER HARDENING -- Re-scan  [/]")
console.print()
report2, posture2 = do_scan()
reporter.render(report2, posture=posture2)

# === DELTA ===
b_score = posture1["overall_score"]
b_grade = posture1["grade"]
a_score = posture2["overall_score"]
a_grade = posture2["grade"]
delta = a_score - b_score
fixed = len(report1.findings) - len(report2.findings)

delta_text = (
    f"[bold]Before:[/bold]  {b_grade} ({b_score}/100) "
    f"- {len(report1.findings)} findings\n"
    f"[bold]After:[/bold]   {a_grade} ({a_score}/100) "
    f"- {len(report2.findings)} findings\n"
    f"\n"
    f"[bold green]+{delta:.1f} points[/bold green], "
    f"[bold green]-{fixed} findings fixed[/bold green]"
)
console.print()
console.print(
    Panel(
        delta_text,
        title="[bold]Hardening Impact Summary[/bold]",
        border_style="green",
    )
)

html = console.export_html(inline_styles=True)
with open("/tmp/agentsec_report.html", "w") as f:
    f.write(html)

print("\nReport saved to /tmp/agentsec_report.html")
