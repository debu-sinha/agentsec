#!/usr/bin/env python3
"""Head-to-head comparison of agentsec vs mcp-scan vs Cisco MCP Scanner.

Runs all three tools (where available) against the same corpus and produces
a structured comparison report for the conference paper.

Usage:
    # Compare on the red-team fixtures (built-in)
    python scripts/compare_scanners.py --fixtures docs/benchmarks/redteam

    # Compare on a single MCP server repo
    python scripts/compare_scanners.py --repo modelcontextprotocol/servers

    # Compare on ecosystem study repos
    python scripts/compare_scanners.py --repo-list docs/ecosystem-study/data/repos.csv

    # Generate comparison table only (from existing results)
    python scripts/compare_scanners.py --from-results comparison_results/
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Tool availability detection
# ---------------------------------------------------------------------------


def check_tool_available(name: str) -> bool:
    """Check if a scanner tool is installed and accessible."""
    cmds = {
        "agentsec": [sys.executable, "-m", "agentsec", "--version"],
        "mcp-scan": ["uvx", "mcp-scan@latest", "--version"],
        "cisco-mcp-scanner": ["mcp-scanner", "--version"],
    }
    cmd = cmds.get(name)
    if not cmd:
        return False
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass
class ToolFinding:
    """Normalized finding from any scanner."""

    tool: str  # agentsec, mcp-scan, cisco
    severity: str
    category: str
    title: str
    file: str = ""
    line: int = 0
    confidence: str = "medium"


@dataclass
class ComparisonResult:
    """Comparison results for a single target."""

    target: str
    target_type: str  # repo, fixture, config

    agentsec_findings: list[ToolFinding] = field(default_factory=list)
    mcpscan_findings: list[ToolFinding] = field(default_factory=list)
    cisco_findings: list[ToolFinding] = field(default_factory=list)

    agentsec_time_ms: float = 0
    mcpscan_time_ms: float = 0
    cisco_time_ms: float = 0

    agentsec_error: str | None = None
    mcpscan_error: str | None = None
    cisco_error: str | None = None


# ---------------------------------------------------------------------------
# Scanner runners
# ---------------------------------------------------------------------------


def run_agentsec(
    target_path: Path, output_file: Path
) -> tuple[list[ToolFinding], float, str | None]:
    """Run agentsec and return normalized findings."""
    start = time.perf_counter()
    try:
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "agentsec",
                "scan",
                str(target_path),
                "--format",
                "json",
                "-f",
                str(output_file),
                "--fail-on",
                "none",
            ],
            capture_output=True,
            text=True,
            timeout=300,
            env={**os.environ, "PYTHONIOENCODING": "utf-8"},
        )
        elapsed_ms = (time.perf_counter() - start) * 1000
    except subprocess.TimeoutExpired:
        return [], (time.perf_counter() - start) * 1000, "timeout"

    if not output_file.exists():
        return [], elapsed_ms, f"no output (exit={result.returncode})"

    try:
        data = json.loads(output_file.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        return [], elapsed_ms, f"JSON parse error: {e}"

    findings = []
    for f in data.get("findings", []):
        findings.append(
            ToolFinding(
                tool="agentsec",
                severity=f.get("severity", "info").lower(),
                category=f.get("category", "unknown"),
                title=f.get("title", "unknown"),
                file=f.get("location", {}).get("file", "")
                if isinstance(f.get("location"), dict)
                else "",
                line=f.get("location", {}).get("line", 0)
                if isinstance(f.get("location"), dict)
                else 0,
                confidence=f.get("confidence", "medium"),
            )
        )
    return findings, elapsed_ms, None


def run_mcp_scan(
    target_path: Path, output_file: Path
) -> tuple[list[ToolFinding], float, str | None]:
    """Run mcp-scan and return normalized findings."""
    # mcp-scan works on MCP config files, not source directories
    # Look for MCP config files in the target
    mcp_configs = list(target_path.glob("**/mcp.json")) + list(target_path.glob("**/.mcp.json"))

    if not mcp_configs:
        return [], 0, "no MCP config files found"

    start = time.perf_counter()
    all_findings: list[ToolFinding] = []

    for config in mcp_configs[:5]:  # Limit to 5 config files
        try:
            result = subprocess.run(
                ["uvx", "mcp-scan@latest", "--json", str(config)],
                capture_output=True,
                text=True,
                timeout=120,
            )
            if result.stdout.strip():
                try:
                    data = json.loads(result.stdout)
                    for f in data.get("findings", []):
                        all_findings.append(
                            ToolFinding(
                                tool="mcp-scan",
                                severity=f.get("severity", "info").lower(),
                                category=f.get("type", "unknown"),
                                title=f.get("message", "unknown"),
                                file=str(config.relative_to(target_path)),
                            )
                        )
                except json.JSONDecodeError:
                    pass
        except (FileNotFoundError, subprocess.TimeoutExpired) as e:
            return [], (time.perf_counter() - start) * 1000, str(e)

    elapsed_ms = (time.perf_counter() - start) * 1000
    return all_findings, elapsed_ms, None


def run_cisco_scanner(
    target_path: Path, output_file: Path
) -> tuple[list[ToolFinding], float, str | None]:
    """Run Cisco MCP Scanner and return normalized findings."""
    # Look for Python MCP server files
    py_files = list(target_path.glob("**/*.py"))
    mcp_files = [f for f in py_files if "mcp" in f.name.lower() or "server" in f.name.lower()]

    if not mcp_files:
        # Fall back to scanning any Python files
        mcp_files = py_files[:10]

    if not mcp_files:
        return [], 0, "no Python files found"

    start = time.perf_counter()
    all_findings: list[ToolFinding] = []

    for pyfile in mcp_files[:5]:
        try:
            result = subprocess.run(
                ["mcp-scanner", "behavioral", str(pyfile), "--format", "json"],
                capture_output=True,
                text=True,
                timeout=120,
            )
            if result.stdout.strip():
                try:
                    data = json.loads(result.stdout)
                    for f in data.get("findings", []):
                        all_findings.append(
                            ToolFinding(
                                tool="cisco",
                                severity=f.get("severity", "info").lower(),
                                category=f.get("type", f.get("ai_taxonomy", "unknown")),
                                title=f.get("description", "unknown"),
                                file=str(pyfile.relative_to(target_path)),
                                line=f.get("locations", [{}])[0].get("line", 0)
                                if f.get("locations")
                                else 0,
                            )
                        )
                except json.JSONDecodeError:
                    pass
        except (FileNotFoundError, subprocess.TimeoutExpired) as e:
            return [], (time.perf_counter() - start) * 1000, str(e)

    elapsed_ms = (time.perf_counter() - start) * 1000
    return all_findings, elapsed_ms, None


# ---------------------------------------------------------------------------
# Comparison logic
# ---------------------------------------------------------------------------


def compare_single_target(
    target_path: Path,
    target_name: str,
    work_dir: Path,
    tools: list[str],
) -> ComparisonResult:
    """Run all available tools on a single target and compare."""
    result = ComparisonResult(target=target_name, target_type="repo")

    if "agentsec" in tools:
        output = work_dir / f"{target_name.replace('/', '__')}_agentsec.json"
        findings, elapsed, error = run_agentsec(target_path, output)
        result.agentsec_findings = findings
        result.agentsec_time_ms = elapsed
        result.agentsec_error = error
        logger.info(
            "  agentsec: %d findings in %.0fms%s",
            len(findings),
            elapsed,
            f" (error: {error})" if error else "",
        )

    if "mcp-scan" in tools:
        output = work_dir / f"{target_name.replace('/', '__')}_mcpscan.json"
        findings, elapsed, error = run_mcp_scan(target_path, output)
        result.mcpscan_findings = findings
        result.mcpscan_time_ms = elapsed
        result.mcpscan_error = error
        logger.info(
            "  mcp-scan: %d findings in %.0fms%s",
            len(findings),
            elapsed,
            f" (error: {error})" if error else "",
        )

    if "cisco" in tools:
        output = work_dir / f"{target_name.replace('/', '__')}_cisco.json"
        findings, elapsed, error = run_cisco_scanner(target_path, output)
        result.cisco_findings = findings
        result.cisco_time_ms = elapsed
        result.cisco_error = error
        logger.info(
            "  cisco:    %d findings in %.0fms%s",
            len(findings),
            elapsed,
            f" (error: {error})" if error else "",
        )

    return result


# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------


def generate_feature_matrix() -> str:
    """Generate the static feature comparison matrix."""
    return """
## Feature Comparison Matrix

| Capability | agentsec | mcp-scan | Cisco MCP Scanner |
|-----------|:--------:|:--------:|:-----------------:|
| **Detection Scope** | | | |
| Installation config analysis | Yes (35+ checks) | No | No |
| Skill/plugin AST analysis | Yes (Python) | No | Yes (Python) |
| MCP tool poisoning | Yes | Yes | Yes |
| Credential scanning | Yes (34 patterns) | Partial | Partial |
| Rug pull detection | Yes (pin-tools) | Yes (hash) | No |
| Behavioral code analysis | No | No | Yes (interprocedural) |
| Runtime monitoring | No | Yes (proxy) | No |
| **Coverage Model** | | | |
| OWASP Agentic mapping | ASI01-ASI10 | No | No |
| Cross-surface compound risk | Yes (doom combo) | No | No |
| Severity escalation | Yes (context-aware) | No | No |
| **Output** | | | |
| SARIF | Yes | No | Yes |
| JSON | Yes | Yes | Yes |
| Rich terminal | Yes | Yes | Yes |
| **Operations** | | | |
| CI/CD policy engine | Yes (YAML) | No | No |
| Pre-install gate | Yes | No | No |
| Config hardening | Yes (3 profiles) | No | No |
| Filesystem watcher | Yes | No | No |
| **Platform Support** | | | |
| OpenClaw | Yes | No | No |
| Claude Code | Yes | Yes | No |
| Cursor | Yes | Yes | No |
| Windsurf | Yes | Yes | No |
| Gemini CLI | Yes | Yes | No |
| Python version | 3.10+ | 3.10+ | 3.11-3.13 |
"""


def generate_comparison_report(results: list[ComparisonResult], output_path: Path) -> None:
    """Generate full comparison report."""
    output_path.parent.mkdir(parents=True, exist_ok=True)

    lines = [
        "# Scanner Comparison Report",
        "",
        f"> Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        "",
        generate_feature_matrix(),
        "",
        "## Detection Results",
        "",
    ]

    # Aggregate statistics
    total_agentsec = sum(len(r.agentsec_findings) for r in results)
    total_mcpscan = sum(len(r.mcpscan_findings) for r in results)
    total_cisco = sum(len(r.cisco_findings) for r in results)

    lines.extend(
        [
            "### Aggregate Findings",
            "",
            "| Scanner | Total Findings | Repos with Findings | Avg Time (ms) |",
            "|---------|---------------:|--------------------:|--------------:|",
        ]
    )

    def avg_time(results: list[ComparisonResult], attr: str) -> float:
        times = [getattr(r, attr) for r in results if getattr(r, attr) > 0]
        return sum(times) / len(times) if times else 0

    active_agentsec = sum(1 for r in results if r.agentsec_findings)
    active_mcpscan = sum(1 for r in results if r.mcpscan_findings)
    active_cisco = sum(1 for r in results if r.cisco_findings)

    lines.append(
        f"| agentsec | {total_agentsec} | {active_agentsec} | "
        f"{avg_time(results, 'agentsec_time_ms'):.0f} |"
    )
    lines.append(
        f"| mcp-scan | {total_mcpscan} | {active_mcpscan} | "
        f"{avg_time(results, 'mcpscan_time_ms'):.0f} |"
    )
    lines.append(
        f"| Cisco | {total_cisco} | {active_cisco} | {avg_time(results, 'cisco_time_ms'):.0f} |"
    )
    lines.append("")

    # Severity breakdown
    def sev_count(findings: list[ToolFinding], sev: str) -> int:
        return sum(1 for f in findings if f.severity == sev)

    all_agentsec = [f for r in results for f in r.agentsec_findings]
    all_mcpscan = [f for r in results for f in r.mcpscan_findings]
    all_cisco = [f for r in results for f in r.cisco_findings]

    lines.extend(
        [
            "### Severity Breakdown",
            "",
            "| Severity | agentsec | mcp-scan | Cisco |",
            "|----------|--------:|--------:|------:|",
        ]
    )
    for sev in ["critical", "high", "medium", "low", "info"]:
        lines.append(
            f"| {sev.upper()} | {sev_count(all_agentsec, sev)} | "
            f"{sev_count(all_mcpscan, sev)} | {sev_count(all_cisco, sev)} |"
        )
    lines.append("")

    # Per-target breakdown
    lines.extend(
        [
            "### Per-Target Results",
            "",
            "| Target | agentsec | mcp-scan | Cisco | Unique to agentsec |",
            "|--------|--------:|--------:|------:|-------------------:|",
        ]
    )
    for r in results:
        # Rough uniqueness: agentsec findings not in other tools
        other_titles = {f.title.lower() for f in r.mcpscan_findings + r.cisco_findings}
        unique = sum(1 for f in r.agentsec_findings if f.title.lower() not in other_titles)

        lines.append(
            f"| {r.target} | {len(r.agentsec_findings)} | "
            f"{len(r.mcpscan_findings)} | {len(r.cisco_findings)} | {unique} |"
        )
    lines.append("")

    # Key differentiators
    lines.extend(
        [
            "## Key Differentiators",
            "",
            "### agentsec Unique Capabilities",
            "- **4-surface coverage**: installation + skill + MCP + credential in one tool",
            "- **OWASP Agentic mapping**: All findings mapped to ASI01-ASI10",
            "- **Cross-surface compound risk**: Doom combo detection "
            "when multiple surfaces are compromised",
            "- **Policy-as-code**: YAML-based CI/CD enforcement engine",
            "- **Pre-install gate**: Scan packages before installation",
            "- **Context-aware severity**: Test/doc files get downgraded findings",
            "",
            "### mcp-scan Unique Capabilities",
            "- **Runtime proxy**: Intercepts live MCP protocol traffic",
            "- **Real-time enforcement**: Blocks malicious operations (not just detection)",
            "- **Rug pull detection**: Hash-based tool description integrity monitoring",
            "",
            "### Cisco Unique Capabilities",
            "- **Behavioral code analysis**: Interprocedural dataflow tracking",
            "- **Cross-boundary deception**: Detects hidden behavior in helper functions",
            "- **Docstring vs implementation**: Verifies tool behavior matches documentation",
            "",
        ]
    )

    output_path.write_text("\n".join(lines), encoding="utf-8")
    logger.info("Report written to %s", output_path)

    # Also save raw JSON for further analysis
    json_path = output_path.with_suffix(".json")
    json_data = [asdict(r) for r in results]
    json_path.write_text(json.dumps(json_data, indent=2, default=str), encoding="utf-8")
    logger.info("Raw data written to %s", json_path)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Compare agentsec with other MCP security scanners"
    )
    parser.add_argument("--repo", help="Single GitHub repo to compare (owner/name)")
    parser.add_argument("--repo-list", type=Path, help="CSV file with repos")
    parser.add_argument("--fixtures", type=Path, help="Local directory with test fixtures")
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("docs/scanner-comparison.md"),
        help="Output report path",
    )
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
    )

    # Detect available tools
    available_tools = []
    for tool in ["agentsec", "mcp-scan", "cisco"]:
        tool_name = "cisco-mcp-scanner" if tool == "cisco" else tool
        if check_tool_available(tool_name):
            logger.info("Found: %s", tool)
            available_tools.append(tool)
        else:
            logger.warning("Not found: %s (will be skipped)", tool)

    if "agentsec" not in available_tools:
        logger.error("agentsec is required for comparison")
        sys.exit(1)

    results: list[ComparisonResult] = []

    with tempfile.TemporaryDirectory(prefix="agentsec_compare_") as work_dir:
        work_path = Path(work_dir)

        if args.fixtures:
            # Scan local fixtures directory
            logger.info("Scanning fixtures at %s", args.fixtures)
            result = compare_single_target(
                args.fixtures, args.fixtures.name, work_path, available_tools
            )
            results.append(result)

        elif args.repo:
            # Clone and scan a single repo
            repo_dir = work_path / args.repo.replace("/", "__")
            url = f"https://github.com/{args.repo}.git"
            logger.info("Cloning %s...", args.repo)
            clone = subprocess.run(
                ["git", "clone", "--depth", "1", url, str(repo_dir)],
                capture_output=True,
                text=True,
                timeout=120,
            )
            if clone.returncode != 0:
                logger.error("Clone failed: %s", clone.stderr[:200])
                sys.exit(1)

            result = compare_single_target(repo_dir, args.repo, work_path, available_tools)
            results.append(result)

        elif args.repo_list:
            import csv

            with open(args.repo_list, newline="", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                repos = list(reader)

            for i, row in enumerate(repos[:20], 1):  # Limit to 20 for comparison
                name = row.get("owner", "") + "/" + row.get("name", "")
                if not name.strip("/"):
                    name = row.get("repo", row.get("target_id", "unknown"))
                url = row.get("url", f"https://github.com/{name}.git")

                logger.info("[%d/%d] %s", i, min(len(repos), 20), name)
                repo_dir = work_path / name.replace("/", "__")

                try:
                    clone = subprocess.run(
                        ["git", "clone", "--depth", "1", url, str(repo_dir)],
                        capture_output=True,
                        text=True,
                        timeout=120,
                    )
                    if clone.returncode != 0:
                        logger.warning("Skip %s: clone failed", name)
                        continue

                    result = compare_single_target(repo_dir, name, work_path, available_tools)
                    results.append(result)
                finally:
                    shutil.rmtree(repo_dir, ignore_errors=True)
        else:
            # Default: generate feature matrix only
            logger.info("No targets specified — generating feature matrix only")

    generate_comparison_report(results, args.output)
    logger.info("Comparison complete: %d targets analyzed", len(results))


if __name__ == "__main__":
    main()
