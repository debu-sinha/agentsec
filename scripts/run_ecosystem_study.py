#!/usr/bin/env python3
"""Ecosystem study runner for MCP server security analysis.

Discovers MCP server repositories on GitHub, clones them, runs agentsec
against each, and produces structured results for the conference paper.

Usage:
    # Discover and scan top N MCP servers by stars
    python scripts/run_ecosystem_study.py --discover --limit 200

    # Scan from a pre-built repo list
    python scripts/run_ecosystem_study.py --repo-list repos.csv

    # Resume a previous run (skip already-scanned repos)
    python scripts/run_ecosystem_study.py --repo-list repos.csv --resume

    # Generate aggregate report from existing results
    python scripts/run_ecosystem_study.py --aggregate-only --results-dir results/
"""

from __future__ import annotations

import argparse
import csv
import json
import logging
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)

# Curated list of popular AI agent platforms and frameworks.
# These exercise all 4 scanner surfaces (installation, skill, MCP, credential).
AGENT_PLATFORM_REPOS: list[dict[str, str | int]] = [
    {
        "owner": "openclaw",
        "name": "openclaw",
        "url": "https://github.com/openclaw/openclaw.git",
        "stars": 0,
    },
    {
        "owner": "anthropics",
        "name": "claude-code",
        "url": "https://github.com/anthropics/claude-code.git",
        "stars": 0,
    },
    {
        "owner": "getcursor",
        "name": "cursor",
        "url": "https://github.com/getcursor/cursor.git",
        "stars": 0,
    },
    {
        "owner": "langchain-ai",
        "name": "langchain",
        "url": "https://github.com/langchain-ai/langchain.git",
        "stars": 0,
    },
    {
        "owner": "microsoft",
        "name": "autogen",
        "url": "https://github.com/microsoft/autogen.git",
        "stars": 0,
    },
    {
        "owner": "crewAIInc",
        "name": "crewAI",
        "url": "https://github.com/crewAIInc/crewAI.git",
        "stars": 0,
    },
    {
        "owner": "phidatahq",
        "name": "phidata",
        "url": "https://github.com/phidatahq/phidata.git",
        "stars": 0,
    },
    {
        "owner": "BerriAI",
        "name": "litellm",
        "url": "https://github.com/BerriAI/litellm.git",
        "stars": 0,
    },
    {
        "owner": "run-llama",
        "name": "llama_index",
        "url": "https://github.com/run-llama/llama_index.git",
        "stars": 0,
    },
    {
        "owner": "openai",
        "name": "openai-agents-python",
        "url": "https://github.com/openai/openai-agents-python.git",
        "stars": 0,
    },
    {
        "owner": "pydantic",
        "name": "pydantic-ai",
        "url": "https://github.com/pydantic/pydantic-ai.git",
        "stars": 0,
    },
    {
        "owner": "anthropics",
        "name": "anthropic-cookbook",
        "url": "https://github.com/anthropics/anthropic-cookbook.git",
        "stars": 0,
    },
    {
        "owner": "modelcontextprotocol",
        "name": "servers",
        "url": "https://github.com/modelcontextprotocol/servers.git",
        "stars": 0,
    },
    {
        "owner": "getzep",
        "name": "graphiti",
        "url": "https://github.com/getzep/graphiti.git",
        "stars": 0,
    },
    {
        "owner": "livekit",
        "name": "agents",
        "url": "https://github.com/livekit/agents.git",
        "stars": 0,
    },
]

# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass
class RepoInfo:
    """Metadata for a single repository."""

    owner: str
    name: str
    stars: int
    url: str
    default_branch: str = "main"
    description: str = ""
    language: str = ""
    topics: list[str] = field(default_factory=list)
    last_push: str = ""
    size_kb: int = 0

    @property
    def full_name(self) -> str:
        return f"{self.owner}/{self.name}"


@dataclass
class ScanResult:
    """Results from scanning a single repository."""

    repo: str
    url: str
    stars: int
    scan_time_ms: float
    total_findings: int
    critical: int
    high: int
    medium: int
    low: int
    info: int
    posture_score: float
    posture_grade: str
    findings_by_scanner: dict[str, int] = field(default_factory=dict)
    findings_by_owasp: dict[str, int] = field(default_factory=dict)
    error: str | None = None
    scanned_at: str = ""


@dataclass
class AggregateStats:
    """Aggregate statistics across all scanned repos."""

    total_repos: int
    successful_scans: int
    failed_scans: int
    total_findings: int
    findings_by_severity: dict[str, int] = field(default_factory=dict)
    findings_by_owasp: dict[str, int] = field(default_factory=dict)
    findings_by_scanner: dict[str, int] = field(default_factory=dict)
    repos_with_critical: int = 0
    repos_with_high: int = 0
    avg_findings_per_repo: float = 0.0
    median_findings_per_repo: float = 0.0
    avg_posture_score: float = 0.0
    grade_distribution: dict[str, int] = field(default_factory=dict)
    top_repos_by_findings: list[dict] = field(default_factory=list)
    scan_date: str = ""
    scanner_version: str = ""


# ---------------------------------------------------------------------------
# GitHub discovery
# ---------------------------------------------------------------------------


def discover_mcp_repos(limit: int = 200, token: str | None = None) -> list[RepoInfo]:
    """Discover MCP server repositories on GitHub using gh CLI."""
    repos: dict[str, RepoInfo] = {}

    search_queries = [
        "mcp-server in:name",
        "mcp server in:description topic:mcp",
        "model-context-protocol in:name,description",
        "topic:mcp-server",
        "topic:model-context-protocol",
        "mcp in:name language:TypeScript",
        "mcp in:name language:Python",
    ]

    for query in search_queries:
        logger.info("Searching: %s", query)
        try:
            cmd = [
                "gh",
                "api",
                "search/repositories",
                "--method",
                "GET",
                "-f",
                f"q={query}",
                "-f",
                "sort=stars",
                "-f",
                "order=desc",
                "-f",
                "per_page=100",
                "--jq",
                ".items[] | {"
                + '"owner": .owner.login, "name": .name, "stars": .stargazers_count, '
                + '"url": .clone_url, "default_branch": .default_branch, '
                + '"description": (.description // ""), "language": (.language // ""), '
                + '"topics": (.topics // []), "last_push": .pushed_at, "size_kb": .size'
                + "}",
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if result.returncode != 0:
                logger.warning("Search failed for %r: %s", query, result.stderr[:200])
                continue

            for line in result.stdout.strip().splitlines():
                if not line.strip():
                    continue
                try:
                    data = json.loads(line)
                    key = f"{data['owner']}/{data['name']}"
                    if key not in repos:
                        repos[key] = RepoInfo(
                            owner=data["owner"],
                            name=data["name"],
                            stars=data["stars"],
                            url=data["url"],
                            default_branch=data.get("default_branch", "main"),
                            description=data.get("description", ""),
                            language=data.get("language", ""),
                            topics=data.get("topics", []),
                            last_push=data.get("last_push", ""),
                            size_kb=data.get("size_kb", 0),
                        )
                except (json.JSONDecodeError, KeyError) as e:
                    logger.debug("Skipping malformed result: %s", e)

        except subprocess.TimeoutExpired:
            logger.warning("Search timed out for %r", query)
        except FileNotFoundError:
            logger.error("gh CLI not found — install from https://cli.github.com/")
            sys.exit(2)

        # Rate limit protection
        time.sleep(2)

    # Sort by stars, take top N
    sorted_repos = sorted(repos.values(), key=lambda r: r.stars, reverse=True)
    logger.info("Discovered %d unique repos, taking top %d", len(sorted_repos), limit)
    return sorted_repos[:limit]


def load_repo_list(csv_path: Path) -> list[RepoInfo]:
    """Load repository list from a CSV file."""
    repos = []
    with open(csv_path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            repos.append(
                RepoInfo(
                    owner=row.get("owner", row.get("repo", "").split("/")[0]),
                    name=row.get("name", row.get("repo", "").split("/")[-1]),
                    stars=int(row.get("stars", 0)),
                    url=row.get("url", f"https://github.com/{row.get('repo', '')}.git"),
                    description=row.get("description", ""),
                    language=row.get("language", ""),
                )
            )
    return repos


def save_repo_list(repos: list[RepoInfo], csv_path: Path) -> None:
    """Save repository list to CSV for reproducibility."""
    csv_path.parent.mkdir(parents=True, exist_ok=True)
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "owner",
                "name",
                "stars",
                "url",
                "description",
                "language",
                "topics",
                "last_push",
                "size_kb",
            ],
        )
        writer.writeheader()
        for repo in repos:
            writer.writerow(
                {
                    "owner": repo.owner,
                    "name": repo.name,
                    "stars": repo.stars,
                    "url": repo.url,
                    "description": repo.description,
                    "language": repo.language,
                    "topics": ";".join(repo.topics),
                    "last_push": repo.last_push,
                    "size_kb": repo.size_kb,
                }
            )
    logger.info("Saved %d repos to %s", len(repos), csv_path)


# ---------------------------------------------------------------------------
# Scanning
# ---------------------------------------------------------------------------


def clone_repo(repo: RepoInfo, target_dir: Path, shallow: bool = True) -> bool:
    """Clone a repository to the target directory."""
    cmd = ["git", "clone", "--single-branch"]
    if shallow:
        cmd.extend(["--depth", "1"])
    cmd.extend([repo.url, str(target_dir)])

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120,
            env={"GIT_TERMINAL_PROMPT": "0", **__import__("os").environ},
        )
        return result.returncode == 0
    except subprocess.TimeoutExpired:
        logger.warning("Clone timed out for %s", repo.full_name)
        return False


def scan_repo(repo_dir: Path, output_file: Path) -> tuple[float, int]:
    """Run agentsec scan on a repository. Returns (scan_time_ms, exit_code)."""
    start = time.perf_counter()
    try:
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "agentsec",
                "scan",
                str(repo_dir),
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
        )
        elapsed_ms = (time.perf_counter() - start) * 1000
        return elapsed_ms, result.returncode
    except subprocess.TimeoutExpired:
        elapsed_ms = (time.perf_counter() - start) * 1000
        return elapsed_ms, -1


def parse_scan_output(output_file: Path, repo: RepoInfo, scan_time_ms: float) -> ScanResult:
    """Parse agentsec JSON output into a ScanResult."""
    try:
        data = json.loads(output_file.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, FileNotFoundError) as e:
        return ScanResult(
            repo=repo.full_name,
            url=repo.url,
            stars=repo.stars,
            scan_time_ms=scan_time_ms,
            total_findings=0,
            critical=0,
            high=0,
            medium=0,
            low=0,
            info=0,
            posture_score=0.0,
            posture_grade="?",
            error=str(e),
            scanned_at=datetime.now(timezone.utc).isoformat(),
        )

    findings = data.get("findings", [])
    posture = data.get("posture", {})

    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    scanner_counts: dict[str, int] = {}
    owasp_counts: dict[str, int] = {}

    for f in findings:
        sev = f.get("severity", "info").lower()
        sev_counts[sev] = sev_counts.get(sev, 0) + 1

        scanner = f.get("scanner", "unknown")
        scanner_counts[scanner] = scanner_counts.get(scanner, 0) + 1

        owasp = f.get("owasp_category", f.get("category", "unknown"))
        owasp_counts[owasp] = owasp_counts.get(owasp, 0) + 1

    return ScanResult(
        repo=repo.full_name,
        url=repo.url,
        stars=repo.stars,
        scan_time_ms=scan_time_ms,
        total_findings=len(findings),
        critical=sev_counts["critical"],
        high=sev_counts["high"],
        medium=sev_counts["medium"],
        low=sev_counts["low"],
        info=sev_counts["info"],
        posture_score=posture.get("overall_score", 0.0),
        posture_grade=posture.get("grade", "?"),
        findings_by_scanner=scanner_counts,
        findings_by_owasp=owasp_counts,
        scanned_at=datetime.now(timezone.utc).isoformat(),
    )


def scan_single_repo(
    repo: RepoInfo,
    results_dir: Path,
    work_dir: Path,
) -> ScanResult:
    """Clone, scan, and collect results for a single repo."""
    repo_dir = work_dir / f"{repo.owner}__{repo.name}"
    output_file = results_dir / f"{repo.owner}__{repo.name}.json"

    logger.info("[%s] cloning...", repo.full_name)
    if not clone_repo(repo, repo_dir):
        return ScanResult(
            repo=repo.full_name,
            url=repo.url,
            stars=repo.stars,
            scan_time_ms=0,
            total_findings=0,
            critical=0,
            high=0,
            medium=0,
            low=0,
            info=0,
            posture_score=0.0,
            posture_grade="?",
            error="clone failed",
            scanned_at=datetime.now(timezone.utc).isoformat(),
        )

    logger.info("[%s] scanning...", repo.full_name)
    scan_time_ms, exit_code = scan_repo(repo_dir, output_file)

    if exit_code == -1:
        result = ScanResult(
            repo=repo.full_name,
            url=repo.url,
            stars=repo.stars,
            scan_time_ms=scan_time_ms,
            total_findings=0,
            critical=0,
            high=0,
            medium=0,
            low=0,
            info=0,
            posture_score=0.0,
            posture_grade="?",
            error="scan timed out",
            scanned_at=datetime.now(timezone.utc).isoformat(),
        )
    else:
        result = parse_scan_output(output_file, repo, scan_time_ms)

    # Clean up cloned repo to save disk space
    shutil.rmtree(repo_dir, ignore_errors=True)

    severity_str = (
        f"C={result.critical} H={result.high} M={result.medium} L={result.low} I={result.info}"
    )
    logger.info(
        "[%s] done: %d findings (%s) in %.0fms",
        repo.full_name,
        result.total_findings,
        severity_str,
        scan_time_ms,
    )
    return result


# ---------------------------------------------------------------------------
# Aggregation
# ---------------------------------------------------------------------------


def compute_aggregate(results: list[ScanResult], scanner_version: str = "") -> AggregateStats:
    """Compute aggregate statistics from scan results."""
    successful = [r for r in results if r.error is None]
    failed = [r for r in results if r.error is not None]

    all_findings_counts = [r.total_findings for r in successful]
    all_findings_counts.sort()

    sev_totals = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    owasp_totals: dict[str, int] = {}
    scanner_totals: dict[str, int] = {}
    grade_dist: dict[str, int] = {}

    for r in successful:
        sev_totals["critical"] += r.critical
        sev_totals["high"] += r.high
        sev_totals["medium"] += r.medium
        sev_totals["low"] += r.low
        sev_totals["info"] += r.info

        for k, v in r.findings_by_owasp.items():
            owasp_totals[k] = owasp_totals.get(k, 0) + v
        for k, v in r.findings_by_scanner.items():
            scanner_totals[k] = scanner_totals.get(k, 0) + v

        grade_dist[r.posture_grade] = grade_dist.get(r.posture_grade, 0) + 1

    n = len(successful)
    median_idx = n // 2
    median_val = all_findings_counts[median_idx] if n > 0 else 0.0

    top_repos = sorted(successful, key=lambda r: r.total_findings, reverse=True)[:20]

    return AggregateStats(
        total_repos=len(results),
        successful_scans=len(successful),
        failed_scans=len(failed),
        total_findings=sum(sev_totals.values()),
        findings_by_severity=sev_totals,
        findings_by_owasp=dict(sorted(owasp_totals.items(), key=lambda x: -x[1])),
        findings_by_scanner=dict(sorted(scanner_totals.items(), key=lambda x: -x[1])),
        repos_with_critical=sum(1 for r in successful if r.critical > 0),
        repos_with_high=sum(1 for r in successful if r.high > 0),
        avg_findings_per_repo=sum(all_findings_counts) / n if n else 0.0,
        median_findings_per_repo=median_val,
        avg_posture_score=sum(r.posture_score for r in successful) / n if n else 0.0,
        grade_distribution=dict(sorted(grade_dist.items())),
        top_repos_by_findings=[
            {"repo": r.repo, "findings": r.total_findings, "critical": r.critical, "high": r.high}
            for r in top_repos
        ],
        scan_date=datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        scanner_version=scanner_version,
    )


def generate_cross_surface_analysis(results: list[ScanResult]) -> dict:
    """Analyze correlations across scanner surfaces (unique to 4-scanner model).

    This is the key differentiator vs single-surface tools like mcp-scan.
    """
    successful = [r for r in results if r.error is None]
    analysis = {
        "compound_risk_repos": [],
        "surface_correlation": {},
        "doom_combo_candidates": [],
    }

    for r in successful:
        surfaces_hit = set(r.findings_by_scanner.keys())
        if len(surfaces_hit) >= 3:
            analysis["compound_risk_repos"].append(
                {
                    "repo": r.repo,
                    "surfaces": sorted(surfaces_hit),
                    "total_findings": r.total_findings,
                    "critical": r.critical,
                    "high": r.high,
                }
            )

        # Track credential + MCP co-occurrence (supply chain + secrets)
        has_cred = r.findings_by_scanner.get("credential", 0) > 0
        has_mcp = r.findings_by_scanner.get("mcp", 0) > 0

        if has_cred and has_mcp:
            analysis["doom_combo_candidates"].append(
                {
                    "repo": r.repo,
                    "pattern": "credential_exposure + mcp_risk",
                    "credential_findings": r.findings_by_scanner.get("credential", 0),
                    "mcp_findings": r.findings_by_scanner.get("mcp", 0),
                }
            )

    # Surface co-occurrence matrix
    surface_pairs = [
        ("credential", "mcp"),
        ("credential", "skill"),
        ("credential", "installation"),
        ("mcp", "skill"),
        ("mcp", "installation"),
        ("skill", "installation"),
    ]
    for a, b in surface_pairs:
        both = sum(
            1
            for r in successful
            if r.findings_by_scanner.get(a, 0) > 0 and r.findings_by_scanner.get(b, 0) > 0
        )
        either = sum(
            1
            for r in successful
            if r.findings_by_scanner.get(a, 0) > 0 or r.findings_by_scanner.get(b, 0) > 0
        )
        analysis["surface_correlation"][f"{a}+{b}"] = {
            "both": both,
            "either": either,
            "jaccard": round(both / either, 3) if either > 0 else 0.0,
        }

    return analysis


# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------


def save_results(
    results: list[ScanResult],
    aggregate: AggregateStats,
    cross_surface: dict,
    output_dir: Path,
) -> None:
    """Save all results to structured files."""
    output_dir.mkdir(parents=True, exist_ok=True)
    date_str = datetime.now(timezone.utc).strftime("%Y%m%d")

    # Individual results as JSONL
    jsonl_path = output_dir / f"findings_{date_str}.jsonl"
    with open(jsonl_path, "w", encoding="utf-8") as f:
        for r in results:
            f.write(json.dumps(asdict(r), default=str) + "\n")
    logger.info("Saved %d results to %s", len(results), jsonl_path)

    # Aggregate summary
    summary_path = output_dir / f"summary_{date_str}.json"
    with open(summary_path, "w", encoding="utf-8") as f:
        json.dump(asdict(aggregate), f, indent=2, default=str)
    logger.info("Saved aggregate to %s", summary_path)

    # Cross-surface analysis
    cross_path = output_dir / f"cross_surface_{date_str}.json"
    with open(cross_path, "w", encoding="utf-8") as f:
        json.dump(cross_surface, f, indent=2, default=str)
    logger.info("Saved cross-surface analysis to %s", cross_path)

    # CSV for easy spreadsheet analysis
    csv_path = output_dir / f"results_{date_str}.csv"
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "repo",
                "stars",
                "total_findings",
                "critical",
                "high",
                "medium",
                "low",
                "info",
                "posture_score",
                "posture_grade",
                "scan_time_ms",
                "error",
            ],
        )
        writer.writeheader()
        for r in results:
            writer.writerow(
                {
                    "repo": r.repo,
                    "stars": r.stars,
                    "total_findings": r.total_findings,
                    "critical": r.critical,
                    "high": r.high,
                    "medium": r.medium,
                    "low": r.low,
                    "info": r.info,
                    "posture_score": round(r.posture_score, 1),
                    "posture_grade": r.posture_grade,
                    "scan_time_ms": round(r.scan_time_ms, 1),
                    "error": r.error or "",
                }
            )
    logger.info("Saved CSV to %s", csv_path)


def print_summary(aggregate: AggregateStats, cross_surface: dict) -> None:
    """Print a human-readable summary to stdout."""
    print("\n" + "=" * 70)
    print("ECOSYSTEM STUDY RESULTS")
    print("=" * 70)
    print(f"Date: {aggregate.scan_date}")
    print(f"Scanner: agentsec {aggregate.scanner_version}")
    print(f"Repos scanned: {aggregate.successful_scans}/{aggregate.total_repos}")
    print(f"Failed: {aggregate.failed_scans}")
    print()

    print("SEVERITY DISTRIBUTION")
    print("-" * 40)
    for sev, count in aggregate.findings_by_severity.items():
        print(f"  {sev.upper():>10}: {count:>5}")
    print(f"  {'TOTAL':>10}: {aggregate.total_findings:>5}")
    print()

    print(f"Repos with CRITICAL: {aggregate.repos_with_critical}")
    print(f"Repos with HIGH:     {aggregate.repos_with_high}")
    print(f"Avg findings/repo:   {aggregate.avg_findings_per_repo:.1f}")
    print(f"Median findings:     {aggregate.median_findings_per_repo:.0f}")
    print(f"Avg posture score:   {aggregate.avg_posture_score:.1f}")
    print()

    print("GRADE DISTRIBUTION")
    print("-" * 40)
    for grade, count in sorted(aggregate.grade_distribution.items()):
        bar = "#" * count
        print(f"  {grade}: {count:>3} {bar}")
    print()

    print("TOP 10 REPOS BY FINDINGS")
    print("-" * 60)
    for i, r in enumerate(aggregate.top_repos_by_findings[:10], 1):
        print(f"  {i:>2}. {r['repo']:<40} {r['findings']:>4} (C={r['critical']} H={r['high']})")
    print()

    print("CROSS-SURFACE ANALYSIS (unique to 4-scanner model)")
    print("-" * 60)
    print(
        f"  Compound risk repos (3+ surfaces): {len(cross_surface.get('compound_risk_repos', []))}"
    )
    print(
        "  Doom combo candidates (cred+MCP):  "
        f"{len(cross_surface.get('doom_combo_candidates', []))}"
    )
    for pair, stats in cross_surface.get("surface_correlation", {}).items():
        print(f"  {pair:<25} Jaccard={stats['jaccard']:.2f} (both={stats['both']})")
    print("=" * 70)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def get_scanner_version() -> str:
    """Get the installed agentsec version."""
    try:
        result = subprocess.run(
            [sys.executable, "-m", "agentsec", "--version"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        return result.stdout.strip().split()[-1] if result.returncode == 0 else "unknown"
    except Exception:
        return "unknown"


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run agentsec ecosystem study on MCP server repositories"
    )
    parser.add_argument(
        "--discover",
        action="store_true",
        help="Discover MCP repos from GitHub (requires gh CLI)",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=200,
        help="Max repos to discover (default: 200)",
    )
    parser.add_argument(
        "--repo-list",
        type=Path,
        help="CSV file with repo list (skip discovery)",
    )
    parser.add_argument(
        "--results-dir",
        type=Path,
        default=Path("docs/ecosystem-study/data"),
        help="Directory for results output",
    )
    parser.add_argument(
        "--resume",
        action="store_true",
        help="Skip repos that already have results",
    )
    parser.add_argument(
        "--aggregate-only",
        action="store_true",
        help="Only compute aggregates from existing JSONL",
    )
    parser.add_argument(
        "--include-agents",
        action="store_true",
        help="Include curated list of popular AI agent platforms/frameworks",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable debug logging",
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
    )

    scanner_version = get_scanner_version()
    logger.info("agentsec version: %s", scanner_version)

    results_dir = args.results_dir
    results_dir.mkdir(parents=True, exist_ok=True)

    # Aggregate-only mode
    if args.aggregate_only:
        jsonl_files = sorted(results_dir.glob("findings_*.jsonl"))
        if not jsonl_files:
            logger.error("No JSONL files found in %s", results_dir)
            sys.exit(1)

        latest = jsonl_files[-1]
        logger.info("Loading results from %s", latest)
        results = []
        with open(latest, encoding="utf-8") as f:
            for line in f:
                data = json.loads(line)
                results.append(
                    ScanResult(
                        repo=data["repo"],
                        url=data.get("url", ""),
                        stars=data.get("stars", 0),
                        scan_time_ms=data.get("scan_time_ms", 0),
                        total_findings=data.get("total_findings", 0),
                        critical=data.get("critical", 0),
                        high=data.get("high", 0),
                        medium=data.get("medium", 0),
                        low=data.get("low", 0),
                        info=data.get("info", 0),
                        posture_score=data.get("posture_score", 0),
                        posture_grade=data.get("posture_grade", "?"),
                        findings_by_scanner=data.get("findings_by_scanner", {}),
                        findings_by_owasp=data.get("findings_by_owasp", {}),
                        error=data.get("error"),
                        scanned_at=data.get("scanned_at", ""),
                    )
                )

        aggregate = compute_aggregate(results, scanner_version)
        cross_surface = generate_cross_surface_analysis(results)
        save_results(results, aggregate, cross_surface, results_dir)
        print_summary(aggregate, cross_surface)
        return

    # Discover or load repos
    if args.discover:
        repos = discover_mcp_repos(limit=args.limit)
        repo_csv = results_dir / "repos.csv"
        save_repo_list(repos, repo_csv)
    elif args.repo_list:
        repos = load_repo_list(args.repo_list)
    else:
        logger.error("Specify --discover or --repo-list")
        sys.exit(2)

    # Optionally include curated agent platform repos
    if args.include_agents:
        existing_names = {r.full_name for r in repos}
        for entry in AGENT_PLATFORM_REPOS:
            name = f"{entry['owner']}/{entry['name']}"
            if name not in existing_names:
                repos.append(
                    RepoInfo(
                        owner=str(entry["owner"]),
                        name=str(entry["name"]),
                        stars=int(entry.get("stars", 0)),
                        url=str(entry["url"]),
                    )
                )
                existing_names.add(name)
        logger.info("Added agent platforms — total repos: %d", len(repos))

    if not repos:
        logger.error("No repositories to scan")
        sys.exit(1)

    logger.info("Scanning %d repositories...", len(repos))

    # Check for existing results (resume mode)
    already_scanned: set[str] = set()
    existing_results: list[ScanResult] = []
    if args.resume:
        jsonl_files = sorted(results_dir.glob("findings_*.jsonl"))
        if jsonl_files:
            with open(jsonl_files[-1], encoding="utf-8") as f:
                for line in f:
                    data = json.loads(line)
                    already_scanned.add(data["repo"])
                    existing_results.append(
                        ScanResult(
                            repo=data["repo"],
                            url=data.get("url", ""),
                            stars=data.get("stars", 0),
                            scan_time_ms=data.get("scan_time_ms", 0),
                            total_findings=data.get("total_findings", 0),
                            critical=data.get("critical", 0),
                            high=data.get("high", 0),
                            medium=data.get("medium", 0),
                            low=data.get("low", 0),
                            info=data.get("info", 0),
                            posture_score=data.get("posture_score", 0),
                            posture_grade=data.get("posture_grade", "?"),
                            findings_by_scanner=data.get("findings_by_scanner", {}),
                            findings_by_owasp=data.get("findings_by_owasp", {}),
                            error=data.get("error"),
                            scanned_at=data.get("scanned_at", ""),
                        )
                    )
            logger.info("Resuming: %d repos already scanned", len(already_scanned))

    # Scan repos
    results = list(existing_results)
    scan_output_dir = results_dir / "raw"
    scan_output_dir.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="agentsec_study_") as work_dir:
        work_path = Path(work_dir)
        to_scan = [r for r in repos if r.full_name not in already_scanned]
        logger.info(
            "Scanning %d repos (%d skipped from resume)", len(to_scan), len(already_scanned)
        )

        for i, repo in enumerate(to_scan, 1):
            logger.info("[%d/%d] Processing %s (★%d)", i, len(to_scan), repo.full_name, repo.stars)
            result = scan_single_repo(repo, scan_output_dir, work_path)
            results.append(result)

            # Periodic checkpoint (every 10 repos)
            if i % 10 == 0:
                logger.info("Checkpoint: %d/%d complete", i, len(to_scan))
                aggregate = compute_aggregate(results, scanner_version)
                cross_surface = generate_cross_surface_analysis(results)
                save_results(results, aggregate, cross_surface, results_dir)

    # Final save
    aggregate = compute_aggregate(results, scanner_version)
    cross_surface = generate_cross_surface_analysis(results)
    save_results(results, aggregate, cross_surface, results_dir)
    print_summary(aggregate, cross_surface)

    logger.info("Study complete: %d repos scanned", len(results))


if __name__ == "__main__":
    main()
