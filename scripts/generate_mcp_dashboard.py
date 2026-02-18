"""Generate the MCP Ecosystem Security Dashboard.

Reads scan results (JSONL + selection CSV) and produces a visual markdown
dashboard at docs/mcp-security-grades.md.

Can also run fresh scans when called with --scan flag.

Usage:
    python scripts/generate_mcp_dashboard.py                    # from existing data
    python scripts/generate_mcp_dashboard.py --scan             # fresh scan + dashboard
    python scripts/generate_mcp_dashboard.py --date 20260215    # specific snapshot
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


# ---------------------------------------------------------------------------
# Grade computation
# ---------------------------------------------------------------------------


def compute_score(critical: int, high: int, medium: int, low: int) -> int:
    """Compute a 0-100 security score from severity counts.

    Uses the same formula as the OWASP scorer (owasp_scorer.py):
    critical*15, high*7, medium*3, low*1 (LOW capped at 15), floor=5.
    """
    raw = 100 - (critical * 15) - (high * 7) - (medium * 3) - min(low * 1, 15)
    return max(5, min(100, raw))


def score_to_grade(score: int) -> str:
    """Convert score to letter grade (matches owasp_scorer._score_to_grade)."""
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 60:
        return "D"
    return "F"


GRADE_COLORS = {"A": "brightgreen", "B": "green", "C": "yellow", "D": "orange", "F": "red"}
GRADE_EMOJI = {
    "A": "\u2705",
    "B": "\U0001f7e2",
    "C": "\U0001f7e1",
    "D": "\U0001f7e0",
    "F": "\U0001f534",
}
SEV_EMOJI = {
    "critical": "\U0001f534",
    "high": "\U0001f7e0",
    "medium": "\U0001f7e1",
    "low": "\U0001f7e2",
    "info": "\U0001f535",
}


# ---------------------------------------------------------------------------
# Data loading
# ---------------------------------------------------------------------------


def load_selection(csv_path: Path) -> dict[str, dict]:
    """Load target metadata keyed by target_id."""
    targets = {}
    with csv_path.open(encoding="utf-8") as f:
        for row in csv.DictReader(f):
            targets[row["target_id"]] = row
    return targets


def load_findings(jsonl_path: Path) -> list[dict]:
    findings = []
    with jsonl_path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                findings.append(json.loads(line))
    return findings


def aggregate_by_target(findings: list[dict]) -> dict[str, dict]:
    """Group findings by target_id and compute per-target metrics."""
    targets: dict[str, dict] = {}
    for f in findings:
        tid = f["target_id"]
        if tid not in targets:
            targets[tid] = {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "info": 0,
                "total": 0,
                "categories": {},
            }
        t = targets[tid]
        sev = f.get("severity", "info").lower()
        if sev in t:
            t[sev] += 1
        t["total"] += 1
        cat = f.get("category", "other")
        t["categories"][cat] = t["categories"].get(cat, 0) + 1
    return targets


# ---------------------------------------------------------------------------
# Dashboard rendering
# ---------------------------------------------------------------------------


def render_dashboard(
    targets_meta: dict[str, dict],
    targets_findings: dict[str, dict],
    snapshot_date: str,
    total_findings: int,
) -> str:
    """Render the full markdown dashboard."""

    # Build per-target rows
    rows = []
    for tid, meta in targets_meta.items():
        stats = targets_findings.get(
            tid,
            {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "info": 0,
                "total": 0,
                "categories": {},
            },
        )
        score = compute_score(stats["critical"], stats["high"], stats["medium"], stats["low"])
        grade = score_to_grade(score)
        rows.append(
            {
                "target_id": tid,
                "stars": int(meta.get("stars", 0)),
                "score": score,
                "grade": grade,
                "critical": stats["critical"],
                "high": stats["high"],
                "medium": stats["medium"],
                "low": stats["low"],
                "total": stats["total"],
            }
        )

    rows.sort(key=lambda r: (-r["score"], r["target_id"]))
    total_targets = len(rows)
    avg_score = round(sum(r["score"] for r in rows) / max(total_targets, 1))
    avg_grade = score_to_grade(avg_score)
    grade_dist = {}
    for r in rows:
        grade_dist[r["grade"]] = grade_dist.get(r["grade"], 0) + 1
    targets_clean = sum(1 for r in rows if r["critical"] == 0 and r["high"] == 0)
    targets_critical = sum(1 for r in rows if r["critical"] > 0)

    # Aggregate categories across all targets
    all_cats: dict[str, int] = {}
    for stats in targets_findings.values():
        for cat, count in stats.get("categories", {}).items():
            all_cats[cat] = all_cats.get(cat, 0) + count
    top_cats = sorted(all_cats.items(), key=lambda x: -x[1])[:8]

    # Category display names and primary OWASP mapping
    cat_labels = {
        "exposed_token": "Exposed Token",
        "plaintext_secret": "Plaintext Secret",
        "insecure_default": "Insecure Default",
        "outdated_version": "Outdated Version",
        "dangerous_pattern": "Dangerous Pattern",
        "prompt_injection_vector": "Prompt Injection",
        "data_exfiltration_risk": "Data Exfiltration",
        "config_drift": "Config Drift",
        "tool_poisoning": "Tool Poisoning",
        "exec_risk": "Exec Risk",
        "supply_chain": "Supply Chain",
        "insecure_permissions": "Insecure Permissions",
        "malicious_skill": "Malicious Skill",
        "secret": "Secret",
        "auth": "Auth",
        "config": "Config",
        "other": "Other",
    }
    cat_owasp = {
        "exposed_token": "ASI05",
        "plaintext_secret": "ASI05",
        "exposed_credentials": "ASI05",
        "insecure_default": "ASI02",
        "outdated_version": "ASI03",
        "dangerous_pattern": "ASI02",
        "prompt_injection_vector": "ASI01",
        "data_exfiltration_risk": "ASI05",
        "config_drift": "ASI10",
        "tool_poisoning": "ASI03",
        "exec_risk": "ASI02",
        "supply_chain": "ASI03",
        "insecure_permissions": "ASI05",
        "malicious_skill": "ASI03",
        "missing_auth": "ASI05",
        "network_exposure": "ASI05",
        "mcp_tool_poisoning": "ASI03",
        "mcp_no_auth": "ASI05",
        "mcp_schema_violation": "ASI03",
        "mcp_cross_origin": "ASI05",
        "mcp_excessive_permissions": "ASI02",
    }

    # Severity totals (include info from the aggregated findings data)
    sev_totals = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for r in rows:
        for s in ("critical", "high", "medium", "low"):
            sev_totals[s] += r[s]
    for stats in targets_findings.values():
        sev_totals["info"] += stats.get("info", 0)

    lines = []

    # -- Hero --
    avg_badge_color = GRADE_COLORS.get(avg_grade, "lightgrey")
    lines.append("# MCP Ecosystem Security Dashboard")
    lines.append("")
    grade_badge = (
        f"![Ecosystem Grade](https://img.shields.io/badge/"
        f"Ecosystem_Grade-{avg_grade}-{avg_badge_color}?style=for-the-badge)"
    )
    score_badge = (
        f"![Avg Score](https://img.shields.io/badge/"
        f"Avg_Score-{avg_score}%2F100-{avg_badge_color}?style=for-the-badge)"
    )
    repos_badge = (
        f"![Repos Scanned](https://img.shields.io/badge/"
        f"Repos_Scanned-{total_targets}-blue?style=for-the-badge)"
    )
    date_badge = (
        f"![Last Updated](https://img.shields.io/badge/"
        f"Last_Scan-{snapshot_date}-grey?style=for-the-badge)"
    )
    lines.append(f"{grade_badge} {score_badge} {repos_badge} {date_badge}")
    lines.append("")
    lines.append(
        "Automated weekly security scan of the top MCP server repositories, "
        "powered by [agentsec](https://github.com/debu-sinha/agentsec). "
        "Findings are mapped to the [OWASP Top 10 for Agentic Applications]"
        "(https://owasp.org/www-project-top-10-for-large-language-model-applications/)."
    )
    lines.append("")

    # -- Table of Contents --
    lines.append(
        "**Jump to:** "
        "[Summary](#at-a-glance) | "
        "[Grades](#grade-distribution) | "
        "[Repos Requiring Attention](#repos-requiring-attention) | "
        "[All Repos](#all-scanned-repos) | "
        "[Methodology](#methodology) | "
        "[Disclaimer](#disclaimer)"
    )
    lines.append("")

    # -- Key Risks callout --
    risky_rows = [r for r in rows if r["grade"] in ("C", "D", "F")]
    if risky_rows:
        worst = max(risky_rows, key=lambda r: r["total"])
        lines.append(
            f"> **{len(risky_rows)} repos** scored below B. "
            f"**{worst['target_id']}** alone has "
            f"**{worst['critical']} critical** and "
            f"**{worst['total']} total findings**."
        )
        lines.append("")

    # -- Quick Stats --
    lines.append("## At a Glance")
    lines.append("")
    lines.append("| Metric | Value |")
    lines.append("|--------|------:|")
    lines.append(f"| Repositories scanned | **{total_targets}** |")
    lines.append(f"| Total findings | **{total_findings}** |")
    lines.append(f"| {SEV_EMOJI['critical']} Critical | **{sev_totals['critical']}** |")
    lines.append(f"| {SEV_EMOJI['high']} High | **{sev_totals['high']}** |")
    lines.append(f"| {SEV_EMOJI['medium']} Medium | **{sev_totals['medium']}** |")
    lines.append(f"| {SEV_EMOJI['low']} Low | **{sev_totals['low']}** |")
    lines.append(f"| {SEV_EMOJI['info']} Info | **{sev_totals['info']}** |")
    lines.append(f"| Repos with zero critical/high findings | **{targets_clean}** |")
    lines.append(f"| Repos with critical findings | **{targets_critical}** |")
    lines.append("")

    # -- Grade Distribution --
    lines.append("## Grade Distribution")
    lines.append("")
    for g in ["A", "B", "C", "D", "F"]:
        count = grade_dist.get(g, 0)
        bar_len = int(count / max(total_targets, 1) * 30)
        bar = "\u2588" * bar_len + "\u2591" * (30 - bar_len)
        pct = round(count / max(total_targets, 1) * 100)
        lines.append(f"**{g}** `{bar}` {count} repos ({pct}%)")
    lines.append("")

    # -- Top Finding Categories --
    lines.append("## Most Common Finding Categories")
    lines.append("")
    lines.append("| # | Category | OWASP | Findings | Share |")
    lines.append("|--:|----------|:-----:|--------:|------:|")
    for i, (cat, count) in enumerate(top_cats, 1):
        label = cat_labels.get(cat, cat.replace("_", " ").title())
        owasp = cat_owasp.get(cat, "---")
        share = round(count / max(total_findings, 1) * 100)
        lines.append(f"| {i} | {label} | {owasp} | {count} | {share}% |")
    lines.append("")

    # -- Repos Requiring Attention (C/D/F sorted worst-first) --
    attention_rows = [r for r in rows if r["grade"] in ("C", "D", "F")]
    attention_rows.sort(key=lambda r: (r["score"], r["target_id"]))
    clean_rows = [r for r in rows if r["grade"] in ("A", "B")]

    lines.append("## Repos Requiring Attention")
    lines.append("")
    if attention_rows:
        lines.append(
            f"> {len(attention_rows)} repositories scored below B and have actionable findings."
        )
        lines.append("")
        lines.append("| # | Repository | Grade | Score | Critical | High | Medium | Low | Total |")
        lines.append("|--:|------------|:-----:|------:|---------:|-----:|-------:|----:|------:|")
        for i, r in enumerate(attention_rows, 1):
            tid = r["target_id"]
            color = GRADE_COLORS[r["grade"]]
            badge = (
                f"![{r['grade']}](https://img.shields.io/badge/"
                f"{r['grade']}-{color}?style=flat-square)"
            )
            repo_link = f"[{tid}](https://github.com/{tid})"
            crit_fmt = f"**{r['critical']}**" if r["critical"] > 0 else "0"
            high_fmt = f"**{r['high']}**" if r["high"] > 0 else "0"
            lines.append(
                f"| {i} | {repo_link} | {badge} | {r['score']} | "
                f"{crit_fmt} | {high_fmt} | {r['medium']} "
                f"| {r['low']} | {r['total']} |"
            )
        lines.append("")
    else:
        lines.append("No repositories scored below B.")
        lines.append("")

    # -- All Scanned Repos (A/B collapsed) --
    lines.append("## All Scanned Repos")
    lines.append("")
    lines.append(f"> {len(clean_rows)} repositories scored A or B.")
    lines.append("")
    lines.append("<details>")
    lines.append(f"<summary>View all {len(clean_rows)} clean repos</summary>")
    lines.append("")
    lines.append("| Repository | Stars | Grade | Score |")
    lines.append("|------------|------:|:-----:|------:|")
    for r in clean_rows:
        tid = r["target_id"]
        color = GRADE_COLORS[r["grade"]]
        badge = (
            f"![{r['grade']}](https://img.shields.io/badge/{r['grade']}-{color}?style=flat-square)"
        )
        repo_link = f"[{tid}](https://github.com/{tid})"
        stars_fmt = f"{r['stars']:,}"
        lines.append(f"| {repo_link} | {stars_fmt} | {badge} | {r['score']} |")
    lines.append("")
    lines.append("</details>")
    lines.append("")

    # -- Methodology --
    lines.append("## Methodology")
    lines.append("")
    lines.append("### Scoring Formula")
    lines.append("")
    lines.append("```")
    lines.append("Score = 100 - (Critical x 15) - (High x 7) - (Medium x 3) - (Low x 1)")
    lines.append("Score is clamped to [5, 100]")
    lines.append("```")
    lines.append("")
    lines.append("Info-severity findings are tracked but do not affect the score.")
    lines.append("")
    lines.append("### Grade Scale")
    lines.append("")
    lines.append("| Grade | Score Range | Meaning |")
    lines.append("|:-----:|:----------:|---------|")
    lines.append(f"| {GRADE_EMOJI['A']} A | 90 -- 100 | Excellent -- minimal risk |")
    lines.append(f"| {GRADE_EMOJI['B']} B | 80 -- 89  | Good -- minor issues only |")
    lines.append(f"| {GRADE_EMOJI['C']} C | 70 -- 79  | Fair -- some high-severity issues |")
    lines.append(f"| {GRADE_EMOJI['D']} D | 60 -- 69  | Poor -- multiple high-severity issues |")
    lines.append(f"| {GRADE_EMOJI['F']} F | 5 -- 59   | Critical -- immediate action required |")
    lines.append("")
    lines.append("### Scanner Coverage")
    lines.append("")
    lines.append(
        "Each repository is scanned with [agentsec](https://pypi.org/project/agentsec-ai/) "
        "which runs 27 named security checks + dynamic credential detection across "
        "the OWASP Agentic Top 10 categories (ASI01 -- ASI10)."
    )
    lines.append("")
    lines.append("### Limitations")
    lines.append("")
    lines.append("- Static analysis only; no runtime or dynamic testing")
    lines.append("- Findings may include false positives that require manual triage")
    lines.append("- Star count is a rough proxy for popularity and may bias the sample")
    lines.append("- Some test fixtures may contain intentional dummy credentials")
    lines.append("")

    # -- How to Improve --
    lines.append("## How to Improve Your Grade")
    lines.append("")
    lines.append("If your repository appears on this dashboard, here is how to improve your score:")
    lines.append("")
    lines.append(
        "1. **Install agentsec** and run it locally: `pip install agentsec-ai && agentsec scan .`"
    )
    lines.append("2. **Review findings** -- each includes a remediation summary and OWASP category")
    lines.append(
        "3. **Fix critical/high issues first** -- they have the largest impact on your score"
    )
    lines.append(
        "4. **Rotate exposed credentials** -- even if redacted here, leaked secrets must be rotated"
    )
    lines.append("5. **Re-scan after fixes** to verify your improvements")
    lines.append("")
    lines.append(
        "> Findings are point-in-time snapshots. "
        "Your grade will update automatically in the next weekly scan."
    )
    lines.append("")

    # -- Responsible Disclosure --
    lines.append("## Responsible Disclosure")
    lines.append("")
    lines.append("- All targets are **public** open-source repositories")
    lines.append("- No exploit payloads are included in this report")
    lines.append("- Credential evidence is redacted (first 4 + last 4 characters only)")
    lines.append(
        "- This dashboard is intended to improve ecosystem security, not to shame maintainers"
    )
    lines.append(
        "- **Contest a finding**: open an issue at "
        "[agentsec/issues](https://github.com/debu-sinha/agentsec/issues) "
        "with the repo name and finding ID"
    )
    lines.append("")

    # -- Disclaimer --
    lines.append("## Disclaimer")
    lines.append("")
    lines.append(
        "This dashboard is provided **as-is** for informational purposes only. "
        "It is generated by automated static analysis and may contain false positives "
        "or miss certain vulnerability classes. Grades reflect a point-in-time snapshot "
        "and do not constitute a comprehensive security audit. No warranty of accuracy, "
        "completeness, or fitness for any purpose is expressed or implied. "
        "Repository maintainers are encouraged to run their own security assessments."
    )
    lines.append("")

    # -- Footer --
    lines.append("---")
    lines.append("")
    lines.append(
        f"*Generated on {snapshot_date} by "
        f"[agentsec](https://github.com/debu-sinha/agentsec) v0.4.2 "
        f"| [Install](https://pypi.org/project/agentsec-ai/) "
        f"| [Report an issue](https://github.com/debu-sinha/agentsec/issues)*"
    )
    lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Scan runner (for --scan mode)
# ---------------------------------------------------------------------------

SKIP_PATTERNS = [
    "awesome-mcp",
    "Awesome-MCP",
    "registry",
    "inspector",
    "mcpso",
    "chatmcp",
    "mcp-use",
]


def run_fresh_scan(date_stamp: str) -> tuple[Path, Path, Path]:
    """Clone top 50 MCP repos, scan each, produce JSONL + CSV + summary."""

    data_dir = REPO_ROOT / "docs" / "mcp-dashboard" / "data"
    data_dir.mkdir(parents=True, exist_ok=True)
    findings_path = data_dir / f"findings_{date_stamp}.jsonl"
    selection_path = data_dir / f"selection_{date_stamp}.csv"
    summary_path = data_dir / f"summary_{date_stamp}.json"

    # Discover repos via GitHub CLI
    print("Discovering top MCP repositories...")
    result = subprocess.run(
        [
            "gh",
            "search",
            "repos",
            "mcp server",
            "--sort",
            "stars",
            "--limit",
            "60",
            "--json",
            "fullName,stargazersCount,updatedAt,url",
        ],
        capture_output=True,
        text=True,
    )
    all_repos = json.loads(result.stdout)
    repos = [r for r in all_repos if not any(p in r["fullName"] for p in SKIP_PATTERNS)][:50]
    print(f"Selected {len(repos)} targets")

    # Write selection CSV
    with selection_path.open("w", encoding="utf-8", newline="") as fp:
        writer = csv.DictWriter(
            fp,
            fieldnames=[
                "rank",
                "target_id",
                "source_type",
                "repo_url",
                "stars",
                "last_commit_utc",
                "adoption_signal",
                "rank_score",
                "snapshot_ref",
            ],
        )
        writer.writeheader()
        for i, r in enumerate(repos, 1):
            writer.writerow(
                {
                    "rank": i,
                    "target_id": r["fullName"],
                    "source_type": "github",
                    "repo_url": r["url"],
                    "stars": r["stargazersCount"],
                    "last_commit_utc": r["updatedAt"],
                    "adoption_signal": 0,
                    "rank_score": r["stargazersCount"],
                    "snapshot_ref": "HEAD",
                }
            )

    work_dir = Path(tempfile.mkdtemp(prefix="mcp_scan_"))
    all_findings: list[dict] = []
    durations: list[float] = []
    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    targets_with_hicrit = 0

    for i, r in enumerate(repos, 1):
        name = r["fullName"]
        safe_name = name.replace("/", "_")
        target_path = work_dir / safe_name

        print(
            f"[{i:>2}/{len(repos)}] {name} ({r['stargazersCount']:,} stars)... ", end="", flush=True
        )

        # Shallow clone
        try:
            clone = subprocess.run(
                ["git", "clone", "--depth", "1", "--quiet", r["url"], str(target_path)],
                capture_output=True,
                text=True,
                timeout=60,
            )
            if clone.returncode != 0:
                print("CLONE FAILED")
                continue
        except subprocess.TimeoutExpired:
            print("CLONE TIMEOUT")
            continue

        # Get commit SHA
        try:
            sha = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                capture_output=True,
                text=True,
                cwd=str(target_path),
            )
            commit_sha = sha.stdout.strip()[:12]
        except Exception:
            commit_sha = "HEAD"

        # Run agentsec scan
        scan_out = target_path / "agentsec-scan.json"
        t0 = time.perf_counter()
        try:
            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "agentsec.cli",
                    "scan",
                    str(target_path),
                    "-o",
                    "json",
                    "-f",
                    str(scan_out),
                    "--fail-on",
                    "none",
                ],
                capture_output=True,
                text=True,
                timeout=180,
                env={**os.environ, "PYTHONIOENCODING": "utf-8"},
            )
        except subprocess.TimeoutExpired:
            print(f"SCAN TIMEOUT ({time.perf_counter() - t0:.1f}s)")
            shutil.rmtree(target_path, ignore_errors=True)
            continue

        elapsed = time.perf_counter() - t0
        durations.append(elapsed)

        if not scan_out.exists():
            print(f"NO OUTPUT ({elapsed:.1f}s)")
            shutil.rmtree(target_path, ignore_errors=True)
            continue

        # Parse findings
        report = json.loads(scan_out.read_text(encoding="utf-8"))
        has_hicrit = False
        for f in report.get("findings", []):
            sev = f.get("severity", "info").lower()
            sev_counts[sev] = sev_counts.get(sev, 0) + 1
            if sev in ("critical", "high"):
                has_hicrit = True

            rem_obj = f.get("remediation")
            rem = rem_obj.get("summary") if isinstance(rem_obj, dict) else None

            all_findings.append(
                {
                    "study_id": f"mcp-weekly-{date_stamp[:4]}-{date_stamp[4:6]}",
                    "target_id": name,
                    "source_type": "github",
                    "snapshot_ref": commit_sha,
                    "scanner": "agentsec",
                    "finding_id": f.get("id", "unknown"),
                    "severity": sev,
                    "category": f.get("category", "other").lower(),
                    "title": f.get("title", "unknown"),
                    "evidence": (f.get("evidence") or "")[:200] or None,
                    "location": None,
                    "confidence": "needs_review",
                    "remediation": rem,
                    "timestamp_utc": datetime.now(timezone.utc).isoformat(),
                }
            )

        if has_hicrit:
            targets_with_hicrit += 1

        target_count = sum(1 for ff in all_findings if ff["target_id"] == name)
        print(f"{target_count} findings ({elapsed:.1f}s)")
        shutil.rmtree(target_path, ignore_errors=True)

    # Write findings JSONL
    with findings_path.open("w", encoding="utf-8") as fp:
        for record in all_findings:
            fp.write(json.dumps(record, ensure_ascii=False) + "\n")

    # Write summary
    sorted_dur = sorted(durations)
    n = len(sorted_dur)
    total = sum(sev_counts.values())
    summary = {
        "snapshot_date": f"{date_stamp[:4]}-{date_stamp[4:6]}-{date_stamp[6:]}",
        "targets_scanned": len(repos),
        "targets_cloned": len(durations),
        "targets_with_critical_or_high": targets_with_hicrit,
        **sev_counts,
        "total_findings": total,
        "avg_findings_per_target": round(total / max(len(durations), 1), 2),
        "runtime_median_s": round(sorted_dur[n // 2], 2) if n else 0,
        "runtime_p95_s": round(sorted_dur[min(int(n * 0.95), n - 1)], 2) if n else 0,
    }
    summary_path.write_text(json.dumps(summary, indent=2) + "\n")

    print(f"\nDone: {total} findings across {len(durations)} targets.")
    shutil.rmtree(work_dir, ignore_errors=True)
    return findings_path, selection_path, summary_path


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main():
    parser = argparse.ArgumentParser(description="Generate MCP Security Dashboard")
    parser.add_argument(
        "--scan",
        action="store_true",
        help="Run fresh scan before generating",
    )
    parser.add_argument(
        "--date",
        default=None,
        help="Date stamp (YYYYMMDD) for data files",
    )
    args = parser.parse_args()

    today = datetime.now(timezone.utc).strftime("%Y%m%d")
    date_stamp = args.date or today

    if args.scan:
        findings_path, selection_path, _ = run_fresh_scan(date_stamp)
    else:
        # Use existing benchmark data
        findings_path = (
            REPO_ROOT / f"docs/benchmarks/top50/reports/top50_findings_{date_stamp}.jsonl"
        )
        selection_path = REPO_ROOT / f"docs/benchmarks/top50/data/top50_selection_{date_stamp}.csv"
        # Also check dashboard data dir
        if not findings_path.exists():
            findings_path = REPO_ROOT / f"docs/mcp-dashboard/data/findings_{date_stamp}.jsonl"
            selection_path = REPO_ROOT / f"docs/mcp-dashboard/data/selection_{date_stamp}.csv"

    if not findings_path.exists():
        print(f"Error: findings file not found: {findings_path}")
        print("Run with --scan to generate fresh data, or --date YYYYMMDD for existing data.")
        sys.exit(1)

    if not selection_path.exists():
        print(f"Error: selection file not found: {selection_path}")
        sys.exit(1)

    print(f"Loading findings from {findings_path}")
    findings = load_findings(findings_path)
    targets_meta = load_selection(selection_path)
    targets_findings = aggregate_by_target(findings)

    snapshot_date = f"{date_stamp[:4]}-{date_stamp[4:6]}-{date_stamp[6:]}"
    dashboard_md = render_dashboard(
        targets_meta,
        targets_findings,
        snapshot_date,
        len(findings),
    )

    output_path = REPO_ROOT / "docs" / "mcp-security-grades.md"
    output_path.write_text(dashboard_md, encoding="utf-8")
    print(f"Dashboard written to {output_path}")


if __name__ == "__main__":
    main()
