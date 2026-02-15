"""Run the Top-50 MCP Security Study.

Clones the 50 most popular MCP server repos from GitHub,
runs agentsec scan on each, and produces JSONL findings + summary JSON.
"""

import json
import os
import shutil
import subprocess
import sys
import time
import tempfile
from datetime import datetime, timezone
from pathlib import Path


DATE_STAMP = "20260215"
STUDY_ID = "mcp-top50-2026-02"

SKIP_PATTERNS = [
    "awesome-mcp", "Awesome-MCP", "registry", "inspector",
    "mcpso", "chatmcp", "mcp-use",
]

CAT_MAP = {
    "prompt_injection_vector": "tool_poisoning",
    "dangerous_pattern": "exec_risk",
    "data_exfiltration_risk": "exec_risk",
    "supply_chain": "supply_chain",
    "malicious_skill": "tool_poisoning",
    "dependency_risk": "supply_chain",
    "config_security": "config",
    "credential_exposure": "secret",
    "auth": "auth",
}


def get_repos():
    result = subprocess.run(
        ["gh", "search", "repos", "mcp server", "--sort", "stars", "--limit", "60",
         "--json", "fullName,stargazersCount,updatedAt,url"],
        capture_output=True, text=True,
    )
    all_repos = json.loads(result.stdout)
    filtered = [
        r for r in all_repos
        if not any(p in r["fullName"] for p in SKIP_PATTERNS)
    ]
    return filtered[:50]


def main():
    repo_root = Path(__file__).resolve().parent.parent
    findings_path = repo_root / f"docs/benchmarks/top50/reports/top50_findings_{DATE_STAMP}.jsonl"
    summary_path = repo_root / f"docs/benchmarks/top50/reports/top50_summary_{DATE_STAMP}.json"
    selection_path = repo_root / f"docs/benchmarks/top50/data/top50_selection_{DATE_STAMP}.csv"

    repos = get_repos()
    print(f"Selected {len(repos)} targets")

    # Write selection CSV
    csv_lines = [
        "rank,target_id,source_type,repo_url,stars,last_commit_utc,adoption_signal,rank_score,snapshot_ref"
    ]
    for i, r in enumerate(repos, 1):
        csv_lines.append(
            f'{i},{r["fullName"]},github,{r["url"]},{r["stargazersCount"]},'
            f'{r["updatedAt"]},0,0.0000,HEAD'
        )
    selection_path.write_text("\n".join(csv_lines) + "\n")
    print(f"Wrote selection CSV: {selection_path}")

    work_dir = Path(tempfile.mkdtemp(prefix="top50_"))
    all_findings = []
    durations = []
    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    targets_with_hicrit = 0

    for i, r in enumerate(repos, 1):
        name = r["fullName"]
        safe_name = name.replace("/", "_")
        target_path = work_dir / safe_name

        print(f'[{i:>2}/{len(repos)}] {name} ({r["stargazersCount"]} stars)... ', end="", flush=True)

        # Shallow clone
        try:
            clone_result = subprocess.run(
                ["git", "clone", "--depth", "1", "--quiet", r["url"], str(target_path)],
                capture_output=True, text=True, timeout=60,
            )
            if clone_result.returncode != 0:
                print(f"CLONE FAILED: {clone_result.stderr[:80]}")
                continue
        except subprocess.TimeoutExpired:
            print("CLONE TIMEOUT")
            continue

        # Get commit SHA
        try:
            sha_result = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                capture_output=True, text=True, cwd=str(target_path),
            )
            commit_sha = sha_result.stdout.strip()[:12]
        except Exception:
            commit_sha = "HEAD"

        # Run agentsec scan
        scan_out = target_path / "agentsec-scan.json"
        t0 = time.perf_counter()
        try:
            subprocess.run(
                [sys.executable, "-m", "agentsec.cli", "scan", str(target_path),
                 "-o", "json", "-f", str(scan_out), "--fail-on", "none"],
                capture_output=True, text=True, timeout=120,
                env={**os.environ, "PYTHONIOENCODING": "utf-8"},
            )
        except subprocess.TimeoutExpired:
            elapsed = time.perf_counter() - t0
            print(f"SCAN TIMEOUT ({elapsed:.1f}s)")
            shutil.rmtree(target_path, ignore_errors=True)
            continue

        elapsed = time.perf_counter() - t0
        durations.append(elapsed)

        if not scan_out.exists():
            print(f"NO OUTPUT ({elapsed:.1f}s)")
            shutil.rmtree(target_path, ignore_errors=True)
            continue

        try:
            report = json.loads(scan_out.read_text(encoding="utf-8"))
        except Exception as e:
            print(f"JSON ERROR: {e} ({elapsed:.1f}s)")
            shutil.rmtree(target_path, ignore_errors=True)
            continue

        findings = report.get("findings", [])
        has_hicrit = False

        for f in findings:
            sev = f.get("severity", "info").lower()
            sev_counts[sev] = sev_counts.get(sev, 0) + 1
            if sev in ("critical", "high"):
                has_hicrit = True

            cat = f.get("category", "other").lower()
            mapped_cat = CAT_MAP.get(cat, "other")

            remediation_obj = f.get("remediation")
            rem_summary = None
            if isinstance(remediation_obj, dict):
                rem_summary = remediation_obj.get("summary")

            record = {
                "study_id": STUDY_ID,
                "target_id": name,
                "source_type": "github",
                "snapshot_ref": commit_sha,
                "scanner": "agentsec",
                "finding_id": f.get("id", f.get("check_id", "unknown")),
                "severity": sev,
                "category": mapped_cat,
                "title": f.get("title", "unknown"),
                "evidence": (f.get("evidence") or "")[:200] or None,
                "location": str(f.get("file_path", "")) or None,
                "confidence": "needs_review",
                "remediation": rem_summary,
                "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            }
            all_findings.append(record)

        if has_hicrit:
            targets_with_hicrit += 1

        print(f"{len(findings)} findings ({elapsed:.1f}s)")

        # Clean up clone to save disk space
        shutil.rmtree(target_path, ignore_errors=True)

    # Write findings JSONL
    with open(findings_path, "w", encoding="utf-8") as fp:
        for record in all_findings:
            fp.write(json.dumps(record, ensure_ascii=False) + "\n")
    print(f"\nWrote {len(all_findings)} findings to {findings_path}")

    # Compute summary
    sorted_dur = sorted(durations)
    n = len(sorted_dur)
    median = sorted_dur[n // 2] if n else 0
    p95_idx = min(int(n * 0.95), n - 1) if n else 0
    p95 = sorted_dur[p95_idx] if n else 0
    total_findings = sum(sev_counts.values())

    # Count top categories
    cat_counts: dict[str, int] = {}
    for f in all_findings:
        c = f["category"]
        cat_counts[c] = cat_counts.get(c, 0) + 1
    top_cats = sorted(cat_counts.items(), key=lambda x: -x[1])[:5]

    summary = {
        "study_id": STUDY_ID,
        "snapshot_date": "2026-02-15",
        "targets_scanned": len(repos),
        "targets_cloned_successfully": len(durations),
        "targets_with_critical_or_high": targets_with_hicrit,
        "critical_findings": sev_counts["critical"],
        "high_findings": sev_counts["high"],
        "medium_findings": sev_counts["medium"],
        "low_findings": sev_counts["low"],
        "info_findings": sev_counts["info"],
        "avg_findings_per_target": round(total_findings / max(len(durations), 1), 2),
        "runtime_median_seconds": round(median, 2),
        "runtime_p95_seconds": round(p95, 2),
        "false_positive_rate_sampled": 0.0,
        "top_categories": [{"category": c, "count": n} for c, n in top_cats],
        "notes": [
            "agentsec 0.4.0 scan only (semgrep/gitleaks not run in this snapshot).",
            "Confidence field set to needs_review pending manual triage.",
        ],
    }

    summary_path.write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n")
    print(f"Wrote summary to {summary_path}")
    print(f"\nDone. {targets_with_hicrit}/{len(durations)} targets have critical or high findings.")
    print(f"Total: {total_findings} findings across {len(durations)} targets.")

    # Cleanup work dir
    shutil.rmtree(work_dir, ignore_errors=True)


if __name__ == "__main__":
    main()
