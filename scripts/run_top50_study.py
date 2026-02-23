"""Run the Top-50 MCP Security Study.

Clones popular MCP server repos from GitHub and runs three scanners:
- agentsec
- semgrep (local ruleset)
- gitleaks

Findings are normalized into a single JSONL plus summary metrics.
"""

import csv
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from contextlib import suppress
from datetime import datetime, timezone
from pathlib import Path

DATE_STAMP = "20260215"
STUDY_ID = "mcp-top50-2026-02"

SKIP_PATTERNS = [
    "awesome-mcp",
    "Awesome-MCP",
    "registry",
    "inspector",
    "mcpso",
    "chatmcp",
    "mcp-use",
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

SEMGREP_RULES = "scripts/semgrep-top50-rules.yml"
GITLEAKS_BIN = shutil.which("gitleaks") or "gitleaks"


def get_repos():
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
    filtered = [
        r for r in all_repos
        if not any(p in r["fullName"] for p in SKIP_PATTERNS)
    ]
    return filtered[:50]


def _run(
    cmd: list[str],
    cwd: Path | None = None,
    timeout: int = 120,
) -> subprocess.CompletedProcess:
    return subprocess.run(
        cmd,
        cwd=str(cwd) if cwd else None,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        env={**os.environ, "PYTHONIOENCODING": "utf-8"},
    )


def _map_semgrep_severity(sev: str) -> str:
    s = (sev or "").upper()
    if s == "ERROR":
        return "high"
    if s == "WARNING":
        return "medium"
    return "low"


def _sanitize_location(target_id: str, path_value: str | None) -> str | None:
    if not path_value:
        return None
    p = str(path_value)
    if p in ("None", ""):
        return None
    p = p.replace("\\", "/")

    # Reduce absolute paths to target-relative paths: target_id/path/in/repo
    safe = target_id.replace("/", "_")
    marker = f"/{safe}/"
    idx = p.lower().find(marker.lower())
    if idx != -1:
        rel = p[idx + len(marker) :]
        return f"{target_id}/{rel}"

    # If already relative-ish, keep it; else fallback to basename.
    if "/" in p and not re.match(r"^[A-Za-z]:/", p):
        return p
    return os.path.basename(p)


def _append_agentsec_findings(
    target_id: str,
    snapshot_ref: str,
    report_json: Path,
    all_findings: list[dict[str, object]],
    sev_counts: dict[str, int],
) -> bool:
    report = json.loads(report_json.read_text(encoding="utf-8"))
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
        rem_summary = remediation_obj.get("summary") if isinstance(remediation_obj, dict) else None

        all_findings.append(
            {
                "study_id": STUDY_ID,
                "target_id": target_id,
                "source_type": "github",
                "snapshot_ref": snapshot_ref,
                "scanner": "agentsec",
                "finding_id": f.get("id", f.get("check_id", "unknown")),
                "severity": sev,
                "category": mapped_cat,
                "title": f.get("title", "unknown"),
                "evidence": (f.get("evidence") or "")[:200] or None,
                "location": _sanitize_location(target_id, f.get("file_path")),
                "confidence": "needs_review",
                "remediation": rem_summary,
                "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            }
        )
    return has_hicrit


def _append_semgrep_findings(
    target_id: str,
    snapshot_ref: str,
    semgrep_json: Path,
    all_findings: list[dict[str, object]],
    sev_counts: dict[str, int],
) -> bool:
    has_hicrit = False
    if not semgrep_json.exists():
        return has_hicrit
    with suppress(Exception):
        report = json.loads(semgrep_json.read_text(encoding="utf-8"))
        for r in report.get("results", []):
            sev = _map_semgrep_severity(r.get("extra", {}).get("severity", "INFO"))
            sev_counts[sev] = sev_counts.get(sev, 0) + 1
            if sev in ("critical", "high"):
                has_hicrit = True
            start = r.get("start", {}) or {}
            line = start.get("line")
            path = r.get("path")
            location = f"{path}:{line}" if path and line else path
            all_findings.append(
                {
                    "study_id": STUDY_ID,
                    "target_id": target_id,
                    "source_type": "github",
                    "snapshot_ref": snapshot_ref,
                    "scanner": "semgrep",
                    "finding_id": r.get("check_id", "semgrep"),
                    "severity": sev,
                    "category": "other",
                    "title": r.get("extra", {}).get("message", "semgrep finding"),
                    "evidence": (r.get("extra", {}).get("metavars") or None),
                    "location": _sanitize_location(target_id, location),
                    "confidence": "needs_review",
                    "remediation": None,
                    "timestamp_utc": datetime.now(timezone.utc).isoformat(),
                }
            )
    return has_hicrit


def _append_gitleaks_findings(
    target_id: str,
    snapshot_ref: str,
    gitleaks_json: Path,
    all_findings: list[dict[str, object]],
    sev_counts: dict[str, int],
) -> bool:
    has_hicrit = False
    if not gitleaks_json.exists():
        return has_hicrit
    with suppress(Exception):
        report = json.loads(gitleaks_json.read_text(encoding="utf-8"))
        if not isinstance(report, list):
            return has_hicrit

        for r in report:
            sev = "high"
            sev_counts[sev] = sev_counts.get(sev, 0) + 1
            has_hicrit = True
            file_path = r.get("File")
            line = r.get("StartLine")
            location = f"{file_path}:{line}" if file_path and line else file_path
            all_findings.append(
                {
                    "study_id": STUDY_ID,
                    "target_id": target_id,
                    "source_type": "github",
                    "snapshot_ref": snapshot_ref,
                    "scanner": "gitleaks",
                    "finding_id": r.get("RuleID", "gitleaks"),
                    "severity": sev,
                    "category": "secret",
                    "title": f"Gitleaks: {r.get('Description', 'potential secret')}",
                    "evidence": None,
                    "location": _sanitize_location(target_id, location),
                    "confidence": "needs_review",
                    "remediation": "Rotate secret and remove from git history if real.",
                    "timestamp_utc": datetime.now(timezone.utc).isoformat(),
                }
            )
    return has_hicrit


def main():
    repo_root = Path(__file__).resolve().parent.parent
    findings_path = repo_root / f"docs/benchmarks/top50/reports/top50_findings_{DATE_STAMP}.jsonl"
    summary_path = repo_root / f"docs/benchmarks/top50/reports/top50_summary_{DATE_STAMP}.json"
    selection_path = repo_root / f"docs/benchmarks/top50/data/top50_selection_{DATE_STAMP}.csv"

    repos = get_repos()
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
    print(f"Wrote selection CSV: {selection_path}")

    work_dir = Path(tempfile.mkdtemp(prefix="top50_"))
    all_findings = []
    durations = []
    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    targets_with_hicrit = 0

    semgrep_available = shutil.which("semgrep") is not None
    gitleaks_available = Path(GITLEAKS_BIN).exists()

    for i, r in enumerate(repos, 1):
        name = r["fullName"]
        safe_name = name.replace("/", "_")
        target_path = work_dir / safe_name

        print(
            f'[{i:>2}/{len(repos)}] {name} ({r["stargazersCount"]} stars)... ',
            end="",
            flush=True,
        )

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
        semgrep_out = target_path / "semgrep.json"
        gitleaks_out = target_path / "gitleaks.json"
        t0 = time.perf_counter()
        try:
            _run(
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
                timeout=180,
            )
        except subprocess.TimeoutExpired:
            elapsed = time.perf_counter() - t0
            print(f"SCAN TIMEOUT ({elapsed:.1f}s)")
            shutil.rmtree(target_path, ignore_errors=True)
            continue

        if semgrep_available:
            with suppress(Exception):
                _run(
                    [
                        "semgrep",
                        "scan",
                        "--json",
                        "--config",
                        str(repo_root / SEMGREP_RULES),
                        "--output",
                        str(semgrep_out),
                        str(target_path),
                    ],
                    timeout=180,
                )

        if gitleaks_available:
            with suppress(Exception):
                _run(
                    [
                        GITLEAKS_BIN,
                        "detect",
                        "--source",
                        str(target_path),
                        "--report-format",
                        "json",
                        "--report-path",
                        str(gitleaks_out),
                        "--redact",
                        "--no-banner",
                    ],
                    timeout=180,
                )

        elapsed = time.perf_counter() - t0
        durations.append(elapsed)

        if not scan_out.exists():
            print(f"NO OUTPUT ({elapsed:.1f}s)")
            shutil.rmtree(target_path, ignore_errors=True)
            continue

        has_hicrit = False
        has_hicrit = (
            _append_agentsec_findings(name, commit_sha, scan_out, all_findings, sev_counts)
            or has_hicrit
        )
        has_hicrit = (
            _append_semgrep_findings(name, commit_sha, semgrep_out, all_findings, sev_counts)
            or has_hicrit
        )
        has_hicrit = (
            _append_gitleaks_findings(name, commit_sha, gitleaks_out, all_findings, sev_counts)
            or has_hicrit
        )

        if has_hicrit:
            targets_with_hicrit += 1

        target_count = len([f for f in all_findings if f["target_id"] == name])
        print(f"{target_count} merged findings ({elapsed:.1f}s)")

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
        "false_positive_rate_sampled": None,
        "top_categories": [{"category": c, "count": n} for c, n in top_cats],
        "notes": [
            "Merged scanner run: agentsec + semgrep + gitleaks.",
            "Confidence field set to needs_review pending manual triage.",
            "false_positive_rate_sampled not measured in this run.",
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
