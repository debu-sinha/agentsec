"""Adversarial consistency audit for launch readiness.

Runs strict checks that public docs are backed by repository artifacts.
Exit code is non-zero when any mismatch is found.
"""

import json
import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]


def _load_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _fail(errors: list[str], msg: str) -> None:
    errors.append(msg)


def _check_benchmark_windows(errors: list[str]) -> None:
    md_path = REPO_ROOT / "docs/benchmarks/results/2026-02-15-v0.4.0.md"
    json_path = REPO_ROOT / "docs/benchmarks/results/2026-02-15-v0.4.0.json"

    md = _load_text(md_path)
    data = json.loads(_load_text(json_path))
    summary = data["aggregate"]

    row = re.search(
        r"\|\s*Windows 11, Python 3\.14\.2\s*\|.*?\|\s*([0-9.]+)\s*ms\s*\|\s*([0-9.]+)\s*ms\s*\|",
        md,
    )
    if not row:
        _fail(errors, f"{md_path}: missing Windows benchmark row")
        return

    md_p50 = float(row.group(1))
    md_p95 = float(row.group(2))
    json_p50 = float(summary["runtime_p50_ms"])
    json_p95 = float(summary["runtime_p95_ms"])

    if md_p50 != json_p50 or md_p95 != json_p95:
        _fail(
            errors,
            f"{md_path}: Windows p50/p95 ({md_p50}/{md_p95}) != JSON ({json_p50}/{json_p95})",
        )


def _check_case_study_metrics(errors: list[str], case_num: int) -> None:
    if case_num == 1:
        case_md = REPO_ROOT / "docs/case-studies/001-insecure-openclaw-workstation.md"
    else:
        case_md = REPO_ROOT / "docs/case-studies/002-public-bot-vps-hardening.md"
    before_json = REPO_ROOT / f"docs/case-studies/artifacts/case{case_num}-before.json"
    after_json = REPO_ROOT / f"docs/case-studies/artifacts/case{case_num}-after.json"

    md = _load_text(case_md)
    before = json.loads(_load_text(before_json))
    after = json.loads(_load_text(after_json))

    before_summary = before["summary"]
    after_summary = after["summary"]
    before_score = before["posture"]["overall_score"]
    after_score = after["posture"]["overall_score"]

    required_strings = [
        f"| Score | {before_score:.1f} | {after_score:.1f} |",
        f"| Critical findings | {before_summary['critical']} | {after_summary['critical']} |",
        f"| High findings | {before_summary['high']} | {after_summary['high']} |",
        (
            f"| Total findings | {before_summary['total_findings']} | "
            f"{after_summary['total_findings']} |"
        ),
    ]
    for required in required_strings:
        if required not in md:
            _fail(errors, f"{case_md}: missing or stale metric row: {required}")


def _check_unbacked_claims(errors: list[str]) -> None:
    checks = {
        REPO_ROOT / "docs/blog/immunize-your-openclaw.md": [
            "135,000",
            "is the only tool",
            "42,900",
            "341 malicious",
            "72%",
        ],
        REPO_ROOT / "docs/design/agentsec-architecture.md": [
            "$100K",
            "42,900+",
            "93%",
            "341 malicious",
            "VCs investing",
            "first comprehensive",
        ],
    }
    for path, banned_terms in checks.items():
        text = _load_text(path).lower()
        for term in banned_terms:
            if term.lower() in text:
                _fail(errors, f"{path}: contains unverified market claim token '{term}'")


def _check_referenced_artifacts_exist(errors: list[str]) -> None:
    paths = [
        REPO_ROOT / "docs/blog/immunize-your-openclaw.md",
        REPO_ROOT / "README.md",
    ]
    pattern = re.compile(r"`(docs/[^`]+\.(?:json|jsonl|md|csv))`")
    for md_path in paths:
        text = _load_text(md_path)
        for rel in pattern.findall(text):
            artifact = REPO_ROOT / rel
            if not artifact.exists():
                _fail(errors, f"{md_path}: referenced artifact missing: {rel}")


def main() -> int:
    errors: list[str] = []

    _check_benchmark_windows(errors)
    _check_case_study_metrics(errors, case_num=1)
    _check_case_study_metrics(errors, case_num=2)
    _check_unbacked_claims(errors)
    _check_referenced_artifacts_exist(errors)

    if errors:
        print("Repository consistency audit FAILED:")
        for err in errors:
            print(f" - {err}")
        return 1

    print("Repository consistency audit PASSED.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
