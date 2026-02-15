# agentsec Benchmark Methodology (v1)

## Purpose

This benchmark is designed to evaluate `agentsec` on:
- Detection quality (precision/recall)
- Practicality (runtime and actionable output)
- Remediation impact (before/after hardening delta)

The benchmark must be reproducible by third parties.

## Scope

Included:
- OpenClaw installation config findings
- Skill malware/prompt-injection findings
- MCP security findings
- Credential findings
- Pre-install gate checks (`agentsec gate`)

Excluded:
- Dynamic/runtime behavioral telemetry
- Closed-source/private package ecosystems without reproducible fixtures

## Fixture Design

Use the fixture matrix in `docs/benchmarks/FIXTURE_MATRIX.md`.

Each fixture should include:
- `fixture_id`
- target type (`openclaw`, `skill`, `mcp`, `credential`, `gate`)
- expected findings (`id`, `severity`, `category`)
- expected safe conditions (for false-positive checks)

## Ground Truth Rules

For each fixture, create an expected manifest:
- `expected_findings.json`
- `expected_no_findings.json` (optional for clean fixtures)

Scoring terms:
- TP: finding expected and detected
- FP: finding not expected but detected
- FN: finding expected but missed

## Metrics

Core metrics:
- Precision = TP / (TP + FP)
- Recall = TP / (TP + FN)
- F1 = 2 * precision * recall / (precision + recall)
- Critical recall = TP_critical / expected_critical
- Runtime p50/p95

Operational metrics:
- Findings fixed after `harden` (count and percent)
- Score delta after hardening
- Remaining critical/high counts after hardening

## Execution Protocol

1. Pin tool version.
2. Run benchmark command set on all fixtures.
3. Save raw outputs (JSON/SARIF/terminal captures).
4. Compute metrics with the same script/version.
5. Publish report with known limitations.

## Reproducibility Requirements

- Include exact commands
- Include fixture hashes (or commit SHA)
- Include OS + Python version
- Include tool version (`agentsec --version`)

## Reporting Format

Publish:
- Summary table (precision/recall/F1/runtime)
- Per-module breakdown
- False-positive and false-negative examples
- Hardening impact section
- Limitations and future work

