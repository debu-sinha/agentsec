# Benchmark Results: [RUN_NAME]

- Date: [YYYY-MM-DD]
- Tool version: [agentsec x.y.z]
- Commit SHA: [sha]
- OS/Python: [os], [python]
- Fixture set version: [tag/sha]

## Executive Summary

- Precision: [0.00]
- Recall: [0.00]
- F1: [0.00]
- Critical Recall: [0.00]
- Runtime p50 / p95: [x.xx s] / [x.xx s]

## Module Breakdown

| Module | Precision | Recall | F1 | Critical Recall | Notes |
|---|---:|---:|---:|---:|---|
| installation |  |  |  |  |  |
| skill |  |  |  |  |  |
| mcp |  |  |  |  |  |
| credential |  |  |  |  |  |
| gate |  |  |  |  |  |

## Hardening Impact

| Scenario | Before Score | After Score | Delta | Findings Fixed | Remaining Critical/High |
|---|---:|---:|---:|---:|---|
| workstation profile |  |  |  |  |  |
| vps profile |  |  |  |  |  |
| public-bot profile |  |  |  |  |  |

## False Positives (Top)

1. [fixture_id] - [finding] - [why FP]
2. [fixture_id] - [finding] - [why FP]
3. [fixture_id] - [finding] - [why FP]

## False Negatives (Top)

1. [fixture_id] - [expected finding] - [why missed]
2. [fixture_id] - [expected finding] - [why missed]
3. [fixture_id] - [expected finding] - [why missed]

## Repro Commands

```bash
agentsec --version
agentsec scan [fixture_path] -o json -f [out].json
agentsec gate [npm|pip] install [pkg] --dry-run --fail-on high
```

## Limitations

- [Known limitation 1]
- [Known limitation 2]
- [Known limitation 3]

