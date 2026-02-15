# Case Study Artifacts

Evidence files produced by case study repro commands. Each file follows the naming convention below so references across case studies stay consistent.

## Naming Convention

```
case<N>-<stage>.<ext>
```

- `<N>` - case study number, zero-padded (e.g., `1`, `2`, `3`)
- `<stage>` - scan phase or artifact type
- `<ext>` - file format

### Stages

| Stage | Description |
|---|---|
| `before` | Baseline scan before any remediation |
| `after` | Scan after hardening or remediation |
| `gate-output` | Pre-install gate CLI output |
| `gate-findings` | Gate findings in JSON or SARIF |
| `scan-results` | Full scan report |

### Formats

| Extension | Use |
|---|---|
| `.json` | Machine-readable scan reports (`agentsec scan -o json -f ...`) |
| `.sarif` | SARIF for GitHub Code Scanning upload (`agentsec scan -o sarif -f ...`) |
| `.txt` | Sanitized CLI output |

## Examples

```
case1-before.json       # Case 001 baseline scan
case1-after.json        # Case 001 post-hardening scan
case2-before.json       # Case 002 baseline scan
case2-after.json        # Case 002 post-hardening scan
case3-gate-output.txt   # Case 003 gate CLI output
case3-gate-findings.json
case4-scan-results.json # Case 004 skill scanner results
```

## Sanitization Rules

Before committing any artifact file:

1. Strip absolute paths (replace with relative or `/tmp/...` placeholders)
2. Redact real tokens and credentials (use `<TYPE_REDACTED>` format)
3. Remove hostnames and IPs that reference internal infrastructure
