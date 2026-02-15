# Case Study: [CUSTOMER_OR_ENV_NAME]

- Date: [YYYY-MM-DD]
- Environment type: [OpenClaw workstation | VPS | public bot | MCP-heavy]
- Scope: [installation/skill/mcp/credential/gate]
- Tool version: [agentsec x.y.z]

## Starting Risk Posture

- Overall score/grade: [x.x/100], [A-F]
- Findings: [total], [critical], [high], [medium], [low]
- Top blockers:
1. [Finding]
2. [Finding]
3. [Finding]

## Actions Taken

1. Ran `agentsec scan`
2. Applied hardening profile: `[workstation|vps|public-bot]`
3. Performed manual fixes:
- [manual fix 1]
- [manual fix 2]
4. Re-scanned and validated with `--fail-on [severity]`

## Measurable Outcomes

| Metric | Before | After | Delta |
|---|---:|---:|---:|
| Score |  |  |  |
| Critical findings |  |  |  |
| High findings |  |  |  |
| Total findings |  |  |  |
| Time to first safe config |  |  |  |

## What Automation Fixed vs Manual

- Auto-fixed by `harden`:
  - [item]
  - [item]
- Manual fixes required:
  - [item]
  - [item]

## Residual Risk

- Remaining critical/high findings:
  - [item]
  - [item]
- Accepted risks and rationale:
  - [item]

## Operator Feedback

> [Short quote from user/maintainer/security engineer]

## Repro Commands

```bash
agentsec scan [target] -v
agentsec harden [target] -p [profile] --apply
agentsec scan [target] --fail-on high
```

## Artifacts

- Raw report JSON: [path/link]
- SARIF: [path/link]
- Config diff: [path/link]
- Ticket/issue references: [path/link]

