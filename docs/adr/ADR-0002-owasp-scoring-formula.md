# ADR-0002: OWASP Posture Scoring Formula

## Status
Accepted

## Context
agentsec maps findings to OWASP Agentic Top 10 categories (ASI01-ASI10) and needs to produce a single posture score (0-100) plus letter grade (A-F) that communicates overall risk. The scoring formula must balance several competing requirements:

1. **Monotonic degradation** - more/worse findings always lower the score
2. **Critical finding dominance** - a single critical finding should dominate the grade
3. **Combinatorial awareness** - certain finding combinations are catastrophic even when individual findings are not
4. **Actionability** - scores must be stable enough for CI gates (no flapping)
5. **Transparency** - users must be able to reason about why they got a specific grade

Existing approaches in the industry (Snyk risk score, GitHub security severity) use weighted sums but don't account for agentic-specific combinatorial risks like "open DM policy + full tool access + no sandbox = unauthenticated RCE."

## Decision

### Fixed-Point Deduction with Hard Caps

Start from 100 and subtract fixed points per severity level:

```
score = 100
score -= critical_count * 15
score -= high_count * 7
score -= medium_count * 3
score -= low_count * 1
score = clamp(score, 5, 100)
```

Then apply hard caps based on critical finding count:
- 3+ critical findings OR doom combo: max 20/100 (grade F)
- 1+ critical finding: max 55/100 (grade F)
- 5+ high findings: max 65/100 (grade D)

### Score Floor at 5

The minimum score is 5, not 0. This distinguishes "has an installation with some controls" from a hypothetical system with zero security. A real deployment that agentsec can scan has _some_ baseline (the agent is installed, configs exist). A score of 0 would imply no security controls exist whatsoever.

### Context-Sensitive Severity Escalation

Some findings are HIGH in isolation but become CRITICAL when combined with other findings:
- Open group/DM policy + disabled auth = unauthenticated access (HIGH -> CRITICAL)
- Risky tool groups + open inbound messages = unauthenticated code execution (HIGH -> CRITICAL)

Escalation runs before scoring, so the formula always operates on the "true" severity.

### Doom Combo Detection

Three specific findings together represent catastrophic risk equivalent to unauthenticated RCE:
- Open DM policy (anyone can message the agent)
- Full tool profile (agent can execute arbitrary code)
- Sandbox disabled (no containment)

When all three are present, the score is hard-capped at 20 regardless of the deduction formula. This prevents a misleading score when the agent is effectively an open shell.

## Alternatives Considered

### 1) Weighted Sum with Category Multipliers
- Formula: `sum(severity_weight * category_multiplier) / max_possible`
- Pros: Standard approach, easy to explain
- Cons: Adding low-severity findings can inflate the denominator and paradoxically improve the score. No combinatorial awareness.
- Rejected: Fails the monotonic degradation requirement

### 2) Minimum-of-Categories Approach
- Formula: `min(category_scores)` where each category scores independently
- Pros: A single bad category dominates (desirable)
- Cons: Ignores breadth of issues. An agent with 1 critical in 1 category scores the same as 1 critical in every category.
- Rejected: Loses breadth information

### 3) Binary Pass/Fail
- Formula: `PASS if no critical/high else FAIL`
- Pros: Simple, unambiguous, great for CI gates
- Cons: No gradient - a single medium finding and 50 medium findings produce the same result. No improvement signal.
- Rejected: Doesn't support the "posture improvement" use case central to agentsec

### 4) CVSS-Style Vector Scoring
- Formula: Composite of exploitability, impact, and environmental metrics
- Pros: Industry standard for vulnerability scoring
- Cons: Designed for individual vulnerabilities, not aggregate posture. Over-engineered for config scanning. Requires attack vector classification that doesn't map to misconfiguration findings.
- Rejected: Wrong abstraction level

## Consequences

### Positive
- Fixed deductions are deterministic and easy to explain ("each critical costs 15 points")
- Hard caps prevent misleading grades when critical issues exist
- Doom combo detection catches the most dangerous agentic-specific risk
- Score floor prevents meaningless zero scores
- CI gates can use `--fail-on` with predictable behavior

### Negative
- Formula is hand-tuned, not empirically derived from real-world breach data
- Hard caps create discontinuities (going from 0 to 1 critical finding is a cliff)
- Score floor of 5 is somewhat arbitrary
- Severity escalation mutates findings in place (not idempotent)

### Neutral
- The formula will need recalibration as the check catalog grows
- Per-category breakdown is computed separately and may tell a different story than the overall score
