# Case Study: OpenClaw Plugin Preflight for TweetClaw

- Date: 2026-07-17
- Environment type: OpenClaw plugin repository
- Scope: `skill` scanner on the plugin's instruction directory
- Tool version: agentsec 0.5.0
- Target: `Xquik-dev/tweetclaw` at commit `3e6f95c63f2d45a84708377446ad314a97aaa1ec`

## Scenario

TweetClaw is an OpenClaw plugin for public X research and account automation through Xquik. A preflight review should examine its agent instructions before installation while keeping credentials outside the repository, package, prompts, and scan artifacts.

## Detection Summary

The agentsec 0.5.0 skill scan produced no findings:

| Target | Scanner | Files Scanned | Critical | High | Medium | Low | Grade |
|---|---|---:|---:|---:|---:|---:|---|
| `Xquik-dev/tweetclaw` | `skill` | 4 | 0 | 0 | 0 | 0 | A |

The scanner traversed these instruction files:

- `skills/tweetclaw/BENCHMARK.md`
- `skills/tweetclaw/SKILL.md`
- `skills/tweetclaw/skill-card.md`
- `skills/tweetclaw/skillspector-report.md`

## Scope Boundary

The `skill` scanner checks instruction content plus source and manifest files inside discovered skill directories. This run did not count the repository-root `openclaw.plugin.json`, `package.json`, or TypeScript source. Review those files separately for package identity, dependencies, permissions, network destinations, and runtime behavior.

A clean static scan is evidence about the checked files, not proof that a plugin or service is safe. Re-run the scan after changes and apply normal code, dependency, and runtime review.

## What To Review Before Install

- Install only from the canonical `@xquik/tweetclaw` npm package or `Xquik-dev/tweetclaw` repository.
- Review `skills/tweetclaw/SKILL.md` for tool scope, setup steps, and untrusted-content boundaries.
- Review `openclaw.plugin.json` and `package.json` for package identity, declared configuration, and runtime dependencies.
- Keep Xquik credentials in the local OpenClaw credential store, never in the plugin repository or scan output.
- Re-run the scan after package updates, new instructions, or changed configuration.

## Reproduction

```bash
git clone https://github.com/Xquik-dev/tweetclaw.git
cd tweetclaw
npm view @xquik/tweetclaw version
agentsec scan . -s skill -o json -f tweetclaw-skill-scan.json --fail-on critical
```

The public npm version at verification time was `1.6.37`.

## Artifact

- Sanitized summary: `docs/case-studies/artifacts/case5-tweetclaw-skill-scan.json`
- Raw report SHA-256: `af0076ed29722a77591db28d08070e89f32a1dc0e0c9ef63879a41c32d3c0285`

The raw report is not committed because it includes local scan metadata. The sanitized summary excludes absolute paths, credentials, timestamps, and machine-specific duration data.

Xquik is an independent third-party service. Not affiliated with X Corp. "Twitter" and "X" are trademarks of X Corp.
