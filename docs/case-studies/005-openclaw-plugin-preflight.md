# Case Study: OpenClaw Plugin Preflight for TweetClaw

- Date: 2026-05-16
- Environment type: OpenClaw plugin repository (developer workstation, macOS)
- Scope: skill scanner (instructions, manifest, dependency and prompt-injection checks)
- Tool version: agentsec 0.4.5

## Scenario

TweetClaw is an OpenClaw plugin for X/Twitter automation through Xquik. It can search tweets, post tweets, post tweet replies, inspect user profiles, download media, upload media, manage direct messages, export followers, monitor tweets, and use webhooks through API-key authenticated endpoints.

That makes it a useful preflight example for high-capability OpenClaw plugins: the security review needs to check the plugin package and instructions while keeping the user's Xquik API key outside the repository, package, and scan artifacts.

## Detection Summary

The skill-only scan produced no findings:

| Target | Scanner | Files Scanned | Critical | High | Medium | Low | Grade |
|---|---|---:|---:|---:|---:|---:|---|
| `xquik-dev/tweetclaw` | `skill` | 1 | 0 | 0 | 0 | 0 | A |

## What To Review Before Install

- Install from the canonical npm package: `@xquik/tweetclaw`.
- Review `skills/tweetclaw/SKILL.md` for tool scope, setup steps, and prompt-injection patterns.
- Review `openclaw.plugin.json` and `package.json` for package identity and runtime dependencies.
- Store the Xquik API key in the local OpenClaw or agent credential store, not in the plugin repo.
- Re-run the scan after package updates, new tool descriptions, or new setup instructions.

## Repro Commands

```bash
git clone https://github.com/Xquik-dev/tweetclaw.git
cd tweetclaw
npm view @xquik/tweetclaw version
agentsec scan . -s skill -o json -f tweetclaw-skill-scan.json --fail-on critical
```

## Artifacts

- Sanitized scan summary: `docs/case-studies/artifacts/case5-tweetclaw-skill-scan.json`

## Notes

- The scan covers the checked-out repository content, not a user's private API key or local runtime state.
- For CI, upload SARIF or JSON as an internal build artifact and avoid committing generated reports with absolute local paths.
- If a local OpenClaw installation also has MCP servers configured, run `agentsec scan ~/.openclaw -s skill,mcp`.
