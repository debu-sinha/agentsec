#!/usr/bin/env python3
"""Apply manual fixes to the demo environment for the video's second act.

After `agentsec harden` fixes the config, this script handles the
"manual action" items: removing leaked credentials, deleting the
malicious skill, and upgrading the version — creating the dramatic
F -> B+ grade improvement.

Usage:
    python demo/fix_demo.py                    # Fix demo-target
    python demo/fix_demo.py /path/to/demo      # Fix custom path

Run order in the video:
    1. agentsec scan demo/demo-target           # Grade: F
    2. agentsec harden demo/demo-target -p workstation --apply
    3. python demo/fix_demo.py                  # Remove creds + skill
    4. agentsec scan demo/demo-target           # Grade: B+ or A-
"""

from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path


def fix_demo(base: Path) -> None:
    """Remove credentials, malicious skill, and upgrade version."""
    oc = base / ".openclaw"

    print(f"Applying manual fixes to: {base}")
    print()

    # 1. Remove the malicious skill
    skill_dir = oc / "skills" / "devops-helper"
    if skill_dir.exists():
        shutil.rmtree(skill_dir)
        print("  [x] Removed malicious skill: devops-helper/")

    # 2. Clean up .env — replace real secrets with env var references
    env_file = base / ".env"
    if env_file.exists():
        env_file.write_text("""\
# Application secrets — use a secrets manager in production
OPENAI_API_KEY=${OPENAI_API_KEY}
ANTHROPIC_API_KEY=${ANTHROPIC_API_KEY}
STRIPE_SECRET_KEY=${STRIPE_SECRET_KEY}
DATABASE_URL=${DATABASE_URL}
GITHUB_TOKEN=${GITHUB_TOKEN}
""")
        print("  [x] Cleaned .env — replaced secrets with ${VAR} references")

    # 3. Clean up integrations.json — remove hardcoded keys
    integrations = oc / "integrations.json"
    if integrations.exists():
        integrations.write_text(json.dumps({
            "providers": {
                "openai": {
                    "api_key": "${OPENAI_API_KEY}",
                },
                "aws": {
                    "access_key_id": "${AWS_ACCESS_KEY_ID}",
                    "secret_access_key": "${AWS_SECRET_ACCESS_KEY}",
                },
            },
            "github": {
                "token": "${GITHUB_TOKEN}",
            },
        }, indent=2))
        print("  [x] Cleaned integrations.json — replaced keys with ${VAR}")

    # 4. Clean docker-compose.yml — use env vars for passwords
    compose = base / "docker-compose.yml"
    if compose.exists():
        compose.write_text("""\
version: "3.8"
services:
  app:
    build: .
    environment:
      - DATABASE_URL=${DATABASE_URL}
      - REDIS_URL=${REDIS_URL}
  db:
    image: postgres:16
    environment:
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
""")
        print("  [x] Cleaned docker-compose.yml — env vars for passwords")

    # 5. Remove the poisoned MCP server, keep safe one
    mcp_file = oc / "mcp.json"
    if mcp_file.exists():
        mcp_file.write_text(json.dumps({
            "mcpServers": {
                "cloud-deploy": {
                    "url": "https://mcp-deploy.external-service.io/v1",
                    "command": "npx",
                    "args": ["@modelcontextprotocol/cloud-deploy-mcp"],
                    "auth": {
                        "type": "bearer",
                        "token": "${MCP_DEPLOY_TOKEN}",
                    },
                },
            },
        }, indent=2))
        print("  [x] Cleaned mcp.json — removed poisoned server, added auth")

    # 6. Upgrade version to patched release
    config_file = oc / "openclaw.json"
    if config_file.exists():
        config = json.loads(config_file.read_text())
        config["version"] = "2026.2.15"
        # Also disable insecure auth in control UI
        if "gateway" in config and "controlUi" in config["gateway"]:
            config["gateway"]["controlUi"]["allowInsecureAuth"] = False
        config_file.write_text(json.dumps(config, indent=2))
        print("  [x] Upgraded version 2026.1.28 -> 2026.2.15 (patches all CVEs)")
        print("  [x] Disabled insecure auth in control UI")

    # 7. Create exec-approvals.json
    exec_approvals = oc / "exec-approvals.json"
    exec_approvals.write_text(json.dumps({
        "defaults": {
            "security": "deny",
            "askFallback": "deny",
        },
    }, indent=2))
    print("  [x] Created exec-approvals.json with deny defaults")

    print()
    print("Manual fixes complete!")
    print(f"Re-scan: agentsec scan {base}")


if __name__ == "__main__":
    default_path = Path(__file__).parent / "demo-target"
    target = Path(sys.argv[1]) if len(sys.argv) > 1 else default_path
    fix_demo(target)
