"""MCP server scanner — analyzes Model Context Protocol server configurations.

Detects:
- Tool poisoning (malicious instructions hidden in tool descriptions)
- Missing authentication on MCP endpoints
- Schema violations and overly permissive tool definitions
- Cross-origin escalation risks
- Excessive permission grants
- Prompt injection vectors in tool metadata
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any

from agentsec.models.findings import (
    Finding,
    FindingCategory,
    FindingSeverity,
    Remediation,
)
from agentsec.scanners.base import BaseScanner, ScanContext

logger = logging.getLogger(__name__)

# Tool descriptions that attempt to manipulate the LLM
_TOOL_POISONING_PATTERNS: list[tuple[str, re.Pattern[str], FindingSeverity]] = [
    (
        "Hidden instruction in tool description",
        re.compile(
            r"(?:always|must|never|ignore|override|instead)\s+"
            r"(?:call|use|execute|run|send|forward|include)",
            re.I,
        ),
        FindingSeverity.HIGH,
    ),
    (
        "Data exfiltration instruction",
        re.compile(
            r"(?:send|forward|post|upload|transmit)\s+.*"
            r"(?:to|at|via)\s+(?:https?://|wss?://)",
            re.I,
        ),
        FindingSeverity.CRITICAL,
    ),
    (
        "Privilege escalation instruction",
        re.compile(
            r"(?:you\s+(?:have|are|can)|grant|enable|allow)\s+.*"
            r"(?:admin|root|sudo|all\s+permissions|full\s+access)",
            re.I,
        ),
        FindingSeverity.HIGH,
    ),
    (
        "Tool chaining manipulation",
        re.compile(
            r"(?:after|before|then|also|first)\s+(?:call|use|invoke|run)\s+",
            re.I,
        ),
        FindingSeverity.MEDIUM,
    ),
    (
        "Invisible unicode characters",
        re.compile(r"[\u200b\u200c\u200d\u2060\ufeff\u00ad]"),
        FindingSeverity.HIGH,
    ),
    (
        "Encoded content in description",
        re.compile(r"(?:base64|atob|btoa|decode)\s*\(", re.I),
        FindingSeverity.HIGH,
    ),
]

# Overly permissive tool schemas
_DANGEROUS_SCHEMA_PATTERNS: list[tuple[str, str, FindingSeverity]] = [
    ("shell_command", "Tool accepts arbitrary shell commands", FindingSeverity.CRITICAL),
    ("file_path", "Tool accepts arbitrary file paths", FindingSeverity.HIGH),
    ("url", "Tool accepts arbitrary URLs", FindingSeverity.MEDIUM),
    ("code", "Tool accepts arbitrary code for execution", FindingSeverity.CRITICAL),
    ("query", "Tool accepts arbitrary database queries", FindingSeverity.HIGH),
    ("sql", "Tool accepts arbitrary SQL statements", FindingSeverity.HIGH),
    ("eval", "Tool accepts expressions for evaluation", FindingSeverity.CRITICAL),
    ("script", "Tool accepts scripts for execution", FindingSeverity.CRITICAL),
]


class McpScanner(BaseScanner):
    """Scans MCP server configurations for security vulnerabilities."""

    @property
    def name(self) -> str:
        return "mcp"

    @property
    def description(self) -> str:
        return (
            "Analyzes MCP server configurations for tool poisoning, missing "
            "authentication, schema violations, and prompt injection vectors."
        )

    def scan(self, context: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        target = context.target_path

        # Find MCP configuration
        mcp_configs = self._find_mcp_configs(target, context)
        if not mcp_configs:
            logger.info("No MCP configurations found in %s", target)
            return findings

        for config_path, config_data in mcp_configs:
            context.files_scanned += 1
            findings.extend(self._analyze_mcp_config(config_path, config_data))

        return findings

    def _find_mcp_configs(
        self, target: Path, context: ScanContext
    ) -> list[tuple[Path, dict[str, Any]]]:
        """Locate MCP server configuration files."""
        configs: list[tuple[Path, dict[str, Any]]] = []

        # Common MCP config locations
        candidates = [
            target / "mcp.json",
            target / ".mcp" / "config.json",
            target / ".openclaw" / "mcp.json",
            target / ".clawdbot" / "mcp.json",
            target / ".config" / "mcp" / "config.json",
            target / "claude_desktop_config.json",
            target / ".claude" / "mcp_servers.json",
        ]

        # Also check main config files for embedded MCP config
        for config_name in ["openclaw.json", "clawdbot.json"]:
            main_config = context.config_files.get(config_name)
            if main_config and main_config.exists():
                try:
                    data = json.loads(main_config.read_text())
                    mcp_section = data.get("mcpServers", data.get("mcp_servers", {}))
                    if mcp_section:
                        configs.append((main_config, {"mcpServers": mcp_section}))
                except (json.JSONDecodeError, OSError):
                    pass

        for candidate in candidates:
            if candidate.exists():
                try:
                    data = json.loads(candidate.read_text())
                    configs.append((candidate, data))
                except (json.JSONDecodeError, OSError):
                    logger.debug("Could not parse MCP config: %s", candidate)

        return configs

    def _analyze_mcp_config(self, config_path: Path, config_data: dict[str, Any]) -> list[Finding]:
        """Analyze a single MCP configuration for security issues."""
        findings: list[Finding] = []

        # Extract servers from various config formats
        servers = (
            config_data.get("mcpServers", {})
            or config_data.get("mcp_servers", {})
            or config_data.get("servers", {})
        )

        if isinstance(servers, dict):
            for server_name, server_config in servers.items():
                if isinstance(server_config, dict):
                    findings.extend(self._analyze_server(config_path, server_name, server_config))

        return findings

    def _analyze_server(
        self,
        config_path: Path,
        server_name: str,
        server_config: dict[str, Any],
    ) -> list[Finding]:
        """Analyze a single MCP server configuration."""
        findings: list[Finding] = []

        # Check command-based servers for dangerous commands
        command = server_config.get("command", "")
        args = server_config.get("args", [])
        full_command = f"{command} {' '.join(str(a) for a in args)}" if args else command

        if command:
            findings.extend(
                self._check_server_command(config_path, server_name, command, full_command)
            )

        # Check for authentication
        findings.extend(self._check_server_auth(config_path, server_name, server_config))

        # Check environment variables for leaked secrets
        env_vars = server_config.get("env", {})
        findings.extend(self._check_server_env(config_path, server_name, env_vars))

        # Check tool definitions if present
        tools = server_config.get("tools", [])
        if isinstance(tools, list):
            for tool in tools:
                if isinstance(tool, dict):
                    findings.extend(self._check_tool_definition(config_path, server_name, tool))

        return findings

    def _check_server_command(
        self,
        config_path: Path,
        server_name: str,
        command: str,
        full_command: str,
    ) -> list[Finding]:
        """Check MCP server command for dangerous patterns."""
        findings: list[Finding] = []

        # CMCP-002: Check for remote/network-based servers
        if re.search(r"https?://", full_command):
            findings.append(
                Finding(
                    scanner=self.name,
                    category=FindingCategory.MCP_CROSS_ORIGIN,
                    severity=FindingSeverity.HIGH,
                    title=f"Remote MCP server '{server_name}' connects to external URL",
                    description=(
                        f"MCP server '{server_name}' connects to a remote endpoint. "
                        f"Remote MCP servers can intercept all tool calls and responses, "
                        f"potentially exfiltrating sensitive data or injecting malicious "
                        f"instructions into tool results."
                    ),
                    evidence=f"Command: {full_command[:120]}",
                    file_path=config_path,
                    remediation=Remediation(
                        summary="Verify the remote server endpoint is trusted",
                        steps=[
                            "Confirm the URL belongs to a trusted service",
                            "Verify TLS certificate and domain ownership",
                            "Consider using a local MCP server proxy with audit logging",
                            "Monitor network traffic for unexpected data exfiltration",
                        ],
                    ),
                    owasp_ids=["ASI03", "ASI05"],
                )
            )

        # CMCP-003: Check for npx/npm with unverified packages
        if re.search(r"npx\s+(?!@(?:anthropic|modelcontextprotocol)/)", full_command):
            pkg_match = re.search(r"npx\s+(\S+)", full_command)
            pkg_name = pkg_match.group(1) if pkg_match else "unknown"
            findings.append(
                Finding(
                    scanner=self.name,
                    category=FindingCategory.SUPPLY_CHAIN,
                    severity=FindingSeverity.MEDIUM,
                    title=f"MCP server '{server_name}' uses npx with unverified package",
                    description=(
                        f"Server '{server_name}' runs via 'npx {pkg_name}', which "
                        f"downloads and executes the package on every invocation. "
                        f"This is vulnerable to supply chain attacks if the package "
                        f"is compromised or typosquatted."
                    ),
                    evidence=f"Command: {full_command[:120]}",
                    file_path=config_path,
                    remediation=Remediation(
                        summary="Pin the package version and verify integrity",
                        steps=[
                            f"Install the package locally: npm install {pkg_name}",
                            "Verify the package source and maintainers",
                            "Use a lock file with integrity hashes",
                            "Consider running in a sandboxed environment",
                        ],
                    ),
                    owasp_ids=["ASI03"],
                )
            )

        return findings

    def _check_server_auth(
        self,
        config_path: Path,
        server_name: str,
        server_config: dict[str, Any],
    ) -> list[Finding]:
        """Check MCP server authentication configuration."""
        findings: list[Finding] = []

        # CMCP-002: Check for URL-based servers without auth
        url = server_config.get("url", "")
        if url and not server_config.get("auth") and not server_config.get("headers"):
            findings.append(
                Finding(
                    scanner=self.name,
                    category=FindingCategory.MCP_NO_AUTH,
                    severity=FindingSeverity.HIGH,
                    title=f"MCP server '{server_name}' has no authentication configured",
                    description=(
                        f"The MCP server '{server_name}' connects to '{url}' without "
                        f"any authentication headers or tokens. This means the connection "
                        f"is unauthenticated and potentially accessible to unauthorized parties."
                    ),
                    file_path=config_path,
                    remediation=Remediation(
                        summary="Configure authentication for the MCP server",
                        steps=[
                            "Add authentication headers or tokens to the server config",
                            "Use OAuth 2.0 with token rotation if the server supports it",
                            "Implement mTLS for server-to-server authentication",
                        ],
                    ),
                    owasp_ids=["ASI05"],
                )
            )

        return findings

    def _check_server_env(
        self,
        config_path: Path,
        server_name: str,
        env_vars: dict[str, Any],
    ) -> list[Finding]:
        """Check MCP server environment variables for hardcoded secrets."""
        findings: list[Finding] = []

        secret_indicators = {"key", "token", "secret", "password", "credential", "auth"}

        for var_name, var_value in env_vars.items():
            if not isinstance(var_value, str):
                continue

            var_lower = var_name.lower()
            is_secret = any(indicator in var_lower for indicator in secret_indicators)

            if is_secret and len(var_value) > 8 and not var_value.startswith("${"):
                # Looks like a hardcoded secret (not an env var reference)
                sanitized = (
                    var_value[:4] + "****" + var_value[-4:] if len(var_value) > 12 else "****"
                )
                findings.append(
                    Finding(
                        scanner=self.name,
                        category=FindingCategory.HARDCODED_CREDENTIAL,
                        severity=FindingSeverity.CRITICAL,
                        title=f"Hardcoded secret in MCP server '{server_name}' config",
                        description=(
                            f"Environment variable '{var_name}' for MCP server "
                            f"'{server_name}' contains a hardcoded secret value. "
                            f"This secret is stored in plaintext in the config file."
                        ),
                        evidence=f"{var_name}={sanitized}",
                        file_path=config_path,
                        remediation=Remediation(
                            summary="Move secret to environment variable or secrets manager",
                            steps=[
                                f"Remove hardcoded value for '{var_name}' from config",
                                f"Set as environment variable: export {var_name}=...",
                                "Or reference via ${{env:VAR_NAME}} syntax",
                                "Rotate the exposed credential immediately",
                            ],
                        ),
                        owasp_ids=["ASI05", "ASI03"],
                    )
                )

        return findings

    def _check_tool_definition(
        self,
        config_path: Path,
        server_name: str,
        tool: dict[str, Any],
    ) -> list[Finding]:
        """Check a single tool definition for poisoning and schema issues."""
        findings: list[Finding] = []
        tool_name = tool.get("name", "unknown")

        # CMCP-001: Check description for tool poisoning
        description = tool.get("description", "")
        for pattern_name, pattern, severity in _TOOL_POISONING_PATTERNS:
            if pattern.search(description):
                findings.append(
                    Finding(
                        scanner=self.name,
                        category=FindingCategory.MCP_TOOL_POISONING,
                        severity=severity,
                        title=f"Tool poisoning in '{server_name}/{tool_name}'",
                        description=(
                            f"The tool '{tool_name}' from MCP server '{server_name}' "
                            f"has a description containing a '{pattern_name}' pattern. "
                            f"Tool descriptions are processed by the LLM and can "
                            f"manipulate the agent's behavior, including redirecting "
                            f"data to attacker-controlled endpoints."
                        ),
                        evidence=f"Description: {description[:200]}",
                        file_path=config_path,
                        remediation=Remediation(
                            summary=f"Review and sanitize tool description for '{tool_name}'",
                            steps=[
                                "Inspect the full tool description for hidden instructions",
                                "Remove any behavioral directives from descriptions",
                                "Report to the MCP server maintainer if from third party",
                            ],
                        ),
                        owasp_ids=["ASI01", "ASI03"],
                    )
                )

        # CMCP-001: Check input schema for dangerous parameter names
        input_schema = tool.get("inputSchema", tool.get("input_schema", {}))
        if isinstance(input_schema, dict):
            properties = input_schema.get("properties", {})
            for prop_name, _prop_def in properties.items():
                prop_lower = prop_name.lower()
                for dangerous_name, desc, severity in _DANGEROUS_SCHEMA_PATTERNS:
                    if dangerous_name in prop_lower:
                        findings.append(
                            Finding(
                                scanner=self.name,
                                category=FindingCategory.MCP_EXCESSIVE_PERMISSIONS,
                                severity=severity,
                                title=(
                                    f"Dangerous parameter '{prop_name}' "
                                    f"in '{server_name}/{tool_name}'"
                                ),
                                description=(
                                    f"{desc}. The tool '{tool_name}' accepts a parameter "
                                    f"'{prop_name}' that could be used for arbitrary "
                                    f"command/code execution if the agent is manipulated."
                                ),
                                file_path=config_path,
                                remediation=Remediation(
                                    summary=f"Validate and restrict '{prop_name}' input",
                                    steps=[
                                        "Add input validation with an allowlist "
                                        "of permitted values",
                                        "Implement sandboxing for command/code execution",
                                        "Add rate limiting and audit logging for this tool",
                                    ],
                                ),
                                owasp_ids=["ASI02", "ASI01"],
                            )
                        )
                        break

        return findings
