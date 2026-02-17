"""Installation scanner — detects insecure configurations in agent installations.

Checks for:
- Plaintext credentials in config files
- Insecure file permissions on sensitive files and directories
- Network exposure (gateway bind, mDNS discovery, WebSocket ports)
- Outdated versions with known CVEs
- Insecure default settings (auto-approve, open DMs, full tool profile)
- Missing authentication on admin interfaces
- DM/group identity and routing policy
- Tool policy and sandboxing posture
- Exec approvals and host execution controls
- SOUL.md / workspace file integrity
"""

from __future__ import annotations

import json
import logging
import re
import shlex
import stat
from pathlib import Path

from agentsec.models.findings import (
    Finding,
    FindingCategory,
    FindingSeverity,
    Remediation,
)
from agentsec.scanners.base import BaseScanner, ScanContext
from agentsec.utils import sanitize_secret

logger = logging.getLogger(__name__)

# Patterns that indicate secrets in config files
_SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("API Key", re.compile(r'(?:api[_-]?key|apikey)\s*[:=]\s*["\']?([a-zA-Z0-9_\-]{20,})', re.I)),
    ("Bearer Token", re.compile(r'["\']?Bearer\s+([a-zA-Z0-9_\-\.]{20,})', re.I)),
    ("OpenAI Key", re.compile(r"sk-[a-zA-Z0-9]{20,}")),
    ("Anthropic Key", re.compile(r"sk-ant-[a-zA-Z0-9_\-]{20,}")),
    ("AWS Key", re.compile(r"AKIA[0-9A-Z]{16}")),
    (
        "AWS Secret",
        re.compile(r'(?:aws_secret|secret_key)\s*[:=]\s*["\']?([a-zA-Z0-9/+=]{40})', re.I),
    ),
    ("GitHub Token", re.compile(r"gh[pousr]_[a-zA-Z0-9]{36,}")),
    ("Slack Token", re.compile(r"xox[bpoas]-[a-zA-Z0-9\-]+")),
    ("Private Key", re.compile(r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----")),
    ("Database URL", re.compile(r'(?:postgres|mysql|mongodb)://[^\s"\']+:[^\s"\']+@', re.I)),
    (
        "Generic Secret",
        re.compile(r'(?:password|passwd|secret|token)\s*[:=]\s*["\']?([^\s"\']{8,})', re.I),
    ),
    ("Webhook URL", re.compile(r"https://hooks\.slack\.com/services/[a-zA-Z0-9/]+")),
    ("Discord Webhook", re.compile(r"https://discord\.com/api/webhooks/\d+/[a-zA-Z0-9_\-]+")),
]

# Known OpenClaw config file names and their risk context
_OPENCLAW_CONFIG_FILES: dict[str, str] = {
    "clawdbot.json": "Primary configuration — often contains API keys in plaintext",
    "openclaw.json": "Primary configuration (renamed from clawdbot.json)",
    ".env": "Environment variables — common location for secrets",
    ".env.local": "Local environment overrides — often contains real tokens",
    "SOUL.md": "Agent personality and safety boundaries — tampering alters agent behavior",
    "AGENTS.md": "Agent definitions — tampering alters multi-agent topology",
    "TOOLS.md": "Tool definitions — tampering grants/revokes tool access",
    "USER.md": "User preference overrides — social engineering vector",
    "memory.md": "Conversation history — may contain sensitive discussions",
    "config.json": "Secondary config — may contain service credentials",
    "config.yaml": "Secondary config — may contain service credentials",
    "config.yml": "Secondary config — may contain service credentials",
    "exec-approvals.json": "Exec approval rules — controls host command execution",
}

# Files that should have restricted permissions (owner-only read/write)
_SENSITIVE_FILE_NAMES = {
    "clawdbot.json",
    "openclaw.json",
    ".env",
    ".env.local",
    "config.json",
    "config.yaml",
    "config.yml",
    "exec-approvals.json",
    "auth-profiles.json",
}

# Directories that should be owner-only (700)
_SENSITIVE_DIR_NAMES = {".openclaw", ".clawdbot", ".config/openclaw"}

# Deep paths under agent config that contain sensitive data
_DEEP_SENSITIVE_PATHS = [
    "credentials",
    "agents/*/agent/auth-profiles.json",
    "agents/*/sessions",
    "cron/jobs.json",
]

# Known CVEs for OpenClaw/Moltbot
_KNOWN_CVES: list[dict[str, str]] = [
    {
        "id": "CVE-2026-25253",
        "title": "One-click RCE via WebSocket hijacking",
        "severity": "high",
        "fixed_in": "2026.1.29",
        "description": (
            "Cross-Site WebSocket Hijacking allows attackers to steal authentication "
            "tokens via a malicious link, leading to full system compromise."
        ),
        "reference": "https://nvd.nist.gov/vuln/detail/CVE-2026-25253",
    },
    {
        "id": "CVE-2026-24763",
        "title": "Command injection in Docker sandbox via PATH variable",
        "severity": "high",
        "fixed_in": "2026.1.29",
        "description": (
            "Authenticated command injection in OpenClaw Docker execution due to "
            "unsafe handling of the PATH environment variable when constructing "
            "shell commands. Allows execution of unintended commands inside the "
            "container and exposure of sensitive data."
        ),
        "reference": "https://nvd.nist.gov/vuln/detail/CVE-2026-24763",
    },
    {
        "id": "CVE-2026-25157",
        "title": "SSH command injection via sshNodeCommand",
        "severity": "high",
        "fixed_in": "2026.1.29",
        "description": (
            "OS command injection in the sshNodeCommand and parseSSHTarget functions "
            "allows attackers to execute arbitrary commands on both remote SSH hosts "
            "and local machines through improper input handling and insufficient "
            "validation of user-supplied data."
        ),
        "reference": "https://nvd.nist.gov/vuln/detail/CVE-2026-25157",
    },
    {
        "id": "CVE-2026-25593",
        "title": "Unauthenticated local RCE via WebSocket API",
        "severity": "critical",
        "fixed_in": "2026.1.30",
        "description": (
            "Unauthenticated access to the WebSocket API allows local attackers to "
            "write arbitrary configuration changes and execute commands without "
            "authentication, leading to full system compromise."
        ),
        "reference": "https://www.cve.org/CVERecord?id=CVE-2026-25593",
    },
    {
        "id": "CVE-2026-25475",
        "title": "Path traversal via MEDIA: file extraction",
        "severity": "high",
        "fixed_in": "2026.1.30",
        "description": (
            "The isValidMedia() function fails to properly validate file paths, "
            "allowing agents to read arbitrary files on the system including "
            "absolute paths, home directory paths, and directory traversal "
            "sequences. Enables sensitive data exfiltration."
        ),
        "reference": "https://nvd.nist.gov/vuln/detail/CVE-2026-25475",
    },
]


class InstallationScanner(BaseScanner):
    """Scans agent installations for security misconfigurations."""

    @property
    def name(self) -> str:
        return "installation"

    @property
    def description(self) -> str:
        return (
            "Checks agent installations for plaintext credentials, insecure file "
            "permissions, network exposure, gateway/auth config, DM/group policy, "
            "tool profile, exec approvals, sandbox posture, and known CVEs."
        )

    def scan(self, context: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        target = context.target_path

        if not target.exists():
            logger.warning("Target path does not exist: %s", target)
            return findings

        findings.extend(self._scan_config_files(context))
        findings.extend(self._scan_file_permissions(context))
        findings.extend(self._scan_directory_permissions(context))
        findings.extend(self._scan_deep_sensitive_paths(context))
        findings.extend(self._scan_plaintext_secrets(context))
        findings.extend(self._scan_version_and_cves(context))
        findings.extend(self._scan_gateway_config(context))
        findings.extend(self._scan_identity_policy(context))
        findings.extend(self._scan_tool_policy(context))
        findings.extend(self._scan_exec_approvals(context))
        findings.extend(self._scan_sandbox_config(context))
        findings.extend(self._scan_discovery_config(context))
        findings.extend(self._scan_auth_config(context))
        findings.extend(self._scan_soul_integrity(context))
        findings.extend(self._scan_plugin_config(context))
        findings.extend(self._scan_ssrf_config(context))
        findings.extend(self._scan_safety_scanner_config(context))

        return findings

    def _scan_config_files(self, context: ScanContext) -> list[Finding]:
        """Discover and register config files for cross-scanner use."""
        findings: list[Finding] = []
        target = context.target_path

        for filename in _OPENCLAW_CONFIG_FILES:
            config_path = target / filename
            if config_path.exists():
                context.register_config_file(filename, config_path)
                logger.debug("Found config file: %s", config_path)

        # Check common subdirectories (including legacy paths)
        for subdir in [".openclaw", ".clawdbot", ".config/openclaw", ".moltbot"]:
            sub_path = target / subdir
            if sub_path.is_dir():
                context.metadata["agent_config_dir"] = str(sub_path)
                for child in sub_path.iterdir():
                    if child.is_file():
                        context.register_config_file(child.name, child)

        # Check for exec-approvals.json in .openclaw
        for config_dir_name in [".openclaw", ".clawdbot"]:
            exec_approvals = target / config_dir_name / "exec-approvals.json"
            if exec_approvals.exists():
                context.register_config_file("exec-approvals.json", exec_approvals)

        return findings

    def _scan_file_permissions(self, context: ScanContext) -> list[Finding]:
        """Check that sensitive files have restricted permissions."""
        findings: list[Finding] = []

        for name, path in context.config_files.items():
            if name not in _SENSITIVE_FILE_NAMES:
                continue
            if not path.exists():
                continue

            try:
                file_stat = path.stat()
                mode = file_stat.st_mode

                group_readable = bool(mode & stat.S_IRGRP)
                others_readable = bool(mode & stat.S_IROTH)
                world_writable = bool(mode & stat.S_IWOTH)

                if others_readable or world_writable:
                    findings.append(
                        Finding(
                            scanner=self.name,
                            category=FindingCategory.INSECURE_PERMISSIONS,
                            severity=FindingSeverity.HIGH,
                            title=f"World-readable sensitive file: {name}",
                            description=(
                                f"The file '{path}' is readable by all users on the system. "
                                f"Any local process or user can read its contents, which may "
                                f"include API keys, tokens, and other credentials."
                            ),
                            evidence=f"Permissions: {oct(mode)[-3:]}",
                            file_path=path,
                            remediation=Remediation(
                                summary=f"Restrict permissions on {name} to owner-only",
                                steps=[
                                    f"chmod 600 '{path}'",
                                    "Verify no other processes depend on group/world access",
                                ],
                                automated=True,
                                command=f"chmod 600 {shlex.quote(str(path))}",
                            ),
                            owasp_ids=["ASI05"],
                        )
                    )
                elif group_readable:
                    findings.append(
                        Finding(
                            scanner=self.name,
                            category=FindingCategory.INSECURE_PERMISSIONS,
                            severity=FindingSeverity.MEDIUM,
                            title=f"Group-readable sensitive file: {name}",
                            description=(
                                f"The file '{path}' is readable by group members. "
                                f"Consider restricting to owner-only if it contains secrets."
                            ),
                            evidence=f"Permissions: {oct(mode)[-3:]}",
                            file_path=path,
                            remediation=Remediation(
                                summary=f"Restrict permissions on {name} to owner-only",
                                steps=[f"chmod 600 '{path}'"],
                                automated=True,
                                command=f"chmod 600 {shlex.quote(str(path))}",
                            ),
                            owasp_ids=["ASI05"],
                        )
                    )
            except OSError:
                logger.debug("Could not stat %s", path)

        return findings

    def _scan_directory_permissions(self, context: ScanContext) -> list[Finding]:
        """Check that agent config directories have restricted permissions (700)."""
        findings: list[Finding] = []
        target = context.target_path

        for dir_name in _SENSITIVE_DIR_NAMES:
            dir_path = target / dir_name
            if not dir_path.is_dir():
                continue

            try:
                mode = dir_path.stat().st_mode
                others_access = bool(mode & (stat.S_IROTH | stat.S_IWOTH | stat.S_IXOTH))
                group_access = bool(mode & (stat.S_IRGRP | stat.S_IWGRP | stat.S_IXGRP))

                if others_access:
                    findings.append(
                        Finding(
                            scanner=self.name,
                            category=FindingCategory.INSECURE_PERMISSIONS,
                            severity=FindingSeverity.HIGH,
                            title=f"Agent config directory world-accessible: {dir_name}",
                            description=(
                                f"The directory '{dir_path}' is accessible by all users. "
                                f"This directory contains agent configuration, credentials, "
                                f"session history, and exec approvals."
                            ),
                            evidence=f"Permissions: {oct(mode)[-3:]}",
                            file_path=dir_path,
                            remediation=Remediation(
                                summary=f"Restrict {dir_name} to owner-only access",
                                steps=[f"chmod 700 {shlex.quote(str(dir_path))}"],
                                automated=True,
                                command=f"chmod 700 {shlex.quote(str(dir_path))}",
                            ),
                            owasp_ids=["ASI05"],
                        )
                    )
                elif group_access:
                    findings.append(
                        Finding(
                            scanner=self.name,
                            category=FindingCategory.INSECURE_PERMISSIONS,
                            severity=FindingSeverity.MEDIUM,
                            title=f"Agent config directory group-accessible: {dir_name}",
                            description=(
                                f"The directory '{dir_path}' is accessible by group members. "
                                f"Restrict to owner-only for defense in depth."
                            ),
                            evidence=f"Permissions: {oct(mode)[-3:]}",
                            file_path=dir_path,
                            remediation=Remediation(
                                summary=f"Restrict {dir_name} to owner-only",
                                steps=[f"chmod 700 {shlex.quote(str(dir_path))}"],
                                automated=True,
                                command=f"chmod 700 {shlex.quote(str(dir_path))}",
                            ),
                            owasp_ids=["ASI05"],
                        )
                    )
            except OSError:
                logger.debug("Could not stat directory %s", dir_path)

        return findings

    def _scan_deep_sensitive_paths(self, context: ScanContext) -> list[Finding]:
        """Check deep paths under agent config for insecure permissions."""
        findings: list[Finding] = []

        config_dir = context.metadata.get("agent_config_dir")
        if not config_dir:
            return findings

        config_path = Path(config_dir)
        for pattern in _DEEP_SENSITIVE_PATHS:
            for match_path in config_path.glob(pattern):
                if not match_path.exists():
                    continue
                try:
                    mode = match_path.stat().st_mode
                    others_access = bool(mode & (stat.S_IROTH | stat.S_IWOTH))
                    if others_access:
                        rel = match_path.relative_to(config_path)
                        findings.append(
                            Finding(
                                scanner=self.name,
                                category=FindingCategory.INSECURE_PERMISSIONS,
                                severity=FindingSeverity.HIGH,
                                title=f"Sensitive path world-accessible: {rel}",
                                description=(
                                    f"The path '{match_path}' contains sensitive agent data "
                                    f"(credentials, auth profiles, or session history) and is "
                                    f"readable by all users."
                                ),
                                evidence=f"Permissions: {oct(mode)[-3:]}",
                                file_path=match_path,
                                remediation=Remediation(
                                    summary="Restrict to owner-only",
                                    steps=[f"chmod 600 {shlex.quote(str(match_path))}"],
                                    automated=True,
                                    command=f"chmod 600 {shlex.quote(str(match_path))}",
                                ),
                                owasp_ids=["ASI05"],
                            )
                        )
                except OSError:
                    pass

        return findings

    def _scan_plaintext_secrets(self, context: ScanContext) -> list[Finding]:
        """Scan config files for plaintext secrets using regex patterns."""
        findings: list[Finding] = []

        for name, path in context.config_files.items():
            if not path.exists() or not path.is_file():
                continue

            try:
                file_size = path.stat().st_size
                if file_size > self.config.extra.get("max_file_size", 10_000_000):
                    continue

                content = path.read_text(errors="replace")
                context.files_scanned += 1

                for secret_type, pattern in _SECRET_PATTERNS:
                    for match in pattern.finditer(content):
                        matched_text = match.group(0)
                        sanitized = sanitize_secret(matched_text)

                        line_num = content[: match.start()].count("\n") + 1

                        context.register_secrets_location(path)

                        findings.append(
                            Finding(
                                scanner=self.name,
                                category=FindingCategory.PLAINTEXT_SECRET,
                                severity=FindingSeverity.CRITICAL,
                                title=f"Plaintext {secret_type} in {name}",
                                description=(
                                    f"A {secret_type} was found stored in plaintext in '{name}'. "
                                    f"Plaintext credentials are trivially extractable by any "
                                    f"malware, infostealer, or local process with read access."
                                ),
                                evidence=f"Pattern match: {sanitized} (line {line_num})",
                                file_path=path,
                                line_number=line_num,
                                remediation=Remediation(
                                    summary=f"Move {secret_type} to OS keychain or secrets manager",
                                    steps=[
                                        "Rotate the exposed credential immediately",
                                        f"Remove plaintext value from {name}",
                                        "Store in OS keychain, secrets manager, or env var",
                                        f"Add {name} to .gitignore if not already excluded",
                                    ],
                                ),
                                owasp_ids=["ASI05", "ASI03"],
                            )
                        )

            except (OSError, UnicodeDecodeError):
                logger.debug("Could not read %s", path)

        return findings

    def _scan_version_and_cves(self, context: ScanContext) -> list[Finding]:
        """Check installed version against known CVEs."""
        findings: list[Finding] = []
        version = self._detect_version(context)

        if not version:
            findings.append(
                Finding(
                    scanner=self.name,
                    category=FindingCategory.OUTDATED_VERSION,
                    severity=FindingSeverity.INFO,
                    title="Could not determine agent version",
                    description=(
                        "Unable to detect the installed agent version. "
                        "Cannot check for known CVEs without version information."
                    ),
                    remediation=Remediation(
                        summary="Ensure agent is updated to latest version",
                        steps=["Run 'npm update -g openclaw' or check release notes"],
                    ),
                    owasp_ids=["ASI03"],
                )
            )
            return findings

        context.metadata["agent_version"] = version

        for cve in _KNOWN_CVES:
            if self._version_is_vulnerable(version, cve["fixed_in"]):
                findings.append(
                    Finding(
                        scanner=self.name,
                        category=FindingCategory.CVE_MATCH,
                        severity=FindingSeverity(cve["severity"]),
                        title=f"{cve['id']}: {cve['title']}",
                        description=cve["description"],
                        evidence=f"Installed version: {version}, fixed in: {cve['fixed_in']}",
                        cve_ids=[cve["id"]],
                        remediation=Remediation(
                            summary=f"Update to version {cve['fixed_in']} or later",
                            steps=[
                                "npm update -g openclaw  # updates to latest",
                                "Rotate all tokens and credentials after updating",
                                "Review audit logs for signs of exploitation",
                            ],
                            references=[cve["reference"]],
                        ),
                        owasp_ids=["ASI03"],
                    )
                )

        return findings

    # -----------------------------------------------------------------------
    # Gateway exposure checks (CGW-001 through CGW-004)
    # -----------------------------------------------------------------------

    def _scan_gateway_config(self, context: ScanContext) -> list[Finding]:
        """Check gateway bind mode, auth, control UI, and proxy config."""
        findings: list[Finding] = []
        config_data = self._load_main_config(context)
        if config_data is None:
            return findings

        config_path = self._get_main_config_path(context)

        # --- CGW-001: Gateway bind not loopback ---
        gateway = config_data.get("gateway", {})
        bind_mode = gateway.get("bind", "loopback")
        if bind_mode in ("lan", "tailnet", "custom", "0.0.0.0", "::"):
            findings.append(
                Finding(
                    scanner=self.name,
                    category=FindingCategory.NETWORK_EXPOSURE,
                    severity=FindingSeverity.CRITICAL,
                    title="Gateway bound to non-loopback interface",
                    description=(
                        f"The OpenClaw Gateway is configured with bind='{bind_mode}', "
                        f"exposing the control interface beyond localhost. Unless protected "
                        f"by a firewall and strong auth, this allows remote attackers to "
                        f"interact with the agent directly."
                    ),
                    evidence=f"gateway.bind = {bind_mode}",
                    file_path=config_path,
                    remediation=Remediation(
                        summary="Bind Gateway to loopback or add strong authentication",
                        steps=[
                            "Set gateway.bind to 'loopback' (default)",
                            "If remote access is needed, use a reverse proxy with auth",
                            "Ensure firewall rules restrict access to trusted IPs",
                        ],
                        automated=True,
                        command="agentsec harden ~ -p workstation --apply",
                    ),
                    owasp_ids=["ASI05", "ASI02"],
                )
            )

        # Also check legacy websocket/server host settings
        ws_config = config_data.get("websocket", config_data.get("server", {}))
        host = ws_config.get("host", "")
        if host in ("0.0.0.0", "::"):
            findings.append(
                Finding(
                    scanner=self.name,
                    category=FindingCategory.NETWORK_EXPOSURE,
                    severity=FindingSeverity.CRITICAL,
                    title="WebSocket server bound to all network interfaces",
                    description=(
                        f"The WebSocket server listens on '{host}', making it reachable "
                        f"from any network. Combined with CVE-2026-25253, this enables "
                        f"one-click RCE via Cross-Site WebSocket Hijacking."
                    ),
                    evidence=f"host = {host}",
                    file_path=config_path,
                    remediation=Remediation(
                        summary="Bind WebSocket to 127.0.0.1",
                        steps=[
                            "Set host to '127.0.0.1'",
                            "Use a reverse proxy for remote access",
                        ],
                        references=["https://nvd.nist.gov/vuln/detail/CVE-2026-25253"],
                    ),
                    owasp_ids=["ASI05", "ASI02"],
                )
            )

        # CORS / origin validation
        cors_config = ws_config.get("cors", ws_config.get("allowed_origins"))
        if (cors_config is None or cors_config == "*") and (host or bind_mode != "loopback"):
            findings.append(
                Finding(
                    scanner=self.name,
                    category=FindingCategory.MISSING_AUTH,
                    severity=FindingSeverity.HIGH,
                    title="No WebSocket origin validation configured",
                    description=(
                        "The WebSocket server does not validate the Origin header. "
                        "This enables Cross-Site WebSocket Hijacking from malicious webpages."
                    ),
                    file_path=config_path,
                    remediation=Remediation(
                        summary="Configure allowed origins",
                        steps=["Set 'allowed_origins' to specific trusted domains"],
                        automated=True,
                        command="agentsec harden ~ -p workstation --apply",
                    ),
                    owasp_ids=["ASI05", "ASI01"],
                )
            )

        # --- CGW-002: Gateway auth missing ---
        gw_auth = gateway.get("auth", gateway.get("authentication", {}))
        if not gw_auth and bind_mode != "loopback":
            findings.append(
                Finding(
                    scanner=self.name,
                    category=FindingCategory.MISSING_AUTH,
                    severity=FindingSeverity.CRITICAL,
                    title="Gateway auth missing on non-loopback interface",
                    description=(
                        f"The Gateway is bound to '{bind_mode}' but has no authentication "
                        f"configured. Any device on the network can control the agent."
                    ),
                    evidence=f"gateway.bind={bind_mode}, gateway.auth=<missing>",
                    file_path=config_path,
                    remediation=Remediation(
                        summary="Configure token or password authentication",
                        steps=[
                            "Set gateway.auth.token or gateway.auth.password",
                            "Prefer token-based auth for programmatic access",
                        ],
                        automated=True,
                        command="agentsec harden ~ -p workstation --apply",
                        references=["https://docs.openclaw.ai/gateway/security"],
                    ),
                    owasp_ids=["ASI05", "ASI02"],
                )
            )

        # --- CGW-003: Control UI insecure auth flags ---
        control_ui = gateway.get("controlUi", gateway.get("control_ui", {}))
        if control_ui.get("allowInsecureAuth"):
            findings.append(
                Finding(
                    scanner=self.name,
                    category=FindingCategory.INSECURE_CONFIG,
                    severity=FindingSeverity.HIGH,
                    title="Control UI allows insecure authentication",
                    description=(
                        "gateway.controlUi.allowInsecureAuth is enabled, allowing "
                        "authentication over unencrypted connections. Credentials can "
                        "be intercepted by network eavesdroppers."
                    ),
                    evidence="controlUi.allowInsecureAuth = true",
                    file_path=config_path,
                    remediation=Remediation(
                        summary="Disable insecure auth; use HTTPS",
                        steps=["Remove or set allowInsecureAuth to false", "Enable TLS"],
                    ),
                    owasp_ids=["ASI05"],
                )
            )

        danger_flags = [
            "dangerouslyDisableDeviceAuth",
            "dangerouslyDisableAuth",
        ]
        for flag in danger_flags:
            if config_data.get(flag) or gateway.get(flag) or control_ui.get(flag):
                findings.append(
                    Finding(
                        scanner=self.name,
                        category=FindingCategory.INSECURE_CONFIG,
                        severity=FindingSeverity.CRITICAL,
                        title=f"Dangerous auth bypass flag enabled: {flag}",
                        description=(
                            f"The flag '{flag}' is set to true, completely disabling "
                            f"authentication. This is intended for development only and "
                            f"must never be used in production."
                        ),
                        evidence=f"{flag} = true",
                        file_path=config_path,
                        remediation=Remediation(
                            summary=f"Remove {flag} from configuration",
                            steps=[f"Delete or set {flag} to false"],
                            automated=True,
                            command="agentsec harden ~ -p workstation --apply",
                        ),
                        owasp_ids=["ASI05", "ASI10"],
                    )
                )

        # --- CGW-004: Reverse proxy without trustedProxies ---
        if (gateway.get("reverseProxy") or gateway.get("proxy")) and not gateway.get(
            "trustedProxies"
        ):
            findings.append(
                Finding(
                    scanner=self.name,
                    category=FindingCategory.INSECURE_CONFIG,
                    severity=FindingSeverity.MEDIUM,
                    title="Reverse proxy without trustedProxies",
                    description=(
                        "A reverse proxy is configured but trustedProxies is not set. "
                        "Without this, proxy headers can be spoofed to bypass IP-based "
                        "access controls."
                    ),
                    file_path=config_path,
                    remediation=Remediation(
                        summary="Set gateway.trustedProxies to your proxy IPs",
                        steps=["Add trustedProxies array with proxy CIDR ranges"],
                    ),
                    owasp_ids=["ASI05"],
                )
            )

        return findings

    # -----------------------------------------------------------------------
    # DM/group identity policy checks (CID-001 through CID-003)
    # -----------------------------------------------------------------------

    def _scan_identity_policy(self, context: ScanContext) -> list[Finding]:
        """Check DM policy, group policy, and session scoping."""
        findings: list[Finding] = []
        config_data = self._load_main_config(context)
        if config_data is None:
            return findings

        config_path = self._get_main_config_path(context)

        # --- CID-001: DMs are open ---
        dm_policy = config_data.get("dmPolicy", config_data.get("dm_policy", ""))
        session = config_data.get("session", {})
        if dm_policy == "open":
            findings.append(
                Finding(
                    scanner=self.name,
                    category=FindingCategory.INSECURE_CONFIG,
                    severity=FindingSeverity.CRITICAL,
                    title="DM policy set to 'open' — anyone can message the agent",
                    description=(
                        "The agent accepts direct messages from anyone without pairing "
                        "or allowlisting. This makes the agent a direct target for prompt "
                        "injection attacks from untrusted users."
                    ),
                    evidence="dmPolicy = open",
                    file_path=config_path,
                    remediation=Remediation(
                        summary="Restrict DM access to paired/allowlisted users",
                        steps=[
                            "Set dmPolicy to 'paired' or 'allowlist'",
                            "Use 'openclaw config set dmPolicy paired'",
                        ],
                        automated=True,
                        command="agentsec harden ~ -p workstation --apply",
                        references=["https://docs.openclaw.ai/gateway/security"],
                    ),
                    owasp_ids=["ASI01", "ASI02", "ASI10"],
                )
            )

        # --- CID-002: Group policy open/allow-all ---
        group_policy = config_data.get("groupPolicy", config_data.get("group_policy", ""))
        if group_policy == "open":
            findings.append(
                Finding(
                    scanner=self.name,
                    category=FindingCategory.INSECURE_CONFIG,
                    severity=FindingSeverity.HIGH,
                    title="Group policy is 'open' — agent responds in any group",
                    description=(
                        "The agent will respond to messages in any group it's added to. "
                        "In large or public groups, untrusted users can inject prompts "
                        "and trigger tool execution."
                    ),
                    evidence="groupPolicy = open",
                    file_path=config_path,
                    remediation=Remediation(
                        summary="Restrict group policy to allowlisted groups",
                        steps=[
                            "Set groupPolicy to 'allowlist'",
                            "Maintain an explicit list of trusted group IDs",
                        ],
                        automated=True,
                        command="agentsec harden ~ -p workstation --apply",
                    ),
                    owasp_ids=["ASI01", "ASI02"],
                )
            )

        group_allow = config_data.get("groupAllowlist", config_data.get("group_allowlist", []))
        if isinstance(group_allow, list) and "*" in group_allow:
            findings.append(
                Finding(
                    scanner=self.name,
                    category=FindingCategory.INSECURE_CONFIG,
                    severity=FindingSeverity.HIGH,
                    title="Group allowlist contains wildcard '*'",
                    description=(
                        "The group allowlist includes '*', which effectively allows "
                        "the agent to respond in any group — same risk as groupPolicy=open."
                    ),
                    evidence="groupAllowlist contains '*'",
                    file_path=config_path,
                    remediation=Remediation(
                        summary="Replace wildcard with specific group IDs",
                        steps=["Remove '*' from groupAllowlist, add only trusted group IDs"],
                    ),
                    owasp_ids=["ASI01", "ASI02"],
                )
            )

        # --- CID-003: DM scope shared across users ---
        dm_scope = session.get("dmScope", session.get("dm_scope", ""))
        if dm_scope and dm_scope not in ("per-channel-peer", "per_channel_peer"):
            findings.append(
                Finding(
                    scanner=self.name,
                    category=FindingCategory.INSECURE_CONFIG,
                    severity=FindingSeverity.MEDIUM,
                    title="DM scope not isolated per channel peer",
                    description=(
                        f"session.dmScope is '{dm_scope}'. Without per-channel-peer "
                        f"isolation, conversations from different users may share "
                        f"context, leading to information leakage between users."
                    ),
                    evidence=f"session.dmScope = {dm_scope}",
                    file_path=config_path,
                    remediation=Remediation(
                        summary="Set dmScope to per-channel-peer for isolation",
                        steps=["Set session.dmScope to 'per-channel-peer'"],
                        automated=True,
                        command="agentsec harden ~ -p workstation --apply",
                    ),
                    owasp_ids=["ASI05", "ASI07"],
                )
            )

        return findings

    # -----------------------------------------------------------------------
    # Tool policy + sandboxing checks (CTO-001 through CTO-003)
    # -----------------------------------------------------------------------

    def _scan_tool_policy(self, context: ScanContext) -> list[Finding]:
        """Check tool profiles, group:runtime access, and tool restrictions."""
        findings: list[Finding] = []
        config_data = self._load_main_config(context)
        if config_data is None:
            return findings

        config_path = self._get_main_config_path(context)
        tools_config = config_data.get("tools", {})

        # --- CTO-001: tools.profile is full (or unset) in exposed contexts ---
        profile = tools_config.get("profile", "")
        dm_policy = config_data.get("dmPolicy", "")
        is_exposed = dm_policy == "open" or config_data.get("groupPolicy") == "open"

        if profile in ("full", "") and is_exposed:
            findings.append(
                Finding(
                    scanner=self.name,
                    category=FindingCategory.INSECURE_DEFAULT,
                    severity=FindingSeverity.CRITICAL,
                    title="Full tool profile with open inbound access",
                    description=(
                        f"tools.profile is '{profile or 'unset (defaults to full)'}' and the "
                        f"agent accepts messages from untrusted sources. This gives "
                        f"prompt-injected inputs access to all tools including exec, "
                        f"browser, and filesystem."
                    ),
                    evidence=f"tools.profile={profile or 'unset'}, dmPolicy={dm_policy}",
                    file_path=config_path,
                    remediation=Remediation(
                        summary="Restrict tool profile for untrusted input routes",
                        steps=[
                            "Set tools.profile to 'messaging' or 'minimal'",
                            "Explicitly allow only needed tools via tools.allow",
                            "Use 'openclaw config set tools.profile messaging'",
                        ],
                        automated=True,
                        command="agentsec harden ~ -p workstation --apply",
                        references=["https://docs.openclaw.ai/tools"],
                    ),
                    owasp_ids=["ASI02", "ASI01", "ASI10"],
                )
            )

        # --- CTO-002: group:runtime enabled for untrusted routes ---
        allow_list = tools_config.get("allow", [])
        if isinstance(allow_list, list):
            runtime_groups = {"group:runtime", "group:all"}
            enabled_risky = runtime_groups & {str(x) for x in allow_list}
            if enabled_risky and is_exposed:
                findings.append(
                    Finding(
                        scanner=self.name,
                        category=FindingCategory.INSECURE_DEFAULT,
                        severity=FindingSeverity.HIGH,
                        title=(
                            f"Risky tool group enabled with open access: {', '.join(enabled_risky)}"
                        ),
                        description=(
                            f"Tool groups {enabled_risky} expand to exec/bash/process "
                            f"capabilities. With open DM or group policy, untrusted users "
                            f"can potentially trigger host command execution."
                        ),
                        evidence=f"tools.allow includes {enabled_risky}",
                        file_path=config_path,
                        remediation=Remediation(
                            summary="Remove group:runtime from allow list for public agents",
                            steps=[
                                "Remove 'group:runtime' from tools.allow",
                                "Explicitly allow only needed individual tools",
                            ],
                            references=["https://docs.openclaw.ai/tools"],
                        ),
                        owasp_ids=["ASI02", "ASI08"],
                    )
                )

        return findings

    def _scan_exec_approvals(self, context: ScanContext) -> list[Finding]:
        """Check exec approval configuration (CEX-001 through CEX-003)."""
        findings: list[Finding] = []
        config_data = self._load_main_config(context)

        if not config_data:
            return findings

        # Check if exec tool is potentially active
        tools_config = config_data.get("tools", {})
        profile = tools_config.get("profile", "full")
        deny_list = tools_config.get("deny", [])
        exec_denied = isinstance(deny_list, list) and "exec" in deny_list

        if profile in ("full", ""):
            # Exec could be active; check for approvals file
            exec_path = context.config_files.get("exec-approvals.json")

            # --- CEX-001: Exec approvals missing ---
            if not exec_path and not exec_denied:
                findings.append(
                    Finding(
                        scanner=self.name,
                        category=FindingCategory.INSECURE_DEFAULT,
                        severity=FindingSeverity.HIGH,
                        title="Exec approvals file missing — host execution uncontrolled",
                        description=(
                            "No exec-approvals.json found. Without exec approval rules, "
                            "the exec tool can run arbitrary commands on the host without "
                            "explicit per-command authorization."
                        ),
                        remediation=Remediation(
                            summary="Create exec-approvals.json with restrictive defaults",
                            steps=[
                                "Create ~/.openclaw/exec-approvals.json",
                                "Set defaults.security to 'deny' or 'allowlist'",
                                "Set askFallback to 'deny'",
                            ],
                            references=["https://docs.openclaw.ai/tools/exec-approvals"],
                        ),
                        owasp_ids=["ASI02", "ASI08"],
                    )
                )
            elif exec_path and exec_path.exists():
                findings.extend(self._check_exec_approvals_content(exec_path))

        return findings

    def _check_exec_approvals_content(self, exec_path: Path) -> list[Finding]:
        """Check exec-approvals.json for overly permissive settings."""
        findings: list[Finding] = []

        try:
            data = json.loads(exec_path.read_text())
        except (json.JSONDecodeError, OSError):
            return findings

        defaults = data.get("defaults", {})

        # --- CEX-002: Approvals defaults too permissive ---
        security = defaults.get("security", "")
        if security == "full":
            findings.append(
                Finding(
                    scanner=self.name,
                    category=FindingCategory.INSECURE_DEFAULT,
                    severity=FindingSeverity.HIGH,
                    title="Exec approvals defaults.security set to 'full'",
                    description=(
                        "The exec approval defaults allow full command execution without "
                        "per-command review. Any tool call that triggers exec can run "
                        "arbitrary host commands."
                    ),
                    evidence="defaults.security = full",
                    file_path=exec_path,
                    remediation=Remediation(
                        summary="Set defaults.security to 'deny' or 'allowlist'",
                        steps=["Change defaults.security to 'allowlist' in exec-approvals.json"],
                        references=["https://docs.openclaw.ai/tools/exec-approvals"],
                    ),
                    owasp_ids=["ASI02", "ASI08"],
                )
            )

        ask_fallback = defaults.get("askFallback", "")
        if ask_fallback == "full":
            findings.append(
                Finding(
                    scanner=self.name,
                    category=FindingCategory.INSECURE_DEFAULT,
                    severity=FindingSeverity.MEDIUM,
                    title="Exec approvals askFallback set to 'full'",
                    description=(
                        "When the user is not available to approve an exec command, "
                        "the fallback is 'full' (allow all). This means unattended "
                        "agent sessions can execute arbitrary commands."
                    ),
                    evidence="defaults.askFallback = full",
                    file_path=exec_path,
                    remediation=Remediation(
                        summary="Set askFallback to 'deny'",
                        steps=["Change defaults.askFallback to 'deny'"],
                    ),
                    owasp_ids=["ASI02", "ASI08"],
                )
            )

        # --- CEX-003: safeBins expanded beyond defaults ---
        tools_section = data.get("tools", data.get("exec", {}))
        safe_bins = tools_section.get("safeBins", [])
        default_safe_bins = {"cat", "ls", "echo", "date", "whoami", "pwd", "head", "tail", "wc"}
        if isinstance(safe_bins, list) and len(safe_bins) > 0:
            custom_bins = set(safe_bins) - default_safe_bins
            if custom_bins:
                findings.append(
                    Finding(
                        scanner=self.name,
                        category=FindingCategory.INSECURE_CONFIG,
                        severity=FindingSeverity.MEDIUM,
                        title="Exec safeBins expanded with custom binaries",
                        description=(
                            f"The safeBins list has been expanded with: "
                            f"{', '.join(sorted(custom_bins))}. "
                            f"These binaries bypass exec approval checks and run without "
                            f"user confirmation."
                        ),
                        evidence=f"Custom safeBins: {sorted(custom_bins)}",
                        file_path=exec_path,
                        remediation=Remediation(
                            summary="Review expanded safeBins for necessity",
                            steps=[
                                "Remove binaries that don't need bypass approval",
                                "safeBins should only contain read-only, stdin-only tools",
                            ],
                        ),
                        owasp_ids=["ASI02"],
                    )
                )

        return findings

    def _scan_sandbox_config(self, context: ScanContext) -> list[Finding]:
        """Check sandbox configuration (CTO-003)."""
        findings: list[Finding] = []
        config_data = self._load_main_config(context)
        if config_data is None:
            return findings

        config_path = self._get_main_config_path(context)
        sandbox = config_data.get("sandbox", {})
        tools_config = config_data.get("tools", {})

        # Check if sandbox is disabled when tool profile suggests it should be on
        sandbox_mode = sandbox.get("mode", "")
        profile = tools_config.get("profile", "full")

        if profile in ("full", "") and sandbox_mode in ("off", "none", "disabled", ""):
            is_exposed = (
                config_data.get("dmPolicy") == "open" or config_data.get("groupPolicy") == "open"
            )
            if is_exposed:
                findings.append(
                    Finding(
                        scanner=self.name,
                        category=FindingCategory.INSECURE_DEFAULT,
                        severity=FindingSeverity.HIGH,
                        title="Sandboxing disabled with full tool access and open input",
                        description=(
                            "The agent has full tool access and accepts untrusted input, "
                            "but sandboxing is not enabled. Without container isolation, "
                            "compromised tool calls run directly on the host."
                        ),
                        evidence=(
                            f"sandbox.mode={sandbox_mode or 'unset'}, "
                            f"tools.profile={profile or 'unset'}"
                        ),
                        file_path=config_path,
                        remediation=Remediation(
                            summary="Enable sandboxing for untrusted-input agents",
                            steps=[
                                "Set sandbox.mode to 'all' or 'non-main'",
                                "Or restrict tools.profile to 'messaging'/'minimal'",
                            ],
                            automated=True,
                            command="agentsec harden ~ -p workstation --apply",
                            references=["https://docs.openclaw.ai/tools/multi-agent-sandbox-tools"],
                        ),
                        owasp_ids=["ASI02", "ASI08"],
                    )
                )

        return findings

    # -----------------------------------------------------------------------
    # SSRF protection check (CGW-005)
    # -----------------------------------------------------------------------

    def _scan_ssrf_config(self, context: ScanContext) -> list[Finding]:
        """Check SSRF protection configuration (CGW-005).

        OpenClaw v2026.2.12 added SSRF deny policies for URL-based inputs.
        Agents processing user-supplied URLs without SSRF protection are
        vulnerable to internal network scanning and metadata endpoint access.
        """
        findings: list[Finding] = []
        config_data = self._load_main_config(context)
        if config_data is None:
            return findings

        config_path = self._get_main_config_path(context)

        # Check for SSRF protection settings
        security = config_data.get("security", {})
        ssrf = security.get("ssrf", security.get("urlPolicy", {}))

        ssrf_deny = ssrf.get("denyPolicy", ssrf.get("deny", None))
        hostname_allowlist = ssrf.get("hostnameAllowlist", ssrf.get("allowedHosts", None))

        # Check if SSRF protection is missing on agents that process URLs
        tools_config = config_data.get("tools", {})
        profile = tools_config.get("profile", "full")
        has_url_tools = profile in ("full", "")

        if has_url_tools and not ssrf_deny and not hostname_allowlist:
            findings.append(
                Finding(
                    scanner=self.name,
                    category=FindingCategory.INSECURE_DEFAULT,
                    severity=FindingSeverity.HIGH,
                    title="No SSRF protection configured for URL-based inputs",
                    description=(
                        "The agent can process URL-based inputs (input_file, input_image) "
                        "but has no SSRF deny policy or hostname allowlist configured. "
                        "Attackers can use the agent to scan internal networks, access "
                        "cloud metadata endpoints (169.254.169.254), or exfiltrate data "
                        "to external servers."
                    ),
                    evidence="security.ssrf.denyPolicy and hostnameAllowlist are both absent",
                    file_path=config_path,
                    remediation=Remediation(
                        summary="Configure SSRF deny policy and hostname allowlist",
                        steps=[
                            "Set security.ssrf.denyPolicy to block internal/private ranges",
                            "Set security.ssrf.hostnameAllowlist to trusted domains",
                            "Enable audit logging for blocked fetch attempts",
                            "Update to OpenClaw v2026.2.12+ which includes built-in SSRF deny",
                        ],
                        references=["https://nvd.nist.gov/vuln/detail/CVE-2026-25475"],
                    ),
                    owasp_ids=["ASI05", "ASI02"],
                )
            )

        return findings

    # -----------------------------------------------------------------------
    # Built-in safety scanner check (CSF-001)
    # -----------------------------------------------------------------------

    def _scan_safety_scanner_config(self, context: ScanContext) -> list[Finding]:
        """Check if built-in safety scanner is enabled (CSF-001).

        OpenClaw v2026.2.6 added a built-in skill/plugin code safety scanner
        and credential redaction. Flag if these are explicitly disabled.
        """
        findings: list[Finding] = []
        config_data = self._load_main_config(context)
        if config_data is None:
            return findings

        config_path = self._get_main_config_path(context)
        version = context.metadata.get("agent_version")

        # Only check if version is 2026.2.6+
        if version and self._version_gte(version, "2026.2.6"):
            safety = config_data.get("safety", config_data.get("safetyScanner", {}))
            if isinstance(safety, dict) and safety.get("enabled") is False:
                findings.append(
                    Finding(
                        scanner=self.name,
                        category=FindingCategory.INSECURE_CONFIG,
                        severity=FindingSeverity.HIGH,
                        title="Built-in safety scanner explicitly disabled",
                        description=(
                            "OpenClaw v2026.2.6+ includes a built-in skill/plugin code "
                            "safety scanner, but it has been explicitly disabled in config. "
                            "This removes the platform's own defense against malicious skills "
                            "and credential leaks in config responses."
                        ),
                        evidence="safety.enabled = false",
                        file_path=config_path,
                        remediation=Remediation(
                            summary="Re-enable the built-in safety scanner",
                            steps=[
                                "Remove safety.enabled = false from config",
                                "Or set safety.enabled to true",
                                "The built-in scanner complements agentsec with runtime checks",
                            ],
                        ),
                        owasp_ids=["ASI03", "ASI10"],
                    )
                )

            # Check credential redaction
            cred_redact = config_data.get(
                "credentialRedaction", config_data.get("redactCredentials", None)
            )
            if cred_redact is False:
                findings.append(
                    Finding(
                        scanner=self.name,
                        category=FindingCategory.INSECURE_CONFIG,
                        severity=FindingSeverity.MEDIUM,
                        title="Credential redaction disabled in config responses",
                        description=(
                            "OpenClaw v2026.2.6+ redacts credentials from config API "
                            "responses by default, but redaction has been explicitly "
                            "disabled. This exposes secrets in API responses and logs."
                        ),
                        evidence="credentialRedaction = false",
                        file_path=config_path,
                        remediation=Remediation(
                            summary="Re-enable credential redaction",
                            steps=["Remove credentialRedaction = false from config"],
                        ),
                        owasp_ids=["ASI05"],
                    )
                )

        return findings

    @staticmethod
    def _version_gte(installed: str, minimum: str) -> bool:
        """Returns True if installed >= minimum."""
        try:
            inst_parts = [int(x) for x in installed.replace("-", ".").split(".")]
            min_parts = [int(x) for x in minimum.replace("-", ".").split(".")]
            return inst_parts >= min_parts
        except (ValueError, AttributeError):
            return False

    # -----------------------------------------------------------------------
    # Discovery / mDNS check
    # -----------------------------------------------------------------------

    def _scan_discovery_config(self, context: ScanContext) -> list[Finding]:
        """Check mDNS and discovery settings for information leakage."""
        findings: list[Finding] = []
        config_data = self._load_main_config(context)
        if config_data is None:
            return findings

        config_path = self._get_main_config_path(context)
        discovery = config_data.get("discovery", {})
        mdns = discovery.get("mdns", {})
        mdns_mode = mdns.get("mode", "")

        if mdns_mode == "full":
            findings.append(
                Finding(
                    scanner=self.name,
                    category=FindingCategory.NETWORK_EXPOSURE,
                    severity=FindingSeverity.MEDIUM,
                    title="mDNS discovery set to 'full' — broadcasts install path",
                    description=(
                        "discovery.mdns.mode is 'full', which broadcasts the agent's "
                        "installation path and metadata on the local network via mDNS. "
                        "This reveals agent presence and configuration details to anyone "
                        "on the same network segment."
                    ),
                    evidence="discovery.mdns.mode = full",
                    file_path=config_path,
                    remediation=Remediation(
                        summary="Set mDNS discovery to 'minimal' or 'off'",
                        steps=["Set discovery.mdns.mode to 'minimal' or 'off'"],
                    ),
                    owasp_ids=["ASI05", "ASI09"],
                )
            )

        return findings

    # -----------------------------------------------------------------------
    # Auth config checks (original, enhanced)
    # -----------------------------------------------------------------------

    def _scan_auth_config(self, context: ScanContext) -> list[Finding]:
        """Check for missing or weak authentication settings."""
        findings: list[Finding] = []
        config_data = self._load_main_config(context)
        if config_data is None:
            return findings

        config_path = self._get_main_config_path(context)

        # Check for authentication enabled
        auth_config = config_data.get("auth", config_data.get("authentication", {}))
        gateway = config_data.get("gateway", {})
        gw_auth = gateway.get("auth", {})

        # Only flag missing auth if not already caught by gateway checks
        if (not auth_config or not auth_config.get("enabled", False)) and not gw_auth:
            bind_mode = gateway.get("bind", "loopback")
            if bind_mode != "loopback":
                findings.append(
                    Finding(
                        scanner=self.name,
                        category=FindingCategory.MISSING_AUTH,
                        severity=FindingSeverity.CRITICAL,
                        title="Authentication disabled on non-loopback agent",
                        description=(
                            "The agent is accessible beyond localhost but has no "
                            "authentication configured. Anyone who can reach the interface "
                            "can issue commands and access credentials."
                        ),
                        file_path=config_path,
                        remediation=Remediation(
                            summary="Enable authentication",
                            steps=[
                                "Enable auth in agent configuration",
                                "Set a strong, unique access token",
                            ],
                        ),
                        owasp_ids=["ASI05", "ASI02"],
                    )
                )

        # Check for auto-approve settings
        auto_approve = config_data.get("auto_approve", config_data.get("autoApprove", {}))
        if isinstance(auto_approve, dict) and auto_approve.get("enabled", False):
            findings.append(
                Finding(
                    scanner=self.name,
                    category=FindingCategory.INSECURE_DEFAULT,
                    severity=FindingSeverity.HIGH,
                    title="Auto-approve enabled for agent actions",
                    description=(
                        "The agent automatically approves actions without human "
                        "confirmation. This removes the last defense against prompt "
                        "injection and goal hijacking."
                    ),
                    file_path=config_path,
                    remediation=Remediation(
                        summary="Disable auto-approve or restrict to safe operations",
                        steps=[
                            "Disable auto_approve in configuration",
                            "If needed, restrict to read-only operations only",
                        ],
                    ),
                    owasp_ids=["ASI01", "ASI02", "ASI10"],
                )
            )

        return findings

    # -----------------------------------------------------------------------
    # Plugin config check
    # -----------------------------------------------------------------------

    def _scan_plugin_config(self, context: ScanContext) -> list[Finding]:
        """Check plugin allowlist configuration (CPL-001)."""
        findings: list[Finding] = []
        config_data = self._load_main_config(context)
        if config_data is None:
            return findings

        config_path = self._get_main_config_path(context)
        plugins = config_data.get("plugins", {})

        # Check if extensions directory exists but no allowlist is configured
        extensions_dirs = [
            context.target_path / ".openclaw" / "extensions",
            context.target_path / ".clawdbot" / "extensions",
        ]
        has_extensions = any(d.is_dir() and any(d.iterdir()) for d in extensions_dirs if d.exists())

        if has_extensions and not plugins.get("allow") and not plugins.get("entries"):
            findings.append(
                Finding(
                    scanner=self.name,
                    category=FindingCategory.INSECURE_CONFIG,
                    severity=FindingSeverity.MEDIUM,
                    title="Plugins installed without explicit allowlist",
                    description=(
                        "Extensions are installed but no plugins.allow or plugins.entries "
                        "allowlist is configured. Without an allowlist, any installed "
                        "plugin runs in-process with full Gateway access."
                    ),
                    file_path=config_path,
                    remediation=Remediation(
                        summary="Configure plugins.allow with explicit plugin IDs",
                        steps=[
                            "Add plugins.allow array with allowed plugin IDs",
                            "Review each installed extension in ~/.openclaw/extensions/",
                        ],
                        references=["https://docs.openclaw.ai/gateway/security"],
                    ),
                    owasp_ids=["ASI03", "ASI02"],
                )
            )

        return findings

    def _scan_soul_integrity(self, context: ScanContext) -> list[Finding]:
        """Check SOUL.md and workspace files for tampering."""
        findings: list[Finding] = []

        # Check SOUL.md, AGENTS.md, TOOLS.md, USER.md
        workspace_files = ["SOUL.md", "AGENTS.md", "TOOLS.md", "USER.md"]
        tamper_patterns = [
            (
                re.compile(r"ignore\s+(previous|all|above)\s+instructions", re.I),
                "Instruction override attempt",
            ),
            (re.compile(r"you\s+are\s+now\s+", re.I), "Identity reassignment attempt"),
            (re.compile(r"system\s*:\s*", re.I), "System prompt injection marker"),
            (re.compile(r"<\|im_start\|>", re.I), "Chat template injection marker"),
            (
                re.compile(r"(?:curl|wget|fetch)\s+https?://", re.I),
                "External data fetch instruction",
            ),
            (
                re.compile(r"(?:eval|exec|__import__|subprocess)", re.I),
                "Code execution instruction",
            ),
        ]

        for ws_file in workspace_files:
            file_path = context.config_files.get(ws_file)
            if not file_path or not file_path.exists():
                continue

            try:
                content = file_path.read_text()
            except OSError:
                continue

            for pattern, desc in tamper_patterns:
                for match in pattern.finditer(content):
                    line_num = content[: match.start()].count("\n") + 1
                    findings.append(
                        Finding(
                            scanner=self.name,
                            category=FindingCategory.CONFIG_DRIFT,
                            severity=FindingSeverity.HIGH,
                            title=f"Suspicious pattern in {ws_file}: {desc}",
                            description=(
                                f"The workspace file '{ws_file}' contains a pattern "
                                f"commonly associated with prompt injection or tampering. "
                                f"This may indicate unauthorized modification to alter "
                                f"the agent's behavior."
                            ),
                            evidence=f"Pattern: '{match.group(0)[:60]}' at line {line_num}",
                            file_path=file_path,
                            line_number=line_num,
                            remediation=Remediation(
                                summary=f"Review {ws_file} for unauthorized modifications",
                                steps=[
                                    "Compare against known-good version in version control",
                                    "Remove any suspicious instructions",
                                    "Enable file integrity monitoring",
                                ],
                            ),
                            owasp_ids=["ASI01", "ASI04", "ASI06"],
                        )
                    )

        return findings

    # -----------------------------------------------------------------------
    # Helper methods
    # -----------------------------------------------------------------------

    _MAX_CONFIG_SIZE = 10 * 1024 * 1024  # 10 MB

    def _load_main_config(self, context: ScanContext) -> dict | None:
        """Load the primary OpenClaw/Clawdbot config as dict. Cached in metadata."""
        cache_key = "_main_config_data"
        if cache_key in context.metadata:
            cached: dict | None = context.metadata[cache_key]
            return cached

        config_path = self._get_main_config_path(context)
        if not config_path or not config_path.exists():
            context.metadata[cache_key] = None
            return None

        try:
            if config_path.stat().st_size > self._MAX_CONFIG_SIZE:
                logger.warning("Config file too large, skipping: %s", config_path)
                context.metadata[cache_key] = None
                return None
            data: dict = json.loads(config_path.read_text())
            context.metadata[cache_key] = data
            return data
        except (json.JSONDecodeError, OSError):
            context.metadata[cache_key] = None
            return None

    def _get_main_config_path(self, context: ScanContext) -> Path | None:
        """Get path to the primary OpenClaw/Clawdbot config file."""
        return context.config_files.get("openclaw.json") or context.config_files.get(
            "clawdbot.json"
        )

    def _detect_version(self, context: ScanContext) -> str | None:
        """Try to detect the installed agent version."""
        for config_name in ["openclaw.json", "clawdbot.json"]:
            config_path = context.config_files.get(config_name)
            if config_path and config_path.exists():
                try:
                    data = json.loads(config_path.read_text())
                    version = data.get("version")
                    if version:
                        return str(version)
                except (json.JSONDecodeError, OSError):
                    pass

        pkg_json = context.target_path / "node_modules" / "openclaw" / "package.json"
        if not pkg_json.exists():
            pkg_json = context.target_path / "node_modules" / "clawdbot" / "package.json"

        if pkg_json.exists():
            try:
                data = json.loads(pkg_json.read_text())
                ver = data.get("version")
                return str(ver) if ver is not None else None
            except (json.JSONDecodeError, OSError):
                pass

        return None

    @staticmethod
    def _version_is_vulnerable(installed: str, fixed_in: str) -> bool:
        """Simple version comparison. Returns True if installed < fixed_in."""
        try:
            inst_parts = [int(x) for x in installed.replace("-", ".").split(".")]
            fix_parts = [int(x) for x in fixed_in.replace("-", ".").split(".")]
            return inst_parts < fix_parts
        except (ValueError, AttributeError):
            return False
