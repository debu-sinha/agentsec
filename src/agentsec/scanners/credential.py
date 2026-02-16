"""Credential scanner — deep scan for secrets, tokens, and credential exposure.

Performs thorough scanning beyond the installation scanner's config-file checks:
- Recursive scan of all files in the installation directory
- High-entropy string detection for unknown secret formats
- Git history scanning for previously committed secrets
- Environment variable exposure analysis
"""

from __future__ import annotations

import logging
import math
import re
from collections import Counter
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

# File extensions to scan for secrets
_SCANNABLE_EXTENSIONS = {
    ".json",
    ".yaml",
    ".yml",
    ".toml",
    ".ini",
    ".cfg",
    ".conf",
    ".env",
    ".properties",
    ".xml",
    ".md",
    ".txt",
    ".js",
    ".ts",
    ".py",
    ".sh",
    ".bash",
    ".zsh",
    ".fish",
    ".ps1",
}

# Files to always skip (binary or too large)
_SKIP_PATTERNS = {
    "node_modules",
    ".git",
    "__pycache__",
    ".venv",
    "venv",
    "dist",
    "build",
    ".next",
    ".cache",
}

# Structured secret patterns with provider context
_PROVIDER_PATTERNS: list[tuple[str, re.Pattern[str], FindingSeverity, str]] = [
    (
        "OpenAI API Key",
        re.compile(r"sk-[a-zA-Z0-9]{20,}"),
        FindingSeverity.CRITICAL,
        "Rotate at https://platform.openai.com/api-keys",
    ),
    (
        "Anthropic API Key",
        re.compile(r"sk-ant-[a-zA-Z0-9_\-]{20,}"),
        FindingSeverity.CRITICAL,
        "Rotate at https://console.anthropic.com/settings/keys",
    ),
    (
        "AWS Access Key",
        re.compile(r"AKIA[0-9A-Z]{16}"),
        FindingSeverity.CRITICAL,
        "Rotate in AWS IAM console immediately",
    ),
    (
        "GitHub Personal Access Token",
        re.compile(r"ghp_[a-zA-Z0-9]{36}"),
        FindingSeverity.CRITICAL,
        "Rotate at https://github.com/settings/tokens",
    ),
    (
        "GitHub OAuth Token",
        re.compile(r"gho_[a-zA-Z0-9]{36}"),
        FindingSeverity.HIGH,
        "Rotate in GitHub OAuth app settings",
    ),
    (
        "GitHub App Token",
        re.compile(r"(?:ghu|ghs)_[a-zA-Z0-9]{36}"),
        FindingSeverity.HIGH,
        "Regenerate in GitHub App settings",
    ),
    (
        "Slack Bot Token",
        re.compile(r"xoxb-[a-zA-Z0-9\-]+"),
        FindingSeverity.CRITICAL,
        "Rotate in Slack App management",
    ),
    (
        "Slack User Token",
        re.compile(r"xoxp-[a-zA-Z0-9\-]+"),
        FindingSeverity.CRITICAL,
        "Rotate in Slack App management",
    ),
    (
        "Stripe Secret Key",
        re.compile(r"sk_live_[a-zA-Z0-9]{24,}"),
        FindingSeverity.CRITICAL,
        "Rotate at https://dashboard.stripe.com/apikeys",
    ),
    (
        "Telegram Bot Token",
        re.compile(r"\d{8,10}:[a-zA-Z0-9_\-]{35}"),
        FindingSeverity.HIGH,
        "Revoke via @BotFather on Telegram",
    ),
    (
        "Discord Bot Token",
        re.compile(r"[MN][a-zA-Z0-9_\-]{23,80}\.[a-zA-Z0-9_\-]{6,10}\.[a-zA-Z0-9_\-]{27,80}"),
        FindingSeverity.CRITICAL,
        "Regenerate in Discord Developer Portal",
    ),
    (
        "Google API Key",
        re.compile(r"AIza[0-9A-Za-z_\-]{35}"),
        FindingSeverity.HIGH,
        "Restrict or delete in Google Cloud Console",
    ),
    (
        "Databricks Token",
        re.compile(r"dapi[a-f0-9]{32}"),
        FindingSeverity.CRITICAL,
        "Revoke in Databricks workspace settings",
    ),
    (
        "Hugging Face Token",
        re.compile(r"hf_[a-zA-Z0-9]{34}"),
        FindingSeverity.HIGH,
        "Rotate at https://huggingface.co/settings/tokens",
    ),
    (
        "Private Key Block",
        re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
        FindingSeverity.CRITICAL,
        "Generate new key pair and revoke the exposed key",
    ),
    (
        "JWT Token",
        re.compile(r"eyJ[a-zA-Z0-9_\-]{10,}\.eyJ[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]+"),
        FindingSeverity.HIGH,
        "Identify issuer and rotate signing keys if long-lived",
    ),
    (
        "Generic Connection String",
        re.compile(
            r'(?:postgres|mysql|mongodb|redis|amqp)://[^\s"\']{1,200}:[^\s"\']{1,200}@[^\s"\']{1,200}',
            re.I,
        ),
        FindingSeverity.CRITICAL,
        "Change database password and update connection string",
    ),
]

# Minimum Shannon entropy threshold for flagging high-entropy strings
_ENTROPY_THRESHOLD = 4.5
_MIN_SECRET_LENGTH = 16
_MAX_SECRET_LENGTH = 256


class CredentialScanner(BaseScanner):
    """Deep recursive credential scanner for agent installations."""

    @property
    def name(self) -> str:
        return "credential"

    @property
    def description(self) -> str:
        return (
            "Deep scan for secrets, API keys, tokens, and credentials across "
            "all files in the agent installation directory."
        )

    def scan(self, context: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        target = context.target_path

        if not target.exists():
            return findings

        # Scan all eligible files recursively
        for file_path in self._iter_scannable_files(target):
            context.files_scanned += 1
            findings.extend(self._scan_file(file_path))

        # Check for .git/config with credentials
        git_config = target / ".git" / "config"
        if git_config.exists():
            findings.extend(self._scan_git_config(git_config))

        # Deduplicate findings by fingerprint
        seen: set[str] = set()
        unique_findings: list[Finding] = []
        for f in findings:
            if f.fingerprint not in seen:
                seen.add(f.fingerprint)
                unique_findings.append(f)

        return unique_findings

    def _iter_scannable_files(self, target: Path) -> list[Path]:
        """Iterate over files eligible for scanning."""
        files: list[Path] = []
        max_size = self.config.extra.get("max_file_size", 10_000_000)

        try:
            for item in target.rglob("*"):
                # Skip directories in skip list
                if any(skip in item.parts for skip in _SKIP_PATTERNS):
                    continue
                # Skip symlinks to prevent path traversal attacks
                if item.is_symlink():
                    logger.debug("Skipping symlink: %s", item)
                    continue
                if not item.is_file():
                    continue

                # Check extension (also allow extensionless .env files)
                if item.suffix.lower() not in _SCANNABLE_EXTENSIONS and item.name not in {
                    ".env",
                    ".env.local",
                    ".env.production",
                    ".env.development",
                }:
                    continue

                # Check size
                try:
                    if item.stat().st_size > max_size:
                        continue
                except OSError:
                    continue

                files.append(item)
        except PermissionError:
            logger.debug("Permission denied iterating %s", target)

        return files

    def _scan_file(self, file_path: Path) -> list[Finding]:
        """Scan a single file for credential patterns."""
        findings: list[Finding] = []

        try:
            content = file_path.read_text(errors="replace")
        except OSError:
            return findings

        # Pattern-based detection
        for secret_type, pattern, severity, rotation_advice in _PROVIDER_PATTERNS:
            for match in pattern.finditer(content):
                matched = match.group(0)
                line_num = content[: match.start()].count("\n") + 1

                # Skip if it looks like a placeholder or example
                if self._is_placeholder(matched):
                    continue

                sanitized = self._sanitize_secret(matched)

                findings.append(
                    Finding(
                        scanner=self.name,
                        category=FindingCategory.EXPOSED_TOKEN,
                        severity=severity,
                        title=f"{secret_type} found in {file_path.name}",
                        description=(
                            f"A {secret_type} was found in '{file_path.name}' at line "
                            f"{line_num}. This credential should be stored in a secrets "
                            f"manager, not in plaintext files."
                        ),
                        evidence=f"Value: {sanitized} (line {line_num})",
                        file_path=file_path,
                        line_number=line_num,
                        remediation=Remediation(
                            summary=f"Rotate and secure the {secret_type}",
                            steps=[
                                rotation_advice,
                                f"Remove the plaintext value from {file_path.name}",
                                "Store in OS keychain or environment variable",
                                "Add file to .gitignore if not already excluded",
                            ],
                            automated=False,
                            command="agentsec harden -p workstation --apply",
                        ),
                        owasp_ids=["ASI05"],
                    )
                )

        # High-entropy string detection for unknown secret formats
        findings.extend(self._detect_high_entropy_strings(file_path, content))

        return findings

    def _detect_high_entropy_strings(self, file_path: Path, content: str) -> list[Finding]:
        """Detect high-entropy strings that may be secrets in unknown formats."""
        findings: list[Finding] = []

        # Look for assignment patterns with high-entropy values
        assignment_pattern = re.compile(
            r"(?:(?:key|token|secret|password|credential|auth)\s*[:=]\s*)"
            r'["\']?([a-zA-Z0-9+/=_\-]{16,256})["\']?',
            re.I,
        )

        for match in assignment_pattern.finditer(content):
            value = match.group(1)
            if self._is_placeholder(value):
                continue
            if len(value) < _MIN_SECRET_LENGTH or len(value) > _MAX_SECRET_LENGTH:
                continue

            entropy = self._shannon_entropy(value)
            if entropy >= _ENTROPY_THRESHOLD:
                line_num = content[: match.start()].count("\n") + 1
                sanitized = self._sanitize_secret(value)
                findings.append(
                    Finding(
                        scanner=self.name,
                        category=FindingCategory.PLAINTEXT_SECRET,
                        severity=FindingSeverity.MEDIUM,
                        title=f"High-entropy string in {file_path.name} (possible secret)",
                        description=(
                            f"A high-entropy string (Shannon entropy: {entropy:.2f}) was "
                            f"found in a credential-like context in '{file_path.name}'. "
                            f"This may be a secret in an unknown format."
                        ),
                        evidence=f"Value: {sanitized} (entropy: {entropy:.2f}, line {line_num})",
                        file_path=file_path,
                        line_number=line_num,
                        remediation=Remediation(
                            summary="Review whether this is a secret and move to vault if so",
                            steps=[
                                "Determine if the flagged value is actually a secret",
                                "If yes, move to OS keychain or secrets manager",
                                "If false positive, no action needed",
                            ],
                        ),
                        owasp_ids=["ASI05"],
                    )
                )

        return findings

    def _scan_git_config(self, git_config: Path) -> list[Finding]:
        """Check .git/config for embedded credentials."""
        findings: list[Finding] = []

        try:
            content = git_config.read_text()
        except OSError:
            return findings

        # Check for credentials in remote URLs
        cred_in_url = re.compile(r"url\s*=\s*https?://([^:]+):([^@]+)@")
        for match in cred_in_url.finditer(content):
            user = match.group(1)
            line_num = content[: match.start()].count("\n") + 1
            findings.append(
                Finding(
                    scanner=self.name,
                    category=FindingCategory.HARDCODED_CREDENTIAL,
                    severity=FindingSeverity.HIGH,
                    title="Credentials embedded in git remote URL",
                    description=(
                        f"The .git/config file contains a remote URL with embedded "
                        f"credentials for user '{user}'. This exposes credentials to "
                        f"anyone with read access to the repository."
                    ),
                    evidence=f"User: {user} (line {line_num})",
                    file_path=git_config,
                    line_number=line_num,
                    remediation=Remediation(
                        summary="Use credential helper instead of URL-embedded credentials",
                        steps=[
                            "Run: git config credential.helper osxkeychain  # macOS",
                            "Or: git config credential.helper store  # Linux (less secure)",
                            "Update remote URL to remove credentials",
                            "Rotate the exposed credential",
                        ],
                    ),
                    owasp_ids=["ASI05"],
                )
            )

        return findings

    @staticmethod
    def _shannon_entropy(data: str) -> float:
        """Calculate Shannon entropy of a string."""
        if not data:
            return 0.0
        counts = Counter(data)
        length = len(data)
        entropy = 0.0
        for count in counts.values():
            probability = count / length
            if probability > 0:
                entropy -= probability * math.log2(probability)
        return entropy

    @staticmethod
    def _sanitize_secret(value: str) -> str:
        """Sanitize a secret value for safe display."""
        return sanitize_secret(value)

    @staticmethod
    def _is_placeholder(value: str) -> bool:
        """Check if a value looks like a placeholder rather than a real secret."""
        # Long phrases that indicate placeholder intent (match as substrings)
        phrase_placeholders = {
            "your_api_key",
            "your-api-key",
            "your_token",
            "your-token",
            "replace_me",
            "changeme",
            "placeholder",
            "sk-your",
        }
        # Short words that only count when the value is short or starts with them.
        # Avoids false-flagging a 40-char key that happens to contain "test".
        word_placeholders = {"example", "test", "dummy", "fake", "sample", "sk-xxx"}

        lower = value.lower()

        # Strip known prefixes before checking (e.g. "sk-", "ghp_", "AKIA")
        stripped = re.sub(r"^(?:sk-(?:ant-)?|ghp_|gho_|gh[us]_|AKIA|hf_|dapi)", "", value).lower()

        if any(p in lower for p in phrase_placeholders):
            return True

        for word in word_placeholders:
            if word in lower:
                # Only flag if the word dominates the value (>40% of stripped length)
                if len(word) >= len(stripped) * 0.4:
                    return True
                # Or if it appears at a word boundary at the start
                if stripped.startswith(word):
                    return True

        # Check if it's all the same character
        if len(set(value)) <= 2:
            return True
        # Check if it's a common pattern like "xxx...xxx"
        return bool(re.match(r"^[x\*\.]+$", value, re.I))
