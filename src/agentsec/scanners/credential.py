"""Credential scanner — deep scan for secrets, tokens, and credential exposure.

Uses Yelp's detect-secrets library as the scanning engine for battle-tested
false positive handling, then maps results to agentsec's Finding model with
OWASP categorization and severity classification.

Also performs:
- Git config scanning for embedded credentials
- File-path context awareness (test/doc files get downgraded severity)
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

from detect_secrets import SecretsCollection
from detect_secrets.settings import transient_settings

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
    ".go",
    ".rb",
    ".java",
    ".kt",
    ".rs",
    ".php",
    ".tf",
    ".tfvars",
    ".hcl",
    ".pem",
    ".key",
    ".gradle",
    ".cs",
    ".swift",
    ".r",
    ".sql",
    ".ipynb",
    ".csv",
    ".jsonc",
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

# Lock files to skip entirely (contain integrity hashes, not secrets)
_LOCK_FILE_NAMES = {
    "pnpm-lock.yaml",
    "pnpm-lock.json",
    "package-lock.json",
    "yarn.lock",
    "pipfile.lock",
    "poetry.lock",
    "cargo.lock",
    "gemfile.lock",
    "composer.lock",
    "bun.lockb",
    "go.sum",
    "flake.lock",
    "packages.lock.json",
    "pdm.lock",
    "uv.lock",
}

# Known config template files where placeholder credentials are expected
_TEMPLATE_CONFIG_FILES = {
    "alembic.ini",
    ".env.example",
    ".env.sample",
    ".env.template",
    "config.example.yml",
    "config.sample.yml",
}

# detect-secrets plugin configuration
_DETECT_SECRETS_PLUGINS = [
    {"name": "AWSKeyDetector"},
    {"name": "ArtifactoryDetector"},
    {"name": "AzureStorageKeyDetector"},
    {"name": "BasicAuthDetector"},
    {"name": "CloudantDetector"},
    {"name": "DiscordBotTokenDetector"},
    {"name": "GitHubTokenDetector"},
    {"name": "GitLabTokenDetector"},
    {"name": "Base64HighEntropyString", "limit": 5.0},
    {"name": "HexHighEntropyString", "limit": 3.5},
    {"name": "IbmCloudIamDetector"},
    {"name": "IbmCosHmacDetector"},
    {"name": "JwtTokenDetector"},
    {"name": "KeywordDetector"},
    {"name": "MailchimpDetector"},
    {"name": "NpmDetector"},
    {"name": "PrivateKeyDetector"},
    {"name": "SendGridDetector"},
    {"name": "SlackDetector"},
    {"name": "SoftlayerDetector"},
    {"name": "SquareOAuthDetector"},
    {"name": "StripeDetector"},
    {"name": "TwilioKeyDetector"},
]

# detect-secrets filter configuration (built-in FP reduction)
_DETECT_SECRETS_FILTERS = [
    {"path": "detect_secrets.filters.allowlist_filter.is_line_allowlisted"},
    {"path": "detect_secrets.filters.heuristic.is_sequential_string"},
    {"path": "detect_secrets.filters.heuristic.is_potential_uuid"},
    {"path": "detect_secrets.filters.heuristic.is_templated_secret"},
    {"path": "detect_secrets.filters.heuristic.is_prefixed_with_dollar_sign"},
    {"path": "detect_secrets.filters.heuristic.is_indirect_reference"},
    {"path": "detect_secrets.filters.heuristic.is_lock_file"},
    {"path": "detect_secrets.filters.heuristic.is_not_alphanumeric_string"},
    {"path": "detect_secrets.filters.heuristic.is_swagger_file"},
    {"path": "detect_secrets.filters.heuristic.is_non_text_file"},
    {"path": "detect_secrets.filters.heuristic.is_likely_id_string"},
]

# Map detect-secrets secret types to agentsec severity levels
_SEVERITY_MAP: dict[str, FindingSeverity] = {
    "AWS Access Key": FindingSeverity.CRITICAL,
    "Artifactory Credentials": FindingSeverity.HIGH,
    "Azure Storage Account access key": FindingSeverity.CRITICAL,
    "Basic Auth Credentials": FindingSeverity.HIGH,
    "Cloudant Credentials": FindingSeverity.HIGH,
    "Discord Bot Token": FindingSeverity.CRITICAL,
    "GitHub Token": FindingSeverity.CRITICAL,
    "GitLab Token": FindingSeverity.HIGH,
    "Base64 High Entropy String": FindingSeverity.MEDIUM,
    "Hex High Entropy String": FindingSeverity.MEDIUM,
    "IBM Cloud IAM Key": FindingSeverity.CRITICAL,
    "IBM COS HMAC Credentials": FindingSeverity.HIGH,
    "JSON Web Token": FindingSeverity.HIGH,
    "Secret Keyword": FindingSeverity.MEDIUM,
    "Mailchimp Access Key": FindingSeverity.HIGH,
    "NPM tokens": FindingSeverity.HIGH,
    "Private Key": FindingSeverity.CRITICAL,
    "SendGrid API Key": FindingSeverity.CRITICAL,
    "Slack Token": FindingSeverity.CRITICAL,
    "SoftLayer Credentials": FindingSeverity.HIGH,
    "Square OAuth Secret": FindingSeverity.HIGH,
    "Stripe Access Key": FindingSeverity.CRITICAL,
    "Twilio API Key": FindingSeverity.HIGH,
}

# Map detect-secrets types to rotation advice
_ROTATION_ADVICE: dict[str, str] = {
    "AWS Access Key": "Rotate in AWS IAM console immediately",
    "Discord Bot Token": "Regenerate in Discord Developer Portal",
    "GitHub Token": "Rotate at https://github.com/settings/tokens",
    "GitLab Token": "Rotate in GitLab personal access token settings",
    "Private Key": "Generate new key pair and revoke the exposed key",
    "Slack Token": "Rotate in Slack App management",
    "Stripe Access Key": "Rotate at https://dashboard.stripe.com/apikeys",
    "SendGrid API Key": "Rotate at https://app.sendgrid.com/settings/api_keys",
}

# Additional provider patterns not covered by detect-secrets
_EXTRA_PATTERNS: list[tuple[str, re.Pattern[str], FindingSeverity, str]] = [
    (
        "OpenAI API Key",
        re.compile(r"sk-(?!ant-)(?:proj-|svcacct-)?[a-zA-Z0-9_\-]{20,200}"),
        FindingSeverity.CRITICAL,
        "Rotate at https://platform.openai.com/api-keys",
    ),
    (
        "Anthropic API Key",
        re.compile(r"sk-ant-[a-zA-Z0-9_\-]{20,200}"),
        FindingSeverity.CRITICAL,
        "Rotate at https://console.anthropic.com/settings/keys",
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
        "Google API Key",
        re.compile(r"AIza[0-9A-Za-z_\-]{35}"),
        FindingSeverity.HIGH,
        "Restrict or delete in Google Cloud Console",
    ),
    (
        "Groq API Key",
        re.compile(r"gsk_[a-zA-Z0-9]{20,200}"),
        FindingSeverity.CRITICAL,
        "Rotate at https://console.groq.com/keys",
    ),
    (
        "Replicate API Token",
        re.compile(r"r8_[a-zA-Z0-9]{20,200}"),
        FindingSeverity.CRITICAL,
        "Rotate at https://replicate.com/account/api-tokens",
    ),
    (
        "Pinecone API Key",
        re.compile(r"pcsk_[a-zA-Z0-9_]{30,200}"),
        FindingSeverity.CRITICAL,
        "Rotate at https://app.pinecone.io/organizations/-/projects/-/keys",
    ),
    (
        "Cohere API Key",
        re.compile(r"co-[a-zA-Z0-9]{35,200}"),
        FindingSeverity.CRITICAL,
        "Rotate at https://dashboard.cohere.com/api-keys",
    ),
    (
        "Vercel Token",
        re.compile(r"vercel_[a-zA-Z0-9]{20,200}"),
        FindingSeverity.HIGH,
        "Rotate at https://vercel.com/account/tokens",
    ),
    (
        "Generic Connection String",
        re.compile(
            r"(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|rediss?|amqps?|mariadb|mssql)"
            r'://[^\s"\':@]{1,200}:[^\s"\'@]{1,200}@[^\s"\']{1,200}',
            re.I,
        ),
        FindingSeverity.CRITICAL,
        "Change database password and update connection string",
    ),
]

# Common placeholder passwords found in docker-compose, documentation, and examples
_PLACEHOLDER_PASSWORDS: set[str] = {
    "password",
    "pass",
    "changeme",
    "mysecretpassword",
    "secret",
    "testpass",
    "test",
    "admin",
    "root",
    "your-password",
    "example",
    "changeit",
    "default",
    "postgres",
    "mysql",
    "redis",
    "guest",
    "user",
    "foobar",
    "foo",
    "bar",
    "baz",
    "qwerty",
    "abc123",
    "123456",
    "letmein",
    "welcome",
    "master",
    "dbname",
    "dbpass",
    "dbpassword",
    "testpassword",
    "supersecret",
    "topsecret",
    "passw0rd",
    "p@ssw0rd",
    "hunter2",
}

# File names that indicate documentation context
_DOC_FILE_NAMES: set[str] = {
    "readme.md",
    "readme.rst",
    "readme.txt",
    "changelog.md",
    "contributing.md",
    "claude.md",
    "agents.md",
    "testing.md",
    "curl_testing.md",
}

# Directory names that indicate test/documentation/example context
_LOW_CONFIDENCE_DIRS: set[str] = {
    "docs",
    "doc",
    "documentation",
    "examples",
    "example",
    "fixtures",
    "test",
    "tests",
    "__tests__",
    "__mocks__",
    "testdata",
    "test_data",
    "mocks",
    "testutils",
    "test_helpers",
}


class CredentialScanner(BaseScanner):
    """Deep recursive credential scanner for agent installations.

    Uses detect-secrets (Yelp) as the primary scanning engine with built-in
    heuristic filters for false positive reduction. Supplements with custom
    patterns for providers not covered by detect-secrets (OpenAI, Anthropic,
    Databricks, Hugging Face, connection strings).
    """

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

        scannable_files = self._iter_scannable_files(target)
        context.files_scanned += len(scannable_files)

        # Phase 1: detect-secrets scanning (battle-tested FP handling)
        findings.extend(self._scan_with_detect_secrets(scannable_files))

        # Phase 2: Custom patterns for providers detect-secrets doesn't cover
        for file_path in scannable_files:
            findings.extend(self._scan_extra_patterns(file_path))

        # Phase 3: Check .git/config for embedded credentials
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

                # Skip lock files (contain integrity hashes, not secrets)
                if item.name.lower() in _LOCK_FILE_NAMES:
                    continue

                # Check extension (also allow .env* files and key extensionless files)
                name_lower = item.name.lower()
                if (
                    item.suffix.lower() not in _SCANNABLE_EXTENSIONS
                    and not name_lower.startswith(".env")
                    and name_lower
                    not in {
                        "dockerfile",
                        ".npmrc",
                        ".pypirc",
                        ".netrc",
                        ".pgpass",
                        ".bashrc",
                        ".bash_profile",
                        ".zshrc",
                        ".profile",
                        "makefile",
                    }
                ):
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

    def _scan_with_detect_secrets(self, files: list[Path]) -> list[Finding]:
        """Run detect-secrets on all scannable files and map results to Findings."""
        findings: list[Finding] = []

        secrets = SecretsCollection()
        with transient_settings(
            {
                "plugins_used": _DETECT_SECRETS_PLUGINS,
                "filters_used": _DETECT_SECRETS_FILTERS,
            }
        ):
            for file_path in files:
                try:
                    secrets.scan_file(str(file_path))
                except Exception:  # noqa: BLE001
                    logger.debug("detect-secrets failed on %s", file_path)
                    continue

        for filename in secrets.files:
            file_path = Path(filename)
            is_low_confidence = self._is_test_or_doc_context(file_path)

            for secret in secrets[filename]:
                # Skip placeholders that detect-secrets doesn't filter
                if secret.secret_value and self._is_placeholder(secret.secret_value):
                    continue

                # Entropy gate for Secret Keyword findings. KeywordDetector
                # fires on variable names like "password" / "secret" / "token"
                # and captures their values — but low-entropy values (e.g.,
                # "changeme", "test123", short words) are almost always FPs.
                if secret.type == "Secret Keyword":
                    if not secret.secret_value:
                        continue
                    if self._shannon_entropy(secret.secret_value) < 3.0:
                        continue

                severity = _SEVERITY_MAP.get(secret.type, FindingSeverity.MEDIUM)
                rotation = _ROTATION_ADVICE.get(
                    secret.type,
                    "Rotate the credential and store in a secrets manager",
                )

                # Downgrade severity for test/doc context
                metadata: dict[str, str] = {"detector": secret.type}
                if is_low_confidence:
                    if severity in (
                        FindingSeverity.CRITICAL,
                        FindingSeverity.HIGH,
                        FindingSeverity.MEDIUM,
                    ):
                        severity = FindingSeverity.LOW
                    metadata["context"] = "test_or_doc"

                # Build sanitized evidence from the secret hash (we don't
                # retain the plaintext value for security)
                evidence = (
                    f"Type: {secret.type} (line {secret.line_number}, "
                    f"hash: {secret.secret_hash[:12]}...)"
                )

                findings.append(
                    Finding(
                        scanner=self.name,
                        category=FindingCategory.EXPOSED_TOKEN,
                        severity=severity,
                        title=f"{secret.type} found in {file_path.name}",
                        description=(
                            f"A {secret.type} was found in '{file_path.name}' at line "
                            f"{secret.line_number}. This credential should be stored in "
                            f"a secrets manager, not in plaintext files."
                        ),
                        evidence=evidence,
                        file_path=file_path,
                        line_number=secret.line_number,
                        remediation=Remediation(
                            summary=f"Rotate and secure the {secret.type}",
                            steps=[
                                rotation,
                                f"Remove the plaintext value from {file_path.name}",
                                "Store in OS keychain or environment variable",
                                "Add file to .gitignore if not already excluded",
                            ],
                        ),
                        owasp_ids=["ASI05"],
                        metadata=metadata,
                    )
                )

        return findings

    def _scan_extra_patterns(self, file_path: Path) -> list[Finding]:
        """Scan for provider patterns not covered by detect-secrets."""
        findings: list[Finding] = []

        try:
            content = file_path.read_text(errors="replace")
        except OSError:
            return findings

        is_low_confidence = self._is_test_or_doc_context(file_path)

        for secret_type, pattern, severity, rotation_advice in _EXTRA_PATTERNS:
            for match in pattern.finditer(content):
                matched = match.group(0)
                line_num = content[: match.start()].count("\n") + 1

                # Skip placeholders and examples
                if self._is_placeholder(matched):
                    continue

                # Skip connection strings with placeholder passwords
                if (
                    secret_type == "Generic Connection String"
                    and self._is_placeholder_connection_string(matched)
                ):
                    continue

                # Downgrade severity for test/doc context
                effective_severity = severity
                metadata: dict[str, str] = {}
                if is_low_confidence:
                    if severity in (
                        FindingSeverity.CRITICAL,
                        FindingSeverity.HIGH,
                        FindingSeverity.MEDIUM,
                    ):
                        effective_severity = FindingSeverity.LOW
                    metadata["context"] = "test_or_doc"

                sanitized = sanitize_secret(matched)

                findings.append(
                    Finding(
                        scanner=self.name,
                        category=FindingCategory.EXPOSED_TOKEN,
                        severity=effective_severity,
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
                        ),
                        owasp_ids=["ASI05"],
                        metadata=metadata if metadata else {},
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
    def _is_placeholder(value: str) -> bool:
        """Check if a value looks like a placeholder rather than a real secret."""
        lower = value.lower()

        # Exact match against known placeholder passwords / common defaults
        if lower in _PLACEHOLDER_PASSWORDS:
            return True

        phrase_placeholders = {
            "your_api_key",
            "your-api-key",
            "your_token",
            "your-token",
            "replace_me",
            "changeme",
            "placeholder",
            "sk-your",
            "mysecretpassword",
            "your-secret-key",
            "my-test-salt",
            "secret123",
            "password123",
            "for_testing_only",
        }
        word_placeholders = {
            "example",
            "test",
            "dummy",
            "fake",
            "sample",
            "sk-xxx",
            "placeholder",
        }

        # Strip known prefixes before checking (e.g. "sk-", "ghp_", "AKIA")
        stripped = re.sub(r"^(?:sk-(?:ant-)?|ghp_|gho_|gh[us]_|AKIA|hf_|dapi)", "", value).lower()

        if any(p in lower for p in phrase_placeholders):
            return True

        # Word placeholder check: suppress if (a) the word dominates the value
        # (makes up >= 40% of the stripped length), or (b) multiple placeholder
        # words appear in the same value. Do NOT use startswith to avoid
        # suppressing real secrets like sk-testABC123... where "test" is just
        # the first 4 random chars after prefix stripping.
        placeholder_hits = sum(1 for w in word_placeholders if w in lower)
        if placeholder_hits >= 2:
            return True
        for word in word_placeholders:
            if word in lower and len(word) >= len(stripped) * 0.4:
                return True

        # Check if it's all the same character
        if len(set(value)) <= 2:
            return True
        # Check if it's a common pattern like "xxx...xxx"
        if re.match(r"^[x\*\.]+$", value, re.I):
            return True

        # Template syntax: {{ var }}, <YOUR_KEY>, %{var}
        if re.search(r"\{\{.*?\}\}", value):
            return True
        if re.match(r"^<[A-Z_]+>$", value):
            return True
        if re.search(r"%\{.+?\}", value):
            return True

        # Detect sequential/obviously-fake patterns
        stripped_alnum = re.sub(r"[^a-z0-9]", "", value.lower())
        if "1234567890" in stripped_alnum:
            return True
        return "abcdefghij" in stripped_alnum

    @staticmethod
    def _is_placeholder_connection_string(value: str) -> bool:
        """Check if a connection string contains placeholder credentials."""
        m = re.match(r"[a-z]+://[^:]+:([^@]+)@", value, re.I)
        if not m:
            return False
        password = m.group(1)

        # Check for env var reference: ${VAR_NAME} or $VAR_NAME (uppercase+underscore)
        if password.startswith("${") and "}" in password:
            return True
        if re.match(r"^\$[A-Z_][A-Z0-9_]*$", password):
            return True
        # Check for angle-bracket placeholder: <password>
        if password.startswith("<") and password.endswith(">"):
            return True
        # Check against known placeholder passwords
        if password.lower() in _PLACEHOLDER_PASSWORDS:
            return True
        # Check if password itself is a placeholder
        return CredentialScanner._is_placeholder(password)

    @staticmethod
    def _is_test_or_doc_context(file_path: Path) -> bool:
        """Check if file is in a test/documentation/example context."""
        name_lower = file_path.name.lower()
        parts_lower = {p.lower() for p in file_path.parts}

        # All markdown files are documentation context
        if name_lower.endswith(".md") or name_lower.endswith(".rst"):
            return True
        # Named documentation files
        if name_lower in _DOC_FILE_NAMES:
            return True
        # Python test files: test_*.py, *_test.py, conftest.py
        if name_lower.startswith("test_") or name_lower.endswith("_test.py"):
            return True
        if name_lower == "conftest.py":
            return True
        # JS/TS test files: *.test.ts, *.test.js, *.spec.ts, *.spec.js, etc.
        if ".test." in name_lower or ".spec." in name_lower:
            return True
        # Integration test files: *.integration.test.ts, etc.
        if "integration" in name_lower and ("test" in name_lower or "spec" in name_lower):
            return True
        # Go test files: *_test.go
        if name_lower.endswith("_test.go"):
            return True
        # Mock/stub/fixture files
        if "mock" in name_lower or "stub" in name_lower or "fixture" in name_lower:
            return True
        # Known config template files
        if name_lower in _TEMPLATE_CONFIG_FILES:
            return True
        # Docker compose files (common placeholder passwords)
        if name_lower.startswith("docker-compose") or name_lower == "compose.yml":
            return True
        # Example/template files
        if ".example" in name_lower or ".sample" in name_lower or ".template" in name_lower:
            return True
        # Documentation/test/example directories
        return bool(_LOW_CONFIDENCE_DIRS & parts_lower)

    @staticmethod
    def _sanitize_secret(value: str) -> str:
        """Sanitize a secret value for safe display."""
        return sanitize_secret(value)

    @staticmethod
    def _shannon_entropy(data: str) -> float:
        """Calculate Shannon entropy of a string."""
        import math
        from collections import Counter

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
