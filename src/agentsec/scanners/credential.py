"""Credential scanner — deep scan for secrets, tokens, and credential exposure.

Uses Yelp's detect-secrets library as the scanning engine for battle-tested
false positive handling, then maps results to agentsec's Finding model with
OWASP categorization and severity classification.

Also performs:
- Git config scanning for embedded credentials
- File-path context awareness (test/doc files get downgraded severity)
"""

from __future__ import annotations

import base64
import binascii
import logging
import re
import subprocess
from collections.abc import Iterator
from pathlib import Path

from detect_secrets import SecretsCollection
from detect_secrets.settings import transient_settings

from agentsec.models.findings import (
    Finding,
    FindingCategory,
    FindingConfidence,
    FindingSeverity,
    Remediation,
)
from agentsec.scanners.base import BaseScanner, ScanContext
from agentsec.utils import sanitize_secret
from agentsec.utils.verifier import compute_passive_hints, verify_secret

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Well-known example values that should NEVER trigger findings.
# These appear in official documentation and tutorials across the ecosystem.
# ---------------------------------------------------------------------------
_KNOWN_EXAMPLE_VALUES: set[str] = {
    # AWS official documentation example keys
    "AKIAIOSFODNN7EXAMPLE",
    "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
}

# Databricks documentation example token prefix — built at runtime to avoid
# GitHub push protection flagging the literal string as a secret.
_KNOWN_EXAMPLE_DATABRICKS_PREFIX = "dapi" + "1234567890ab1cde"

# jwt.io canonical example token prefix — the header+payload is stable across
# all copies of the jwt.io sample; only the signature varies.
_KNOWN_EXAMPLE_JWT_PREFIX = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIi"

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

# Agentsec output file prefixes — skip to avoid FPs from our own scan results
_AGENTSEC_OUTPUT_PREFIXES = ("scan-", "agentsec-report")

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
    {"name": "HexHighEntropyString", "limit": 4.5},
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

# Candidate base64 / hex blobs to decode and re-scan for hidden secrets.
_BASE64_BLOB = re.compile(r"[A-Za-z0-9+/]{24,}={0,2}")
_HEX_BLOB = re.compile(r"(?:0x)?[0-9a-fA-F]{40,}")


def _iter_decoded_blobs(content: str) -> Iterator[tuple[str, str, str]]:
    """Yield (encoding_label, raw_blob, decoded_text) for each decodable blob.

    Only blobs that decode to mostly-printable text are returned, which keeps
    the downstream provider-pattern match meaningful and avoids binary noise.
    """
    for match in _BASE64_BLOB.finditer(content):
        blob = match.group(0)
        if len(blob) % 4 != 0:
            continue
        try:
            raw = base64.b64decode(blob, validate=True)
        except (binascii.Error, ValueError):
            continue
        decoded = raw.decode("utf-8", errors="replace")
        if decoded and _is_mostly_printable(decoded):
            yield "base64", blob, decoded

    for match in _HEX_BLOB.finditer(content):
        blob = match.group(0)
        hex_digits = blob[2:] if blob.lower().startswith("0x") else blob
        if len(hex_digits) % 2 != 0:
            continue
        try:
            raw = bytes.fromhex(hex_digits)
        except ValueError:
            continue
        decoded = raw.decode("utf-8", errors="replace")
        if decoded and _is_mostly_printable(decoded):
            yield "hex", blob, decoded


def _is_mostly_printable(text: str, threshold: float = 0.9) -> bool:
    """True when at least ``threshold`` of characters are printable ASCII."""
    if not text:
        return False
    printable = sum(1 for ch in text if 0x20 <= ord(ch) <= 0x7E)
    return printable / len(text) >= threshold


# Additional provider patterns not covered by detect-secrets
_EXTRA_PATTERNS: list[tuple[str, re.Pattern[str], FindingSeverity, str]] = [
    (
        "OpenAI API Key",
        re.compile(r"sk-(?!ant-)(?:proj-|svcacct-|admin-)?[a-zA-Z0-9_\-]{20,200}"),
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
        # Elevated to CRITICAL: as of Feb 2026, enabling the Gemini Generative
        # Language API grants every existing project API key (including Maps and
        # Firebase keys) access to Gemini, so any leaked AIza key is a live AI
        # credential (Truffle Security, "Google API keys weren't secrets").
        FindingSeverity.CRITICAL,
        "Restrict or delete in Google Cloud Console; check for Gemini API access",
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
        "Mistral API Key",
        re.compile(
            r"(?:mistral|MISTRAL)[_-]?(?:API[_-]?)?KEY\s*[:=]\s*['\"]?([a-zA-Z0-9]{32,})",
            re.I,
        ),
        FindingSeverity.CRITICAL,
        "Rotate at https://console.mistral.ai/api-keys",
    ),
    (
        "Together AI API Key",
        re.compile(
            r"(?:together|TOGETHER)[_-]?(?:API[_-]?)?KEY\s*[:=]\s*['\"]?([a-zA-Z0-9]{40,})",
            re.I,
        ),
        FindingSeverity.CRITICAL,
        "Rotate at https://api.together.xyz/settings/api-keys",
    ),
    (
        "Fireworks AI API Key",
        re.compile(r"fw_[a-zA-Z0-9]{20,200}"),
        FindingSeverity.CRITICAL,
        "Rotate at https://fireworks.ai/account/api-keys",
    ),
    (
        "Perplexity API Key",
        re.compile(r"pplx-[a-zA-Z0-9]{40,200}"),
        FindingSeverity.CRITICAL,
        "Rotate at https://www.perplexity.ai/settings/api",
    ),
    (
        "DeepSeek API Key",
        re.compile(r"sk-[a-f0-9]{48,}"),
        FindingSeverity.CRITICAL,
        "Rotate at https://platform.deepseek.com/api_keys",
    ),
    (
        "Generic Connection String",
        # Explicit, non-overlapping character classes keep this linear-time.
        # Each segment excludes the delimiter that follows it (':' then '@'),
        # so the engine never backtracks across boundaries (ReDoS-safe).
        re.compile(
            r"(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|rediss?|amqps?|mariadb|mssql)"
            r"://"
            r"[A-Za-z0-9._%+\-]{1,128}"  # username (no ':' or '@')
            r":"
            r"[^\s\"'@/]{1,128}"  # password (no '@', '/', whitespace, or quotes)
            r"@"
            r"[A-Za-z0-9._\-]{1,128}",  # host
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
    "__fixtures__",
    "test",
    "tests",
    "__tests__",
    "__mocks__",
    "testdata",
    "test_data",
    "test-data",
    "test-fixtures",
    "snapshot-tests",
    "snapshots",
    "__snapshots__",
    "mocks",
    "testutils",
    "test_helpers",
    # Localization / i18n: translated UI strings trip keyword detectors but are
    # not credentials.
    "locales",
    "locale",
    "i18n",
    "translations",
    "lang",
    "langs",
    "intl",
}

# Loopback hosts in a connection/basic-auth string: dev scaffolding, not a
# remotely usable credential.
_LOOPBACK_HOST_RE = re.compile(
    r"@(?:localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\]|host\.docker\.internal)\b",
    re.I,
)

# Markers that the line sits inside a test function/block (Rust, Python, Go,
# JS/TS). A secret a few lines under one of these is a test vector.
_TEST_BLOCK_MARKERS = re.compile(
    r"#\[test\]|#\[cfg\(test\)\]|\bfn\s+test_|\bdef\s+test_|\bfunc\s+Test"
    r"|\b(?:describe|it|test)\s*\(",
    re.I,
)


def _line_in_test_block(lines: list[str], idx: int, window: int = 40) -> bool:
    """True when a test marker appears within ``window`` lines above ``idx``."""
    start = max(0, idx - window)
    end = min(idx + 1, len(lines))
    return any(_TEST_BLOCK_MARKERS.search(lines[i]) for i in range(start, end))


def _looks_like_identifier_phrase(value: str) -> bool:
    """True when ``value`` is a descriptive identifier rather than a secret.

    Splits on separators and camelCase boundaries; if the result is two or more
    real word tokens (each 3-12 alpha chars) plus optional short numbers, it is
    an enum/const/method name (e.g. "SecurityApiKey", "clientSecretBasic",
    "password_auth"), not a random credential. Real high-entropy keys decompose
    into short two-character fragments and are not matched.
    """
    if len(value) > 40:
        return False
    tokens: list[str] = []
    for part in re.split(r"[-_.:/\s]", value):
        if not part:
            continue
        camel = re.findall(r"[A-Z]+(?=[A-Z][a-z])|[A-Z]?[a-z]+|[A-Z]+|\d+", part)
        tokens.extend(camel if camel else [part])
    if len(tokens) < 2:
        return False
    words = [t for t in tokens if t.isalpha() and 3 <= len(t) <= 12]
    digits = [t for t in tokens if t.isdigit() and len(t) <= 4]
    return len(words) >= 2 and (len(words) + len(digits)) == len(tokens)


def _looks_like_regex_pattern(value: str) -> bool:
    """True when ``value`` is a regex/validation pattern, not a literal secret.

    Matches values containing a character class plus quantifier (``[..]{n}``),
    regex escapes (``\\d``/``\\w``/``\\s``), or a non-capturing group (``(?:``).
    """
    return bool(
        re.search(r"\[[^\]]+\]\s*[*+{]", value)
        or re.search(r"\\[dwsDWS]", value)
        or "(?:" in value
        or "(?<" in value
    )


# Files that intentionally contain fake/example secrets: the configs and
# allowlists of other secret-scanning tools. Any "secret" here is a known
# test vector, not a live credential.
_SECRET_SCANNER_CONFIG_FILES: set[str] = {
    ".gitguardian.yaml",
    ".gitguardian.yml",
    ".gitleaks.toml",
    ".gitleaksignore",
    ".secrets.baseline",
    ".trufflehog.yaml",
    ".trufflehog.yml",
    ".detect-secrets.yaml",
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
        # Filter out files matching .agentsecignore patterns
        scannable_files = [f for f in scannable_files if not context.is_ignored(f)]
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

        # Phase 4: Scan git history for credentials committed then removed
        if context.scan_history and (target / ".git").is_dir():
            findings.extend(self._scan_git_history(target, context.history_depth))

        # Deduplicate findings by fingerprint
        seen: set[str] = set()
        unique_findings: list[Finding] = []
        for f in findings:
            if f.fingerprint not in seen:
                seen.add(f.fingerprint)
                unique_findings.append(f)

        # Phase 5: Enrich findings with passive verification hints
        for f in unique_findings:
            if f.category == FindingCategory.EXPOSED_TOKEN:
                hints = compute_passive_hints(
                    f.file_path,
                    f.line_number,
                    f.metadata.get("detector", f.title),
                )
                f.metadata.update(hints)

        # Phase 6: Active verification (opt-in only via --verify)
        if context.metadata.get("verify"):
            self._run_active_verification(unique_findings, target)

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

                # Skip agentsec output files (contain hashes from our own scan)
                name_lower = item.name.lower()
                if name_lower.startswith(_AGENTSEC_OUTPUT_PREFIXES) and name_lower.endswith(
                    (".json", ".sarif")
                ):
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
                except (OSError, UnicodeDecodeError) as exc:
                    # Unreadable or non-text file: expected, low signal.
                    logger.debug("detect-secrets skipped %s: %s", file_path, exc)
                    continue
                except Exception as exc:  # noqa: BLE001
                    # Unexpected: a plugin or library bug. Surface it (warning)
                    # so a silently unscanned file is visible, but keep scanning.
                    logger.warning(
                        "detect-secrets failed on %s (%s: %s); file not scanned",
                        file_path,
                        type(exc).__name__,
                        exc,
                    )
                    continue

        for filename in secrets.files:
            file_path = Path(filename)
            path_low_confidence = self._is_test_or_doc_context(file_path)

            # Read file lines once for line-level context checks (loopback
            # hosts, test-block detection, private-key body length).
            try:
                file_lines = Path(filename).read_text(errors="replace").splitlines()
            except OSError:
                file_lines = []

            for secret in secrets[filename]:
                line_idx = (secret.line_number or 0) - 1
                line_text = file_lines[line_idx] if 0 <= line_idx < len(file_lines) else ""

                # Loopback basic-auth / connection strings are dev scaffolding.
                if secret.type == "Basic Auth Credentials" and _LOOPBACK_HOST_RE.search(line_text):
                    continue

                # A secret inside a test function/block is a test vector even if
                # the file itself is not test-named (e.g. an inline #[test] in a
                # production .rs module).
                is_low_confidence = path_low_confidence or (
                    bool(file_lines) and _line_in_test_block(file_lines, line_idx)
                )
                # Skip well-known example values (AWS EXAMPLE keys, jwt.io, etc.)
                if secret.secret_value and self._is_known_example_value(
                    secret.secret_value, secret.type
                ):
                    continue

                # Skip placeholders that detect-secrets doesn't filter
                if secret.secret_value and self._is_placeholder(secret.secret_value):
                    continue

                # Private key body check: skip if the key body between
                # BEGIN/END markers is obviously fake (trivially short).
                # Real PEM keys are hundreds of base64 chars; bodies under 10
                # chars like "test" or "fake" are clearly not real.
                if secret.type == "Private Key" and secret.line_number:
                    try:
                        lines = Path(filename).read_text(errors="replace").splitlines()
                        start_idx = secret.line_number - 1  # 1-indexed
                        body_lines = []
                        for i in range(start_idx + 1, min(start_idx + 100, len(lines))):
                            if "-----END" in lines[i]:
                                break
                            body_lines.append(lines[i].strip())
                        body_text = "".join(body_lines)
                        if len(body_text) < 10:
                            continue
                    except (OSError, IndexError):
                        pass  # If we can't read context, proceed normally

                # Entropy gate for Secret Keyword findings. KeywordDetector
                # fires on variable names like "password" / "secret" / "token"
                # and captures their values — but low-entropy values (e.g.,
                # "changeme", "test123", short words) are almost always FPs.
                if secret.type == "Secret Keyword":
                    if not secret.secret_value:
                        continue
                    if self._shannon_entropy(secret.secret_value) < 3.0:
                        continue
                    # KeywordDetector captures the value after a `password=`/
                    # `secret=`/`token=` keyword. Suppress the common non-secret
                    # shapes it picks up: descriptive enum/const identifiers,
                    # validation regex patterns, and CI templating expressions.
                    # These checks are scoped to this detector only so provider
                    # keys (AWS, Private Key, etc.) are never affected.
                    sv = secret.secret_value
                    if (
                        _looks_like_identifier_phrase(sv)
                        or _looks_like_regex_pattern(sv)
                        or "${{" in sv
                    ):
                        continue

                severity = _SEVERITY_MAP.get(secret.type, FindingSeverity.MEDIUM)
                rotation = _ROTATION_ADVICE.get(
                    secret.type,
                    "Rotate the credential and store in a secrets manager",
                )

                # Downgrade severity for test/doc context
                confidence = FindingConfidence.HIGH
                metadata: dict[str, str] = {"detector": secret.type}
                if is_low_confidence:
                    if severity in (
                        FindingSeverity.CRITICAL,
                        FindingSeverity.HIGH,
                        FindingSeverity.MEDIUM,
                    ):
                        severity = FindingSeverity.LOW
                    confidence = FindingConfidence.LOW
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
                        confidence=confidence,
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
                                (
                                    "Check git history with git log -p --all -S '<value>'; "
                                    "purge with git filter-repo if committed"
                                ),
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

                # Skip well-known example values (AWS EXAMPLE, jwt.io, etc.)
                if self._is_known_example_value(matched, secret_type):
                    continue

                # Skip placeholders and examples
                if self._is_placeholder(matched):
                    continue

                # Skip connection strings with placeholder passwords
                if (
                    secret_type == "Generic Connection String"
                    and self._is_placeholder_connection_string(matched)
                ):
                    continue

                # Entropy gate: skip low-entropy matches from extra patterns.
                # Real API keys have high entropy; documentation strings and
                # natural language matches (e.g. "sk-this-is-docs-not-key") don't.
                if (
                    secret_type != "Generic Connection String"
                    and self._shannon_entropy(matched) < 3.0
                ):
                    continue

                # Character class diversity: real API keys mix lowercase, uppercase,
                # and digits. Pure-lowercase strings like "sk-this-is-not-a-key" are
                # natural language, not secrets. Strip known prefix before checking.
                if secret_type not in ("Generic Connection String", "Private Key"):
                    body = re.sub(
                        r"^(?:sk-(?:ant-|proj-|svcacct-|admin-)?|ghp_|gho_|gh[us]_|AKIA"
                        r"|hf_|dapi|gsk_|r8_|pcsk_|co-|vercel_|AIza)",
                        "",
                        matched,
                    )
                    if len(body) >= 12 and not self._has_char_class_diversity(body):
                        continue

                # Downgrade severity for test/doc context
                effective_severity = severity
                confidence = FindingConfidence.HIGH
                metadata: dict[str, str] = {}
                if is_low_confidence:
                    if severity in (
                        FindingSeverity.CRITICAL,
                        FindingSeverity.HIGH,
                        FindingSeverity.MEDIUM,
                    ):
                        effective_severity = FindingSeverity.LOW
                    confidence = FindingConfidence.LOW
                    metadata["context"] = "test_or_doc"

                sanitized = sanitize_secret(matched)

                findings.append(
                    Finding(
                        scanner=self.name,
                        category=FindingCategory.EXPOSED_TOKEN,
                        severity=effective_severity,
                        confidence=confidence,
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
                                (
                                    "Check git history with git log -p --all -S '<value>'; "
                                    "purge with git filter-repo if committed"
                                ),
                            ],
                        ),
                        owasp_ids=["ASI05"],
                        metadata=metadata if metadata else {},
                    )
                )

        # Obfuscation pass: base64/hex-encoded secrets hide from plain pattern
        # matching. Decode embedded blobs and re-run provider patterns on the
        # plaintext. Every paper on agent-secret scanning (SKILL-INJECT,
        # MCPSecBench) flags this as the standard gap in static scanners.
        findings.extend(self._scan_decoded_blobs(content, file_path, is_low_confidence))

        return findings

    def _scan_decoded_blobs(
        self, content: str, file_path: Path, is_low_confidence: bool
    ) -> list[Finding]:
        """Decode base64/hex blobs in ``content`` and re-scan for provider keys.

        Only emits a finding when the decoded plaintext matches a known provider
        key format, so precision stays high (a random base64 blob that does not
        decode to a real key shape is ignored).
        """
        findings: list[Finding] = []
        seen: set[str] = set()

        for encoding, blob, decoded in _iter_decoded_blobs(content):
            for secret_type, pattern, severity, rotation_advice in _EXTRA_PATTERNS:
                # Connection strings and PEM bodies do not survive a clean
                # round-trip through base64/hex in a way worth chasing here.
                if secret_type in ("Generic Connection String", "Private Key"):
                    continue
                match = pattern.search(decoded)
                if not match:
                    continue
                matched = match.group(0)
                if self._is_placeholder(matched) or self._shannon_entropy(matched) < 3.0:
                    continue
                if matched in seen:
                    continue
                seen.add(matched)

                line_num = content[: content.find(blob)].count("\n") + 1
                effective_severity = severity
                confidence = FindingConfidence.HIGH
                metadata: dict[str, str] = {"encoding": encoding, "obfuscated": "true"}
                if is_low_confidence:
                    if severity != FindingSeverity.LOW:
                        effective_severity = FindingSeverity.LOW
                    confidence = FindingConfidence.LOW
                    metadata["context"] = "test_or_doc"

                findings.append(
                    Finding(
                        scanner=self.name,
                        category=FindingCategory.EXPOSED_TOKEN,
                        severity=effective_severity,
                        confidence=confidence,
                        title=f"{encoding}-encoded {secret_type} found in {file_path.name}",
                        description=(
                            f"A {secret_type} was found {encoding}-encoded in "
                            f"'{file_path.name}' near line {line_num}. Encoding a "
                            f"credential hides it from plain text scanning but it is "
                            f"still a live secret once decoded at runtime."
                        ),
                        evidence=(
                            f"Decoded: {sanitize_secret(matched)} ({encoding}, line {line_num})"
                        ),
                        file_path=file_path,
                        line_number=line_num,
                        remediation=Remediation(
                            summary=f"Rotate and secure the {secret_type}",
                            steps=[
                                rotation_advice,
                                f"Remove the encoded value from {file_path.name}",
                                "Store in OS keychain or environment variable",
                                "Encoding is not encryption; do not rely on it",
                            ],
                        ),
                        owasp_ids=["ASI05"],
                        metadata=metadata,
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
                            "Purge from git history with git filter-repo if previously committed",
                        ],
                    ),
                    owasp_ids=["ASI05"],
                )
            )

        return findings

    def _scan_git_history(self, target: Path, depth: int) -> list[Finding]:
        """Scan git history for credentials that were committed then removed.

        Runs ``git log -p`` to extract diffs, then checks added lines against
        the custom credential patterns.  Findings are tagged with
        ``metadata.source = "git_history"`` and the commit SHA.

        Deduplicates by (secret_type, matched_value): if the same secret
        appears in multiple commits only one finding is emitted, annotated
        with the first and last commit SHAs.
        """
        findings: list[Finding] = []

        try:
            result = subprocess.run(
                [
                    "git",
                    "log",
                    "--all",
                    "-p",
                    "-U0",
                    f"--max-count={depth}",
                    "--no-color",
                    "--diff-filter=ACMR",
                ],
                capture_output=True,
                text=True,
                cwd=str(target),
                timeout=120,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            logger.debug("git not available or timed out; skipping history scan")
            return findings
        except OSError:
            logger.debug("Failed to run git log; skipping history scan")
            return findings

        if result.returncode != 0:
            logger.debug("git log failed (rc=%d); skipping history scan", result.returncode)
            return findings

        # Parse the diff output, tracking current commit and file
        current_commit: str | None = None
        current_file: str | None = None
        # Dedup key: (secret_type, matched_value) -> finding + commit list
        seen: dict[tuple[str, str], tuple[Finding, list[str]]] = {}

        for line in result.stdout.splitlines():
            # Track commit boundaries
            if line.startswith("commit "):
                current_commit = line.split()[1][:12]
                continue

            # Track file names from diff headers
            if line.startswith("+++ b/"):
                current_file = line[6:]
                continue

            # Only scan added lines (lines starting with single +, not +++)
            if not line.startswith("+") or line.startswith("+++"):
                continue

            added_content = line[1:]  # Strip leading +
            if not added_content.strip():
                continue

            # Run extra patterns against the added content
            for secret_type, pattern, severity, rotation_advice in _EXTRA_PATTERNS:
                for match in pattern.finditer(added_content):
                    matched = match.group(0)

                    # Apply the same FP filters as the live scanner
                    if self._is_known_example_value(matched, secret_type):
                        continue
                    if self._is_placeholder(matched):
                        continue
                    if (
                        secret_type == "Generic Connection String"
                        and self._is_placeholder_connection_string(matched)
                    ):
                        continue
                    if (
                        secret_type != "Generic Connection String"
                        and self._shannon_entropy(matched) < 3.0
                    ):
                        continue
                    if secret_type not in ("Generic Connection String", "Private Key"):
                        body = re.sub(
                            r"^(?:sk-(?:ant-|proj-|svcacct-|admin-)?|ghp_|gho_|gh[us]_|AKIA"
                            r"|hf_|dapi|gsk_|r8_|pcsk_|co-|vercel_|AIza)",
                            "",
                            matched,
                        )
                        if len(body) >= 12 and not self._has_char_class_diversity(body):
                            continue

                    dedup_key = (secret_type, matched)
                    if dedup_key in seen:
                        # Update last-seen commit
                        _, commits = seen[dedup_key]
                        if current_commit and current_commit not in commits:
                            commits.append(current_commit)
                        continue

                    sanitized = sanitize_secret(matched)
                    file_display = current_file or "unknown"
                    commit_display = current_commit or "unknown"

                    finding = Finding(
                        scanner=self.name,
                        category=FindingCategory.EXPOSED_TOKEN,
                        severity=severity,
                        confidence=FindingConfidence.MEDIUM,
                        title=f"{secret_type} found in git history ({file_display})",
                        description=(
                            f"A {secret_type} was found in git history, commit "
                            f"{commit_display}. Even though the credential may have been "
                            f"removed from the working tree, it remains in the repository "
                            f"history and can be recovered by anyone with clone access."
                        ),
                        evidence=f"Value: {sanitized} (commit {commit_display})",
                        file_path=Path(file_display) if current_file else None,
                        remediation=Remediation(
                            summary=f"Rotate the {secret_type} and purge from git history",
                            steps=[
                                rotation_advice,
                                "Purge from history: git filter-repo --invert-paths "
                                f"--path '{file_display}'",
                                "Or use BFG Repo Cleaner: bfg --replace-text passwords.txt",
                                "Force-push all branches after purging",
                                "Notify affected team members to re-clone",
                            ],
                        ),
                        owasp_ids=["ASI05"],
                        metadata={
                            "source": "git_history",
                            "commit": commit_display,
                        },
                    )

                    seen[dedup_key] = (finding, [commit_display])

        # Annotate findings with commit span info
        for (_, _), (finding, commits) in seen.items():
            if len(commits) > 1:
                finding.metadata["first_seen"] = commits[-1]  # oldest
                finding.metadata["last_seen"] = commits[0]  # newest
                finding.metadata["commit_count"] = str(len(commits))
            findings.append(finding)

        return findings

    def _run_active_verification(self, findings: list[Finding], target: Path) -> None:
        """Probe discovered credentials against provider APIs (opt-in).

        Mutates finding metadata in-place to add ``verified`` status.
        Only checks credentials from the extra-pattern scanner (which
        retains the plaintext value in the evidence field).
        """
        for f in findings:
            if f.category != FindingCategory.EXPOSED_TOKEN:
                continue
            # Extract the secret type from metadata or title
            secret_type = f.metadata.get("detector") or ""
            for pattern_type, _, _, _ in _EXTRA_PATTERNS:
                if pattern_type in f.title:
                    secret_type = pattern_type
                    break
            if not secret_type:
                continue

            # Try to recover the plaintext from the evidence field
            # Format: "Value: sk-pr...ngth99 (line 3)" or hash-based
            evidence = f.evidence or ""
            if not evidence.startswith("Value: "):
                f.metadata["verified"] = "unknown"
                f.metadata["verify_method"] = "no_plaintext_available"
                continue

            # We cannot recover the full secret from sanitized evidence.
            # Active verification requires the raw secret, which we only have
            # during scanning.  For now, re-read the file and extract.
            if not f.file_path or not f.line_number:
                f.metadata["verified"] = "unknown"
                f.metadata["verify_method"] = "no_file_location"
                continue

            try:
                file_path = Path(f.file_path)
                if not file_path.is_absolute():
                    file_path = target / file_path
                content = file_path.read_text(errors="replace")
                lines = content.splitlines()
                if f.line_number - 1 < len(lines):
                    line = lines[f.line_number - 1]
                else:
                    continue
            except OSError:
                continue

            # Re-match the pattern on the specific line
            for pattern_type, pattern, _, _ in _EXTRA_PATTERNS:
                if pattern_type != secret_type:
                    continue
                m = pattern.search(line)
                if m:
                    result = verify_secret(secret_type, m.group(0))
                    f.metadata.update(result)
                    break

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
            "insert_here",
            "do_not_use",
            "not-a-real",
            "notareal",
            "for_documentation",
            "fordocumentation",
            "for_docs",
            "fordocs",
        }
        word_placeholders = {
            "example",
            "test",
            "dummy",
            "fake",
            "sample",
            "sk-xxx",
            "placeholder",
            "demo",
            "mock",
            "stub",
            "invalid",
            "redacted",
            "revoked",
            "expired",
            "todo",
            "fixme",
        }

        # Strip known prefixes before checking (e.g. "sk-", "ghp_", "AKIA")
        stripped = re.sub(
            r"^(?:sk-(?:ant-|proj-|svcacct-|admin-)?|ghp_|gho_|gh[us]_|AKIA|hf_|dapi"
            r"|gsk_|r8_|pcsk_|co-|vercel_|AIza|fw_|pplx-)",
            "",
            value,
        ).lower()

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

        # Self-describing kebab/snake phrase: a real key is not a run of
        # lowercase word tokens joined by - or _, e.g.
        # "very-private-api-key-12345" or "my_fake_secret_token". Require 3+
        # segments that are all either short alpha words or pure digits, with
        # at least two word segments. UUIDs and real keys do not fit this shape.
        segments = re.split(r"[-_]", stripped)
        if len(segments) >= 3:
            word_like = [s for s in segments if s.isalpha() and len(s) <= 12]
            digit_like = [s for s in segments if s.isdigit()]
            if len(word_like) >= 2 and len(word_like) + len(digit_like) == len(segments):
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
        m = re.match(r"[a-z]+://[^:]+:([^@]+)@([^:/?\s]+)", value, re.I)
        if not m:
            return False
        password = m.group(1)
        host = m.group(2).lower()

        # Loopback hosts are dev scaffolding, not a remotely usable credential.
        if host in ("localhost", "127.0.0.1", "0.0.0.0", "::1", "host.docker.internal"):
            return True

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
        # Rust test files: *_tests.rs, *_test.rs, and bare tests.rs / test.rs modules
        if name_lower.endswith(("_tests.rs", "_test.rs")) or name_lower in ("tests.rs", "test.rs"):
            return True
        # Secret-scanner config/allowlist files (deliberately hold fake tokens)
        if name_lower in _SECRET_SCANNER_CONFIG_FILES:
            return True
        # Localization message files: en-US.lang.ts, messages.i18n.json, etc.
        if ".lang." in name_lower or ".i18n." in name_lower or ".messages." in name_lower:
            return True
        # Mock/stub/fixture/dummy/example files
        if "mock" in name_lower or "stub" in name_lower or "fixture" in name_lower:
            return True
        if "dummy" in name_lower or "fake" in name_lower:
            return True
        if name_lower.startswith("example") or name_lower.startswith("sample"):
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
        # Documentation/test/example directories (exact match)
        if _LOW_CONFIDENCE_DIRS & parts_lower:
            return True
        # Any path segment that is clearly a fixture/snapshot/mock dir, e.g.
        # "__fixtures__", "test-fixtures", "snapshot-tests" under nested trees.
        return any(("fixture" in p or "snapshot" in p or "__mocks__" in p) for p in parts_lower)

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

    @staticmethod
    def _has_char_class_diversity(value: str) -> bool:
        """Check if the body of a secret has at least 2 character classes.

        Real API keys almost always mix lowercase + uppercase + digits.
        Strings like ``sk-this-is-docs-not-key`` (all lowercase + hyphens)
        are virtually always natural language, not secrets.
        """
        has_lower = False
        has_upper = False
        has_digit = False
        for ch in value:
            if ch.islower():
                has_lower = True
            elif ch.isupper():
                has_upper = True
            elif ch.isdigit():
                has_digit = True
            # Early exit once 2+ classes confirmed
            if (has_lower + has_upper + has_digit) >= 2:
                return True
        return False

    @staticmethod
    def _is_known_example_value(value: str, secret_type: str) -> bool:
        """Check if a matched value is a well-known example/documentation value."""
        if value in _KNOWN_EXAMPLE_VALUES:
            return True
        # Databricks documentation example token (prefix-based to avoid GitHub
        # push protection flagging the full literal)
        if value.startswith(_KNOWN_EXAMPLE_DATABRICKS_PREFIX):
            return True
        # jwt.io canonical example token check (prefix-based, signature varies)
        if secret_type in ("JSON Web Token", "JWT Token") and value.startswith(
            _KNOWN_EXAMPLE_JWT_PREFIX
        ):
            return True
        # Check for EXAMPLE as a delimited word in credential context.
        # Exclude matches inside domain names (e.g. "example.com") which are
        # common in documentation URLs and connection strings.
        if re.search(r"(?i)\bEXAMPLE\b", value):
            # If "example" only appears as part of a domain name, it's not a
            # fake credential indicator.
            cleaned = re.sub(r"(?i)example\.\w+", "", value)
            if re.search(r"(?i)\bEXAMPLE\b", cleaned):
                return True
        return False
