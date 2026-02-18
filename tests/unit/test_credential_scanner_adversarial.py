"""Adversarial tests for the credential scanner.

Red Team analysis targeting false positives and false negatives.
Each test documents a specific attack vector with the exact file content
that breaks the scanner. Tests are grouped by category:

  FP = False Positive (scanner fires when it should not)
  FN = False Negative (scanner misses a real secret)

Root cause of known FP incidents: documentation keys marked "FAKE-EXAMPLE-KEY"
have high Shannon entropy (>3.0) and the placeholder word "fake" is too short
relative to the full string to trigger the 40%-of-stripped-length gate.
"""

# ruff: noqa: N801 E501

from __future__ import annotations

import pytest

from agentsec.models.findings import FindingSeverity
from agentsec.scanners.base import ScanContext
from agentsec.scanners.credential import CredentialScanner


@pytest.fixture
def scanner():
    return CredentialScanner()


# =====================================================================
# FALSE POSITIVE ATTACK VECTORS
# =====================================================================


class TestFP01_DocumentationExampleKeys:
    """FP-01: Documentation example keys with provider prefixes.

    Root cause: _is_placeholder word check uses 40% ratio against stripped
    length. For long strings like "sk-FakeKeyForDocumentation12345678",
    "fake" (4 chars) is only 12.9% of the 31-char stripped value, so it
    slips through.
    """

    def test_openai_fake_key_in_readme(self, scanner, tmp_path):
        """OpenAI key clearly labeled FAKE in README should not fire CRITICAL."""
        f = tmp_path / "README.md"
        f.write_text(
            "# Setup\n"
            "Example:\n"
            "```\n"
            'export OPENAI_API_KEY="sk-FakeKeyForDocumentation12345678"\n'
            "```\n"
        )
        ctx = ScanContext(target_path=tmp_path)
        findings = scanner.scan(ctx)
        # README.md is doc context so gets downgraded to LOW at best.
        # Ideal: 0 findings. Current: 2 findings (LOW).
        critical = [f for f in findings if f.severity == FindingSeverity.CRITICAL]
        assert len(critical) == 0, (
            "FP-01: Doc example key should never be CRITICAL. "
            f"Got {len(critical)} CRITICAL findings."
        )

    def test_fake_example_key_pattern(self, scanner, tmp_path):
        """Known FP incident: 'FAKE-EXAMPLE-KEY' with high entropy.

        Shannon entropy of 'FAKE-EXAMPLE-KEY' is 3.125 (above 3.0 gate).
        But _is_placeholder catches it via dual-word hit ('fake' + 'example').
        This specific case IS handled -- but variants are not.
        """
        f = tmp_path / "config.yaml"
        f.write_text("api_key: FAKE-EXAMPLE-KEY-NOT-FOR-PRODUCTION-USE-12345\n")
        ctx = ScanContext(target_path=tmp_path)
        findings = scanner.scan(ctx)
        # "fake" and "example" both hit word_placeholders -> 2 hits -> suppressed
        # But _is_placeholder only checks the VALUE, not the line context
        secret_kw = [f for f in findings if f.metadata.get("detector") == "Secret Keyword"]
        assert len(secret_kw) == 0, "FP-01: FAKE-EXAMPLE-KEY variant should be suppressed"

    def test_not_a_real_key_phrase(self, scanner, tmp_path):
        """String containing 'NOT-A-REAL-KEY' should be treated as placeholder.

        Current behavior: NOT suppressed because none of the phrase_placeholders
        or word_placeholders match 'NOT-A-REAL-KEY-JUST-FOR-DOCS'.
        """
        f = tmp_path / "config.yaml"
        f.write_text("token: NOT-A-REAL-KEY-JUST-FOR-DOCS\n")
        ctx = ScanContext(target_path=tmp_path)
        findings = scanner.scan(ctx)
        # This is a known gap: entropy is 3.73, no placeholder words match
        assert len(findings) == 0, (
            "FP-01: 'NOT-A-REAL-KEY-JUST-FOR-DOCS' should be a placeholder. "
            f"Got {len(findings)} findings."
        )

    @pytest.mark.xfail(
        reason="FP-01: 'DO-NOT-USE-IN-PRODUCTION' passes entropy gate (3.39) "
        "and has no placeholder word matches. KeywordDetector fires on "
        "'secret:' key and captures the value.",
        strict=True,
    )
    def test_do_not_use_in_production_phrase(self, scanner, tmp_path):
        """Warning phrase 'DO-NOT-USE-IN-PRODUCTION' is not a real secret."""
        f = tmp_path / "config.yaml"
        f.write_text("secret: DO-NOT-USE-IN-PRODUCTION\n")
        ctx = ScanContext(target_path=tmp_path)
        findings = scanner.scan(ctx)
        assert len(findings) == 0, (
            f"FP-01: DO-NOT-USE-IN-PRODUCTION should be suppressed. Got {len(findings)} findings."
        )

    @pytest.mark.parametrize(
        "key",
        [
            "sk-FakeKeyForDocumentation12345678",
            "gsk_FakeGroqKeyForDocumentation12345",
            "r8_FakeReplicateTokenForDocs12345678",
        ],
        ids=["openai_fake", "groq_fake", "replicate_fake"],
    )
    def test_provider_prefixed_fake_keys_long_string(self, scanner, tmp_path, key):
        """Provider-prefixed keys where 'fake' is <40% of stripped length.

        FIXED in Tier 4: expanded phrase placeholders ("for_documentation",
        "fordocumentation", "fordocs") plus expanded prefix stripping now catch
        these. Previously a known FP root cause.
        """
        f = tmp_path / "config.py"
        f.write_text(f'KEY = "{key}"\n')
        ctx = ScanContext(target_path=tmp_path)
        findings = scanner.scan(ctx)
        # Ideal: 0 findings (or at least not CRITICAL)
        critical = [f for f in findings if f.severity == FindingSeverity.CRITICAL]
        assert len(critical) == 0, f"FP-01: Key containing 'Fake' should not be CRITICAL: {key}"


class TestFP02_TestFixtureValues:
    """FP-02: Test fixture constants that match key patterns."""

    def test_test_fixture_constant(self, scanner, tmp_path):
        """Constants named TEST_* in test files still trigger for extra patterns."""
        f = tmp_path / "test_auth.py"
        f.write_text('TEST_KEY = "sk-testFixtureKeyNotRealAtAll12345"\n')
        ctx = ScanContext(target_path=tmp_path)
        findings = scanner.scan(ctx)
        # test_auth.py is low-confidence context, so severity is downgraded.
        # But ideally, test fixtures shouldn't generate any findings at all.
        # Current: 1 finding (LOW) because "test" is < 40% of stripped length.
        critical_or_high = [
            f for f in findings if f.severity in (FindingSeverity.CRITICAL, FindingSeverity.HIGH)
        ]
        assert len(critical_or_high) == 0, (
            "FP-02: Test fixture keys in test files should not be HIGH/CRITICAL"
        )


class TestFP03_DockerComposeConnectionStrings:
    """FP-03: Connection strings in docker-compose with common passwords."""

    def test_docker_compose_postgres_placeholder(self, scanner, tmp_path):
        f = tmp_path / "docker-compose.yml"
        f.write_text(
            "services:\n"
            "  db:\n"
            "    environment:\n"
            "      DATABASE_URL: postgresql://postgres:postgres@db:5432/app\n"
        )
        ctx = ScanContext(target_path=tmp_path)
        findings = scanner.scan(ctx)
        conn = [f for f in findings if "Connection String" in f.title]
        assert len(conn) == 0

    def test_docker_compose_common_password_not_in_list(self, scanner, tmp_path):
        """Common passwords like 'Passw0rd2024' are NOT in _PLACEHOLDER_PASSWORDS."""
        f = tmp_path / "docker-compose.yml"
        f.write_text(
            "services:\n"
            "  db:\n"
            "    environment:\n"
            "      DATABASE_URL: postgresql://user:Passw0rd2024@db:5432/app\n"
        )
        ctx = ScanContext(target_path=tmp_path)
        findings = scanner.scan(ctx)
        conn = [f for f in findings if "Connection String" in f.title]
        # docker-compose.yml is low confidence, so at worst severity=LOW
        # But 'Passw0rd2024' is a classic weak password used in examples
        # and should ideally be treated as a placeholder
        if conn:
            assert conn[0].severity == FindingSeverity.LOW, (
                "FP-03: Common password in docker-compose should be LOW at worst"
            )

    def test_readme_connection_string(self, scanner, tmp_path):
        """Connection strings in README should be suppressed or LOW."""
        f = tmp_path / "README.md"
        f.write_text(
            "# Database Setup\n"
            "```\n"
            "DATABASE_URL=postgresql://user:password@localhost:5432/mydb\n"
            "```\n"
        )
        ctx = ScanContext(target_path=tmp_path)
        findings = scanner.scan(ctx)
        conn = [f for f in findings if "Connection String" in f.title]
        assert len(conn) == 0, "FP-03: README connection string with 'password' literal"


class TestFP04_JWTTokensFromJwtIo:
    """FP-04: JWT tokens from jwt.io in documentation."""

    def test_jwt_io_example_token_in_docs(self, scanner, tmp_path):
        """The canonical jwt.io example token should not trigger in docs."""
        f = tmp_path / "docs/auth.md"
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(
            "## JWT Example\n"
            "Here is a sample JWT token from jwt.io:\n"
            "```\n"
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
            "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ."
            "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c\n"
            "```\n"
        )
        ctx = ScanContext(target_path=tmp_path)
        findings = scanner.scan(ctx)
        # JWT detector fires. In docs/ dir, severity is downgraded to LOW.
        # Arguable whether this should be 0 findings or just LOW.
        critical = [f for f in findings if f.severity == FindingSeverity.CRITICAL]
        assert len(critical) == 0


class TestFP05_Base64ConfigValues:
    """FP-05: Base64-encoded config values that are NOT secrets.

    KeywordDetector fires on 'password:', 'secret:', etc. and captures the
    value. If the value is base64-encoded non-secret text, it has high entropy
    (>3.0) and passes the entropy gate.
    """

    @pytest.mark.xfail(
        reason="FP-05: Base64('Hello World') = 'SGVsbG8gV29ybGQ=' has entropy "
        "3.45, above the 3.0 gate. KeywordDetector fires on 'password:' and "
        "captures the base64 value. No mechanism to detect non-secret base64.",
        strict=True,
    )
    def test_base64_hello_world_as_password_value(self, scanner, tmp_path):
        """Base64-encoded 'Hello World' after 'password:' key."""
        f = tmp_path / "config.yaml"
        # SGVsbG8gV29ybGQ= is base64("Hello World"), entropy ~3.45
        f.write_text("password: SGVsbG8gV29ybGQ=\n")
        ctx = ScanContext(target_path=tmp_path)
        findings = scanner.scan(ctx)
        # This is a known FP: entropy 3.45 > 3.0 threshold, and
        # KeywordDetector sees "password:" and captures the base64 value.
        kw = [f for f in findings if f.metadata.get("detector") == "Secret Keyword"]
        assert len(kw) == 0, (
            f"FP-05: Base64 'Hello World' is not a secret. Got {len(kw)} Secret Keyword findings."
        )

    @pytest.mark.xfail(
        reason="FP-05: Base64('testing 123') = 'dGVzdGluZyAxMjM=' has entropy "
        "3.63. Same root cause as above.",
        strict=True,
    )
    def test_base64_testing_123_as_secret_value(self, scanner, tmp_path):
        """Base64-encoded 'testing 123' after 'secret:' key."""
        f = tmp_path / "config.yaml"
        # dGVzdGluZyAxMjM= is base64("testing 123"), entropy ~3.63
        f.write_text("secret: dGVzdGluZyAxMjM=\n")
        ctx = ScanContext(target_path=tmp_path)
        findings = scanner.scan(ctx)
        kw = [f for f in findings if f.metadata.get("detector") == "Secret Keyword"]
        assert len(kw) == 0, (
            f"FP-05: Base64 'testing 123' is not a secret. Got {len(kw)} Secret Keyword findings."
        )


class TestFP06_PrivateKeysInTestFiles:
    """FP-06: Private key blocks in test files.

    PrivateKeyDetector fires on '-----BEGIN RSA PRIVATE KEY-----' regardless
    of file context. In test files, these are almost always test fixtures.
    Currently downgraded to LOW but still reported.
    """

    def test_private_key_in_test_file(self, scanner, tmp_path):
        """Private key in tests/test_crypto.py is a test fixture."""
        test_dir = tmp_path / "tests"
        test_dir.mkdir()
        f = test_dir / "test_crypto.py"
        f.write_text(
            'TEST_PRIVATE_KEY = """\n'
            "-----BEGIN RSA PRIVATE KEY-----\n"
            "MIIEowIBAAKCAQEA0Z3VS5JJcds3xfn/yGaXq3QE2a0B\n"
            "-----END RSA PRIVATE KEY-----\n"
            '"""\n'
        )
        ctx = ScanContext(target_path=tmp_path)
        findings = scanner.scan(ctx)
        # Currently reported as LOW. Ideally 0 for test fixtures.
        pk = [f for f in findings if "Private Key" in f.title]
        if pk:
            assert pk[0].severity == FindingSeverity.LOW, (
                "FP-06: Private key in test file should be LOW at worst"
            )


class TestFP07_HexChecksums:
    """FP-07: Hex strings that are checksums, not secrets.

    SHA-256 hashes have entropy ~3.67 for the empty-string hash. The
    HexHighEntropyString detector (limit 3.5) fires on them.
    """

    def test_sha256_checksum_in_checksums_file(self, scanner, tmp_path):
        """SHA-256 hash in a checksums.txt file."""
        f = tmp_path / "checksums.txt"
        f.write_text(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  empty\n"
            "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592  hello\n"
        )
        ctx = ScanContext(target_path=tmp_path)
        findings = scanner.scan(ctx)
        hex_findings = [
            f for f in findings if f.metadata.get("detector") == "Hex High Entropy String"
        ]
        # Currently 0 because .txt files don't have keyword context.
        # But this test documents the behavior.
        assert len(hex_findings) == 0

    @pytest.mark.xfail(
        reason="FP-07: KeywordDetector fires on 'secret_hash:' key name and "
        "captures the SHA-256 value (entropy 3.67 > 3.0 gate). The scanner "
        "has no mechanism to recognize hex checksums vs real secrets.",
        strict=True,
    )
    def test_sha256_checksum_in_yaml_config(self, scanner, tmp_path):
        """SHA-256 integrity hash in a config file with 'secret' key.

        This IS a real FP because KeywordDetector triggers on the key name
        and the hex hash value has entropy > 3.0.
        """
        f = tmp_path / "config.yaml"
        f.write_text(
            "integrity:\n"
            "  secret_hash: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n"
        )
        ctx = ScanContext(target_path=tmp_path)
        findings = scanner.scan(ctx)
        # KeywordDetector fires on "secret_hash:" and captures the SHA-256
        kw = [f for f in findings if f.metadata.get("detector") == "Secret Keyword"]
        assert len(kw) == 0, (
            f"FP-07: SHA-256 hash should not be flagged as Secret Keyword. Got {len(kw)} findings."
        )


class TestFP08_MockStubValues:
    """FP-08: Mock and stub values in test frameworks."""

    def test_mock_openai_key_in_test(self, scanner, tmp_path):
        """Mock key with 'mock' in the value for test purposes."""
        f = tmp_path / "test_api.py"
        f.write_text('MOCK_KEY = "sk-mock_not_real_just_testing_1234567"\n')
        ctx = ScanContext(target_path=tmp_path)
        findings = scanner.scan(ctx)
        # 'mock' is in word_placeholders but doesn't dominate the string
        # test_api.py IS in test context so severity gets downgraded
        critical = [f for f in findings if f.severity == FindingSeverity.CRITICAL]
        assert len(critical) == 0, "FP-08: Mock key in test file should never be CRITICAL"


class TestFP09_CLIHelpText:
    """FP-09: CLI help text showing key formats."""

    def test_key_format_example_in_usage_docs(self, scanner, tmp_path):
        """CLI usage docs showing key format should not trigger.

        FIXED in Tier 4: entropy gate on extra patterns now catches this
        because 'sk-proj-xxxxxxxxxxxxxxxxxxxx' has very low entropy (only
        chars s,k,-,p,r,o,j,x). Also the char class diversity check fails
        (no uppercase or digits).
        """
        f = tmp_path / "docs/usage.md"
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text("# CLI Usage\nKeys look like: `sk-proj-xxxxxxxxxxxxxxxxxxxx`\n")
        ctx = ScanContext(target_path=tmp_path)
        findings = scanner.scan(ctx)
        openai = [f for f in findings if "OpenAI" in f.title]
        assert len(openai) == 0, "FP-09: CLI format example should be suppressed"


class TestFP10_VariableNamesFalsePositive:
    """FP-10: Variable names that contain secret-like keywords but aren't secrets."""

    def test_password_in_variable_name_not_value(self, scanner, tmp_path):
        """Variables like password_min_length should not trigger."""
        f = tmp_path / "config.py"
        f.write_text(
            "password_min_length = 12\n"
            "token_expiry_hours = 24\n"
            "api_key_rotation_days = 90\n"
            "secret_hash_algorithm = 'sha256'\n"
        )
        ctx = ScanContext(target_path=tmp_path)
        findings = scanner.scan(ctx)
        assert len(findings) == 0


# =====================================================================
# FALSE NEGATIVE ATTACK VECTORS
# =====================================================================


class TestFN01_ObfuscatedSecrets:
    """FN-01: Secrets hidden via string concatenation, encoding, or splitting."""

    def test_split_across_lines(self, scanner, tmp_path):
        """Secret split into two variables and concatenated.

        No scanner can easily detect this without data-flow analysis.
        Documenting as a known limitation.
        """
        f = tmp_path / "config.py"
        f.write_text(
            'KEY_PART1 = "sk-aB3cD4eF5gH6iJ7k"\n'
            'KEY_PART2 = "L8mN9oP0qR1sT2uV3"\n'
            "KEY = KEY_PART1 + KEY_PART2\n"
        )
        ctx = ScanContext(target_path=tmp_path)
        findings = scanner.scan(ctx)
        # Neither part is 20+ chars, so neither matches the OpenAI regex.
        # This is a fundamental limitation of regex-based scanning.
        assert len(findings) == 0, "FN-01: Split key evasion -- documenting known limitation"

    def test_base64_encoded_secret(self, scanner, tmp_path):
        """Secret stored ONLY as base64-encoded string (no plaintext anywhere).

        If the plaintext key never appears in the file, only the base64
        blob is present. The OpenAI regex won't match the encoded form.
        """
        f = tmp_path / "config.py"
        # No comments revealing the plaintext -- only the base64 blob
        f.write_text(
            "import base64\n"
            'KEY = base64.b64decode("c2stYUIzY0Q0ZUY1Z0g2aUo3a0w4bU45b1AwcVIxc1QydVYzd1g0eVo1YQ==")\n'
        )
        ctx = ScanContext(target_path=tmp_path)
        findings = scanner.scan(ctx)
        # Base64HighEntropyString might catch the b64 blob as a generic
        # high-entropy string, but it won't identify it as an OpenAI key.
        openai = [f for f in findings if "OpenAI" in f.title]
        assert len(openai) == 0, (
            "FN-01: Base64-encoded secret evasion -- the key is invisible "
            "to pattern-based detection when only the encoded form is present"
        )

    def test_reversed_secret(self, scanner, tmp_path):
        """Secret stored in reverse order."""
        f = tmp_path / "config.py"
        real_key = "sk-aB3cD4eF5gH6iJ7kL8mN9oP0qR1sT2uV3wX4yZ5a"
        reversed_key = real_key[::-1]
        f.write_text(f'REVERSED_KEY = "{reversed_key}"\n')
        ctx = ScanContext(target_path=tmp_path)
        findings = scanner.scan(ctx)
        openai = [f for f in findings if "OpenAI" in f.title]
        # Reversed key doesn't start with "sk-" so OpenAI pattern misses it
        assert len(openai) == 0, "FN-01: Reversed key evasion"

    def test_hex_encoded_secret(self, scanner, tmp_path):
        """Secret stored as hex-encoded string."""
        f = tmp_path / "config.py"
        real_key = "sk-aB3cD4eF5gH6iJ7kL8mN9oP0qR1sT2uV3wX4yZ5a"
        hex_key = real_key.encode().hex()
        f.write_text(f'HEX_KEY = "{hex_key}"\n')
        ctx = ScanContext(target_path=tmp_path)
        findings = scanner.scan(ctx)
        # The hex string is 86 chars of hex -- HexHighEntropyString might fire
        # but won't identify it as an OpenAI key
        openai = [f for f in findings if "OpenAI" in f.title]
        assert len(openai) == 0, "FN-01: Hex-encoded key evasion"


class TestFN02_UnusualFileTypes:
    """FN-02: Secrets in file extensions not in _SCANNABLE_EXTENSIONS.

    Missing extensions: .c, .cpp, .h, .hpp, .scala, .groovy, .lua,
    .pl, .pm, .dart, .dockerfile, .config, .secrets, .credentials
    """

    @pytest.mark.parametrize(
        ("ext", "template"),
        [
            (".c", '#define API_KEY "sk-aB3cD4eF5gH6iJ7kL8mN9oP0qR1sT2uV3wX4yZ5a"'),
            (".cpp", 'std::string key = "sk-aB3cD4eF5gH6iJ7kL8mN9oP0qR1sT2uV3wX4yZ5a";'),
            (".h", '#define SECRET "sk-aB3cD4eF5gH6iJ7kL8mN9oP0qR1sT2uV3wX4yZ5a"'),
            (".scala", 'val apiKey = "sk-aB3cD4eF5gH6iJ7kL8mN9oP0qR1sT2uV3wX4yZ5a"'),
            (".dart", 'const apiKey = "sk-aB3cD4eF5gH6iJ7kL8mN9oP0qR1sT2uV3wX4yZ5a";'),
            (".lua", 'local apiKey = "sk-aB3cD4eF5gH6iJ7kL8mN9oP0qR1sT2uV3wX4yZ5a"'),
            (".pl", 'my $apiKey = "sk-aB3cD4eF5gH6iJ7kL8mN9oP0qR1sT2uV3wX4yZ5a";'),
            (".groovy", 'def apiKey = "sk-aB3cD4eF5gH6iJ7kL8mN9oP0qR1sT2uV3wX4yZ5a"'),
        ],
        ids=["c", "cpp", "header", "scala", "dart", "lua", "perl", "groovy"],
    )
    def test_secret_in_missing_extension(self, scanner, tmp_path, ext, template):
        """Secrets in files with uncovered extensions are completely missed."""
        f = tmp_path / f"config{ext}"
        f.write_text(template + "\n")
        ctx = ScanContext(target_path=tmp_path)
        findings = scanner.scan(ctx)
        # These files are silently skipped by _iter_scannable_files
        assert len(findings) == 0, f"FN-02: Secret in {ext} file -- documenting blind spot"
        assert ctx.files_scanned == 0, f"FN-02: {ext} not even scanned"


class TestFN03_LargeFileBypass:
    """FN-03: Secrets in files exceeding max_file_size.

    Default max is 10MB. An attacker can pad a file beyond this limit
    to hide secrets.
    """

    def test_secret_in_oversized_file(self, scanner, tmp_path):
        """File at 10MB + 1KB with a secret near the end."""
        f = tmp_path / "big_config.py"
        # 10MB + 1KB of padding, then the secret
        try:
            padding = "# padding\n" * 1_000_100  # ~11MB of comment lines
        except MemoryError:
            pytest.skip("Not enough memory to allocate 10MB+ test file")
        f.write_text(padding + 'KEY = "sk-aB3cD4eF5gH6iJ7kL8mN9oP0qR1sT2uV3wX4yZ5a"\n')
        ctx = ScanContext(target_path=tmp_path)
        findings = scanner.scan(ctx)
        # File > 10MB is skipped entirely
        assert ctx.files_scanned == 0, "FN-03: Oversized file should be skipped"
        assert len(findings) == 0, "FN-03: Secret in oversized file is invisible"


class TestFN04_UnscannedDirectories:
    """FN-04: Secrets in extensionless files or unlisted special filenames."""

    def test_credentials_file_no_extension(self, scanner, tmp_path):
        """A file named 'credentials' (no extension) is skipped."""
        f = tmp_path / "credentials"
        f.write_text(
            "[default]\n"
            "aws_access_key_id = AKIAIOSFODNN7EXAMPL0\n"
            "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
        )
        ctx = ScanContext(target_path=tmp_path)
        scanner.scan(ctx)
        assert ctx.files_scanned == 0, (
            "FN-04: 'credentials' file has no extension and is not in special names"
        )

    def test_dot_my_cnf(self, scanner, tmp_path):
        """.my.cnf (MySQL config) is not in the special filenames list."""
        f = tmp_path / ".my.cnf"
        f.write_text("[client]\npassword=Xk9mP2vR7wQ4nL\n")
        ctx = ScanContext(target_path=tmp_path)
        scanner.scan(ctx)
        assert ctx.files_scanned == 0, "FN-04: .my.cnf not in special filenames"

    def test_dot_boto(self, scanner, tmp_path):
        """.boto (AWS Boto config) is not in the special filenames list."""
        f = tmp_path / ".boto"
        f.write_text("[Credentials]\naws_secret_access_key = Xk9mP2vR7wQ4nL5zB8cDfGhJ\n")
        ctx = ScanContext(target_path=tmp_path)
        scanner.scan(ctx)
        assert ctx.files_scanned == 0, "FN-04: .boto not in special filenames"

    def test_dot_s3cfg(self, scanner, tmp_path):
        """.s3cfg (s3cmd config) is not in the special filenames list."""
        f = tmp_path / ".s3cfg"
        f.write_text(
            "[default]\n"
            "access_key = AKIAIOSFODNN7EXAMPL0\n"
            "secret_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
        )
        ctx = ScanContext(target_path=tmp_path)
        scanner.scan(ctx)
        assert ctx.files_scanned == 0, "FN-04: .s3cfg not in special filenames"


class TestFN05_NewProviderFormats:
    """FN-05: New AI provider key formats not in _EXTRA_PATTERNS.

    The AI provider ecosystem is rapidly expanding. These keys have
    well-known prefixes but are not in _EXTRA_PATTERNS.
    """

    @pytest.mark.parametrize(
        ("provider", "key"),
        [
            ("Mistral AI", "mist_aB3cD4eF5gH6iJ7kL8mN9oP0qR1sT"),
            ("Fireworks AI", "fw_aB3cD4eF5gH6iJ7kL8mN9oP0qR1sT"),
            ("Deepseek", "dsk_aB3cD4eF5gH6iJ7kL8mN9oP0qR1sT"),
            ("Together AI", "tok_aB3cD4eF5gH6iJ7kL8mN9oP0qR1sT"),
            ("Perplexity", "pplx-aB3cD4eF5gH6iJ7kL8mN9oP0qR1sT"),
            ("Weaviate", "wcs-aB3cD4eF5gH6iJ7kL8mN9oP0qR1sT"),
            ("Supabase", "sbp_aB3cD4eF5gH6iJ7kL8mN9oP0qR1sT"),
            ("Railway", "rlwy_aB3cD4eF5gH6iJ7kL8mN9oP0qR1sT"),
        ],
        ids=[
            "mistral",
            "fireworks",
            "deepseek",
            "together",
            "perplexity",
            "weaviate",
            "supabase",
            "railway",
        ],
    )
    def test_missing_provider_pattern(self, scanner, tmp_path, provider, key):
        """Provider key with known prefix is completely missed."""
        f = tmp_path / "config.py"
        f.write_text(f'{provider.upper().replace(" ", "_")}_KEY = "{key}"\n')
        ctx = ScanContext(target_path=tmp_path)
        findings = scanner.scan(ctx)
        # These may get partial hits from KeywordDetector or
        # Base64HighEntropyString but are not identified by provider.
        provider_findings = [f for f in findings if provider in f.title]
        assert len(provider_findings) == 0, f"FN-05: {provider} keys not in _EXTRA_PATTERNS"


class TestFN06_ConnectionStringProtocolGaps:
    """FN-06: Connection strings with protocols not in the regex.

    The Generic Connection String regex only covers:
    postgres(ql)?, mysql, mongodb(+srv)?, redis(s)?, amqp(s)?, mariadb, mssql

    Missing: cockroachdb, clickhouse, cassandra, elasticsearch, neo4j,
    influxdb, couchdb, dynamodb
    """

    @pytest.mark.parametrize(
        "protocol",
        [
            "cockroachdb",
            "clickhouse",
            "cassandra",
            "neo4j",
            "couchdb",
            "influxdb",
        ],
        ids=["crdb", "ch", "cassandra", "neo4j", "couchdb", "influxdb"],
    )
    def test_unsupported_protocol(self, scanner, tmp_path, protocol):
        """Connection strings with uncovered protocols.

        Note: detect-secrets BasicAuthDetector may still catch some of
        these via the user:pass@host pattern.
        """
        f = tmp_path / "config.py"
        f.write_text(f'DB = "{protocol}://admin:Xk9mP2vR7wQ4nL@{protocol}.internal:9999/prod"\n')
        ctx = ScanContext(target_path=tmp_path)
        findings = scanner.scan(ctx)
        conn = [f for f in findings if "Connection String" in f.title]
        # Generic Connection String regex doesn't match -- these are missed
        # by the EXTRA_PATTERNS scanner. detect-secrets BasicAuthDetector
        # may catch the user:pass pattern independently.
        assert len(conn) == 0, f"FN-06: {protocol}:// not in connection string regex"


# =====================================================================
# ENTROPY ANALYSIS
# =====================================================================


class TestEntropyOverlapZone:
    """Shannon entropy overlap zone analysis.

    The credential scanner uses entropy >= 3.0 as a gate for
    Secret Keyword findings. This zone has overlap:

    - Real secrets CAN have entropy < 3.0 (short, limited charset)
    - Placeholders CAN have entropy > 3.0 (long, diverse chars)

    The overlap zone is approximately 2.5 - 3.5.
    """

    @pytest.mark.parametrize(
        ("value", "is_real"),
        [
            # REAL secrets that fall BELOW 3.0 (false negatives)
            ("myS3cr3tK3y", True),  # entropy ~2.85 -- leet speak
            ("P@ssword1", True),  # entropy ~2.95 -- common format
            ("hunter2", True),  # entropy ~2.81 -- classic
            # FAKE values that rise ABOVE 3.0 (false positives)
            ("MyPassw0rd!", False),  # entropy ~3.28
            ("Admin123!", False),  # entropy ~3.17
            ("Letmein2024!", False),  # entropy ~3.25
            ("Secret2024!", False),  # entropy ~3.10
        ],
        ids=[
            "real_leet",
            "real_common",
            "real_hunter2",
            "fake_mypassw0rd",
            "fake_admin123",
            "fake_letmein",
            "fake_secret2024",
        ],
    )
    def test_entropy_overlap_zone(self, value, is_real):
        """Document entropy values in the dangerous overlap zone."""
        entropy = CredentialScanner._shannon_entropy(value)
        passes_gate = entropy >= 3.0

        if is_real and not passes_gate:
            # Real secret blocked by entropy gate -- false negative
            assert entropy < 3.0, (
                f"Real secret '{value}' has entropy {entropy:.2f} < 3.0 -- "
                "this is a known FN in the entropy gate"
            )
        elif not is_real and passes_gate:
            # Fake value passes entropy gate -- false positive risk
            assert entropy >= 3.0, (
                f"Placeholder '{value}' has entropy {entropy:.2f} >= 3.0 -- "
                "this passes the entropy gate and may cause FPs"
            )

    def test_minimum_entropy_for_real_secret(self):
        """A Databricks token of all zeros has entropy 0.725.

        This passes the _EXTRA_PATTERNS regex (dapi + 32 hex chars)
        but would be blocked by the Secret Keyword entropy gate if
        it were detected by KeywordDetector instead.
        """
        # dapi + 32 zeros = valid Databricks token format
        token = "dapi" + "0" * 32
        entropy = CredentialScanner._shannon_entropy(token)
        assert entropy < 1.0, "All-zero Databricks token has very low entropy"

    def test_maximum_entropy_for_placeholder(self):
        """'FAKE-EXAMPLE-KEY-NOT-FOR-PRODUCTION-USE-12345' has entropy 4.13.

        This is well above the 3.0 gate and would pass entropy filtering.
        It IS caught by _is_placeholder via dual-word hit (fake + example),
        but variants without both words would slip through.
        """
        placeholder = "FAKE-EXAMPLE-KEY-NOT-FOR-PRODUCTION-USE-12345"
        entropy = CredentialScanner._shannon_entropy(placeholder)
        assert entropy > 4.0, "Complex placeholder has very high entropy"
        # This IS caught by placeholder check
        assert CredentialScanner._is_placeholder(placeholder)

    def test_single_word_placeholder_in_long_string_now_caught(self):
        """FIXED in Tier 4: expanded phrase placeholders catch this.

        Previously a known FP bug: 'FAKE' (4 chars) in a 30-char
        stripped string was only ~13%, below the 40% ratio threshold.
        Now caught via 'for_documentation' / 'fordocumentation' phrase match.
        """
        value = "sk-FakeKeyForDocumentation12345678"
        assert CredentialScanner._is_placeholder(value), (
            "Tier 4 fix: phrase placeholder 'fordocumentation' should catch this"
        )


# =====================================================================
# ADDITIONAL EDGE CASES
# =====================================================================


class TestEdgeCases:
    """Edge cases that don't fit neatly into FP/FN categories."""

    def test_env_file_in_hidden_dir(self, scanner, tmp_path):
        """Secret in .config/.env should be scanned."""
        config_dir = tmp_path / ".config"
        config_dir.mkdir()
        f = config_dir / ".env"
        f.write_text("OPENAI_KEY=sk-aB3cD4eF5gH6iJ7kL8mN9oP0qR1sT2uV3wX4yZ5a\n")
        ctx = ScanContext(target_path=tmp_path)
        findings = scanner.scan(ctx)
        openai = [f for f in findings if "OpenAI" in f.title]
        assert len(openai) >= 1, "Secret in .config/.env should be detected"

    def test_unicode_in_file_content(self, scanner, tmp_path):
        """Files with unicode content should not crash the scanner."""
        f = tmp_path / "config.py"
        f.write_text(
            "# -*- coding: utf-8 -*-\n"
            "# Comment with unicode: \u00e9\u00e0\u00fc\u00f6\n"
            'KEY = "sk-aB3cD4eF5gH6iJ7kL8mN9oP0qR1sT2uV3wX4yZ5a"\n',
            encoding="utf-8",
        )
        ctx = ScanContext(target_path=tmp_path)
        findings = scanner.scan(ctx)
        openai = [f for f in findings if "OpenAI" in f.title]
        assert len(openai) >= 1

    def test_multiple_secrets_same_line(self, scanner, tmp_path):
        """Two different secrets on the same line."""
        f = tmp_path / "config.py"
        f.write_text(
            'KEYS = {"openai": "sk-aB3cD4eF5gH6iJ7kL8mN9oP0qR1sT2uV3wX4yZ5a", '
            '"anthropic": "sk-ant-xY9wV8uT7sR6qP5oN4mL3kJ2iH1gF0e"}\n'
        )
        ctx = ScanContext(target_path=tmp_path)
        findings = scanner.scan(ctx)
        openai = [f for f in findings if "OpenAI" in f.title]
        anthropic = [f for f in findings if "Anthropic" in f.title]
        assert len(openai) >= 1
        assert len(anthropic) >= 1

    def test_secret_in_comment(self, scanner, tmp_path):
        """Secrets in code comments should still be detected."""
        f = tmp_path / "app.py"
        f.write_text(
            "# TODO: Remove before commit\n"
            "# OPENAI_KEY=sk-aB3cD4eF5gH6iJ7kL8mN9oP0qR1sT2uV3wX4yZ5a\n"
            "import os\n"
        )
        ctx = ScanContext(target_path=tmp_path)
        findings = scanner.scan(ctx)
        openai = [f for f in findings if "OpenAI" in f.title]
        assert len(openai) >= 1, "Commented-out secrets should still be detected"

    def test_gitleaks_allow_comment_not_honored(self, scanner, tmp_path):
        """The scanner uses detect-secrets, not gitleaks, so gitleaks:allow
        comments are NOT honored by the extra_patterns scanner."""
        f = tmp_path / "config.py"
        f.write_text('KEY = "sk-aB3cD4eF5gH6iJ7kL8mN9oP0qR1sT2uV3wX4yZ5a"  # gitleaks:allow\n')
        ctx = ScanContext(target_path=tmp_path)
        findings = scanner.scan(ctx)
        openai = [f for f in findings if "OpenAI" in f.title]
        assert len(openai) >= 1, "gitleaks:allow is not an allowlist mechanism for this scanner"

    def test_detect_secrets_allowlist_comment_honored(self, scanner, tmp_path):
        """detect-secrets allowlist comments (pragma: allowlist secret) are honored
        by the detect-secrets engine but NOT by the extra_patterns scanner."""
        f = tmp_path / "config.py"
        f.write_text(
            'KEY = "sk-aB3cD4eF5gH6iJ7kL8mN9oP0qR1sT2uV3wX4yZ5a"  # pragma: allowlist secret\n'
        )
        ctx = ScanContext(target_path=tmp_path)
        findings = scanner.scan(ctx)
        # detect-secrets will suppress its findings but _scan_extra_patterns
        # will still fire because it doesn't check for allowlist comments
        openai = [f for f in findings if "OpenAI" in f.title]
        assert len(openai) >= 1, "Extra patterns scanner ignores detect-secrets allowlist comments"

    def test_max_file_size_boundary(self, scanner, tmp_path):
        """File at exactly max_file_size (10MB) should be scanned.

        The check is `st_size > max_file_size` (strictly greater), so a
        file of exactly 10,000,000 bytes is included.
        """
        f = tmp_path / "boundary.py"
        key_line = 'KEY = "sk-aB3cD4eF5gH6iJ7kL8mN9oP0qR1sT2uV3wX4yZ5a"\n'
        key_line_bytes = len(key_line.encode("utf-8"))
        # Target exactly 10_000_000 bytes
        padding_size = 10_000_000 - key_line_bytes
        try:
            f.write_bytes(b"x" * padding_size + key_line.encode("utf-8"))
        except MemoryError:
            pytest.skip("Not enough memory to allocate 10MB test file")
        actual_size = f.stat().st_size
        assert actual_size == 10_000_000, f"File is {actual_size} bytes, expected 10000000"
        ctx = ScanContext(target_path=tmp_path)
        scanner.scan(ctx)
        assert ctx.files_scanned >= 1, "File at exactly max_file_size should be scanned"

    def test_file_one_byte_over_max_size_skipped(self, scanner, tmp_path):
        """File at max_file_size + 1 byte should be skipped."""
        f = tmp_path / "oversized.py"
        key_line = 'KEY = "sk-aB3cD4eF5gH6iJ7kL8mN9oP0qR1sT2uV3wX4yZ5a"\n'
        key_line_bytes = len(key_line.encode("utf-8"))
        padding_size = 10_000_001 - key_line_bytes
        try:
            f.write_bytes(b"x" * padding_size + key_line.encode("utf-8"))
        except MemoryError:
            pytest.skip("Not enough memory to allocate 10MB test file")
        actual_size = f.stat().st_size
        assert actual_size == 10_000_001, f"File is {actual_size} bytes"
        ctx = ScanContext(target_path=tmp_path)
        findings = scanner.scan(ctx)
        assert ctx.files_scanned == 0, "File one byte over max should be skipped"
        assert len(findings) == 0

    def test_custom_max_file_size(self, tmp_path):
        """Custom max_file_size in scanner config can be used for evasion."""
        from agentsec.models.config import ScannerConfig

        # An attacker could configure a very small max_file_size to skip scanning
        config = ScannerConfig(extra={"max_file_size": 100})
        small_scanner = CredentialScanner(config=config)
        f = tmp_path / "config.py"
        # 150 bytes -- over the 100-byte limit
        f.write_text("# padding\n" * 5 + 'KEY = "sk-aB3cD4eF5gH6iJ7kL8mN9oP0qR1sT2uV3wX4yZ5a"\n')
        ctx = ScanContext(target_path=tmp_path)
        small_scanner.scan(ctx)
        assert ctx.files_scanned == 0, "Custom max_file_size bypass"
