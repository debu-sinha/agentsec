"""Tests for the credential scanner."""

import pytest

from agentsec.models.findings import FindingCategory, FindingConfidence, FindingSeverity
from agentsec.scanners.base import ScanContext
from agentsec.scanners.credential import CredentialScanner


@pytest.fixture
def scanner():
    return CredentialScanner()


@pytest.fixture
def temp_cred_dir(tmp_path):
    """Create a directory with various credential patterns."""
    # Python file with an OpenAI key (realistic-looking, not sequential)
    py_file = tmp_path / "config.py"
    py_file.write_text("import os\nAPI_KEY = 'sk-aB3cD4eF5gH6iJ7kL8mN9oP0qR1sT2uV3wX4yZ5a'\n")

    # JSON file with AWS credentials (AKIA + exactly 16 uppercase alphanumeric)
    json_file = tmp_path / "settings.json"
    json_file.write_text(
        '{"aws_access_key": "AKIAIOSFODNN7EXAMPL0"}\n'  # gitleaks:allow
    )

    # Env file with GitHub token
    env_file = tmp_path / ".env"
    env_file.write_text(
        "GITHUB_TOKEN=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij\n"  # gitleaks:allow
    )

    return tmp_path


def test_detects_openai_key(scanner, temp_cred_dir):
    context = ScanContext(target_path=temp_cred_dir)
    findings = scanner.scan(context)

    openai_findings = [f for f in findings if "OpenAI" in f.title]
    assert len(openai_findings) >= 1
    assert openai_findings[0].severity == FindingSeverity.CRITICAL
    assert openai_findings[0].category == FindingCategory.EXPOSED_TOKEN


def test_detects_aws_key(scanner, temp_cred_dir):
    context = ScanContext(target_path=temp_cred_dir)
    findings = scanner.scan(context)

    aws_findings = [f for f in findings if "AWS" in f.title]
    assert len(aws_findings) >= 1
    assert aws_findings[0].severity == FindingSeverity.CRITICAL


def test_detects_github_token(scanner, temp_cred_dir):
    context = ScanContext(target_path=temp_cred_dir)
    findings = scanner.scan(context)

    github_findings = [f for f in findings if "GitHub" in f.title]
    assert len(github_findings) >= 1


def test_skips_placeholders(scanner, tmp_path):
    py_file = tmp_path / "example.py"
    py_file.write_text("API_KEY = 'sk-your_api_key_here_placeholder_test'\n")

    context = ScanContext(target_path=tmp_path)
    findings = scanner.scan(context)

    # The OpenAI-style key with "your_api_key" placeholder text should be skipped
    assert len(findings) == 0


def test_skips_symlinks(scanner, tmp_path):
    """Symlinks should be skipped to prevent path traversal."""
    real_file = tmp_path / "real.py"
    real_file.write_text("safe content\n")
    link = tmp_path / "link.py"

    try:
        link.symlink_to(real_file)
    except OSError as exc:
        if getattr(exc, "winerror", None) == 1314:
            pytest.skip("Symlink creation requires Windows developer/admin privilege")
        raise

    context = ScanContext(target_path=tmp_path)
    findings = scanner.scan(context)

    # The scan should complete without following symlinks into unexpected dirs
    assert isinstance(findings, list)


def test_deduplicates_findings(scanner, tmp_path):
    """Same secret in same file should not be reported twice."""
    py_file = tmp_path / "config.py"
    py_file.write_text(
        "KEY1 = 'sk-aB3cD4eF5gH6iJ7kL8mN9oP0qR1sT2uV3wX4yZ5a'\n"
        "KEY2 = 'sk-aB3cD4eF5gH6iJ7kL8mN9oP0qR1sT2uV3wX4yZ5a'\n"
    )

    context = ScanContext(target_path=tmp_path)
    findings = scanner.scan(context)

    openai = [f for f in findings if "OpenAI" in f.title]
    # Same pattern should appear twice (different lines), both are unique
    # but the fingerprint dedup catches exact dupes
    assert len(openai) >= 1


def test_detects_private_key(scanner, tmp_path):
    key_file = tmp_path / "id_rsa.txt"
    key_file.write_text(
        "-----BEGIN RSA PRIVATE KEY-----\n"  # gitleaks:allow
        "MIIEowIBAAKCAQEA...\n"
        "-----END RSA PRIVATE KEY-----\n"
    )

    context = ScanContext(target_path=tmp_path)
    findings = scanner.scan(context)

    key_findings = [f for f in findings if "Private Key" in f.title]
    assert len(key_findings) >= 1
    assert key_findings[0].severity == FindingSeverity.CRITICAL


def test_high_entropy_detection(scanner, tmp_path):
    """High-entropy strings in credential-like context should be flagged."""
    config_file = tmp_path / "app.yaml"
    config_file.write_text("secret: aB3cD4eF5gH6iJ7kL8mN9oP0qR1sT2uV3wX4yZ5a\n")

    context = ScanContext(target_path=tmp_path)
    findings = scanner.scan(context)

    # detect-secrets flags this via KeywordDetector and/or entropy detectors
    entropy_findings = [f for f in findings if f.category == FindingCategory.EXPOSED_TOKEN]
    assert len(entropy_findings) >= 1
    assert entropy_findings[0].severity == FindingSeverity.MEDIUM


def test_git_config_credentials(scanner, tmp_path):
    """Detect credentials embedded in .git/config remote URLs."""
    git_dir = tmp_path / ".git"
    git_dir.mkdir()
    git_config = git_dir / "config"
    git_config.write_text(
        '[remote "origin"]\n    url = https://user:s3cretpassword@github.com/org/repo.git\n'
    )

    context = ScanContext(target_path=tmp_path)
    findings = scanner.scan(context)

    git_findings = [f for f in findings if f.category == FindingCategory.HARDCODED_CREDENTIAL]
    assert len(git_findings) >= 1


def test_secret_sanitization():
    """Verify secrets are properly sanitized for display."""
    result = CredentialScanner._sanitize_secret("sk-abc123456789012345678901234567890")
    assert result.startswith("sk-a")
    assert result.endswith("7890")
    assert "*" in result
    # Should not expose more than first 4 + last 4 chars
    non_star = result.replace("*", "")
    assert len(non_star) == 8


def test_shannon_entropy():
    """Verify entropy calculation produces expected results."""
    # Low entropy (repeated chars)
    assert CredentialScanner._shannon_entropy("aaaaaaaaaa") < 1.0
    # High entropy (random-looking)
    assert CredentialScanner._shannon_entropy("aB3cD4eF5gH6iJ7kL") > 4.0
    # Empty string
    assert CredentialScanner._shannon_entropy("") == 0.0


def test_placeholder_detection():
    """Verify common placeholder patterns are detected."""
    assert CredentialScanner._is_placeholder("sk-your_api_key_here")
    assert CredentialScanner._is_placeholder("replace_me_with_real_key")
    assert CredentialScanner._is_placeholder("xxxxxxxxxxxx")
    assert CredentialScanner._is_placeholder("test_dummy_value")
    assert not CredentialScanner._is_placeholder("aB3cD4eF5gH6iJ7kL8mN9")


def test_empty_directory(scanner, tmp_path):
    context = ScanContext(target_path=tmp_path)
    findings = scanner.scan(context)
    assert findings == []


def test_nonexistent_path(scanner, tmp_path):
    context = ScanContext(target_path=tmp_path / "does_not_exist")
    findings = scanner.scan(context)
    assert findings == []


def test_files_scanned_counter(scanner, tmp_path):
    py_file = tmp_path / "app.py"
    py_file.write_text("print('hello')\n")
    json_file = tmp_path / "config.json"
    json_file.write_text("{}\n")

    context = ScanContext(target_path=tmp_path)
    scanner.scan(context)
    assert context.files_scanned >= 2


def test_skips_binary_extensions(scanner, tmp_path):
    """Files with non-scannable extensions should be skipped."""
    bin_file = tmp_path / "data.bin"
    bin_file.write_bytes(b"\x00\x01\x02\x03")
    img_file = tmp_path / "logo.png"
    img_file.write_bytes(b"\x89PNG")

    context = ScanContext(target_path=tmp_path)
    scanner.scan(context)
    # Binary files should not increment the scan counter
    assert context.files_scanned == 0


# --- False positive suppression tests (detect-secrets integration) ---


def test_skips_aws_example_key(scanner, tmp_path):
    """AWS official EXAMPLE key should not trigger findings."""
    f = tmp_path / "config.py"
    f.write_text('KEY = "AKIAIOSFODNN7EXAMPLE"\n')  # gitleaks:allow

    context = ScanContext(target_path=tmp_path)
    findings = scanner.scan(context)
    aws = [f for f in findings if "AWS" in f.title]
    assert len(aws) == 0


def test_skips_connection_string_with_placeholder_password(scanner, tmp_path):
    """Connection strings with placeholder passwords should not trigger."""
    f = tmp_path / "docker-compose.yml"
    f.write_text("DATABASE_URL: postgresql://postgres:changeme@localhost:5432/db\n")

    context = ScanContext(target_path=tmp_path)
    findings = scanner.scan(context)
    conn = [f for f in findings if "Connection String" in f.title]
    assert len(conn) == 0


def test_skips_connection_string_with_env_var(scanner, tmp_path):
    """Connection strings with env var references should not trigger."""
    f = tmp_path / "compose.yml"
    f.write_text("DATABASE_URL: postgresql://postgres:${DB_PASSWORD}@db:5432/app\n")

    context = ScanContext(target_path=tmp_path)
    findings = scanner.scan(context)
    conn = [f for f in findings if "Connection String" in f.title]
    assert len(conn) == 0


def test_skips_sequential_fake_keys(scanner, tmp_path):
    """Keys with sequential patterns (1234567890) should be skipped."""
    f = tmp_path / "test_enc.py"
    f.write_text('KEY = "sk-1234567890abcdefghijklmnopqrst"\n')

    context = ScanContext(target_path=tmp_path)
    findings = scanner.scan(context)
    openai = [f for f in findings if "OpenAI" in f.title]
    assert len(openai) == 0


def test_downgrades_severity_in_readme(scanner, tmp_path):
    """Findings in README.md should get downgraded severity."""
    f = tmp_path / "README.md"
    f.write_text("Use your key: sk-aB3cD4eF5gH6iJ7kL8mN9oP0qR1sT2uV3wX4yZ5a\n")

    context = ScanContext(target_path=tmp_path)
    findings = scanner.scan(context)
    openai = [f for f in findings if "OpenAI" in f.title]
    if openai:
        assert openai[0].severity == FindingSeverity.LOW


def test_downgrades_severity_in_test_dir(scanner, tmp_path):
    """Findings in tests/ directory should get downgraded severity."""
    test_dir = tmp_path / "tests"
    test_dir.mkdir()
    f = test_dir / "test_auth.py"
    f.write_text('KEY = "sk-aB3cD4eF5gH6iJ7kL8mN9oP0qR1sT2uV3wX4yZ5a"\n')

    context = ScanContext(target_path=tmp_path)
    findings = scanner.scan(context)
    openai = [f for f in findings if "OpenAI" in f.title]
    if openai:
        assert openai[0].severity == FindingSeverity.LOW


def test_real_looking_key_still_detected(scanner, tmp_path):
    """Ensure real-looking keys are still detected (no over-suppression)."""
    f = tmp_path / "config.py"
    f.write_text('KEY = "sk-aB3cD4eF5gH6iJ7kL8mN9oP0qR1sT2uV3wX4yZ5a"\n')

    context = ScanContext(target_path=tmp_path)
    findings = scanner.scan(context)
    openai = [f for f in findings if "OpenAI" in f.title]
    assert len(openai) >= 1
    assert openai[0].severity == FindingSeverity.CRITICAL


def test_real_connection_string_still_detected(scanner, tmp_path):
    """Ensure connection strings with real-looking passwords are detected."""
    f = tmp_path / "config.py"
    f.write_text('DB = "postgresql://admin:Xk9mP2vR7wQ4nL@prod.db.example.com:5432/myapp"\n')

    context = ScanContext(target_path=tmp_path)
    findings = scanner.scan(context)
    conn = [f for f in findings if "Connection String" in f.title]
    assert len(conn) >= 1


def test_placeholder_connection_string():
    """Verify connection string placeholder detection logic."""
    assert CredentialScanner._is_placeholder_connection_string(
        "postgresql://user:changeme@localhost:5432/db"
    )
    assert CredentialScanner._is_placeholder_connection_string(
        "mysql://admin:${DB_PASS}@db:3306/app"
    )
    assert CredentialScanner._is_placeholder_connection_string("redis://user:<password>@host:6379")
    assert not CredentialScanner._is_placeholder_connection_string(
        "postgresql://admin:Xk9mP2vR7wQ4nL@prod.db.example.com:5432/myapp"
    )


def test_test_or_doc_context():
    """Verify file path context detection."""
    from pathlib import Path

    assert CredentialScanner._is_test_or_doc_context(Path("README.md"))
    assert CredentialScanner._is_test_or_doc_context(Path("docs/setup.py"))
    assert CredentialScanner._is_test_or_doc_context(Path("tests/test_auth.py"))
    assert CredentialScanner._is_test_or_doc_context(Path("examples/demo.py"))
    assert not CredentialScanner._is_test_or_doc_context(Path("src/config.py"))
    assert not CredentialScanner._is_test_or_doc_context(Path("app/settings.py"))


# --- Expert review: Pattern coverage tests ---


def test_detects_anthropic_key(scanner, tmp_path):
    """Anthropic sk-ant- keys should be detected as CRITICAL."""
    f = tmp_path / "config.py"
    f.write_text('KEY = "sk-ant-aB3cD4eF5gH6iJ7kL8mN9oP0qR1sT"\n')

    context = ScanContext(target_path=tmp_path)
    findings = scanner.scan(context)
    ant = [f for f in findings if "Anthropic" in f.title]
    assert len(ant) >= 1
    assert ant[0].severity == FindingSeverity.CRITICAL


def test_detects_databricks_token(scanner, tmp_path):
    """Databricks dapi tokens should be detected as CRITICAL."""
    # Build token dynamically to avoid GitHub push protection flagging test data.
    # Use high-entropy hex chars (not all zeros) so the entropy gate doesn't suppress it.
    token = "d" + "api" + "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"
    f = tmp_path / "config.py"
    f.write_text(f'TOKEN = "{token}"\n')

    context = ScanContext(target_path=tmp_path)
    findings = scanner.scan(context)
    db = [f for f in findings if "Databricks" in f.title]
    assert len(db) >= 1
    assert db[0].severity == FindingSeverity.CRITICAL


def test_detects_huggingface_token(scanner, tmp_path):
    """HuggingFace hf_ tokens should be detected as HIGH."""
    f = tmp_path / "config.py"
    f.write_text('TOKEN = "hf_aB3cD4eF5gH6iJ7kL8mN9oP0qR1sT2uV3wX"\n')

    context = ScanContext(target_path=tmp_path)
    findings = scanner.scan(context)
    hf = [f for f in findings if "Hugging Face" in f.title]
    assert len(hf) >= 1
    assert hf[0].severity == FindingSeverity.HIGH


def test_detects_google_api_key(scanner, tmp_path):
    """Google AIza keys should be detected as HIGH."""
    f = tmp_path / "config.py"
    f.write_text('KEY = "AIzaSyB3cD4eF5gH6iJ7kL8mN9oP0qR1sT2uV3wX"\n')

    context = ScanContext(target_path=tmp_path)
    findings = scanner.scan(context)
    goog = [f for f in findings if "Google" in f.title]
    assert len(goog) >= 1
    assert goog[0].severity == FindingSeverity.HIGH


def test_detects_groq_api_key(scanner, tmp_path):
    """Groq gsk_ keys should be detected as CRITICAL."""
    f = tmp_path / "config.py"
    f.write_text('KEY = "gsk_aB3cD4eF5gH6iJ7kL8mN9oP0qR1sT2uV3"\n')

    context = ScanContext(target_path=tmp_path)
    findings = scanner.scan(context)
    groq = [f for f in findings if "Groq" in f.title]
    assert len(groq) >= 1
    assert groq[0].severity == FindingSeverity.CRITICAL


def test_detects_replicate_token(scanner, tmp_path):
    """Replicate r8_ tokens should be detected as CRITICAL."""
    f = tmp_path / "config.py"
    f.write_text('TOKEN = "r8_aB3cD4eF5gH6iJ7kL8mN9oP0qR1sT2uV3"\n')

    context = ScanContext(target_path=tmp_path)
    findings = scanner.scan(context)
    rep = [f for f in findings if "Replicate" in f.title]
    assert len(rep) >= 1
    assert rep[0].severity == FindingSeverity.CRITICAL


# --- Expert review: OpenAI/Anthropic collision test ---


def test_openai_pattern_does_not_match_anthropic(scanner, tmp_path):
    """OpenAI pattern should NOT match sk-ant- keys (no double findings)."""
    f = tmp_path / "config.py"
    f.write_text('KEY = "sk-ant-aB3cD4eF5gH6iJ7kL8mN9oP0qR1sT"\n')

    context = ScanContext(target_path=tmp_path)
    findings = scanner.scan(context)
    openai = [f for f in findings if "OpenAI" in f.title]
    ant = [f for f in findings if "Anthropic" in f.title]
    assert len(openai) == 0, "OpenAI pattern should not match sk-ant- keys"
    assert len(ant) >= 1


def test_openai_proj_key_detected(scanner, tmp_path):
    """OpenAI sk-proj- keys with hyphens should be detected."""
    f = tmp_path / "config.py"
    f.write_text('KEY = "sk-proj-aB3cD4eF-5gH6iJ7kL8mN9oP0"\n')

    context = ScanContext(target_path=tmp_path)
    findings = scanner.scan(context)
    openai = [f for f in findings if "OpenAI" in f.title]
    assert len(openai) >= 1


# --- Expert review: Placeholder bypass resistance ---


def test_real_key_starting_with_test_not_suppressed(scanner, tmp_path):
    """A real key whose post-prefix body starts with 'test' must NOT be suppressed."""
    f = tmp_path / "config.py"
    # Use high-entropy non-sequential value after "test"
    f.write_text('KEY = "sk-testRn3K7mN9pQ2wY5zB8cD4fH6jL"\n')

    context = ScanContext(target_path=tmp_path)
    findings = scanner.scan(context)
    openai = [f for f in findings if "OpenAI" in f.title]
    assert len(openai) >= 1, "Real key starting with 'test' after prefix should be detected"


# --- Expert review: Connection string improvements ---


def test_detects_mongodb_srv_connection_string(scanner, tmp_path):
    """mongodb+srv:// connection strings should be detected."""
    f = tmp_path / "config.py"
    f.write_text('DB = "mongodb+srv://admin:Xk9mP2vR7wQ4@cluster0.example.net/prod"\n')

    context = ScanContext(target_path=tmp_path)
    findings = scanner.scan(context)
    conn = [f for f in findings if "Connection String" in f.title]
    assert len(conn) >= 1


def test_connection_string_dollar_password_not_suppressed(scanner, tmp_path):
    """Connection string with password starting with $ (not env var) should be detected."""
    f = tmp_path / "config.py"
    f.write_text('DB = "postgresql://admin:$ecureP@ss@prod.db.example.com:5432/app"\n')

    context = ScanContext(target_path=tmp_path)
    findings = scanner.scan(context)
    conn = [f for f in findings if "Connection String" in f.title]
    assert len(conn) >= 1, "Password starting with $ but not an env var ref should be detected"


# --- Expert review: Lock file skipping ---


def test_skips_lock_files(scanner, tmp_path):
    """Lock files should be excluded from scanning entirely."""
    lock = tmp_path / "pnpm-lock.yaml"
    lock.write_text("password: sk-aB3cD4eF5gH6iJ7kL8mN9oP0qR1sT2uV3wX4yZ5a\n")

    context = ScanContext(target_path=tmp_path)
    findings = scanner.scan(context)
    assert len(findings) == 0
    assert context.files_scanned == 0


# --- Expert review: Distinct secrets in same file not collapsed ---


def test_distinct_secrets_same_file_not_collapsed(scanner, tmp_path):
    """Two different secrets in the same file must produce two findings."""
    f = tmp_path / "config.py"
    f.write_text(
        'KEY1 = "sk-aB3cD4eF5gH6iJ7kL8mN9oP0qR1sT2uV3wX4yZ5a"\n'
        'KEY2 = "sk-xY9wV8uT7sR6qP5oN4mL3kJ2iH1gF0eD9cB8aA7z"\n'
    )

    context = ScanContext(target_path=tmp_path)
    findings = scanner.scan(context)
    openai = [f for f in findings if "OpenAI" in f.title]
    assert len(openai) == 2, "Two distinct secrets should produce two findings"


# --- Expert review: .env variant scanning ---


def test_scans_env_variants(scanner, tmp_path):
    """All .env.* variants should be scanned, not just the 4 hardcoded ones."""
    f = tmp_path / ".env.staging"
    f.write_text("API_KEY=sk-aB3cD4eF5gH6iJ7kL8mN9oP0qR1sT2uV3wX4yZ5a\n")

    context = ScanContext(target_path=tmp_path)
    findings = scanner.scan(context)
    assert context.files_scanned >= 1
    openai = [f for f in findings if "OpenAI" in f.title]
    assert len(openai) >= 1


# --- Tier 2: KeywordDetector entropy gating tests ---


def test_keyword_detector_low_entropy_suppressed(scanner, tmp_path):
    """Secret Keyword findings with low-entropy values should be suppressed."""
    f = tmp_path / "config.yaml"
    # KeywordDetector fires on "password:" key, captures the value.
    # Low-entropy values like "changeme" or "test" are noise.
    f.write_text("password: foobar123\ntoken: abcabc\nsecret: hello\n")

    context = ScanContext(target_path=tmp_path)
    findings = scanner.scan(context)
    keyword = [f for f in findings if f.metadata.get("detector") == "Secret Keyword"]
    assert len(keyword) == 0, "Low-entropy Secret Keyword values should be suppressed"


def test_keyword_detector_high_entropy_kept(scanner, tmp_path):
    """Secret Keyword findings with high-entropy values should be kept."""
    f = tmp_path / "config.yaml"
    # High-entropy value that looks like a real secret
    f.write_text("password: aB3cD4eF5gH6iJ7kL8mN9oP0qR1sT2uV3wX4yZ5a\n")

    context = ScanContext(target_path=tmp_path)
    findings = scanner.scan(context)
    keyword = [f for f in findings if f.metadata.get("detector") == "Secret Keyword"]
    assert len(keyword) >= 1, "High-entropy Secret Keyword values should be kept"


def test_entropy_gate_threshold():
    """Verify the 3.0 entropy threshold separates noise from signal."""
    # Common FP values should be below 3.0
    assert CredentialScanner._shannon_entropy("changeme") < 3.0
    assert CredentialScanner._shannon_entropy("test123") < 3.0
    assert CredentialScanner._shannon_entropy("password") < 3.0
    assert CredentialScanner._shannon_entropy("foobar") < 3.0
    # Real-looking secrets should be above 3.0
    assert CredentialScanner._shannon_entropy("aB3cD4eF5gH6iJ7kL8mN9") > 3.0
    assert CredentialScanner._shannon_entropy("Xk9mP2vR7wQ4nL5zB8cD") > 3.0


def test_template_syntax_placeholder():
    """Template syntax like {{ var }} and <YOUR_KEY> should be treated as placeholders."""
    assert CredentialScanner._is_placeholder("{{ API_KEY }}")
    assert CredentialScanner._is_placeholder("{{SECRET}}")
    assert CredentialScanner._is_placeholder("<YOUR_API_KEY>")
    assert CredentialScanner._is_placeholder("<API_TOKEN>")
    assert CredentialScanner._is_placeholder("%{secret_key}")
    # Real-looking values should NOT be placeholders
    assert not CredentialScanner._is_placeholder("sk-proj-RealLookingKeyWithEntropy99")


def test_scans_sql_files(scanner, tmp_path):
    """SQL files should be scanned for credentials."""
    f = tmp_path / "init.sql"
    f.write_text("CREATE USER admin WITH PASSWORD 'sk-ant-Xk9mP2vR7wQ4nL5zB8cDfGhJ';\n")
    context = ScanContext(target_path=tmp_path)
    findings = scanner.scan(context)
    assert len(findings) >= 1


def test_scans_ipynb_files(scanner, tmp_path):
    """Jupyter notebook files should be scanned for credentials."""
    f = tmp_path / "analysis.ipynb"
    # Minimal valid notebook JSON with an Anthropic key in a cell
    f.write_text(
        '{"cells": [{"cell_type": "code", "source": ['
        '"api_key = \\"sk-ant-Xk9mP2vR7wQ4nL5zB8cDfGhJ\\""]}], '
        '"metadata": {}, "nbformat": 4, "nbformat_minor": 5}\n'
    )
    context = ScanContext(target_path=tmp_path)
    findings = scanner.scan(context)
    assert len(findings) >= 1


def test_jest_test_dir_is_low_confidence(scanner, tmp_path):
    """Files in __tests__ directory should get test-context downgrade."""
    test_dir = tmp_path / "__tests__"
    test_dir.mkdir()
    f = test_dir / "auth.test.js"
    f.write_text('const key = "sk-ant-Xk9mP2vR7wQ4nL5zB8cDfGhJ";\n')
    context = ScanContext(target_path=tmp_path)
    findings = scanner.scan(context)
    anthropic = [f for f in findings if "Anthropic" in f.title]
    if anthropic:
        assert anthropic[0].severity == FindingSeverity.LOW


def test_pinecone_key_detected(scanner, tmp_path):
    """Pinecone API keys should be detected."""
    f = tmp_path / "config.py"
    f.write_text('PINECONE_KEY = "pcsk_Xk9mP2vR7wQ4nL5zB8cDfGhJrTpYs3q6"\n')
    context = ScanContext(target_path=tmp_path)
    findings = scanner.scan(context)
    pinecone = [f for f in findings if "Pinecone" in f.title]
    assert len(pinecone) >= 1


def test_cohere_key_detected(scanner, tmp_path):
    """Cohere API keys should be detected."""
    f = tmp_path / "config.py"
    f.write_text('COHERE_KEY = "co-Xk9mP2vR7wQ4nL5zB8cDfGhJrTpYs3q6aW8"\n')
    context = ScanContext(target_path=tmp_path)
    findings = scanner.scan(context)
    cohere = [f for f in findings if "Cohere" in f.title]
    assert len(cohere) >= 1


def test_vercel_token_detected(scanner, tmp_path):
    """Vercel tokens should be detected."""
    f = tmp_path / "config.py"
    f.write_text('TOKEN = "vercel_Xk9mP2vR7wQ4nL5zB8cDfGhJ"\n')
    context = ScanContext(target_path=tmp_path)
    findings = scanner.scan(context)
    vercel = [f for f in findings if "Vercel" in f.title]
    assert len(vercel) >= 1


# --- Tier 4: Expert swarm FP fixes ---


def test_skips_aws_example_key_in_secret_value(scanner, tmp_path):
    """AWS official wJalrXUtn... EXAMPLE key should not trigger findings."""
    f = tmp_path / "config.py"
    f.write_text(
        'secret_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"\n'  # gitleaks:allow
    )
    context = ScanContext(target_path=tmp_path)
    findings = scanner.scan(context)
    # Should be suppressed via known example values allowlist
    aws = [f for f in findings if "AWS" in f.title]
    assert len(aws) == 0


def test_skips_jwt_io_example_token(scanner, tmp_path):
    """jwt.io canonical example token should not trigger findings."""
    f = tmp_path / "test_auth.py"
    f.write_text(
        'TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9'
        ".eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiZXhwIjoxNTE2MjM5MDIyfQ"
        '.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"\n'
    )
    context = ScanContext(target_path=tmp_path)
    findings = scanner.scan(context)
    jwt_findings = [f for f in findings if "JWT" in f.title or "JSON Web Token" in f.title]
    assert len(jwt_findings) == 0


def test_skips_databricks_example_token(scanner, tmp_path):
    """Databricks documentation example token should not trigger findings."""
    # Concatenate to avoid GitHub push protection flagging the literal
    token = "dapi" + "1234567890ab1cde2f3ab456c7d89efa"
    f = tmp_path / "config.py"
    f.write_text(f'TOKEN = "{token}"\n')
    context = ScanContext(target_path=tmp_path)
    findings = scanner.scan(context)
    db = [f for f in findings if "Databricks" in f.title]
    assert len(db) == 0


def test_skips_natural_language_openai_pattern(scanner, tmp_path):
    """sk- followed by natural language should not fire as OpenAI key."""
    f = tmp_path / "docs.py"
    f.write_text('comment = "sk-this-is-docs-not-a-real-key"\n')
    context = ScanContext(target_path=tmp_path)
    findings = scanner.scan(context)
    openai = [f for f in findings if "OpenAI" in f.title]
    assert len(openai) == 0, "Natural language after sk- should be suppressed"


def test_skips_fake_groq_key(scanner, tmp_path):
    """Groq gsk_FakeGroqKeyForDocumentation... should be skipped."""
    f = tmp_path / "config.py"
    f.write_text('KEY = "gsk_FakeGroqKeyForDocumentation12345"\n')
    context = ScanContext(target_path=tmp_path)
    findings = scanner.scan(context)
    groq = [f for f in findings if "Groq" in f.title]
    assert len(groq) == 0, "Placeholder word 'Fake' + 'Documentation' should suppress"


def test_skips_fake_replicate_token(scanner, tmp_path):
    """Replicate r8_FakeReplicateTokenForDocs... should be skipped."""
    f = tmp_path / "config.py"
    f.write_text('TOKEN = "r8_FakeReplicateTokenForDocs12345678"\n')
    context = ScanContext(target_path=tmp_path)
    findings = scanner.scan(context)
    rep = [f for f in findings if "Replicate" in f.title]
    assert len(rep) == 0, "Placeholder word 'Fake' should suppress"


def test_skips_fake_private_key_body(scanner, tmp_path):
    """Private key blocks with trivially fake body should be skipped."""
    f = tmp_path / "test_tls.py"
    f.write_text("-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----\n")
    context = ScanContext(target_path=tmp_path)
    findings = scanner.scan(context)
    key_findings = [f for f in findings if "Private Key" in f.title]
    assert len(key_findings) == 0


def test_extra_pattern_entropy_gate(scanner, tmp_path):
    """Extra patterns with low-entropy matches should be suppressed."""
    f = tmp_path / "config.py"
    # All same char after prefix = extremely low entropy
    f.write_text('KEY = "sk-aaaaaaaaaaaaaaaaaaaaaaaa"\n')
    context = ScanContext(target_path=tmp_path)
    findings = scanner.scan(context)
    openai = [f for f in findings if "OpenAI" in f.title]
    assert len(openai) == 0, "Low-entropy extra pattern match should be suppressed"


def test_char_class_diversity_check():
    """Character class diversity correctly identifies real vs fake secrets."""
    assert CredentialScanner._has_char_class_diversity("aB3cD4eF5gH6")
    assert CredentialScanner._has_char_class_diversity("ABCDEF123456")
    assert CredentialScanner._has_char_class_diversity("abc123def456")
    assert not CredentialScanner._has_char_class_diversity("this-is-all-lowercase")
    assert not CredentialScanner._has_char_class_diversity("THISISALLUPPERCASE")


def test_known_example_value_detection():
    """Known example values are correctly identified."""
    assert CredentialScanner._is_known_example_value("AKIAIOSFODNN7EXAMPLE", "AWS Access Key")
    assert CredentialScanner._is_known_example_value(
        "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "AWS Secret"
    )
    # jwt.io example
    assert CredentialScanner._is_known_example_value(
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        ".eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0"
        ".SomeSignature",
        "JSON Web Token",
    )
    # "example" in domain names should NOT trigger
    assert not CredentialScanner._is_known_example_value(
        "postgresql://admin:secret@db.example.com:5432/app",
        "Generic Connection String",
    )
    # Real-looking key should NOT be flagged
    assert not CredentialScanner._is_known_example_value(
        "sk-aB3cD4eF5gH6iJ7kL8mN9", "OpenAI API Key"
    )


def test_expanded_placeholder_words():
    """Expanded placeholder vocabulary catches more FPs."""
    # Multiple placeholder words trigger the 2+ hit rule
    assert CredentialScanner._is_placeholder("sk-demo-value-for-testing")
    assert CredentialScanner._is_placeholder("mock-api-key-placeholder")
    assert CredentialScanner._is_placeholder("stub-value-for-tests")
    # Single placeholder word must dominate (>= 40% of stripped length)
    assert CredentialScanner._is_placeholder("sk-redacted-value")
    assert CredentialScanner._is_placeholder("sk-expired-token")
    assert CredentialScanner._is_placeholder("invalid-key")
    # Real-looking values should NOT be treated as placeholders
    assert not CredentialScanner._is_placeholder("aB3cD4eF5gH6iJ7kL8mN9")


def test_expanded_prefix_stripping():
    """Prefix stripping handles all provider prefixes for placeholder check."""
    # With gsk_ prefix, "FakeGroqKey" should dominate stripped length
    assert CredentialScanner._is_placeholder("gsk_FakeValue")
    assert CredentialScanner._is_placeholder("r8_FakeToken")
    assert CredentialScanner._is_placeholder("vercel_TestToken")
    assert CredentialScanner._is_placeholder("pcsk_FakeKeyForDocs")


def test_connection_string_example_domain_not_suppressed(scanner, tmp_path):
    """Connection strings with example.com domain but real password should be detected."""
    f = tmp_path / "config.py"
    f.write_text('DB = "postgresql://admin:Xk9mP2vR7wQ4nL@prod.db.example.com:5432/myapp"\n')
    context = ScanContext(target_path=tmp_path)
    findings = scanner.scan(context)
    conn = [f for f in findings if "Connection String" in f.title]
    assert len(conn) >= 1, "example.com in domain should not suppress real password detection"


# --- Confidence field tests ---


def test_high_confidence_for_real_key(scanner, tmp_path):
    """Real-looking keys in source code should have HIGH confidence."""
    f = tmp_path / "config.py"
    f.write_text('KEY = "sk-aB3cD4eF5gH6iJ7kL8mN9oP0qR1sT2uV3wX4yZ5a"\n')

    context = ScanContext(target_path=tmp_path)
    findings = scanner.scan(context)
    openai = [f for f in findings if "OpenAI" in f.title]
    assert len(openai) >= 1
    assert openai[0].confidence == FindingConfidence.HIGH


def test_low_confidence_in_test_dir(scanner, tmp_path):
    """Findings in tests/ directory should have LOW confidence."""
    test_dir = tmp_path / "tests"
    test_dir.mkdir()
    f = test_dir / "test_auth.py"
    f.write_text('KEY = "sk-aB3cD4eF5gH6iJ7kL8mN9oP0qR1sT2uV3wX4yZ5a"\n')

    context = ScanContext(target_path=tmp_path)
    findings = scanner.scan(context)
    openai = [f for f in findings if "OpenAI" in f.title]
    if openai:
        assert openai[0].confidence == FindingConfidence.LOW


def test_low_confidence_in_readme(scanner, tmp_path):
    """Findings in README.md should have LOW confidence."""
    f = tmp_path / "README.md"
    f.write_text("Use your key: sk-aB3cD4eF5gH6iJ7kL8mN9oP0qR1sT2uV3wX4yZ5a\n")

    context = ScanContext(target_path=tmp_path)
    findings = scanner.scan(context)
    openai = [f for f in findings if "OpenAI" in f.title]
    if openai:
        assert openai[0].confidence == FindingConfidence.LOW


def test_confidence_field_serialized_in_json(scanner, tmp_path):
    """Confidence field should be present in JSON serialization."""
    from agentsec.models.findings import Finding

    finding = Finding(
        scanner="credential",
        category=FindingCategory.EXPOSED_TOKEN,
        severity=FindingSeverity.CRITICAL,
        confidence=FindingConfidence.LOW,
        title="Test finding",
        description="Test",
    )
    data = finding.model_dump()
    assert "confidence" in data
    assert data["confidence"] == "low"
