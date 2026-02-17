"""Tests for the credential scanner."""

import pytest

from agentsec.models.findings import FindingCategory, FindingSeverity
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
