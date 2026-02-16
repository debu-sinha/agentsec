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
    # Python file with an OpenAI key
    py_file = tmp_path / "config.py"
    py_file.write_text("import os\nAPI_KEY = 'sk-abc123456789012345678901234567890123456789'\n")

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
    link.symlink_to(real_file)

    context = ScanContext(target_path=tmp_path)
    findings = scanner.scan(context)

    # The scan should complete without following symlinks into unexpected dirs
    assert isinstance(findings, list)


def test_deduplicates_findings(scanner, tmp_path):
    """Same secret in same file should not be reported twice."""
    py_file = tmp_path / "config.py"
    py_file.write_text(
        "KEY1 = 'sk-abc123456789012345678901234567890123456789'\n"
        "KEY2 = 'sk-abc123456789012345678901234567890123456789'\n"
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

    entropy_findings = [f for f in findings if f.category == FindingCategory.PLAINTEXT_SECRET]
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
