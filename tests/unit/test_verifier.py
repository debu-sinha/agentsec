"""Tests for secret verification utilities (Issue #31)."""

from __future__ import annotations

import time
from unittest.mock import patch

from agentsec.scanners.base import ScanContext
from agentsec.scanners.credential import CredentialScanner
from agentsec.utils.verifier import compute_passive_hints, verify_secret

# ---------------------------------------------------------------------------
# Passive hint tests
# ---------------------------------------------------------------------------


def test_passive_hints_recent_file(tmp_path):
    """Recently modified file should get hint_file_age=recent."""
    f = tmp_path / "config.py"
    f.write_text("SECRET = 'something'\n")

    hints = compute_passive_hints(f, 1, "OpenAI API Key")
    assert hints.get("hint_file_age") == "recent"


def test_passive_hints_stale_file(tmp_path):
    """File modified > 90 days ago should get hint_file_age=stale."""
    f = tmp_path / "config.py"
    f.write_text("SECRET = 'something'\n")
    # Set mtime to 120 days ago
    old_time = time.time() - (120 * 86400)
    import os

    os.utime(str(f), (old_time, old_time))

    hints = compute_passive_hints(f, 1, "OpenAI API Key")
    assert hints.get("hint_file_age") == "stale"


def test_passive_hints_production_env(tmp_path):
    """A .env file should get hint_file_type=production_env."""
    f = tmp_path / ".env"
    f.write_text("API_KEY=sk-test\n")

    hints = compute_passive_hints(f, 1, "OpenAI API Key")
    assert hints.get("hint_file_type") == "production_env"
    assert hints.get("hint_risk_level") == "high"


def test_passive_hints_template_file(tmp_path):
    """A .env.example file should get hint_file_type=template and low risk."""
    f = tmp_path / ".env.example"
    f.write_text("API_KEY=your_key_here\n")

    hints = compute_passive_hints(f, 1, "OpenAI API Key")
    assert hints.get("hint_file_type") == "env_variant"


def test_passive_hints_near_revocation_word(tmp_path):
    """Finding near 'deprecated' comment should get low risk."""
    f = tmp_path / "config.py"
    f.write_text("# deprecated - this key was rotated\nOLD_KEY = 'sk-abc123'\n")

    hints = compute_passive_hints(f, 2, "OpenAI API Key")
    assert "near_revocation_word" in hints.get("hint_context", "")
    assert hints.get("hint_risk_level") == "low"


def test_passive_hints_no_file():
    """No file path should return medium risk."""
    hints = compute_passive_hints(None, None, "OpenAI API Key")
    assert hints.get("hint_risk_level") == "medium"


def test_passive_hints_nonexistent_file(tmp_path):
    """Nonexistent file should handle gracefully."""
    fake_path = tmp_path / "nonexistent.py"
    hints = compute_passive_hints(fake_path, 1, "OpenAI API Key")
    # Should not crash; risk level defaults to medium
    assert "hint_risk_level" in hints


# ---------------------------------------------------------------------------
# Active verification tests (mocked)
# ---------------------------------------------------------------------------


def test_verify_unknown_provider():
    """Unknown secret type should return unknown."""
    result = verify_secret("FooBar Token", "abc123")
    assert result["verified"] == "unknown"
    assert "no_verifier" in result["verify_method"]


@patch("agentsec.utils.verifier.urllib.request.urlopen")
def test_verify_github_active(mock_urlopen):
    """Active GitHub token should return verified=active."""
    mock_resp = mock_urlopen.return_value.__enter__.return_value
    mock_resp.status = 200

    result = verify_secret("GitHub Token", "ghp_test123")
    assert result["verified"] == "active"
    assert "github" in result["verify_method"]


@patch("agentsec.utils.verifier.urllib.request.urlopen")
def test_verify_github_inactive(mock_urlopen):
    """Revoked GitHub token should return verified=inactive."""
    import urllib.error

    mock_urlopen.side_effect = urllib.error.HTTPError(
        url="", code=401, msg="Unauthorized", hdrs=None, fp=None
    )

    result = verify_secret("GitHub Token", "ghp_revoked123")
    assert result["verified"] == "inactive"


@patch("agentsec.utils.verifier.urllib.request.urlopen")
def test_verify_openai_active(mock_urlopen):
    """Active OpenAI key should return verified=active."""
    mock_resp = mock_urlopen.return_value.__enter__.return_value
    mock_resp.status = 200

    result = verify_secret("OpenAI API Key", "sk-test123")
    assert result["verified"] == "active"
    assert "openai" in result["verify_method"]


@patch("agentsec.utils.verifier.urllib.request.urlopen")
def test_verify_anthropic_inactive(mock_urlopen):
    """Revoked Anthropic key should return verified=inactive."""
    import urllib.error

    mock_urlopen.side_effect = urllib.error.HTTPError(
        url="", code=401, msg="Unauthorized", hdrs=None, fp=None
    )

    result = verify_secret("Anthropic API Key", "sk-ant-test123")
    assert result["verified"] == "inactive"


@patch("agentsec.utils.verifier.urllib.request.urlopen")
def test_verify_network_error(mock_urlopen):
    """Network error should return verified=error."""
    import urllib.error

    mock_urlopen.side_effect = urllib.error.URLError("Connection refused")

    result = verify_secret("GitHub Token", "ghp_test123")
    assert result["verified"] == "error"
    assert "network_error" in result["verify_method"]


# ---------------------------------------------------------------------------
# Integration: passive hints wired into credential scanner
# ---------------------------------------------------------------------------


def test_credential_scanner_adds_passive_hints(tmp_path):
    """Credential scanner should add hint_risk_level to findings."""
    f = tmp_path / "config.py"
    f.write_text("API_KEY = 'sk-proj-RealLookingKeyWithProperEntropyAndLength99'\n")

    scanner = CredentialScanner()
    context = ScanContext(target_path=tmp_path)
    findings = scanner.scan(context)

    openai = [f for f in findings if "OpenAI" in f.title]
    assert len(openai) >= 1
    assert "hint_risk_level" in openai[0].metadata


def test_credential_scanner_env_file_gets_high_risk(tmp_path):
    """Findings in .env should get hint_risk_level=high."""
    f = tmp_path / ".env"
    f.write_text("OPENAI_KEY=sk-proj-RealLookingKeyWithProperEntropyAndLength99\n")

    scanner = CredentialScanner()
    context = ScanContext(target_path=tmp_path)
    findings = scanner.scan(context)

    openai = [f for f in findings if "OpenAI" in f.title]
    assert len(openai) >= 1
    assert openai[0].metadata.get("hint_risk_level") == "high"
