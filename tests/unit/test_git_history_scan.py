"""Tests for git history credential scanning (Issue #27)."""

from __future__ import annotations

import subprocess

import pytest

from agentsec.models.findings import FindingCategory, FindingConfidence
from agentsec.scanners.base import ScanContext
from agentsec.scanners.credential import CredentialScanner


@pytest.fixture
def scanner():
    return CredentialScanner()


def _git(cwd, *args):
    """Run a git command in the given directory."""
    result = subprocess.run(
        ["git", *args],
        cwd=str(cwd),
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, f"git {' '.join(args)} failed: {result.stderr}"
    return result


def _init_git_repo(tmp_path):
    """Initialize a git repo with a dummy commit."""
    _git(tmp_path, "init")
    _git(tmp_path, "config", "user.email", "test@test.com")
    _git(tmp_path, "config", "user.name", "Test")
    # Initial empty commit
    readme = tmp_path / "README.md"
    readme.write_text("# Test repo\n")
    _git(tmp_path, "add", "README.md")
    _git(tmp_path, "commit", "-m", "Initial commit")


def test_detects_secret_in_git_history(scanner, tmp_path):
    """A real-looking key committed and then removed should be detected."""
    _init_git_repo(tmp_path)

    # Commit a file with a secret
    config = tmp_path / "config.py"
    config.write_text("KEY = 'sk-proj-RealLookingKeyWithProperEntropyAndLength99'\n")
    _git(tmp_path, "add", "config.py")
    _git(tmp_path, "commit", "-m", "Add config with key")

    # Remove the file
    config.unlink()
    _git(tmp_path, "add", "config.py")
    _git(tmp_path, "commit", "-m", "Remove leaked key")

    context = ScanContext(target_path=tmp_path, scan_history=True, history_depth=10)
    findings = scanner.scan(context)

    history_findings = [f for f in findings if f.metadata.get("source") == "git_history"]
    assert len(history_findings) >= 1
    assert history_findings[0].category == FindingCategory.EXPOSED_TOKEN
    assert history_findings[0].confidence == FindingConfidence.MEDIUM
    assert "git history" in history_findings[0].title
    assert history_findings[0].metadata.get("commit")


def test_no_findings_when_history_disabled(scanner, tmp_path):
    """scan_history=False should skip git history scanning entirely."""
    _init_git_repo(tmp_path)

    config = tmp_path / "config.py"
    config.write_text("KEY = 'sk-proj-RealLookingKeyWithProperEntropyAndLength99'\n")
    _git(tmp_path, "add", "config.py")
    _git(tmp_path, "commit", "-m", "Add config with key")
    config.unlink()
    _git(tmp_path, "add", "config.py")
    _git(tmp_path, "commit", "-m", "Remove key")

    context = ScanContext(target_path=tmp_path, scan_history=False, history_depth=10)
    findings = scanner.scan(context)

    history_findings = [f for f in findings if f.metadata.get("source") == "git_history"]
    assert len(history_findings) == 0


def test_skips_placeholder_in_history(scanner, tmp_path):
    """Placeholder values in git history should be suppressed."""
    _init_git_repo(tmp_path)

    config = tmp_path / "config.py"
    config.write_text("KEY = 'sk-your-api-key-here-placeholder-example'\n")
    _git(tmp_path, "add", "config.py")
    _git(tmp_path, "commit", "-m", "Add placeholder")
    config.unlink()
    _git(tmp_path, "add", "config.py")
    _git(tmp_path, "commit", "-m", "Remove config")

    context = ScanContext(target_path=tmp_path, scan_history=True, history_depth=10)
    findings = scanner.scan(context)

    history_findings = [f for f in findings if f.metadata.get("source") == "git_history"]
    assert len(history_findings) == 0


def test_deduplicates_across_commits(scanner, tmp_path):
    """Same secret in multiple commits should produce one finding."""
    _init_git_repo(tmp_path)

    # Commit the same key in two different files
    f1 = tmp_path / "config1.py"
    f1.write_text("KEY = 'sk-proj-RealLookingKeyWithProperEntropyAndLength99'\n")
    _git(tmp_path, "add", "config1.py")
    _git(tmp_path, "commit", "-m", "Add config1")

    f2 = tmp_path / "config2.py"
    f2.write_text("KEY = 'sk-proj-RealLookingKeyWithProperEntropyAndLength99'\n")
    _git(tmp_path, "add", "config2.py")
    _git(tmp_path, "commit", "-m", "Add config2")

    # Remove both
    f1.unlink()
    f2.unlink()
    _git(tmp_path, "add", "config1.py", "config2.py")
    _git(tmp_path, "commit", "-m", "Remove secrets")

    context = ScanContext(target_path=tmp_path, scan_history=True, history_depth=10)
    findings = scanner.scan(context)

    history_findings = [f for f in findings if f.metadata.get("source") == "git_history"]
    # Same secret value should be deduplicated to one finding
    openai_history = [f for f in history_findings if "OpenAI" in f.title]
    assert len(openai_history) == 1
    # Should have commit span metadata
    assert "commit_count" in openai_history[0].metadata


def test_no_git_repo_no_crash(scanner, tmp_path):
    """When target is not a git repo, history scan should silently skip."""
    config = tmp_path / "config.py"
    config.write_text("KEY = 'sk-proj-RealLookingKeyWithProperEntropyAndLength99'\n")

    context = ScanContext(target_path=tmp_path, scan_history=True, history_depth=10)
    # Should not raise — .git dir doesn't exist, so Phase 4 guard skips
    findings = scanner.scan(context)
    history_findings = [f for f in findings if f.metadata.get("source") == "git_history"]
    assert len(history_findings) == 0


def test_history_finding_has_remediation(scanner, tmp_path):
    """History findings should include git filter-repo remediation steps."""
    _init_git_repo(tmp_path)

    config = tmp_path / "config.py"
    config.write_text("KEY = 'sk-proj-RealLookingKeyWithProperEntropyAndLength99'\n")
    _git(tmp_path, "add", "config.py")
    _git(tmp_path, "commit", "-m", "Add key")
    config.unlink()
    _git(tmp_path, "add", "config.py")
    _git(tmp_path, "commit", "-m", "Remove key")

    context = ScanContext(target_path=tmp_path, scan_history=True, history_depth=10)
    findings = scanner.scan(context)

    history_findings = [f for f in findings if f.metadata.get("source") == "git_history"]
    assert len(history_findings) >= 1

    remediation = history_findings[0].remediation
    assert remediation is not None
    assert "purge" in remediation.summary.lower() or "rotate" in remediation.summary.lower()
    steps_text = " ".join(remediation.steps)
    assert "filter-repo" in steps_text or "BFG" in steps_text


def test_history_depth_limits_scan(scanner, tmp_path):
    """history_depth=1 should only scan the most recent commit."""
    _init_git_repo(tmp_path)

    # Commit a secret in the first commit
    f1 = tmp_path / "old.py"
    f1.write_text("KEY = 'sk-proj-OldKeyThatShouldBeMissedByDepthLimit99'\n")
    _git(tmp_path, "add", "old.py")
    _git(tmp_path, "commit", "-m", "Old secret")

    # Add 5 more commits without secrets
    for i in range(5):
        filler = tmp_path / f"filler{i}.txt"
        filler.write_text(f"filler content {i}\n")
        _git(tmp_path, "add", f"filler{i}.txt")
        _git(tmp_path, "commit", "-m", f"Filler commit {i}")

    context = ScanContext(target_path=tmp_path, scan_history=True, history_depth=1)
    findings = scanner.scan(context)

    history_findings = [f for f in findings if f.metadata.get("source") == "git_history"]
    # With depth=1, the old secret commit should not be reached
    assert len(history_findings) == 0


def test_connection_string_in_history(scanner, tmp_path):
    """Connection strings with real-looking passwords should be detected in history."""
    _init_git_repo(tmp_path)

    config = tmp_path / "docker-compose.yml"
    config.write_text(
        "DATABASE_URL: postgresql://admin:Xk9mP2vR7wQ4nL@prod.db.internal:5432/myapp\n"
    )
    _git(tmp_path, "add", "docker-compose.yml")
    _git(tmp_path, "commit", "-m", "Add docker-compose")
    config.unlink()
    _git(tmp_path, "add", "docker-compose.yml")
    _git(tmp_path, "commit", "-m", "Remove compose file")

    context = ScanContext(target_path=tmp_path, scan_history=True, history_depth=10)
    findings = scanner.scan(context)

    history_findings = [f for f in findings if f.metadata.get("source") == "git_history"]
    conn_findings = [f for f in history_findings if "Connection String" in f.title]
    assert len(conn_findings) >= 1


def test_skips_known_example_in_history(scanner, tmp_path):
    """Well-known example values (AWS EXAMPLE) should be skipped in history."""
    _init_git_repo(tmp_path)

    config = tmp_path / "config.py"
    config.write_text("AWS_KEY = 'AKIAIOSFODNN7EXAMPLE'\n")
    _git(tmp_path, "add", "config.py")
    _git(tmp_path, "commit", "-m", "Add example AWS key")
    config.unlink()
    _git(tmp_path, "add", "config.py")
    _git(tmp_path, "commit", "-m", "Remove config")

    context = ScanContext(target_path=tmp_path, scan_history=True, history_depth=10)
    findings = scanner.scan(context)

    history_findings = [f for f in findings if f.metadata.get("source") == "git_history"]
    # AKIAIOSFODNN7EXAMPLE is in the known-example allowlist
    assert len(history_findings) == 0
