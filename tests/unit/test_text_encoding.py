"""Scanned and rewritten files are handled as UTF-8 on every platform."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from agentsec.hardener import harden
from agentsec.scanners.base import ScanContext
from agentsec.scanners.installation import InstallationScanner
from agentsec.scanners.mcp import McpScanner

# Valid UTF-8 that has no mapping in the Windows-1252 code page.
_NON_LATIN = "“quoted” 服务器"

_FLAVORS = ["non_latin", "invalid_byte", "bom"]


def _write_config(path: Path, data: dict, flavor: str) -> None:
    """Write a JSON config the way a real file can look on disk."""
    data = {**data, "note": _NON_LATIN if flavor == "non_latin" else "plain note"}
    raw = json.dumps(data, ensure_ascii=False).encode("utf-8")
    if flavor == "invalid_byte":
        raw = raw.replace(b"plain note", b"plain \xff note")
    elif flavor == "bom":
        raw = b"\xef\xbb\xbf" + raw
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)


@pytest.mark.parametrize("flavor", _FLAVORS)
def test_installation_scanner_reports_despite_odd_bytes(tmp_path, flavor):
    _write_config(
        tmp_path / ".claude" / "settings.json",
        {"permissions": {"allow": ["Bash(*)"], "deny": []}},
        flavor,
    )

    findings = InstallationScanner().run(ScanContext(target_path=tmp_path))

    assert "CHK-002" in {f.check_id for f in findings}
    assert [f.title for f in findings if "skipped" in f.title] == []


@pytest.mark.parametrize("flavor", _FLAVORS)
def test_mcp_scanner_reports_despite_odd_bytes(tmp_path, flavor):
    config_path = tmp_path / "openclaw.json"
    _write_config(
        config_path,
        {"mcpServers": {"remote": {"url": "http://mcp.example.com/sse"}}},
        flavor,
    )
    context = ScanContext(target_path=tmp_path)
    context.register_config_file("openclaw.json", config_path)

    findings = McpScanner().run(context)

    assert "CMCP-004" in {f.check_id for f in findings}
    assert [f.title for f in findings if "skipped" in f.title] == []


def test_harden_keeps_non_ascii_values(tmp_path):
    config = {"version": "2026.2.12", "owner": _NON_LATIN}
    path = tmp_path / "openclaw.json"
    path.write_bytes(json.dumps(config, ensure_ascii=False).encode("utf-8"))

    result = harden(tmp_path, "workstation", dry_run=False)

    assert result.errors == []
    assert json.loads(path.read_bytes().decode("utf-8"))["owner"] == _NON_LATIN


def test_harden_refuses_config_it_cannot_decode(tmp_path):
    path = tmp_path / "openclaw.json"
    original = b'{"version": "2026.2.12", "owner": "a\xffb"}'
    path.write_bytes(original)

    result = harden(tmp_path, "workstation", dry_run=False)

    assert len(result.errors) == 1
    assert result.errors[0].startswith("Failed to read config")
    assert path.read_bytes() == original
    assert list(tmp_path.glob("openclaw.json.bak.*")) == []


# Runs in a child interpreter started with -X warn_default_encoding and prints
# the agentsec source lines that did text I/O without naming an encoding.
# A warning reaches either the recorded list or, once something has called
# logging.captureWarnings, the "py.warnings" logger. The probe reads both.
_ENCODING_PROBE = r"""
import json
import logging
import re
import sys
import warnings
from pathlib import Path

from click.testing import CliRunner

import agentsec
from agentsec.cli import main

target = Path(sys.argv[1])
package = Path(agentsec.__file__).resolve().parent
seen = []


class Collect(logging.Handler):
    def emit(self, record):
        seen.append(record.getMessage())


warnings_log = logging.getLogger("py.warnings")
warnings_log.setLevel(logging.WARNING)
warnings_log.addHandler(Collect())
with warnings.catch_warnings(record=True) as caught:
    warnings.simplefilter("always", EncodingWarning)
    for fmt in ("json", "sarif"):
        out = str(target / f"report.{fmt}")
        CliRunner().invoke(main, ["scan", str(target), "-o", fmt, "-f", out, "--fail-on", "none"])
    CliRunner().invoke(main, ["harden", str(target), "--profile", "workstation", "--apply"])
seen += [warnings.formatwarning(w.message, w.category, w.filename, w.lineno) for w in caught]
hits = set()
for text in seen:
    found = re.match(r"(.+):(\d+): EncodingWarning", text)
    if found and Path(found.group(1)).resolve().is_relative_to(package):
        hits.add(f"{Path(found.group(1)).name}:{found.group(2)}")
print(json.dumps(sorted(hits)))
"""


def test_cli_does_no_text_io_in_the_platform_encoding(tmp_path):
    """Scan, both file reports and harden run clean under -X warn_default_encoding."""
    (tmp_path / "openclaw.json").write_bytes(b'{"version": "2026.2.12"}')
    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude" / "settings.json").write_bytes(b'{"permissions": {"allow": ["Bash(*)"]}}')
    (tmp_path / "mcp.json").write_bytes(
        b'{"mcpServers": {"remote": {"url": "http://mcp.example.com/sse"}}}'
    )
    (tmp_path / ".env").write_bytes(b"API_KEY=placeholder\n")

    proc = subprocess.run(
        [sys.executable, "-X", "warn_default_encoding", "-c", _ENCODING_PROBE, str(tmp_path)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=True,
    )

    assert json.loads(proc.stdout.strip().splitlines()[-1]) == []
