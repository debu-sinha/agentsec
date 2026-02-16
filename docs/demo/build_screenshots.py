"""Build publication-ready terminal screenshots from agentsec scan output.

Runs real scans against fixtures, captures Rich HTML output, then
post-processes into dark-themed terminal-style HTML files suitable
for README screenshots.

Usage:
    python docs/demo/build_screenshots.py

Outputs:
    docs/demo/screenshots/scan-insecure.html
    docs/demo/screenshots/scan-clean.html
    docs/demo/screenshots/hero-banner.svg   (animated shield+lobster)
"""

from __future__ import annotations

import io
import json
import re
from pathlib import Path

from rich.console import Console

from agentsec.analyzers.owasp_scorer import OwaspScorer
from agentsec.models.config import AgentsecConfig, ScanTarget
from agentsec.orchestrator import run_scan
from agentsec.reporters.terminal import TerminalReporter


SCREENSHOTS_DIR = Path("docs") / "demo" / "screenshots"
FIXTURES_DIR = SCREENSHOTS_DIR / "fixtures"

# Color remapping: Rich's 8-color dark palette → bright colors for dark bg
COLOR_MAP = {
    "#800000": "#ff5555",   # dark red → bright red
    "#808000": "#e3b341",   # dark yellow → bright yellow
    "#000080": "#6699ff",   # dark blue → bright blue
    "#008000": "#50fa7b",   # dark green → bright green
    "#800080": "#bd93f9",   # dark magenta → bright magenta
    "#008080": "#58d1eb",   # dark cyan → bright cyan
    "#000000": "#e6edf3",   # black → light gray (for bold text)
    "#7f7f7f": "#8b949e",   # gray → slightly brighter gray
    "#870000": "#b62324",   # OWASP badge bg → slightly brighter
}

TERMINAL_TEMPLATE = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<style>
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{
  background: #0d1117;
  padding: 32px;
  display: flex;
  justify-content: center;
}}
.terminal {{
  background: #161b22;
  border: 1px solid #30363d;
  border-radius: 12px;
  width: 960px;
  overflow: hidden;
  box-shadow: 0 16px 48px rgba(0,0,0,0.4);
}}
.titlebar {{
  background: #21262d;
  padding: 10px 16px;
  display: flex;
  align-items: center;
  gap: 8px;
  border-bottom: 1px solid #30363d;
}}
.dot {{ width: 12px; height: 12px; border-radius: 50%; display: inline-block; }}
.dot-r {{ background: #ff5f57; }}
.dot-y {{ background: #febc2e; }}
.dot-g {{ background: #28c840; }}
.cmd {{ color: #8b949e; font-size: 13px; margin-left: 12px;
        font-family: 'Cascadia Code','Fira Code','JetBrains Mono','Consolas',monospace; }}
.body {{
  padding: 16px 20px;
  color: #c9d1d9;
  background: #161b22;
}}
.body pre {{
  font-family: 'Cascadia Code','Fira Code','JetBrains Mono','Consolas',monospace;
  font-size: 13.5px;
  line-height: 1.65;
  white-space: pre;
  overflow-x: auto;
}}
</style>
</head>
<body>
<div class="terminal">
  <div class="titlebar">
    <span class="dot dot-r"></span>
    <span class="dot dot-y"></span>
    <span class="dot dot-g"></span>
    <span class="cmd">{title_cmd}</span>
  </div>
  <div class="body">
    {rich_html}
  </div>
</div>
</body>
</html>
"""


HERO_BANNER_SVG = """\
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 600 220">
  <defs>
    <style>
      @keyframes shieldPulse {
        0%, 100% { transform: scale(1); opacity: 1; }
        50% { transform: scale(1.06); opacity: 0.92; }
      }
      @keyframes scanLine {
        0% { transform: translateY(-60px); opacity: 0; }
        20% { opacity: 0.7; }
        80% { opacity: 0.7; }
        100% { transform: translateY(60px); opacity: 0; }
      }
      @keyframes clawSnap {
        0%, 70%, 100% { transform: rotate(0deg); }
        80% { transform: rotate(-8deg); }
        90% { transform: rotate(3deg); }
      }
      .shield-group {
        animation: shieldPulse 3s ease-in-out infinite;
        transform-origin: 190px 110px;
      }
      .scan-beam {
        animation: scanLine 2.5s ease-in-out infinite;
      }
      .claw-l { animation: clawSnap 4s ease-in-out infinite; transform-origin: 155px 85px; }
      .claw-r { animation: clawSnap 4s ease-in-out infinite 0.15s; transform-origin: 225px 85px; }
      text { font-family: 'Cascadia Code','Fira Code','JetBrains Mono','Consolas',monospace; }
    </style>
  </defs>

  <!-- Background -->
  <rect width="600" height="220" rx="12" fill="#0d1117"/>

  <!-- Lobster body (simplified claw/agent shape) -->
  <g transform="translate(190,110)">
    <!-- Body -->
    <ellipse cx="0" cy="12" rx="28" ry="20" fill="#da3633" opacity="0.85"/>
    <!-- Tail segments -->
    <ellipse cx="0" cy="36" rx="20" ry="10" fill="#b62324" opacity="0.7"/>
    <ellipse cx="0" cy="50" rx="14" ry="7" fill="#8b1a1a" opacity="0.6"/>
    <!-- Eyes -->
    <circle cx="-10" cy="-4" r="3.5" fill="#f0f6fc"/>
    <circle cx="10" cy="-4" r="3.5" fill="#f0f6fc"/>
    <circle cx="-10" cy="-4" r="1.8" fill="#0d1117"/>
    <circle cx="10" cy="-4" r="1.8" fill="#0d1117"/>
    <!-- Antennae -->
    <line x1="-8" y1="-8" x2="-22" y2="-28" stroke="#ff7b72" stroke-width="2" stroke-linecap="round"/>
    <line x1="8" y1="-8" x2="22" y2="-28" stroke="#ff7b72" stroke-width="2" stroke-linecap="round"/>
    <!-- Legs -->
    <line x1="-18" y1="18" x2="-32" y2="30" stroke="#da3633" stroke-width="2"/>
    <line x1="-16" y1="24" x2="-28" y2="38" stroke="#da3633" stroke-width="2"/>
    <line x1="18" y1="18" x2="32" y2="30" stroke="#da3633" stroke-width="2"/>
    <line x1="16" y1="24" x2="28" y2="38" stroke="#da3633" stroke-width="2"/>
  </g>

  <!-- Left claw -->
  <g class="claw-l">
    <path d="M155,85 Q130,65 125,50 Q122,42 130,40 Q138,38 142,48 Q146,58 155,68 Z"
          fill="#ff5555" opacity="0.9"/>
    <path d="M155,85 Q140,75 135,60 Q133,52 140,52 Q147,52 150,62 Z"
          fill="#da3633" opacity="0.8"/>
  </g>

  <!-- Right claw -->
  <g class="claw-r">
    <path d="M225,85 Q250,65 255,50 Q258,42 250,40 Q242,38 238,48 Q234,58 225,68 Z"
          fill="#ff5555" opacity="0.9"/>
    <path d="M225,85 Q240,75 245,60 Q247,52 240,52 Q233,52 230,62 Z"
          fill="#da3633" opacity="0.8"/>
  </g>

  <!-- Shield overlay -->
  <g class="shield-group">
    <!-- Shield shape -->
    <path d="M190,72 L214,82 L214,108 Q214,128 190,140 Q166,128 166,108 L166,82 Z"
          fill="#238636" opacity="0.9" stroke="#3fb950" stroke-width="2"/>
    <!-- Checkmark on shield -->
    <polyline points="178,105 186,115 202,95" fill="none"
             stroke="#f0f6fc" stroke-width="3.5" stroke-linecap="round" stroke-linejoin="round"/>
    <!-- Scan beam -->
    <rect class="scan-beam" x="168" y="80" width="44" height="3" rx="1.5"
          fill="#58a6ff" opacity="0"/>
  </g>

  <!-- Text -->
  <text x="340" y="95" fill="#f0f6fc" font-size="28" font-weight="700">agentsec</text>
  <text x="340" y="120" fill="#8b949e" font-size="13">AI Agent Security Scanner</text>
  <text x="340" y="145" fill="#58a6ff" font-size="11">OWASP Agentic Top 10 &bull; 27 checks &bull; 4 scanners</text>
  <text x="340" y="165" fill="#3fb950" font-size="11">pip install agentsec-ai</text>
</svg>
"""


def _ensure_fixtures() -> tuple[Path, Path]:
    """Create insecure and clean OpenClaw fixtures."""
    insecure = FIXTURES_DIR / "insecure"
    clean = FIXTURES_DIR / "clean"

    def _write(path: Path, data: dict) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data, indent=2), encoding="utf-8")

    _write(
        insecure / ".openclaw" / "openclaw.json",
        {
            "version": "2026.1.0",
            "gateway": {"bind": "lan"},
            "dmPolicy": "open",
            "groupPolicy": "open",
            "tools": {"profile": "full"},
            "sandbox": {"mode": "off"},
        },
    )
    _write(
        clean / ".openclaw" / "openclaw.json",
        {
            "version": "2026.2.12",
            "gateway": {"bind": "loopback", "auth": {"token": "redacted-token"}},
            "dmPolicy": "paired",
            "groupPolicy": "allowlist",
            "tools": {"profile": "messaging"},
            "sandbox": {"mode": "all"},
            "session": {"dmScope": "per-channel-peer"},
        },
    )
    _write(
        clean / ".openclaw" / "exec-approvals.json",
        {"defaults": {"security": "allowlist", "askFallback": "deny"}},
    )
    return insecure, clean


def _capture_rich_html(target: Path) -> str:
    """Run a real scan and return the Rich HTML <pre> block."""
    sink = io.StringIO()
    console = Console(
        record=True,
        width=100,
        force_terminal=True,
        color_system="truecolor",
        file=sink,
        legacy_windows=False,
    )
    reporter = TerminalReporter(console=console, verbose=False)

    config = AgentsecConfig(targets=[ScanTarget(path=target)])
    report = run_scan(config)
    posture = OwaspScorer().compute_posture_score(report.findings)
    reporter.render(report, posture)

    html = console.export_html(inline_styles=True)
    return html


def _remap_colors(html: str) -> str:
    """Remap Rich's dark 8-color palette to bright colors for dark bg."""
    for old, new in COLOR_MAP.items():
        html = html.replace(old, new)
    return html


def _clean_paths(html: str) -> str:
    """Replace Windows fixture paths with clean Unix-style paths."""
    # Match any path ending in fixtures/insecure or fixtures/clean
    html = re.sub(
        r"[A-Z]:\\[^<\s]+?fixtures\\insecure",
        "~/.openclaw",
        html,
    )
    html = re.sub(
        r"[A-Z]:\\[^<\s]+?fixtures\\clean",
        "~/.openclaw",
        html,
    )
    # Also handle forward-slash variants
    html = re.sub(
        r"[A-Z]:/[^<\s]+?fixtures/insecure",
        "~/.openclaw",
        html,
    )
    html = re.sub(
        r"[A-Z]:/[^<\s]+?fixtures/clean",
        "~/.openclaw",
        html,
    )
    return html


def _build_screenshot(target: Path, title_cmd: str, output_name: str) -> Path:
    """Capture scan, post-process, write final HTML."""
    raw_html = _capture_rich_html(target)
    html = _remap_colors(raw_html)
    html = _clean_paths(html)

    # Strip the Rich wrapper (keep just the <pre>...</pre>)
    # Rich export_html returns just the styled content with <pre><code>
    final = TERMINAL_TEMPLATE.format(
        title_cmd=title_cmd,
        rich_html=html,
    )

    out = SCREENSHOTS_DIR / output_name
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(final, encoding="utf-8")
    return out


def main() -> None:
    insecure, clean = _ensure_fixtures()

    f1 = _build_screenshot(insecure, "agentsec scan ~/.openclaw", "scan-insecure.html")
    f2 = _build_screenshot(clean, "agentsec scan ~/.openclaw  # after hardening", "scan-clean.html")

    # Write hero banner SVG
    banner = SCREENSHOTS_DIR / "hero-banner.svg"
    banner.write_text(HERO_BANNER_SVG, encoding="utf-8")

    print("Built screenshots:")
    print(f"  {f1.as_posix()}")
    print(f"  {f2.as_posix()}")
    print(f"  {banner.as_posix()}")
    print()
    print("Open in Chrome and screenshot with Win+Shift+S,")
    print("or embed the SVG banner directly in the README.")


if __name__ == "__main__":
    main()
