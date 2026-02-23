#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────
# agentsec LinkedIn Demo — Recording Script
# ─────────────────────────────────────────────────────────────────
#
# This script walks through the exact demo sequence for recording.
# It pauses between steps so you can narrate and the viewer can read.
#
# BEFORE RECORDING:
#   1. Run: python demo/setup_demo.py
#   2. Set terminal: JetBrains Mono 20pt, dark theme, ~105 columns
#   3. Start OBS/screen recorder at 1920x1080, 30fps
#   4. Clear terminal: clear
#
# RECORDING APPROACH:
#   Option A: Run this script and record (automated with pauses)
#   Option B: Type commands manually for authenticity (recommended)
#
# If typing manually, follow the SHOT LIST below.
# ─────────────────────────────────────────────────────────────────

set -e

DEMO_DIR="$(dirname "$0")/demo-target"
PAUSE_SHORT=2
PAUSE_MEDIUM=4
PAUSE_LONG=6

# Colors for script feedback (not shown in recording)
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

pause() {
    echo -e "${YELLOW}[PAUSE ${1}s — $2]${NC}" >&2
    sleep "$1"
}

divider() {
    echo -e "${GREEN}═══════════════════════════════════════════════${NC}" >&2
    echo -e "${GREEN}  SHOT: $1${NC}" >&2
    echo -e "${GREEN}═══════════════════════════════════════════════${NC}" >&2
}

# ─────────────────────────────────────────────────
# PRE-FLIGHT: Ensure demo environment exists
# ─────────────────────────────────────────────────
if [ ! -d "$DEMO_DIR" ]; then
    echo "Demo target not found. Building..."
    python "$(dirname "$0")/setup_demo.py"
fi

clear

# ─────────────────────────────────────────────────
# SHOT 1: THE INSTALL (0:03-0:15)
# ─────────────────────────────────────────────────
divider "1 — pip install"

echo '$ pip install agentsec-ai'
pause $PAUSE_SHORT "let viewer read the command"
# Simulate install output (in real recording, use actual pip install)
echo "Successfully installed agentsec-ai-0.4.4"
pause $PAUSE_MEDIUM "let install sink in"

# ─────────────────────────────────────────────────
# SHOT 2: FIRST SCAN — THE REVEAL (0:15-1:45)
# ─────────────────────────────────────────────────
divider "2 — first scan (the reveal)"

echo '$ agentsec scan demo/demo-target'
pause $PAUSE_SHORT "dramatic pause before Enter"

# Run the actual scan
agentsec scan "$DEMO_DIR" --fail-on none

pause $PAUSE_LONG "let viewer absorb the F grade and findings"

# ─────────────────────────────────────────────────
# SHOT 3: VERBOSE SCAN — DEEP DIVE (1:45-3:00)
# ─────────────────────────────────────────────────
divider "3 — verbose scan (deep dive into findings)"

echo '$ agentsec scan demo/demo-target --verbose'
pause $PAUSE_SHORT "before Enter"

agentsec scan "$DEMO_DIR" --verbose --fail-on none

pause $PAUSE_LONG "let viewer read the detailed findings"

# ─────────────────────────────────────────────────
# SHOT 4: HARDEN DRY-RUN — PREVIEW THE FIX (3:00-3:30)
# ─────────────────────────────────────────────────
divider "4 — harden dry-run (preview changes)"

echo '$ agentsec harden demo/demo-target -p workstation --dry-run'
pause $PAUSE_SHORT "before Enter"

agentsec harden "$DEMO_DIR" -p workstation --dry-run

pause $PAUSE_MEDIUM "let viewer see what will change"

# ─────────────────────────────────────────────────
# SHOT 5: HARDEN APPLY — THE FIX (3:30-4:00)
# ─────────────────────────────────────────────────
divider "5 — harden apply (the transformation)"

echo '$ agentsec harden demo/demo-target -p workstation --apply'
pause $PAUSE_SHORT "before Enter"

agentsec harden "$DEMO_DIR" -p workstation --apply

pause $PAUSE_MEDIUM "let the fix sink in"

# ─────────────────────────────────────────────────
# SHOT 5b: MANUAL FIXES — THE REAL WORK (4:00-4:20)
# ─────────────────────────────────────────────────
divider "5b — manual fixes (remove creds, malicious skill, upgrade)"

echo '$ python demo/fix_demo.py'
pause $PAUSE_SHORT "before Enter"

python "$(dirname "$0")/fix_demo.py"

pause $PAUSE_MEDIUM "let the manual fixes sink in"

# ─────────────────────────────────────────────────
# SHOT 6: RE-SCAN — THE PAYOFF (4:20-4:45)
# ─────────────────────────────────────────────────
divider "6 — re-scan (the grade improvement)"

echo '$ agentsec scan demo/demo-target'
pause $PAUSE_SHORT "before Enter"

agentsec scan "$DEMO_DIR" --fail-on none

pause $PAUSE_LONG "THE MONEY SHOT — F to A grade improvement"

# ─────────────────────────────────────────────────
# SHOT 7: SARIF OUTPUT — CI/CD TEASER (4:30-4:45)
# ─────────────────────────────────────────────────
divider "7 — SARIF output (CI/CD teaser)"

echo '$ agentsec scan demo/demo-target --format sarif -f results.sarif'
pause $PAUSE_SHORT "before Enter"

agentsec scan "$DEMO_DIR" --format sarif -f /tmp/agentsec-demo-results.sarif --fail-on none
echo "SARIF output written to results.sarif"
echo "# Drop into .github/workflows/ci.yml for GitHub Code Scanning"

pause $PAUSE_MEDIUM "CI/CD mention"

# ─────────────────────────────────────────────────
# DONE
# ─────────────────────────────────────────────────
divider "DONE — Stop recording"
echo ""
echo "Demo complete. Key moments for editing:"
echo "  - SHOT 2: The F grade reveal (thumbnail screenshot)"
echo "  - SHOT 3: Detailed findings walkthrough"
echo "  - SHOT 6: The grade improvement (before/after)"
echo ""
echo "Post-production:"
echo "  1. Add burned-in captions"
echo "  2. Add text overlay on first frame: 'I SCANNED MY AI AGENT'"
echo "  3. Create 90-second cut from shots 2, 3 (highlights), 5, 6"
echo "  4. Export 1080x1080 (square) for LinkedIn"
