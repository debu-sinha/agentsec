"""Text file reads with a fixed encoding.

The platform default encoding differs between machines (UTF-8 on Linux and
macOS, a legacy code page on Windows), and the files agentsec scans are
written as UTF-8 by the agents that own them.
"""

from __future__ import annotations

from pathlib import Path


def read_text_lossy(path: Path) -> str:
    """Read a file as UTF-8 text without failing on its bytes.

    A scanned file is read to be analyzed, so a byte that is not valid UTF-8
    becomes U+FFFD instead of raising, and a leading byte order mark is
    dropped. Filesystem errors still raise ``OSError``.
    """
    return path.read_text(encoding="utf-8-sig", errors="replace")
