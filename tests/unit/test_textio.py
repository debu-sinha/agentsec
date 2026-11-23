"""Tests for the fixed-encoding text reader."""

from __future__ import annotations

import pytest

from agentsec.utils.textio import read_text_lossy


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (b"plain ascii", "plain ascii"),
        ("café “quoted” 服务器".encode(), "café “quoted” 服务器"),
        (b"bad \xff byte", "bad � byte"),
        (b"\xef\xbb\xbf{}", "{}"),
        (b"one\r\ntwo\rthree\n", "one\ntwo\nthree\n"),
        (b"", ""),
    ],
    ids=["ascii", "utf8", "invalid_byte", "bom", "newlines", "empty"],
)
def test_read_text_lossy(tmp_path, raw, expected):
    path = tmp_path / "sample.txt"
    path.write_bytes(raw)

    assert read_text_lossy(path) == expected


def test_read_text_lossy_raises_for_a_missing_file(tmp_path):
    with pytest.raises(FileNotFoundError):
        read_text_lossy(tmp_path / "missing.txt")
