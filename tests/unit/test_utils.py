"""Tests for agentsec.utils helpers."""

from agentsec import utils


def test_posix_permissions_supported_off_on_windows(monkeypatch):
    monkeypatch.setattr(utils.os, "name", "nt")
    assert utils.posix_permissions_supported() is False


def test_posix_permissions_supported_on_posix(monkeypatch):
    monkeypatch.setattr(utils.os, "name", "posix")
    assert utils.posix_permissions_supported() is True


def test_sanitize_secret_masks_middle():
    assert utils.sanitize_secret("sk-abcdefghijklmnop") == "sk-a***********mnop"
    assert utils.sanitize_secret("short") == "*****"
