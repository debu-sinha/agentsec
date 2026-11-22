"""Utility functions for agentsec."""

import os


def posix_permissions_supported() -> bool:
    """Return True when ``stat().st_mode`` reflects who can read or write a file.

    On Windows, CPython builds the mode from the read-only attribute and mirrors
    the owner bits to group and other, so every writable file reports as 0o666.
    NTFS access is governed by ACLs that ``st_mode`` does not expose, so a mode
    bit check there is noise and ``chmod`` does not change who can read a file.
    """
    return os.name != "nt"


def sanitize_secret(value: str) -> str:
    """Sanitize a secret value for safe display.

    Shows the first 4 and last 4 characters with masked middle.
    Consistent across all scanners.
    """
    if len(value) > 12:
        return value[:4] + "*" * min(len(value) - 8, 16) + value[-4:]
    return "*" * len(value)
