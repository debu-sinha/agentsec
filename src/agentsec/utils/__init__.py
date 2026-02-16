"""Utility functions for agentsec."""


def sanitize_secret(value: str) -> str:
    """Sanitize a secret value for safe display.

    Shows the first 4 and last 4 characters with masked middle.
    Consistent across all scanners.
    """
    if len(value) > 12:
        return value[:4] + "*" * min(len(value) - 8, 16) + value[-4:]
    return "*" * len(value)
