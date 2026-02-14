"""Scanner registry — central lookup for all scanner modules."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from agentsec.scanners.base import BaseScanner


def _load_scanners() -> dict[str, type[BaseScanner]]:
    """Lazy import to avoid circular dependencies."""
    from agentsec.scanners.credential import CredentialScanner
    from agentsec.scanners.installation import InstallationScanner
    from agentsec.scanners.mcp import McpScanner
    from agentsec.scanners.skill import SkillAnalyzer

    return {
        "installation": InstallationScanner,
        "skill": SkillAnalyzer,
        "mcp": McpScanner,
        "credential": CredentialScanner,
    }


# Populated on first access
SCANNER_REGISTRY: dict[str, type[BaseScanner]] = {}


def get_scanner(name: str) -> type[BaseScanner]:
    """Get a scanner class by name."""
    if not SCANNER_REGISTRY:
        SCANNER_REGISTRY.update(_load_scanners())
    if name not in SCANNER_REGISTRY:
        available = ", ".join(sorted(SCANNER_REGISTRY.keys()))
        raise KeyError(f"Unknown scanner '{name}'. Available: {available}")
    return SCANNER_REGISTRY[name]


def get_all_scanners() -> dict[str, type[BaseScanner]]:
    """Get all registered scanner classes."""
    if not SCANNER_REGISTRY:
        SCANNER_REGISTRY.update(_load_scanners())
    return dict(SCANNER_REGISTRY)
