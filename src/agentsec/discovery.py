"""Auto-discovery of installed AI agents.

Scans the local filesystem for known AI agent installations by checking
marker paths, config files, and MCP configuration locations from the
agent registry. Works across macOS, Linux, and Windows.
"""

from __future__ import annotations

import glob
import logging
import os
import platform
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from agentsec.models.agents import AGENT_REGISTRY

logger = logging.getLogger(__name__)


@dataclass
class DiscoveredAgent:
    """Result of discovering an installed AI agent."""

    name: str
    display_name: str
    agent_type: str
    install_path: Path | None
    config_dir: Path | None
    version: str | None
    mcp_config_paths: list[Path]
    config_files_found: list[Path]
    scope: str  # "global" or "project"
    supported: bool


def _expand_path(raw: str) -> str:
    """Expand ~ and environment variables in a path string."""
    return os.path.expandvars(os.path.expanduser(raw))


def _resolve_paths(raw_paths: list[str]) -> list[Path]:
    """Expand and resolve a list of path strings, returning those that exist.

    Handles glob patterns (e.g. paths containing *) by expanding them.
    """
    found: list[Path] = []
    for raw in raw_paths:
        expanded = _expand_path(raw)
        if "*" in expanded or "?" in expanded:
            matches = glob.glob(expanded)
            for m in matches:
                p = Path(m)
                if p.exists():
                    found.append(p)
        else:
            p = Path(expanded)
            if p.exists():
                found.append(p)
    return found


def _resolve_project_paths(raw_paths: list[str], target: Path) -> list[Path]:
    """Resolve paths relative to a project target directory.

    Only considers paths that look project-relative (no ~ or env vars at start).
    """
    found: list[Path] = []
    for raw in raw_paths:
        if raw.startswith("~") or raw.startswith("%") or raw.startswith("$"):
            continue
        candidate = target / raw
        if "*" in str(candidate) or "?" in str(candidate):
            matches = glob.glob(str(candidate))
            for m in matches:
                p = Path(m)
                if p.exists():
                    found.append(p)
        elif candidate.exists():
            found.append(candidate)
    return found


def _detect_version(binary_names: list[str]) -> str | None:
    """Try to detect an agent's version by running its binary with --version."""
    for binary in binary_names:
        which_result = shutil.which(binary)
        if not which_result:
            continue
        try:
            result = subprocess.run(
                [which_result, "--version"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            output = (result.stdout or "").strip()
            if not output:
                output = (result.stderr or "").strip()
            if output:
                # Take the first line, strip common prefixes
                first_line = output.splitlines()[0].strip()
                return first_line
        except (subprocess.TimeoutExpired, OSError, subprocess.SubprocessError):
            logger.debug("Failed to get version for %s", binary)
            continue
    return None


def discover_agents(
    target: Path | None = None,
    detect_versions: bool = False,
) -> list[DiscoveredAgent]:
    """Discover installed AI agents on this system.

    Checks each agent in AGENT_REGISTRY for the presence of marker paths,
    config files, and MCP configurations on the current OS.

    Args:
        target: Optional project directory to also check for project-level
            agent configs (e.g. .cursor/mcp.json, .vscode/mcp.json).
        detect_versions: If True, attempt to detect agent versions by
            running their binaries with --version.

    Returns:
        List of DiscoveredAgent sorted by display_name.
    """
    current_os = platform.system().lower()
    # Normalize platform.system() output to match registry keys
    os_key_map = {
        "darwin": "darwin",
        "linux": "linux",
        "windows": "windows",
    }
    os_key = os_key_map.get(current_os)
    if os_key is None:
        logger.warning("Unsupported platform: %s", current_os)
        return []

    discovered: list[DiscoveredAgent] = []

    for agent_def in AGENT_REGISTRY.values():
        marker_paths_raw = agent_def.marker_paths.get(os_key, [])
        config_paths_raw = agent_def.config_paths.get(os_key, [])
        mcp_paths_raw = agent_def.mcp_config_paths.get(os_key, [])

        # Check global marker paths
        global_markers = _resolve_paths(marker_paths_raw)

        # Check project-level paths
        project_configs: list[Path] = []
        project_mcp: list[Path] = []
        if target is not None:
            project_configs = _resolve_project_paths(config_paths_raw, target)
            project_mcp = _resolve_project_paths(mcp_paths_raw, target)

        has_global = len(global_markers) > 0
        has_project = len(project_configs) > 0 or len(project_mcp) > 0

        if not has_global and not has_project:
            continue

        # Collect all config files that exist (global + project)
        global_configs = _resolve_paths(config_paths_raw)
        global_mcp = _resolve_paths(mcp_paths_raw)

        all_configs = list(dict.fromkeys(global_configs + project_configs))
        all_mcp = list(dict.fromkeys(global_mcp + project_mcp))

        # Determine install path from first marker
        install_path = global_markers[0] if global_markers else None

        # Determine config dir from first config found
        config_dir = None
        if all_configs:
            config_dir = all_configs[0].parent
        elif install_path:
            config_dir = install_path if install_path.is_dir() else install_path.parent

        # Version detection
        version = None
        if detect_versions and agent_def.binary_names:
            version = _detect_version(agent_def.binary_names)

        scope = "project" if (has_project and not has_global) else "global"

        discovered.append(
            DiscoveredAgent(
                name=agent_def.name,
                display_name=agent_def.display_name,
                agent_type=agent_def.agent_type,
                install_path=install_path,
                config_dir=config_dir,
                version=version,
                mcp_config_paths=all_mcp,
                config_files_found=all_configs,
                scope=scope,
                supported=agent_def.supported,
            )
        )

    discovered.sort(key=lambda a: a.display_name)
    return discovered
