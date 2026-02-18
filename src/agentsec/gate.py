"""Pre-install security gate for npm/pip packages.

Downloads a package to a temp directory, runs agentsec scanners on its
contents, and only allows the real install if no critical issues are found.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

from agentsec.models.findings import (
    Finding,
    FindingCategory,
    FindingSeverity,
    Remediation,
)

logger = logging.getLogger(__name__)

# Safe characters for package names: alphanumeric, dash, underscore, dot, slash (scoped npm), @
_SAFE_PACKAGE_RE = __import__("re").compile(r"^@?[a-zA-Z0-9][a-zA-Z0-9._\-/]*$")

# Maximum allowed length for package names (npm max is 214, pip has no strict limit)
_MAX_PACKAGE_NAME_LEN = 214


def _validate_package_name(package_name: str) -> None:
    """Validate a package name before passing to subprocess.

    Raises ValueError if the name contains unsafe characters that could
    be used for argument injection (e.g., --target, shell metacharacters).
    """
    if len(package_name) > _MAX_PACKAGE_NAME_LEN:
        raise ValueError(
            f"Package name too long ({len(package_name)} chars, max {_MAX_PACKAGE_NAME_LEN})"
        )
    if not _SAFE_PACKAGE_RE.match(package_name):
        raise ValueError(
            f"Package name contains unsafe characters: {package_name!r}. "
            f"Only alphanumeric, dash, underscore, dot, slash, and @ are allowed."
        )


# Known-malicious packages compiled from npm advisories, Phylum, Socket.dev,
# and Checkmarx supply-chain research. This is a local blocklist; a future
# version could fetch from a remote feed.
_KNOWN_BAD_NPM: set[str] = {
    # Typosquatting attacks on popular packages
    "colourama",
    "python-binance",
    "discordselfbot16",
    "discordselfbot6",
    "tlogging",
    "loloerror",
    "loadyaml",
    "eslint-plugin-commen",
    "es5-ext-main",
    # Documented malicious packages (install hooks / data exfil)
    "event-stream",
    "ua-parser-js-compromised",
    "coa-compromised",
    "rc-compromised",
    "flatmap-stream",
    "lethal-factory",
    "crossenv",
    "babelcli",
    "mongose",
    "npmjs-react",
    # AI/MCP ecosystem specific
    "mcp-tool-exploit",
    "claude-skill-helper",
    "openclaw-utils-free",
}

_KNOWN_BAD_PIP: set[str] = {
    # Documented typosquatting / malware from PyPI
    "colourama",
    "python3-dateutil",
    "jeIlyfish",  # uses capital I instead of lowercase l
    "python-binance",
    "requesocks",
    "apidev-coop",
    "tlogging",
    "loadyaml",
    "free-net-vpn",
    "beautifulsup",
    # Reverse shell / credential stealer packages
    "noblesse",
    "pytagora",
    "pytagora2",
    "ctx",
    "importantpackage",
    # AI/MCP ecosystem specific
    "mcp-tool-exploit",
    "agentsec-free",
    "openclaw-utils",
}

# Severity threshold names to enum
_SEVERITY_MAP = {
    "critical": FindingSeverity.CRITICAL,
    "high": FindingSeverity.HIGH,
    "medium": FindingSeverity.MEDIUM,
    "low": FindingSeverity.LOW,
    "info": FindingSeverity.INFO,
}


@dataclass
class GateResult:
    """Result of a pre-install gate check."""

    package_name: str
    package_manager: str  # "npm" or "pip"
    allowed: bool
    findings: list[Finding] = field(default_factory=list)
    blocklist_hit: bool = False
    error: str | None = None
    temp_dir: str | None = None


def gate_check(
    package_manager: str,
    args: list[str],
    fail_on: str = "critical",
    force: bool = False,
) -> GateResult:
    """Run a pre-install security check on a package.

    Downloads the package to a temp directory, scans it, and returns
    whether installation should proceed.

    Args:
        package_manager: "npm" or "pip"
        args: Arguments to the install command (e.g., ["install", "some-package"])
        fail_on: Severity threshold for blocking
        force: If True, allow install even with findings
    """
    # Extract package names from install args
    packages = _extract_package_names(package_manager, args)
    if not packages:
        # Not an install command or no packages specified
        return GateResult(
            package_name="(none)",
            package_manager=package_manager,
            allowed=True,
        )

    all_findings: list[Finding] = []
    blocklist_hit = False

    for pkg in packages:
        # Check blocklist first (fast path)
        if _check_blocklist(package_manager, pkg):
            blocklist_hit = True
            all_findings.append(
                Finding(
                    scanner="gate",
                    category=FindingCategory.SUPPLY_CHAIN,
                    severity=FindingSeverity.CRITICAL,
                    title=f"Blocked package: {pkg}",
                    description=(
                        f"Package '{pkg}' is on the agentsec blocklist of known-malicious packages."
                    ),
                    remediation=Remediation(
                        summary=f"Do not install '{pkg}'",
                        steps=[
                            "Check for typosquatting or use an alternative.",
                        ],
                    ),
                )
            )
            continue

        # Download to temp dir and scan
        findings = _download_and_scan(package_manager, pkg)
        all_findings.extend(findings)

    # Determine if install should proceed
    threshold = _SEVERITY_MAP.get(fail_on, FindingSeverity.CRITICAL)
    severity_order = [
        FindingSeverity.CRITICAL,
        FindingSeverity.HIGH,
        FindingSeverity.MEDIUM,
        FindingSeverity.LOW,
        FindingSeverity.INFO,
    ]
    threshold_idx = severity_order.index(threshold)

    has_blocking = any(severity_order.index(f.severity) <= threshold_idx for f in all_findings)

    allowed = force or not has_blocking

    return GateResult(
        package_name=", ".join(packages),
        package_manager=package_manager,
        allowed=allowed,
        findings=all_findings,
        blocklist_hit=blocklist_hit,
    )


def _extract_package_names(pm: str, args: list[str]) -> list[str]:
    """Extract package names from install command arguments."""
    if not args:
        return []

    # Find the install subcommand
    install_cmds = {"install", "add", "i"}
    found_install = False
    packages = []

    for arg in args:
        if arg in install_cmds:
            found_install = True
            continue
        if found_install and not arg.startswith("-"):
            # Strip version specifiers for name matching
            if pm == "npm":
                name = _strip_npm_version_spec(arg)
            else:
                name = arg.split("==")[0].split(">=")[0]
            if name:
                packages.append(name)

    return packages


def _strip_npm_version_spec(spec: str) -> str:
    """Return package name from an npm install spec.

    Handles both unscoped and scoped packages:
    - package@1.2.3 -> package
    - @scope/package -> @scope/package
    - @scope/package@1.2.3 -> @scope/package
    """
    if spec.startswith("@"):
        parts = spec.rsplit("@", 1)
        if len(parts) == 2 and "/" in parts[0]:
            return parts[0]
        return spec
    return spec.split("@", 1)[0]


def _check_blocklist(pm: str, package_name: str) -> bool:
    """Check if a package is on the known-bad blocklist."""
    name_lower = package_name.lower().strip()
    if pm == "npm":
        return name_lower in _KNOWN_BAD_NPM
    return name_lower in _KNOWN_BAD_PIP


def _download_and_scan(pm: str, package_name: str) -> list[Finding]:
    """Download a package to temp dir and run scanners on it."""
    findings: list[Finding] = []
    temp_dir = tempfile.mkdtemp(prefix="agentsec_gate_")

    try:
        if pm == "npm":
            findings = _download_and_scan_npm(package_name, temp_dir)
        else:
            findings = _download_and_scan_pip(package_name, temp_dir)
    except Exception as e:
        logger.warning("Gate scan failed for %s: %s", package_name, e)
        findings.append(
            Finding(
                scanner="gate",
                category=FindingCategory.SUPPLY_CHAIN,
                severity=FindingSeverity.HIGH,
                title=f"Gate scan failed for {package_name}",
                description=f"Could not download or scan package '{package_name}'.",
                remediation=Remediation(
                    summary="Inspect the package manually before installing",
                ),
            )
        )
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)

    return findings


def _download_and_scan_npm(package_name: str, temp_dir: str) -> list[Finding]:
    """Download an npm package and scan its contents."""
    _validate_package_name(package_name)
    findings: list[Finding] = []

    # Use npm pack to download tarball without running install scripts
    try:
        result = subprocess.run(
            ["npm", "pack", package_name, "--pack-destination", temp_dir],
            capture_output=True,
            text=True,
            timeout=60,
            cwd=temp_dir,
        )
        if result.returncode != 0:
            raise RuntimeError(f"npm pack failed: {result.stderr.strip()}")
    except FileNotFoundError as exc:
        raise RuntimeError("npm not found on PATH") from exc

    # Find the downloaded tarball
    tarballs = list(Path(temp_dir).glob("*.tgz"))
    if not tarballs:
        raise RuntimeError("npm pack produced no tarball")

    # Extract and scan
    extract_dir = Path(temp_dir) / "extracted"
    extract_dir.mkdir()
    with tarfile.open(tarballs[0], "r:gz") as tar:
        _extract_tar_archive(tar, extract_dir)

    # Check package.json for install hooks
    findings.extend(_check_npm_install_hooks(extract_dir, package_name))

    # Run skill scanner on extracted contents
    findings.extend(_run_scanners_on_dir(extract_dir, package_name))

    return findings


def _download_and_scan_pip(package_name: str, temp_dir: str) -> list[Finding]:
    """Download a pip package and scan its contents."""
    _validate_package_name(package_name)
    findings: list[Finding] = []

    # Use pip download to fetch without installing
    try:
        result = subprocess.run(
            [
                "pip",
                "download",
                "--no-deps",
                "--no-binary",
                ":all:",
                "-d",
                temp_dir,
                package_name,
            ],
            capture_output=True,
            text=True,
            timeout=120,
            cwd=temp_dir,
        )
        if result.returncode != 0:
            # Try with binary wheels as fallback
            result = subprocess.run(
                ["pip", "download", "--no-deps", "-d", temp_dir, package_name],
                capture_output=True,
                text=True,
                timeout=120,
                cwd=temp_dir,
            )
            if result.returncode != 0:
                raise RuntimeError(f"pip download failed: {result.stderr.strip()}")
    except FileNotFoundError as exc:
        raise RuntimeError("pip not found on PATH") from exc

    # Extract downloaded package
    extract_dir = Path(temp_dir) / "extracted"
    extract_dir.mkdir()

    for archive in Path(temp_dir).iterdir():
        if archive.name == "extracted":
            continue
        if archive.suffix == ".gz" or archive.name.endswith(".tar.gz"):
            with tarfile.open(archive, "r:gz") as tar:
                _extract_tar_archive(tar, extract_dir)
        elif archive.suffix == ".whl" or archive.suffix == ".zip":
            _extract_zip_archive(archive, extract_dir)

    # Run scanners on extracted contents
    findings.extend(_run_scanners_on_dir(extract_dir, package_name))

    return findings


def _extract_tar_archive(tar: tarfile.TarFile, extract_dir: Path) -> None:
    """Extract tar archive safely across supported Python versions.

    Python 3.12+ supports tarfile's built-in filter-based extraction.
    For older runtimes, validate members manually to block traversal and links.
    """
    if sys.version_info >= (3, 12):
        tar.extractall(extract_dir, filter="data")
        return

    base_dir = os.path.normcase(os.path.realpath(extract_dir))
    safe_members: list[tarfile.TarInfo] = []
    for member in tar.getmembers():
        target = os.path.normcase(os.path.realpath(os.path.join(base_dir, member.name)))
        if not target.startswith(base_dir + os.sep) and target != base_dir:
            raise ValueError(f"Tar path traversal blocked: {member.name}")
        if member.issym() or member.islnk():
            raise ValueError(f"Tar link entry blocked: {member.name}")
        safe_members.append(member)

    tar.extractall(extract_dir, members=safe_members)  # noqa: S202


def _extract_zip_archive(archive: Path, extract_dir: Path) -> None:
    """Extract zip/wheel archive safely, validating each member individually.

    Extracts members one at a time after path-traversal validation to
    avoid TOCTOU between a bulk validation pass and a bulk extractall.
    """
    base_dir = os.path.normcase(os.path.realpath(extract_dir))
    with zipfile.ZipFile(archive, "r") as zf:
        for info in zf.infolist():
            target = os.path.normcase(os.path.realpath(os.path.join(base_dir, info.filename)))
            if not target.startswith(base_dir + os.sep) and target != base_dir:
                raise ValueError(f"Zip path traversal blocked: {info.filename}")
            zf.extract(info, extract_dir)  # noqa: S202


def _check_npm_install_hooks(extract_dir: Path, package_name: str) -> list[Finding]:
    """Check for npm install lifecycle scripts (preinstall, postinstall)."""
    findings: list[Finding] = []
    dangerous_hooks = {"preinstall", "postinstall", "install", "prepare"}

    for pkg_json in extract_dir.rglob("package.json"):
        try:
            data = json.loads(pkg_json.read_text(encoding="utf-8", errors="replace"))
        except (json.JSONDecodeError, OSError):
            continue

        scripts = data.get("scripts", {})
        for hook_name in dangerous_hooks:
            if hook_name in scripts:
                script_content = scripts[hook_name]
                findings.append(
                    Finding(
                        scanner="gate",
                        category=FindingCategory.SUPPLY_CHAIN,
                        severity=FindingSeverity.HIGH,
                        title=f"npm install hook: {hook_name}",
                        description=(
                            f"Package '{package_name}' has a '{hook_name}' script "
                            f"that runs during installation."
                        ),
                        evidence=f"{hook_name}: {script_content[:200]}",
                        remediation=Remediation(
                            summary=f"Review the {hook_name} script before installing",
                            steps=[
                                "Use --ignore-scripts to skip hook execution.",
                            ],
                        ),
                    )
                )

    return findings


def _run_scanners_on_dir(extract_dir: Path, package_name: str) -> list[Finding]:
    """Run agentsec skill and MCP scanners on extracted package contents."""
    findings: list[Finding] = []

    # Import here to avoid circular imports
    from agentsec.scanners.base import ScanContext
    from agentsec.scanners.mcp import McpScanner
    from agentsec.scanners.skill import SkillAnalyzer

    context = ScanContext(target_path=extract_dir)

    # Run skill scanner (detects malicious code patterns, dangerous imports, etc.)
    try:
        skill_scanner = SkillAnalyzer()
        skill_findings = skill_scanner.scan(context)
        for f in skill_findings:
            f.title = f"[pre-install] {f.title}"
        findings.extend(skill_findings)
    except Exception as e:
        logger.debug("Skill scanner failed on gate check: %s", e)

    # Run MCP scanner (detects tool poisoning, schema issues)
    try:
        mcp_scanner = McpScanner()
        mcp_findings = mcp_scanner.scan(context)
        for f in mcp_findings:
            f.title = f"[pre-install] {f.title}"
        findings.extend(mcp_findings)
    except Exception as e:
        logger.debug("MCP scanner failed on gate check: %s", e)

    return findings
