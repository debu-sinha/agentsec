"""Skill analyzer — deep analysis of agent skills/plugins for malicious patterns.

Analyzes skills installed in an agent for:
- Dangerous code patterns (exec, eval, subprocess, network exfiltration)
- Prompt injection vectors in skill descriptions and tool schemas
- Dependency risk (known vulnerable or typosquatted packages)
- Data exfiltration pathways
- Obfuscation techniques
- Integrity verification (checksums, signatures)
"""

from __future__ import annotations

import ast
import json
import logging
import re
from pathlib import Path

from agentsec.models.findings import (
    Finding,
    FindingCategory,
    FindingSeverity,
    Remediation,
)
from agentsec.scanners.base import BaseScanner, ScanContext

logger = logging.getLogger(__name__)

# Dangerous AST node types that indicate code execution capability
_DANGEROUS_AST_CALLS: dict[str, tuple[FindingSeverity, str]] = {
    "eval": (FindingSeverity.CRITICAL, "Arbitrary code execution via eval()"),
    "exec": (FindingSeverity.CRITICAL, "Arbitrary code execution via exec()"),
    "compile": (FindingSeverity.HIGH, "Dynamic code compilation"),
    "__import__": (FindingSeverity.HIGH, "Dynamic module import"),
    "getattr": (FindingSeverity.MEDIUM, "Dynamic attribute access — can bypass restrictions"),
    "setattr": (FindingSeverity.MEDIUM, "Dynamic attribute modification"),
}

# Module-level dangerous imports
_DANGEROUS_IMPORTS: dict[str, tuple[FindingSeverity, str]] = {
    "subprocess": (FindingSeverity.HIGH, "Shell command execution capability"),
    "os.system": (FindingSeverity.HIGH, "Shell command execution via os.system"),
    "os.popen": (FindingSeverity.HIGH, "Shell command execution via os.popen"),
    "os.exec": (FindingSeverity.HIGH, "Process replacement via os.exec*"),
    "shutil.rmtree": (FindingSeverity.MEDIUM, "Recursive directory deletion capability"),
    "ctypes": (FindingSeverity.HIGH, "Native code execution via ctypes"),
    "socket": (FindingSeverity.MEDIUM, "Raw network socket access"),
    "http.client": (FindingSeverity.LOW, "HTTP client (potential data exfiltration)"),
    "urllib": (FindingSeverity.LOW, "URL handling (potential data exfiltration)"),
    "requests": (FindingSeverity.LOW, "HTTP library (potential data exfiltration)"),
    "paramiko": (FindingSeverity.HIGH, "SSH client — remote access capability"),
    "fabric": (FindingSeverity.HIGH, "Remote execution framework"),
    "pickle": (FindingSeverity.HIGH, "Deserialization — arbitrary code execution risk"),
    "marshal": (FindingSeverity.HIGH, "Binary deserialization risk"),
    "shelve": (FindingSeverity.MEDIUM, "Persistent storage with pickle backend"),
    "tempfile": (FindingSeverity.LOW, "Temporary file creation"),
    "webbrowser": (FindingSeverity.MEDIUM, "Can open URLs in user's browser"),
    "smtplib": (FindingSeverity.MEDIUM, "Email sending capability"),
    "ftplib": (FindingSeverity.MEDIUM, "FTP client — data exfiltration vector"),
}

# Regex patterns for suspicious code constructs
_SUSPICIOUS_PATTERNS: list[tuple[str, re.Pattern[str], FindingSeverity, str]] = [
    (
        "Base64 encoded payload",
        re.compile(r"base64\.(b64decode|decodebytes)\s*\("),
        FindingSeverity.MEDIUM,
        "Decoding base64 payloads — common obfuscation technique",
    ),
    (
        "Encoded string execution",
        re.compile(r"exec\s*\(\s*(?:base64|codecs|bytes)"),
        FindingSeverity.CRITICAL,
        "Executing decoded/obfuscated code — strong malware indicator",
    ),
    (
        "Environment variable harvesting",
        re.compile(r"os\.environ(?:\[|\.get\s*\().*(?:KEY|TOKEN|SECRET|PASSWORD|CRED)", re.I),
        FindingSeverity.HIGH,
        "Accessing credential environment variables",
    ),
    (
        "File read of sensitive paths",
        re.compile(
            r"(?:open|read|Path)\s*\([^)]{0,500}(?:\.ssh|\.aws|\.env|\.gnupg|\.kube|credentials|"
            r"clawdbot\.json|openclaw\.json|SOUL\.md|\.git/config)",
            re.I,
        ),
        FindingSeverity.HIGH,
        "Reading sensitive configuration files",
    ),
    (
        "Reverse shell pattern",
        re.compile(
            r"(?:socket\.socket|subprocess\.Popen)[^;]{0,300}(?:connect|shell|/bin/(?:ba)?sh)",
            re.I,
        ),
        FindingSeverity.CRITICAL,
        "Reverse shell construction — strong malware indicator",
    ),
    (
        "Data exfiltration via HTTP",
        re.compile(
            r"(?:requests\.post|urllib\.request\.urlopen|http\.client)\s*\([^)]{0,300}"
            r"(?:api_key|token|secret|password|credential|\.env)",
            re.I,
        ),
        FindingSeverity.CRITICAL,
        "Sending credentials via HTTP — data exfiltration indicator",
    ),
    (
        "Crypto mining indicators",
        re.compile(r"(?:stratum|mining|hashrate|xmrig|coinhive)", re.I),
        FindingSeverity.CRITICAL,
        "Cryptocurrency mining indicators",
    ),
    (
        "DNS exfiltration",
        re.compile(r"(?:dns\.resolver|socket\.getaddrinfo).*(?:encode|b64|hex)"),
        FindingSeverity.HIGH,
        "DNS-based data exfiltration technique",
    ),
]

# Prompt injection patterns in skill descriptions/schemas
_PROMPT_INJECTION_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("Instruction override", re.compile(r"ignore\s+(?:previous|all|above)\s+instructions", re.I)),
    ("Role reassignment", re.compile(r"you\s+are\s+now\s+", re.I)),
    ("System prompt marker", re.compile(r"<\|(?:im_start|system|endoftext)\|>", re.I)),
    (
        "Hidden instruction",
        re.compile(r"<!--.*(?:execute|run|send|forward|ignore).*-->", re.I | re.DOTALL),
    ),
    ("Invisible unicode", re.compile(r"[\u200b\u200c\u200d\u2060\ufeff]")),
    ("Encoded instruction", re.compile(r"(?:&#x|\\u|%[0-9a-f]{2}){5,}", re.I)),
]

# --- Instruction malware patterns (CSK-001, CSK-004) ---
# These target skills that contain malicious INSTRUCTIONS (markdown/plaintext)
# rather than executable code. Skills can be pure markdown recipes.
_INSTRUCTION_MALWARE_PATTERNS: list[tuple[str, re.Pattern[str], FindingSeverity, str]] = [
    (
        "Remote pipe to shell",
        re.compile(
            r"(?:curl|wget)\s+[^\s|]+\s*\|\s*(?:sh|bash|zsh|sudo\s+(?:sh|bash))",
            re.I,
        ),
        FindingSeverity.CRITICAL,
        "Instructs piping remote content directly into a shell — classic malware delivery",
    ),
    (
        "PowerShell remote execution",
        re.compile(
            r"(?:Invoke-Expression|IEX|Invoke-WebRequest|iwr)\s*[\(\s]",
            re.I,
        ),
        FindingSeverity.CRITICAL,
        "PowerShell remote code execution pattern",
    ),
    (
        "Credential path targeting",
        re.compile(
            r"(?:~/\.openclaw|~/\.clawdbot|~/\.moltbot|auth-profiles\.json|"
            r"credentials/|~/\.ssh|~/\.aws|~/\.gnupg|~/\.kube/config)",
            re.I,
        ),
        FindingSeverity.HIGH,
        "References sensitive credential paths — possible data exfiltration targeting",
    ),
    (
        "Remote script install",
        re.compile(
            r"(?:https?://(?:pastebin\.com|paste\.ee|gist\.github|raw\.githubusercontent|"
            r"bit\.ly|tinyurl|t\.co|hastebin|dpaste|rentry)[^\s]*)",
            re.I,
        ),
        FindingSeverity.HIGH,
        "References a pastebin/shortener URL — common for hosting malicious payloads",
    ),
    (
        "Setup requests running scripts",
        re.compile(
            r"(?:run|execute|install|setup)\s+(?:this|the)\s+(?:script|command|code).*"
            r"(?:https?://|npm\s+(?:install|i)\s+(?!@openclaw))",
            re.I,
        ),
        FindingSeverity.HIGH,
        "Setup instructions requesting execution of external scripts",
    ),
]

# OpenClaw skill frontmatter keys that control dangerous capabilities
_DANGEROUS_SKILL_FRONTMATTER = {
    "filesystem": ("Filesystem access", FindingSeverity.MEDIUM),
    "network": ("Network access", FindingSeverity.MEDIUM),
    "env": ("Environment variable access", FindingSeverity.HIGH),
    "exec": ("Command execution", FindingSeverity.HIGH),
    "sensitive_data": ("Sensitive data access", FindingSeverity.HIGH),
}


class SkillAnalyzer(BaseScanner):
    """Analyzes agent skills and plugins for malicious patterns."""

    @property
    def name(self) -> str:
        return "skill"

    @property
    def description(self) -> str:
        return (
            "Deep analysis of agent skills for dangerous code patterns, prompt injection "
            "vectors, data exfiltration risks, and supply chain vulnerabilities."
        )

    def scan(self, context: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        target = context.target_path

        # Find skill directories
        skill_dirs = self._find_skill_directories(target)
        if not skill_dirs:
            logger.info("No skill directories found in %s", target)
            return findings

        for skill_dir in skill_dirs:
            findings.extend(self._analyze_skill(skill_dir, context))

        return findings

    def _find_skill_directories(self, target: Path) -> list[Path]:
        """Locate skill installation directories with OpenClaw precedence.

        OpenClaw loads skills with precedence:
          workspace/skills > ~/.openclaw/skills (managed) > bundled
        We scan workspace and managed (highest risk first).
        """
        skill_dirs: list[Path] = []
        candidate_paths = [
            # Workspace skills (highest precedence, highest risk)
            target / "skills",
            # Managed/local skills
            target / ".openclaw" / "skills",
            target / ".clawdbot" / "skills",
            target / ".moltbot" / "skills",
            # Legacy and secondary locations
            target / "plugins",
            target / ".config" / "openclaw" / "skills",
        ]

        # Check for extraDirs in config
        extra_dirs = self._get_extra_skill_dirs(target)
        candidate_paths.extend(extra_dirs)

        for candidate in candidate_paths:
            if candidate.is_dir():
                for child in candidate.iterdir():
                    if child.is_dir():
                        skill_dirs.append(child)
                for ext in ("*.py", "*.js", "*.ts", "*.md"):
                    for child in candidate.glob(ext):
                        skill_dirs.append(child)

        return skill_dirs

    def _get_extra_skill_dirs(self, target: Path) -> list[Path]:
        """Read skills.load.extraDirs from OpenClaw config."""
        dirs: list[Path] = []
        for config_name in ["openclaw.json", "clawdbot.json"]:
            config_path = target / config_name
            if not config_path.exists():
                config_path = target / ".openclaw" / config_name
            if not config_path.exists():
                continue
            try:
                data = json.loads(config_path.read_text())
                skills_config = data.get("skills", {})
                load_config = skills_config.get("load", {})
                extra = load_config.get("extraDirs", [])
                if isinstance(extra, list):
                    for d in extra:
                        p = Path(d).expanduser()
                        if p.is_dir():
                            dirs.append(p)
            except (json.JSONDecodeError, OSError):
                pass
        return dirs

    def _analyze_skill(self, skill_path: Path, context: ScanContext) -> list[Finding]:
        """Analyze a single skill for security issues."""
        findings: list[Finding] = []
        skill_name = skill_path.name

        # Analyze manifest if present
        findings.extend(self._check_manifest(skill_path, skill_name))

        # Check OpenClaw frontmatter for dangerous capability requests
        findings.extend(self._check_frontmatter(skill_path, skill_name))

        # Analyze all source files (code)
        source_files: list[Path] = []
        if skill_path.is_file():
            source_files = [skill_path]
        else:
            source_files = list(skill_path.rglob("*.py"))
            source_files.extend(skill_path.rglob("*.js"))
            source_files.extend(skill_path.rglob("*.ts"))

        for source_file in source_files:
            context.files_scanned += 1
            if source_file.suffix == ".py":
                findings.extend(self._analyze_python_source(source_file, skill_name))
            findings.extend(self._scan_regex_patterns(source_file, skill_name))

        # Scan markdown/instruction files for instruction malware
        md_files: list[Path] = []
        if skill_path.is_file() and skill_path.suffix == ".md":
            md_files = [skill_path]
        elif skill_path.is_dir():
            md_files = list(skill_path.rglob("*.md"))
            md_files.extend(skill_path.rglob("*.txt"))

        for md_file in md_files:
            context.files_scanned += 1
            findings.extend(self._scan_instruction_malware(md_file, skill_name))

        # Check dependencies
        findings.extend(self._check_dependencies(skill_path, skill_name))

        return findings

    def _check_manifest(self, skill_path: Path, skill_name: str) -> list[Finding]:
        """Check skill manifest for suspicious declarations."""
        findings: list[Finding] = []

        manifest_candidates = ["manifest.json", "package.json", "skill.json", "skill.yaml"]
        for manifest_name in manifest_candidates:
            manifest_path = (
                skill_path / manifest_name
                if skill_path.is_dir()
                else skill_path.parent / manifest_name
            )
            if not manifest_path.exists():
                continue

            try:
                data = json.loads(manifest_path.read_text())
            except (json.JSONDecodeError, OSError):
                continue

            # Check tool descriptions for prompt injection
            tools = data.get("tools", data.get("functions", []))
            if isinstance(tools, list):
                for tool in tools:
                    desc = tool.get("description", "")
                    tool_name = tool.get("name", "unknown")
                    for pattern_name, pattern in _PROMPT_INJECTION_PATTERNS:
                        if pattern.search(desc):
                            findings.append(
                                Finding(
                                    scanner=self.name,
                                    category=FindingCategory.PROMPT_INJECTION_VECTOR,
                                    severity=FindingSeverity.CRITICAL,
                                    title=(
                                        f"Prompt injection in skill '{skill_name}' tool description"
                                    ),
                                    description=(
                                        f"The tool '{tool_name}' in skill '{skill_name}' contains "
                                        f"a prompt injection pattern ({pattern_name}) in its "
                                        f"description. Tool descriptions are processed by the LLM "
                                        f"and can alter agent behavior."
                                    ),
                                    evidence=f"Pattern: {pattern_name} in tool '{tool_name}'",
                                    file_path=manifest_path,
                                    remediation=Remediation(
                                        summary=(
                                            f"Remove or sanitize tool description in '{skill_name}'"
                                        ),
                                        steps=[
                                            f"Review the tool description for '{tool_name}'",
                                            "Remove any instruction-like content from descriptions",
                                            "Report the skill to ClawHub if from marketplace",
                                        ],
                                    ),
                                    owasp_ids=["ASI01", "ASI03"],
                                )
                            )

            # Check for excessive permission requests
            permissions = data.get("permissions", data.get("capabilities", []))
            dangerous_perms = {"filesystem", "shell", "network", "browser", "admin", "root"}
            if isinstance(permissions, list):
                requested_dangerous = set(permissions) & dangerous_perms
                if len(requested_dangerous) >= 3:
                    findings.append(
                        Finding(
                            scanner=self.name,
                            category=FindingCategory.DANGEROUS_PATTERN,
                            severity=FindingSeverity.HIGH,
                            title=f"Excessive permissions requested by skill '{skill_name}'",
                            description=(
                                f"Skill '{skill_name}' requests {len(requested_dangerous)} "
                                f"dangerous permissions: {', '.join(sorted(requested_dangerous))}. "
                                f"Most legitimate skills need 1-2 permissions."
                            ),
                            evidence=f"Requested: {sorted(requested_dangerous)}",
                            file_path=manifest_path,
                            remediation=Remediation(
                                summary="Review whether all requested permissions are necessary",
                                steps=[
                                    "Evaluate each permission against the skill's stated purpose",
                                    "Deny unnecessary permissions",
                                    "Consider using a sandboxed environment for this skill",
                                ],
                            ),
                            owasp_ids=["ASI02", "ASI03"],
                        )
                    )

        return findings

    def _analyze_python_source(self, file_path: Path, skill_name: str) -> list[Finding]:
        """AST-based analysis of Python source files."""
        findings: list[Finding] = []

        try:
            source = file_path.read_text(errors="replace")
            tree = ast.parse(source, filename=str(file_path))
        except (SyntaxError, OSError):
            return findings

        for node in ast.walk(tree):
            # Check for dangerous function calls
            if isinstance(node, ast.Call):
                func_name = self._get_call_name(node)
                if func_name and func_name in _DANGEROUS_AST_CALLS:
                    severity, desc = _DANGEROUS_AST_CALLS[func_name]
                    findings.append(
                        Finding(
                            scanner=self.name,
                            category=FindingCategory.DANGEROUS_PATTERN,
                            severity=severity,
                            title=f"Dangerous call '{func_name}()' in skill '{skill_name}'",
                            description=(
                                f"{desc}. Found in '{file_path.name}'. "
                                f"This pattern allows arbitrary code execution and is "
                                f"a common indicator of malicious skills."
                            ),
                            file_path=file_path,
                            line_number=getattr(node, "lineno", None),
                            remediation=Remediation(
                                summary=f"Remove or sandbox the '{func_name}()' call",
                                steps=[
                                    f"Review the use of {func_name}() at line {node.lineno}",
                                    "Determine if a safer alternative exists",
                                    "If the call is legitimate, document the justification",
                                ],
                            ),
                            owasp_ids=["ASI02", "ASI03"],
                        )
                    )

            # Check for dangerous imports
            if isinstance(node, ast.Import | ast.ImportFrom):
                imported_names = self._get_import_names(node)
                for imp_name in imported_names:
                    for dangerous_mod, (severity, desc) in _DANGEROUS_IMPORTS.items():
                        if imp_name == dangerous_mod or imp_name.startswith(dangerous_mod + "."):
                            findings.append(
                                Finding(
                                    scanner=self.name,
                                    category=FindingCategory.DANGEROUS_PATTERN,
                                    severity=severity,
                                    title=f"Dangerous import '{imp_name}' in skill '{skill_name}'",
                                    description=(
                                        f"{desc}. Skills should not need direct access to "
                                        f"'{dangerous_mod}' in most cases."
                                    ),
                                    file_path=file_path,
                                    line_number=getattr(node, "lineno", None),
                                    remediation=Remediation(
                                        summary=f"Review whether '{imp_name}' is necessary",
                                        steps=[
                                            "Check if the skill's functionality "
                                            "requires this import",
                                            "Consider sandboxing the skill if the import is needed",
                                        ],
                                    ),
                                    owasp_ids=["ASI02", "ASI03"],
                                )
                            )
                            break

        return findings

    def _scan_regex_patterns(self, file_path: Path, skill_name: str) -> list[Finding]:
        """Regex-based pattern matching for suspicious constructs."""
        findings: list[Finding] = []

        try:
            content = file_path.read_text(errors="replace")
        except OSError:
            return findings

        for pattern_name, pattern, severity, desc in _SUSPICIOUS_PATTERNS:
            for match in pattern.finditer(content):
                line_num = content[: match.start()].count("\n") + 1
                findings.append(
                    Finding(
                        scanner=self.name,
                        category=FindingCategory.DATA_EXFILTRATION_RISK,
                        severity=severity,
                        title=f"{pattern_name} in skill '{skill_name}'",
                        description=f"{desc}. Found in '{file_path.name}'.",
                        evidence=f"Match: '{match.group(0)[:80]}' at line {line_num}",
                        file_path=file_path,
                        line_number=line_num,
                        owasp_ids=["ASI03", "ASI05"],
                    )
                )

        # Also check for prompt injection in string literals
        for pattern_name, pattern in _PROMPT_INJECTION_PATTERNS:
            for match in pattern.finditer(content):
                line_num = content[: match.start()].count("\n") + 1
                findings.append(
                    Finding(
                        scanner=self.name,
                        category=FindingCategory.PROMPT_INJECTION_VECTOR,
                        severity=FindingSeverity.HIGH,
                        title=f"Prompt injection pattern in skill '{skill_name}'",
                        description=(
                            f"Found '{pattern_name}' pattern in '{file_path.name}'. "
                            f"This may be an attempt to manipulate the agent's behavior "
                            f"through prompt injection embedded in skill code."
                        ),
                        evidence=f"Pattern: '{match.group(0)[:60]}' at line {line_num}",
                        file_path=file_path,
                        line_number=line_num,
                        remediation=Remediation(
                            summary="Remove prompt injection pattern from skill source",
                            steps=[
                                "Review the context of the pattern",
                                "Remove if malicious; document if false positive",
                                "Report to ClawHub if skill is from marketplace",
                            ],
                        ),
                        owasp_ids=["ASI01", "ASI03"],
                    )
                )

        return findings

    def _check_dependencies(self, skill_path: Path, skill_name: str) -> list[Finding]:
        """Check skill dependencies for known risks."""
        findings: list[Finding] = []

        if not skill_path.is_dir():
            return findings

        # Check requirements.txt
        req_files = ["requirements.txt", "package.json"]
        for req_name in req_files:
            req_path = skill_path / req_name
            if not req_path.exists():
                continue

            if req_name == "requirements.txt":
                findings.extend(self._check_python_requirements(req_path, skill_name))
            elif req_name == "package.json":
                findings.extend(self._check_npm_dependencies(req_path, skill_name))

        return findings

    def _check_python_requirements(self, req_path: Path, skill_name: str) -> list[Finding]:
        """Check Python requirements for unpinned or suspicious packages."""
        findings: list[Finding] = []

        try:
            lines = req_path.read_text().strip().splitlines()
        except OSError:
            return findings

        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            # Check for unpinned dependencies
            if "==" not in line and ">=" not in line and line.strip() not in (".", "-e ."):
                findings.append(
                    Finding(
                        scanner=self.name,
                        category=FindingCategory.DEPENDENCY_RISK,
                        severity=FindingSeverity.MEDIUM,
                        title=f"Unpinned dependency in skill '{skill_name}'",
                        description=(
                            f"Dependency '{line}' is not version-pinned. "
                            f"Unpinned dependencies can be silently replaced via "
                            f"supply chain attacks."
                        ),
                        evidence=f"Line {line_num}: {line}",
                        file_path=req_path,
                        line_number=line_num,
                        remediation=Remediation(
                            summary="Pin dependency to a specific version with hash",
                            steps=[
                                f"Pin '{line}' to a specific version (e.g., package==1.2.3)",
                                "Use --hash for additional integrity verification",
                            ],
                        ),
                        owasp_ids=["ASI03"],
                    )
                )

        return findings

    def _check_npm_dependencies(self, pkg_path: Path, skill_name: str) -> list[Finding]:
        """Check npm package.json for suspicious or risky dependencies."""
        findings: list[Finding] = []

        try:
            data = json.loads(pkg_path.read_text())
        except (json.JSONDecodeError, OSError):
            return findings

        # Check install scripts (common supply chain attack vector)
        scripts = data.get("scripts", {})
        dangerous_scripts = {"preinstall", "postinstall", "install"}
        for script_name in dangerous_scripts:
            if script_name in scripts:
                script_content = scripts[script_name]
                findings.append(
                    Finding(
                        scanner=self.name,
                        category=FindingCategory.SUPPLY_CHAIN,
                        severity=FindingSeverity.HIGH,
                        title=f"Install hook in skill '{skill_name}': {script_name}",
                        description=(
                            f"The skill has a '{script_name}' script that runs automatically "
                            f"during installation: '{script_content[:100]}'. Install hooks "
                            f"are the primary vector for npm supply chain attacks."
                        ),
                        evidence=f"{script_name}: {script_content[:120]}",
                        file_path=pkg_path,
                        remediation=Remediation(
                            summary=f"Review the '{script_name}' hook before installing",
                            steps=[
                                "Read the script content carefully",
                                "Check if it downloads or executes external code",
                                "Use --ignore-scripts flag during installation if unsure",
                            ],
                        ),
                        owasp_ids=["ASI03"],
                    )
                )

        return findings

    def _scan_instruction_malware(self, file_path: Path, skill_name: str) -> list[Finding]:
        """Scan markdown/instruction files for malicious patterns (CSK-001, CSK-004)."""
        findings: list[Finding] = []

        try:
            content = file_path.read_text(errors="replace")
        except OSError:
            return findings

        for pattern_name, pattern, severity, desc in _INSTRUCTION_MALWARE_PATTERNS:
            for match in pattern.finditer(content):
                line_num = content[: match.start()].count("\n") + 1
                findings.append(
                    Finding(
                        scanner=self.name,
                        category=FindingCategory.MALICIOUS_SKILL,
                        severity=severity,
                        title=f"{pattern_name} in skill '{skill_name}'",
                        description=f"{desc}. Found in '{file_path.name}'.",
                        evidence=f"Match: '{match.group(0)[:100]}' at line {line_num}",
                        file_path=file_path,
                        line_number=line_num,
                        remediation=Remediation(
                            summary=f"Quarantine skill '{skill_name}' and investigate",
                            steps=[
                                "Do NOT follow the instructions in this skill",
                                f"Run: agentsec skill quarantine {skill_name}",
                                "Report to ClawHub if the skill is from marketplace",
                                "Check other skills from the same author",
                            ],
                        ),
                        owasp_ids=["ASI01", "ASI03"],
                    )
                )

        # Also check for prompt injection in instruction files
        for pattern_name, pattern in _PROMPT_INJECTION_PATTERNS:
            for match in pattern.finditer(content):
                line_num = content[: match.start()].count("\n") + 1
                findings.append(
                    Finding(
                        scanner=self.name,
                        category=FindingCategory.PROMPT_INJECTION_VECTOR,
                        severity=FindingSeverity.HIGH,
                        title=f"Prompt injection in skill instructions '{skill_name}'",
                        description=(
                            f"Found '{pattern_name}' in '{file_path.name}'. Skill instructions "
                            f"are injected into the LLM prompt and can manipulate the agent."
                        ),
                        evidence=f"Pattern: '{match.group(0)[:60]}' at line {line_num}",
                        file_path=file_path,
                        line_number=line_num,
                        owasp_ids=["ASI01", "ASI03"],
                    )
                )

        return findings

    def _check_frontmatter(self, skill_path: Path, skill_name: str) -> list[Finding]:
        """Check OpenClaw skill frontmatter for dangerous capability requests (CSK-005).

        Skills declare capabilities via frontmatter like:
          ---
          disable-model-invocation: false
          requires:
            filesystem: true
            exec: true
          ---
        """
        findings: list[Finding] = []

        # Find the main skill file (usually README.md, index.md, or skill.md)
        md_files: list[Path] = []
        if skill_path.is_file() and skill_path.suffix == ".md":
            md_files = [skill_path]
        elif skill_path.is_dir():
            for name in ["README.md", "index.md", "skill.md"]:
                candidate = skill_path / name
                if candidate.exists():
                    md_files.append(candidate)
            if not md_files:
                md_files = list(skill_path.glob("*.md"))[:1]

        for md_file in md_files:
            try:
                content = md_file.read_text(errors="replace")
            except OSError:
                continue

            # Parse YAML frontmatter
            if not content.startswith("---"):
                continue

            end = content.find("---", 3)
            if end == -1:
                continue

            frontmatter = content[3:end].strip()

            # Check disable-model-invocation (CSK-005)
            # If a skill has dangerous tools but doesn't disable model invocation,
            # the skill's instructions get injected into the prompt
            has_dangerous = False
            requested_caps: list[str] = []
            for cap, (desc, _severity) in _DANGEROUS_SKILL_FRONTMATTER.items():
                # Simple YAML parsing for key: true patterns
                pattern = re.compile(rf"^\s*{re.escape(cap)}\s*:\s*(?:true|yes)\s*$", re.I | re.M)
                if pattern.search(frontmatter):
                    has_dangerous = True
                    requested_caps.append(f"{cap} ({desc})")

            if has_dangerous:
                # Check if disable-model-invocation is set
                dmi_pattern = re.compile(
                    r"^\s*disable-model-invocation\s*:\s*(?:true|yes)\s*$", re.I | re.M
                )
                if not dmi_pattern.search(frontmatter):
                    findings.append(
                        Finding(
                            scanner=self.name,
                            category=FindingCategory.DANGEROUS_PATTERN,
                            severity=FindingSeverity.MEDIUM,
                            title=(
                                f"Skill '{skill_name}' has dangerous caps "
                                f"without disable-model-invocation"
                            ),
                            description=(
                                f"Skill '{skill_name}' requests dangerous capabilities "
                                f"({', '.join(requested_caps)}) but does not set "
                                f"disable-model-invocation: true. This means the skill's "
                                f"full instructions are injected into the LLM prompt, "
                                f"increasing the attack surface for prompt injection."
                            ),
                            evidence=f"Capabilities: {', '.join(requested_caps)}",
                            file_path=md_file,
                            remediation=Remediation(
                                summary="Add disable-model-invocation: true to skill frontmatter",
                                steps=[
                                    "Add 'disable-model-invocation: true' "
                                    "to the skill's YAML frontmatter",
                                    "Or review whether the skill truly needs these capabilities",
                                ],
                                references=["https://docs.openclaw.ai/tools/skills"],
                            ),
                            owasp_ids=["ASI01", "ASI02"],
                        )
                    )

        return findings

    # Modules whose .compile() method is safe (not the builtin compile())
    _SAFE_COMPILE_MODULES = {"re", "regex", "pattern", "sre_compile"}

    @staticmethod
    def _get_call_name(node: ast.Call) -> str | None:
        """Extract function name from an AST Call node.

        Returns None for known-safe method calls like re.compile()
        to avoid false positives on the builtin compile() check.
        """
        if isinstance(node.func, ast.Name):
            return node.func.id
        if isinstance(node.func, ast.Attribute):
            attr = node.func.attr
            # Skip re.compile() and similar -- not the dangerous builtin compile()
            if (
                attr == "compile"
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id in SkillAnalyzer._SAFE_COMPILE_MODULES
            ):
                return None
            return attr
        return None

    @staticmethod
    def _get_import_names(node: ast.Import | ast.ImportFrom) -> list[str]:
        """Extract imported module names from an AST Import node."""
        if isinstance(node, ast.Import):
            return [alias.name for alias in node.names]
        if isinstance(node, ast.ImportFrom) and node.module:
            return [node.module]
        return []
