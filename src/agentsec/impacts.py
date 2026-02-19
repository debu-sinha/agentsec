"""Centralized plain-language impact descriptions for scan findings.

Each impact answers: "[WHO] can [ACTION] [CONSEQUENCE]" in <=65 chars.
Applied as a post-processing step after scanners produce findings.
"""

from __future__ import annotations

import re

from agentsec.models.findings import Finding

# Maps (title regex pattern) -> impact string.
# Order matters: first match wins. More specific patterns first.
_IMPACT_MAP: list[tuple[str, str]] = [
    # ── Installation scanner ────────────────────────────────────
    # Gateway / network
    (
        r"gateway.*non-loopback|bind.*(?:0\.0\.0\.0|exposed)",
        "Anyone on the network can reach this agent",
    ),
    (
        r"gateway.*auth.*missing|without auth",
        "Any device on the network can control this agent",
    ),
    (
        r"CORS.*wildcard|WS origin|cross-origin",
        "Malicious websites can hijack the agent connection",
    ),
    (
        r"WebSocket.*exposed|WebSocket.*0\.0\.0\.0",
        "Any device on the network can connect to this agent",
    ),
    (
        r"mDNS.*full|mDNS.*broadcast",
        "Agent presence and config broadcast on the network",
    ),
    # Identity / messaging
    (
        r"DM.*policy.*open|DM.*unrestricted",
        "Any user or tool can message this agent unsupervised",
    ),
    (
        r"group.*policy.*open|group.*unrestricted",
        "Anyone in any group chat can trigger this agent",
    ),
    (
        r"DM.*scope.*shared|scope.*not.*per",
        "One user's conversation leaks into another's session",
    ),
    (
        r"group.*allow.*wildcard|\[\"?\*\"?\]",
        "Any group can trigger this agent without restriction",
    ),
    # Tools / execution
    (
        r"(?:full|unrestricted).*tool.*profile",
        "Untrusted inputs access all tools including exec",
    ),
    (
        r"sandbox.*disabled|unsandboxed",
        "Agent can run any command on your machine unrestricted",
    ),
    (
        r"exec.*approv.*missing|no.*exec.*policy",
        "Agent can execute any host command without approval",
    ),
    (
        r"(?:risky|dangerous).*tool.*enabled",
        "A compromised skill gets access to high-risk tools",
    ),
    (
        r"auto-approve|auto_approve",
        "Agent can take actions without asking for confirmation",
    ),
    # SSRF / network
    (
        r"SSRF|URL.*tool.*no.*SSRF",
        "Agent can be tricked into probing internal services",
    ),
    # Config / safety
    (
        r"safety.*(?:disabled|off|scanner)",
        "Platform defense against malicious skills is off",
    ),
    (
        r"credential.*redaction.*disabled",
        "Agent responses may expose raw API keys and secrets",
    ),
    (
        r"allowInsecureAuth",
        "Connections to this agent can be intercepted",
    ),
    (
        r"(?:dangerous|risky).*(?:flag|config)",
        "Security controls may be weakened or bypassed",
    ),
    (
        r"custom.*bins.*PATH",
        "Agent could run tampered binaries from untrusted paths",
    ),
    (
        r"extensions.*allowed|extension.*policy",
        "Browser extensions can interact with the agent",
    ),
    # Auth
    (
        r"MCP.*server.*no.*auth|MCP.*without.*auth",
        "Anyone who can reach this server can use its tools",
    ),
    (
        r"auth.*(?:bypass|disabled|off|flag)",
        "Authentication is completely off for all connections",
    ),
    # File permissions
    (
        r"world-(?:readable|accessible).*dir",
        "Every user on this machine can browse config files",
    ),
    (
        r"world-(?:readable|writable).*file",
        "Every user on this machine can read your secrets",
    ),
    (
        r"group-(?:readable|accessible)",
        "Other users in your group can read config files",
    ),
    # Version / CVE
    (
        r"(?:known )?CVE.*detected|CVE-\d+",
        "Known exploit exists -- update to the patched version",
    ),
    (
        r"version.*missing|version.*invalid",
        "Cannot verify if known vulnerabilities are patched",
    ),
    # Integrity
    (
        r"SOUL\.md|workspace.*integrity|file.*integrity",
        "Agent behavior can be silently altered by tampering",
    ),
    # Plaintext secrets (installation scanner)
    (
        r"plaintext.*(?:API|key|secret|token|credential)",
        "Attacker who reads this file gets full API access",
    ),
    # Security mode
    (
        r"security.*=.*full",
        "Agent has maximum autonomy with minimal safety checks",
    ),
    (
        r"ask.*fallback.*=.*full",
        "Agent defaults to full access when approval is unclear",
    ),
    # ── Skill scanner ───────────────────────────────────────────
    (r"reverse.shell", "This skill opens a backdoor to your machine"),
    (
        r"(?:arbitrary|eval|exec).*code.*exec",
        "This skill can execute any code on your machine",
    ),
    (
        r"subprocess|shell.*command.*exec",
        "This skill can run shell commands on your machine",
    ),
    (
        r"data.*exfiltrat",
        "This code can silently send your data to outside servers",
    ),
    (
        r"remote.*(?:script|install)",
        "This skill downloads and runs code from the internet",
    ),
    (
        r"env.*(?:harvest|variable|access)",
        "This skill can steal API keys from your environment",
    ),
    (
        r"credential.*(?:file|path).*access",
        "This skill reads your stored passwords and keys",
    ),
    (
        r"prompt.*inject.*(?:skill|instruct|desc)",
        "Skill instructions try to override agent safety rules",
    ),
    (
        r"jailbreak.*pattern",
        "This skill attempts to bypass the agent's safety rules",
    ),
    (
        r"unpinned.*dep",
        "A dependency update could silently introduce malware",
    ),
    (
        r"suspicious.*install.*script",
        "Install script may run harmful code on your machine",
    ),
    (
        r"malicious.*pattern",
        "This skill contains code patterns associated with malware",
    ),
    (
        r"3\+.*dangerous.*function|multiple.*dangerous",
        "This skill uses multiple risky system functions",
    ),
    (
        r"dangerous.*(?:call|import|function|module)",
        "This skill uses functions that can modify your system",
    ),
    (
        r"hardcoded.*prompt",
        "This skill contains hidden instructions embedded in code",
    ),
    (
        r"missing.*DMI|frontmatter",
        "Skill lacks required metadata for trust verification",
    ),
    # ── MCP scanner ─────────────────────────────────────────────
    (
        r"hardcoded.*secret.*(?:MCP|config)",
        "Secret visible in version control and build logs",
    ),
    (
        r"npx.*(?:unscoped|without.*scope)",
        "A typosquatted package could run instead",
    ),
    (
        r"MCP.*no.*auth|MCP.*auth.*missing",
        "Anyone who can reach this server can use its tools",
    ),
    (
        r"tool.*(?:description|schema).*(?:changed|drift|poison)",
        "Tool description manipulates the AI into unsafe acts",
    ),
    (
        r"tool.*removed",
        "A tool was removed -- may indicate supply chain tampering",
    ),
    (
        r"(?:excessive|over).*(?:perm|priv).*(?:MCP|tool)",
        "This tool has more access than it needs",
    ),
    (
        r"remote.*MCP.*server",
        "MCP traffic could be intercepted or tampered with",
    ),
    (
        r"MCP.*untrusted.*source",
        "This MCP server may contain malicious tools",
    ),
    # ── Credential scanner ──────────────────────────────────────
    (
        r"OpenAI.*(?:API|key)",
        "Any app on this machine can use your OpenAI key",
    ),
    (
        r"Anthropic.*(?:API|key)",
        "Any app on this machine can use your Anthropic key",
    ),
    (
        r"AWS.*(?:access|key)",
        "Attacker gets access to your AWS account and resources",
    ),
    (
        r"GitHub.*(?:token|key|PAT)",
        "Attacker gets access to your GitHub repos and actions",
    ),
    (
        r"Databricks.*(?:token|key)",
        "Attacker gets access to your Databricks workspace",
    ),
    (
        r"HuggingFace.*(?:token|key)",
        "Attacker can use your HuggingFace account",
    ),
    (
        r"Google.*(?:API|key|cloud)",
        "Attacker gets access to your Google Cloud resources",
    ),
    (r"Groq.*(?:API|key)", "Any app on this machine can use your Groq API key"),
    (
        r"Replicate.*(?:API|key)",
        "Any app on this machine can use your Replicate API key",
    ),
    (
        r"Slack.*(?:token|key)",
        "Attacker can read and send messages in your Slack",
    ),
    (
        r"private.key.*block|BEGIN.*PRIVATE.*KEY",
        "Attacker can impersonate your server or decrypt traffic",
    ),
    (
        r"connection.string.*password",
        "Database credentials exposed -- full read/write access",
    ),
    (
        r"high.entropy.*secret|possible.secret",
        "This secret is exposed to anyone who can read the file",
    ),
    (
        r"JWT.*token",
        "This token grants access to protected API endpoints",
    ),
]

# Compiled patterns for performance (case-insensitive)
_COMPILED_PATTERNS = [
    (re.compile(pattern, re.IGNORECASE), impact) for pattern, impact in _IMPACT_MAP
]


def apply_impacts(findings: list[Finding]) -> None:
    """Set impact strings on findings that don't already have one.

    Matches finding titles against known patterns and assigns
    a plain-language impact description. Modifies findings in place.
    """
    for finding in findings:
        if finding.impact:
            continue
        for pattern, impact in _COMPILED_PATTERNS:
            if pattern.search(finding.title):
                finding.impact = impact
                break


# OWASP code -> human-readable label for terminal display
OWASP_LABELS: dict[str, str] = {
    "ASI01": "Hijack",
    "ASI02": "Agency",
    "ASI03": "Supply",
    "ASI04": "Poison",
    "ASI05": "Secrets",
    "ASI06": "Memory",
    "ASI07": "Multi",
    "ASI08": "Cascade",
    "ASI09": "Audit",
    "ASI10": "Misalign",
}
