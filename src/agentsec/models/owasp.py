"""OWASP Agentic Top 10 (2026) mapping and scoring.

Reference: https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/

This module encodes the full OWASP Agentic Top 10 taxonomy so every finding
can be mapped to standardized risk categories with compliance-ready output.
"""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class OwaspAgenticCategory(str, Enum):
    """OWASP Top 10 for Agentic Applications (2026).

    Each category represents a class of vulnerability specific to
    autonomous AI agent systems.
    """

    ASI01_AGENT_GOAL_HIJACK = "ASI01"
    ASI02_EXCESSIVE_AGENCY = "ASI02"
    ASI03_SUPPLY_CHAIN_VULNERABILITIES = "ASI03"
    ASI04_KNOWLEDGE_POISONING = "ASI04"
    ASI05_PRIVILEGE_COMPROMISE = "ASI05"
    ASI06_MEMORY_MANIPULATION = "ASI06"
    ASI07_MULTI_AGENT_EXPLOITATION = "ASI07"
    ASI08_UNCONTROLLED_CASCADING = "ASI08"
    ASI09_REPUDIATION_ATTACKS = "ASI09"
    ASI10_MISALIGNED_BEHAVIORS = "ASI10"

    @property
    def title(self) -> str:
        return _CATEGORY_METADATA[self]["title"]

    @property
    def description(self) -> str:
        return _CATEGORY_METADATA[self]["description"]

    @property
    def attack_scenarios(self) -> list[str]:
        return _CATEGORY_METADATA[self]["attack_scenarios"]

    @property
    def controls(self) -> list[str]:
        return _CATEGORY_METADATA[self]["controls"]


_CATEGORY_METADATA: dict[OwaspAgenticCategory, dict[str, Any]] = {
    OwaspAgenticCategory.ASI01_AGENT_GOAL_HIJACK: {
        "title": "Agent Goal Hijack / Prompt Injection",
        "description": (
            "Adversaries alter agent objectives through malicious content embedded in "
            "emails, documents, webpages, or tool outputs. The agent's goals are redirected "
            "to serve attacker interests while appearing to function normally."
        ),
        "attack_scenarios": [
            "Crafted email instructs agent to forward sensitive data to attacker",
            "Malicious webpage visited during browsing embeds hidden instructions",
            "Poisoned RAG document redirects agent to execute unintended commands",
            "Tool output contains hidden prompt injection in metadata fields",
        ],
        "controls": [
            "Input sanitization on all external content before agent processing",
            "Instruction hierarchy enforcement (system > user > tool output)",
            "Behavioral anomaly detection for goal drift",
            "Content isolation between trusted and untrusted sources",
            "Human-in-the-loop for high-impact actions",
        ],
    },
    OwaspAgenticCategory.ASI02_EXCESSIVE_AGENCY: {
        "title": "Excessive Agency / Overprivileged Agents",
        "description": (
            "Agents granted more capabilities or permissions than necessary for their "
            "intended function. Excessive tools, permissions, or autonomy expand the "
            "blast radius of any compromise."
        ),
        "attack_scenarios": [
            "Agent with shell access used for simple Q&A tasks",
            "File system write access granted when only read is needed",
            "Network access available when agent only needs local computation",
            "Admin-level API tokens used for read-only operations",
        ],
        "controls": [
            "Principle of least privilege for all agent capabilities",
            "Tool allowlisting per task context",
            "Capability scoping (read-only vs read-write)",
            "Runtime permission boundaries enforced by sandbox",
            "Regular privilege audits and access reviews",
        ],
    },
    OwaspAgenticCategory.ASI03_SUPPLY_CHAIN_VULNERABILITIES: {
        "title": "Supply Chain Vulnerabilities",
        "description": (
            "Compromised components in the agent's dependency chain — skills, plugins, "
            "MCP servers, models, or packages — introduce backdoors, credential theft, "
            "or remote code execution capabilities."
        ),
        "attack_scenarios": [
            "Malicious ClawHub skill masquerading as legitimate utility",
            "Typosquatted npm/PyPI packages in agent dependencies",
            "Compromised MCP server exfiltrating data through tool calls",
            "Backdoored model weights or adapters in serving pipeline",
        ],
        "controls": [
            "Cryptographic verification of all installed components",
            "Dependency pinning with hash verification",
            "Behavioral analysis in sandboxed environment before deployment",
            "Supply chain SBOM generation and monitoring",
            "Reputation scoring for marketplace components",
        ],
    },
    OwaspAgenticCategory.ASI04_KNOWLEDGE_POISONING: {
        "title": "Knowledge Poisoning / Data Integrity",
        "description": (
            "Attackers corrupt the agent's knowledge sources — RAG databases, vector "
            "indexes, memory stores, or training data — to manipulate agent behavior "
            "without directly injecting prompts."
        ),
        "attack_scenarios": [
            "Poisoned documents in vector index produce misleading retrievals",
            "Manipulated SOUL.md alters agent personality and safety boundaries",
            "Corrupted conversation memory influences future decisions",
            "Tampered configuration files change agent behavior silently",
        ],
        "controls": [
            "Integrity checksums for all knowledge sources",
            "Version control and change detection for configuration",
            "Write protection on critical files (SOUL.md, system prompts)",
            "Regular integrity audits with drift detection",
            "Immutable audit logs for all knowledge base modifications",
        ],
    },
    OwaspAgenticCategory.ASI05_PRIVILEGE_COMPROMISE: {
        "title": "Privilege Compromise / Credential Theft",
        "description": (
            "Agent credentials, API keys, or session tokens are exposed through "
            "insecure storage, network interception, or social engineering of the "
            "agent itself, enabling unauthorized access to connected services."
        ),
        "attack_scenarios": [
            "Plaintext API keys in clawdbot.json readable by any local process",
            "WebSocket session tokens stolen via cross-origin hijacking",
            "Agent tricked into revealing credentials through prompt injection",
            "OAuth tokens stored without encryption in config directory",
        ],
        "controls": [
            "OS keychain / secrets manager for all credentials",
            "Token rotation and expiration enforcement",
            "Encryption at rest for all sensitive configuration",
            "Network-level protections (TLS, origin validation)",
            "Agent guardrails preventing credential disclosure",
        ],
    },
    OwaspAgenticCategory.ASI06_MEMORY_MANIPULATION: {
        "title": "Memory & Context Manipulation",
        "description": (
            "Attackers exploit persistent memory, conversation history, or context "
            "windows to plant instructions that activate later, bypass safety measures, "
            "or cause the agent to act on false premises."
        ),
        "attack_scenarios": [
            "Delayed prompt injection planted in conversation history",
            "Memory poisoning through crafted interactions over time",
            "Context window manipulation to push safety instructions out of scope",
            "Persistent memory entries that override system instructions",
        ],
        "controls": [
            "Memory integrity verification with checksums",
            "Bounded context windows with safety instruction anchoring",
            "Memory sanitization and periodic review",
            "Isolation between user sessions and system memory",
            "Anomaly detection on memory write patterns",
        ],
    },
    OwaspAgenticCategory.ASI07_MULTI_AGENT_EXPLOITATION: {
        "title": "Multi-Agent System Exploitation",
        "description": (
            "In systems with multiple agents, attackers exploit trust relationships "
            "between agents to escalate privileges, propagate malicious instructions, "
            "or bypass safety controls that apply to individual agents."
        ),
        "attack_scenarios": [
            "Compromised agent instructs trusted peer to perform restricted actions",
            "Inter-agent message injection to propagate prompt injection laterally",
            "Trust chain exploitation to escalate from low-privilege to high-privilege agent",
            "Orchestrator manipulation to redirect task routing to attacker-controlled agent",
        ],
        "controls": [
            "Zero-trust between agents (verify every inter-agent message)",
            "Per-agent capability boundaries enforced independently",
            "Message signing and authentication for inter-agent communication",
            "Monitoring of inter-agent traffic for anomalous patterns",
            "Blast radius containment through agent isolation",
        ],
    },
    OwaspAgenticCategory.ASI08_UNCONTROLLED_CASCADING: {
        "title": "Uncontrolled Cascading / Runaway Agents",
        "description": (
            "Agents enter unbounded execution loops, recursive tool calls, or "
            "resource-intensive operations that consume excessive compute, storage, "
            "or API credits without human oversight."
        ),
        "attack_scenarios": [
            "Infinite loop triggered by crafted tool output causing repeated retries",
            "Recursive file operations filling disk or consuming all inodes",
            "Unbounded API calls draining credits or hitting rate limits destructively",
            "Cascading failures across connected services triggered by agent actions",
        ],
        "controls": [
            "Execution budgets (time, tokens, API calls, iterations)",
            "Circuit breakers on tool invocations",
            "Resource usage monitoring and automatic throttling",
            "Human approval gates for high-cost operations",
            "Dead-letter queues for failed operations instead of infinite retry",
        ],
    },
    OwaspAgenticCategory.ASI09_REPUDIATION_ATTACKS: {
        "title": "Repudiation / Insufficient Audit Trail",
        "description": (
            "Absence of adequate logging and audit trails means agent actions cannot "
            "be attributed, reconstructed, or investigated. Attackers exploit this to "
            "cover tracks or deny responsibility for agent-initiated actions."
        ),
        "attack_scenarios": [
            "Agent performs destructive actions with no audit log",
            "Attacker manipulates agent and deletes conversation history",
            "No attribution chain from agent action back to triggering input",
            "Insufficient logging makes incident investigation impossible",
        ],
        "controls": [
            "Immutable, append-only audit logs for all agent actions",
            "Full provenance chain (input → decision → action → outcome)",
            "Tamper-evident log storage",
            "Log retention policies aligned with compliance requirements",
            "Real-time alerting on log gaps or tampering attempts",
        ],
    },
    OwaspAgenticCategory.ASI10_MISALIGNED_BEHAVIORS: {
        "title": "Misaligned Behaviors / Unintended Actions",
        "description": (
            "Agents take actions that are technically within their capabilities but "
            "violate user intent, organizational policies, or safety expectations due "
            "to ambiguous instructions, poor guardrails, or emergent behaviors."
        ),
        "attack_scenarios": [
            "Agent interprets ambiguous instruction in harmful way",
            "Emergent behavior from complex tool interactions causes data loss",
            "Agent optimizes for stated metric in unintended way (reward hacking)",
            "Safety boundaries not enforced consistently across all execution paths",
        ],
        "controls": [
            "Explicit safety boundaries in system configuration",
            "Behavioral testing with adversarial scenarios",
            "Guardrail enforcement at runtime (not just prompt-level)",
            "Anomaly detection comparing actions to expected behavioral envelope",
            "Regular alignment audits with representative task scenarios",
        ],
    },
}


class OwaspMapping(BaseModel):
    """Maps a finding to one or more OWASP Agentic Top 10 categories."""

    finding_id: str
    categories: list[OwaspAgenticCategory]
    risk_score: float = Field(ge=0.0, le=10.0, description="Composite risk score (0-10)")
    rationale: str = Field(description="Why this finding maps to these categories")

    @property
    def highest_category(self) -> OwaspAgenticCategory:
        """Return the category with the lowest ordinal (most critical)."""
        return min(self.categories, key=lambda c: list(OwaspAgenticCategory).index(c))
