"""Secret verification utilities — passive hints and active probes.

Phase 1 (passive): Heuristic indicators of likely credential validity based
on file age, context proximity, and file type.

Phase 2 (active): Safe, read-only API probes for select providers.  Only
runs when the user explicitly passes ``--verify``.  Never logs or transmits
the actual secret value.
"""

from __future__ import annotations

import logging
import time
import urllib.error
import urllib.request
from pathlib import Path

logger = logging.getLogger(__name__)

# Words near a credential that suggest it is no longer active
_REVOCATION_WORDS = frozenset(
    {
        "deprecated",
        "old",
        "revoked",
        "disabled",
        "unused",
        "expired",
        "rotated",
        "replaced",
        "legacy",
        "decommissioned",
        "previous",
        "former",
        "obsolete",
        "do_not_use",
        "do not use",
        "inactive",
    }
)

# File age thresholds (seconds)
_RECENT_THRESHOLD = 7 * 86400  # 7 days
_STALE_THRESHOLD = 90 * 86400  # 90 days


def compute_passive_hints(
    file_path: Path | None,
    line_number: int | None,
    secret_type: str,
) -> dict[str, str]:
    """Return heuristic hints about whether a credential is likely active.

    Always safe to call — no network or subprocess calls.

    Returns a dict with keys like ``"hint_file_age"``, ``"hint_context"``,
    ``"hint_risk_level"`` (high/medium/low).
    """
    hints: dict[str, str] = {}

    if file_path is None:
        hints["hint_risk_level"] = "medium"
        return hints

    # --- File age ---
    try:
        mtime = file_path.stat().st_mtime
        age_seconds = time.time() - mtime
        if age_seconds < _RECENT_THRESHOLD:
            hints["hint_file_age"] = "recent"
        elif age_seconds > _STALE_THRESHOLD:
            hints["hint_file_age"] = "stale"
        else:
            hints["hint_file_age"] = "moderate"
    except OSError:
        pass

    # --- File type context ---
    name_lower = file_path.name.lower()
    if name_lower == ".env":
        hints["hint_file_type"] = "production_env"
    elif name_lower.startswith(".env."):
        hints["hint_file_type"] = "env_variant"
    elif name_lower.endswith((".example", ".sample", ".template")):
        hints["hint_file_type"] = "template"
    elif "docker-compose" in name_lower or name_lower == "compose.yml":
        hints["hint_file_type"] = "compose"

    # --- Context proximity: check lines near the finding for revocation words ---
    if line_number and file_path.exists():
        try:
            lines = file_path.read_text(errors="replace").splitlines()
            start = max(0, line_number - 3)
            end = min(len(lines), line_number + 2)
            context_text = " ".join(lines[start:end]).lower()
            for word in _REVOCATION_WORDS:
                if word in context_text:
                    hints["hint_context"] = f"near_revocation_word:{word}"
                    break
        except OSError:
            pass

    # --- Overall risk level ---
    if (
        hints.get("hint_file_type") == "template"
        or hints.get("hint_context", "").startswith("near_revocation_word")
    ):
        hints["hint_risk_level"] = "low"
    elif hints.get("hint_file_age") == "stale":
        hints["hint_risk_level"] = "medium"
    elif hints.get("hint_file_type") == "production_env" or hints.get("hint_file_age") == "recent":
        hints["hint_risk_level"] = "high"
    else:
        hints["hint_risk_level"] = "medium"

    return hints


# ---------------------------------------------------------------------------
# Active verification (opt-in only)
# ---------------------------------------------------------------------------

# Mapping of secret types to their verification function
_VERIFIERS: dict[str, str] = {
    "GitHub Token": "_verify_github",
    "OpenAI API Key": "_verify_openai",
    "Anthropic API Key": "_verify_anthropic",
}


def verify_secret(secret_type: str, secret_value: str) -> dict[str, str]:
    """Probe whether a credential is active using safe, read-only API calls.

    Only call when the user has explicitly opted in via ``--verify``.

    Returns a dict with:
    - ``"verified"``: ``"active"`` | ``"inactive"`` | ``"unknown"`` | ``"error"``
    - ``"verify_method"``: description of the probe used
    """
    verifier_name = _VERIFIERS.get(secret_type)
    if not verifier_name:
        return {"verified": "unknown", "verify_method": "no_verifier_available"}

    fn = globals().get(verifier_name)
    if not fn or not callable(fn):
        return {"verified": "unknown", "verify_method": "verifier_not_implemented"}

    try:
        return fn(secret_value)
    except Exception as e:
        logger.debug("Verification failed for %s: %s", secret_type, e)
        return {"verified": "error", "verify_method": f"exception:{type(e).__name__}"}


def _verify_github(token: str) -> dict[str, str]:
    """Check if a GitHub token is active via GET /user (read-only, free)."""
    req = urllib.request.Request(
        "https://api.github.com/user",
        headers={
            "Authorization": f"token {token}",
            "User-Agent": "agentsec-verifier/1.0",
            "Accept": "application/vnd.github+json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:  # noqa: S310
            if resp.status == 200:
                return {"verified": "active", "verify_method": "github_get_user"}
    except urllib.error.HTTPError as e:
        if e.code == 401:
            return {"verified": "inactive", "verify_method": "github_get_user"}
        return {"verified": "error", "verify_method": f"github_http_{e.code}"}
    except (urllib.error.URLError, TimeoutError):
        return {"verified": "error", "verify_method": "github_network_error"}

    return {"verified": "unknown", "verify_method": "github_unexpected"}


def _verify_openai(api_key: str) -> dict[str, str]:
    """Check if an OpenAI key is active via GET /v1/models (read-only, free)."""
    req = urllib.request.Request(
        "https://api.openai.com/v1/models",
        headers={
            "Authorization": f"Bearer {api_key}",
            "User-Agent": "agentsec-verifier/1.0",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:  # noqa: S310
            if resp.status == 200:
                return {"verified": "active", "verify_method": "openai_get_models"}
    except urllib.error.HTTPError as e:
        if e.code in (401, 403):
            return {"verified": "inactive", "verify_method": "openai_get_models"}
        return {"verified": "error", "verify_method": f"openai_http_{e.code}"}
    except (urllib.error.URLError, TimeoutError):
        return {"verified": "error", "verify_method": "openai_network_error"}

    return {"verified": "unknown", "verify_method": "openai_unexpected"}


def _verify_anthropic(api_key: str) -> dict[str, str]:
    """Check if an Anthropic key is active via GET /v1/models (read-only)."""
    req = urllib.request.Request(
        "https://api.anthropic.com/v1/models",
        headers={
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
            "User-Agent": "agentsec-verifier/1.0",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:  # noqa: S310
            if resp.status == 200:
                return {"verified": "active", "verify_method": "anthropic_get_models"}
    except urllib.error.HTTPError as e:
        if e.code in (401, 403):
            return {"verified": "inactive", "verify_method": "anthropic_get_models"}
        return {"verified": "error", "verify_method": f"anthropic_http_{e.code}"}
    except (urllib.error.URLError, TimeoutError):
        return {"verified": "error", "verify_method": "anthropic_network_error"}

    return {"verified": "unknown", "verify_method": "anthropic_unexpected"}
