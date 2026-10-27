"""Local AI explanation generator for AccessAtlas findings via Ollama HTTP API.

This module formats finding evidence into a bounded prompt, queries Ollama's
POST /api/generate endpoint using Python's standard library urllib.request,
and caches explanations in memory.

CRITICAL ARCHITECTURAL BOUNDARIES:
- The LLM is used ONLY to explain an existing finding in plain English.
- The LLM is NEVER used for detection, scoring, or severity calculation.
- The prompt is built ONLY from the finding's own fields (rule, severity,
  platforms, evidence, privilege path, recommended action, confidence caveat).
- Ground truth is never loaded or referenced.
"""

from __future__ import annotations

import http.client
import json
import logging
import os
import urllib.error
import urllib.request
from typing import Any

from accessatlas.rules.models import Finding
from accessatlas.utils import load_config

logger = logging.getLogger(__name__)

# In-memory explanation cache keyed by finding_id
_EXPLANATION_CACHE: dict[str, dict[str, Any]] = {}


def clear_cache() -> None:
    """Clear the in-memory explanation cache. Useful for tests."""
    _EXPLANATION_CACHE.clear()


def build_prompt(finding: Finding, max_evidence_chars: int = 1200) -> str:
    """Construct an LLM explanation prompt strictly from finding attributes.

    Instructions are placed at the beginning, followed by structured facts,
    and a concise reminder is placed at the end.
    Only the evidence block is subject to truncation via max_evidence_chars.

    Parameters
    ----------
    finding : Finding
        The security finding to explain.
    max_evidence_chars : int, default=1200
        Maximum characters permitted for the combined evidence list before
        truncating. Instructions and other metadata are never truncated.

    Returns
    -------
    str
        The formatted prompt text.
    """
    instructions = (
        "You are an expert cybersecurity assistant explaining an identity security finding "
        "to a security analyst. Explain in 3 to 4 plain sentences. Use ONLY the facts provided "
        "below. Do not invent names, numbers, platforms, or causes. Mention the caveat if one "
        "is provided, and conclude with the recommended action."
    )

    # Format evidence and truncate ONLY the evidence section if it exceeds max_evidence_chars
    evidence_items = (
        [f"- {e}" for e in finding.evidence]
        if finding.evidence
        else ["- No specific evidence provided."]
    )
    evidence_text = "\n".join(evidence_items)
    if len(evidence_text) > max_evidence_chars:
        evidence_text = evidence_text[:max_evidence_chars] + "\n[... evidence truncated ...]"

    facts_lines = [
        f"Rule: {finding.rule}",
        f"Severity: {finding.severity.upper()}",
        f"Platforms: {', '.join(finding.platforms) if finding.platforms else 'unspecified'}",
    ]
    if finding.privilege_path:
        facts_lines.append(f"Privilege Path: {finding.privilege_path}")
    if finding.confidence_caveat:
        facts_lines.append(f"Caveat: {finding.confidence_caveat}")
    facts_lines.append(f"Evidence:\n{evidence_text}")
    facts_lines.append(f"Recommended Action: {finding.recommended_action}")

    facts_block = "\n".join(facts_lines)

    reminder = (
        "Reminder: Provide a concise 3 to 4 sentence explanation for a security analyst. "
        "Use ONLY the facts provided above and conclude with the recommended action."
    )

    return f"{instructions}\n\n[Finding Details]\n{facts_block}\n\n{reminder}"


def explain_finding(
    finding: Finding,
    config: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Generate or retrieve an explanation for a finding using local Ollama.

    Parameters
    ----------
    finding : Finding
        The existing finding to explain.
    config : dict[str, Any] | None, optional
        Application configuration. If None, loaded via load_config().

    Returns
    -------
    dict[str, Any]
        Dictionary containing:
        - finding_id: str
        - explanation: str
        - model: str
        - generated_by: "ollama"
        - available: bool
    """
    if finding.finding_id in _EXPLANATION_CACHE:
        return _EXPLANATION_CACHE[finding.finding_id]

    cfg = config or load_config()
    llm_cfg = cfg.get("llm", {})

    enabled = bool(llm_cfg.get("enabled", True))
    base_url = str(
        os.environ.get("OLLAMA_BASE_URL", llm_cfg.get("base_url", "http://localhost:11434"))
    ).rstrip("/")
    model = str(llm_cfg.get("model", "llama3.2:latest"))
    timeout_seconds = int(llm_cfg.get("timeout_seconds", 60))
    max_input_chars = int(llm_cfg.get("max_input_chars", 1200))

    unavailable_result: dict[str, Any] = {
        "finding_id": finding.finding_id,
        "explanation": "Local explanation service is unavailable. Please ensure Ollama is running.",
        "model": model,
        "generated_by": "ollama",
        "available": False,
    }

    if not enabled:
        return unavailable_result

    prompt = build_prompt(finding, max_evidence_chars=max_input_chars)
    payload = {
        "model": model,
        "prompt": prompt,
        "stream": False,
        "options": {
            "temperature": 0.2,
            "num_predict": 200,
        },
    }

    url = f"{base_url}/api/generate"
    req_data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=req_data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=timeout_seconds) as resp:
            status_code = resp.getcode()
            if status_code != 200:
                logger.warning(
                    "Ollama returned status code %s for %s", status_code, finding.finding_id
                )
                return unavailable_result

            raw_body = resp.read().decode("utf-8")
            data = json.loads(raw_body)
            response_text = data.get("response", "").strip()

            if not response_text:
                logger.warning("Ollama returned empty response for %s", finding.finding_id)
                return unavailable_result

            result: dict[str, Any] = {
                "finding_id": finding.finding_id,
                "explanation": response_text,
                "model": model,
                "generated_by": "ollama",
                "available": True,
            }
            _EXPLANATION_CACHE[finding.finding_id] = result
            return result

    except (
        urllib.error.URLError,
        urllib.error.HTTPError,
        TimeoutError,
        http.client.RemoteDisconnected,
        http.client.HTTPException,
        ConnectionResetError,
        ConnectionRefusedError,
        json.JSONDecodeError,
        OSError,
    ) as exc:
        logger.warning(
            "Ollama explanation unavailable for finding %s (%s: %s)",
            finding.finding_id,
            type(exc).__name__,
            exc,
        )
        return unavailable_result
