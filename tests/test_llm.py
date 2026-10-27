"""Tests for local Ollama LLM finding explanations (M9).

Tests build_prompt, explain_finding with mocked urllib HTTP responses,
timeout handling, connection refused, 404 behavior, and in-memory caching.
Ensures zero external network calls in CI.
"""

from __future__ import annotations

import json
import urllib.error
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from accessatlas.api.main import app, app_state
from accessatlas.llm.explain import build_prompt, clear_cache, explain_finding
from accessatlas.rules.models import Finding
from accessatlas.utils import load_config

FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture(autouse=True)
def _reset_llm_cache():
    """Ensure explanation cache is empty before and after each test."""
    clear_cache()
    yield
    clear_cache()


@pytest.fixture(scope="module")
def api_client() -> TestClient:
    """Initialize app_state with fixtures and return test client."""
    cfg = load_config()
    cfg["paths"]["fixtures"] = str(FIXTURES_DIR)
    app_state.is_loaded = False
    app_state.load(config=cfg, fixture_dir=FIXTURES_DIR)
    return TestClient(app)


def _make_dummy_finding(
    finding_id: str = "FND-test-001",
    rule: str = "dormant_admin",
    severity: str = "high",
    evidence: list[str] | None = None,
    privilege_path: str | None = "AD: Domain Admins",
    confidence_caveat: str | None = "Identity has 1 unlinked account",
    recommended_action: str = "Revoke inactive administrator access.",
) -> Finding:
    return Finding(
        finding_id=finding_id,
        rule=rule,
        identity_id="E100086",
        account_id="AD-USR-0001",
        platforms=["ad"],
        severity=severity,  # type: ignore[arg-type]
        evidence=evidence
        or ["Last logon was 120 days ago", "Administrative group membership active"],
        privilege_path=privilege_path,
        confidence_caveat=confidence_caveat,
        recommended_action=recommended_action,
    )


def test_build_prompt_includes_all_finding_fields():
    """Prompt must contain rule, severity, platforms, evidence, caveat, and action."""
    finding = _make_dummy_finding()
    prompt = build_prompt(finding)

    assert "dormant_admin" in prompt
    assert "HIGH" in prompt
    assert "ad" in prompt
    assert "Last logon was 120 days ago" in prompt
    assert "AD: Domain Admins" in prompt
    assert "Identity has 1 unlinked account" in prompt
    assert "Revoke inactive administrator access." in prompt
    # Check instructions at start and reminder at end
    assert prompt.startswith("You are an expert cybersecurity assistant")
    assert prompt.strip().endswith("conclude with the recommended action.")


def test_build_prompt_truncates_only_evidence():
    """max_evidence_chars must truncate only evidence, keeping instructions intact."""
    long_evidence = [f"Audit event line {i} with lots of verbose details" for i in range(100)]
    finding = _make_dummy_finding(evidence=long_evidence)

    prompt = build_prompt(finding, max_evidence_chars=200)

    assert "[... evidence truncated ...]" in prompt
    assert prompt.startswith("You are an expert cybersecurity assistant")
    assert "Reminder: Provide a concise 3 to 4 sentence explanation" in prompt
    assert "Revoke inactive administrator access." in prompt


def test_explain_finding_success():
    """Successful Ollama call returns parsed explanation with available=True."""
    finding = _make_dummy_finding()

    mock_resp = MagicMock()
    mock_resp.__enter__.return_value = mock_resp
    mock_resp.getcode.return_value = 200
    fake_body = json.dumps(
        {"response": "The account has retained Domain Admin rights despite 120 days of inactivity."}
    ).encode("utf-8")
    mock_resp.read.return_value = fake_body

    with patch("urllib.request.urlopen", return_value=mock_resp) as mock_urlopen:
        res = explain_finding(finding)

        assert mock_urlopen.call_count == 1
        req = mock_urlopen.call_args[0][0]
        # Verify options in payload
        payload = json.loads(req.data.decode("utf-8"))
        assert payload["stream"] is False
        assert payload["options"]["temperature"] == 0.2
        assert payload["options"]["num_predict"] == 200
        assert payload["model"] == "llama3.2:latest"

        assert res["finding_id"] == finding.finding_id
        assert res["available"] is True
        assert res["generated_by"] == "ollama"
        assert "Domain Admin" in res["explanation"]


def test_explain_finding_caching():
    """Second call for the same finding_id must return cached result without hitting urlopen."""
    finding = _make_dummy_finding()

    mock_resp = MagicMock()
    mock_resp.__enter__.return_value = mock_resp
    mock_resp.getcode.return_value = 200
    mock_resp.read.return_value = json.dumps({"response": "Cached explanation test."}).encode(
        "utf-8"
    )

    with patch("urllib.request.urlopen", return_value=mock_resp) as mock_urlopen:
        res1 = explain_finding(finding)
        res2 = explain_finding(finding)

        assert mock_urlopen.call_count == 1
        assert res1 == res2
        assert res2["explanation"] == "Cached explanation test."


def test_explain_finding_timeout():
    """Timeout during HTTP request must return available=False without raising."""
    finding = _make_dummy_finding()

    with patch("urllib.request.urlopen", side_effect=TimeoutError("Request timed out")):
        res = explain_finding(finding)

        assert res["available"] is False
        assert res["finding_id"] == finding.finding_id
        assert "unavailable" in res["explanation"].lower()


def test_explain_finding_connection_refused():
    """Connection refused (Ollama not running) returns available=False without raising."""
    finding = _make_dummy_finding()

    with patch(
        "urllib.request.urlopen",
        side_effect=urllib.error.URLError(ConnectionRefusedError("Connection refused")),
    ):
        res = explain_finding(finding)

        assert res["available"] is False
        assert res["finding_id"] == finding.finding_id
        assert "unavailable" in res["explanation"].lower()


def test_explain_finding_http_500_error():
    """Ollama server error returns available=False gracefully."""
    finding = _make_dummy_finding()

    mock_resp = MagicMock()
    mock_resp.getcode.return_value = 500
    mock_resp.read.return_value = b'{"error": "model load failed"}'

    with patch("urllib.request.urlopen", return_value=mock_resp):
        res = explain_finding(finding)

        assert res["available"] is False
        assert "unavailable" in res["explanation"].lower()


def test_api_explain_unknown_finding_returns_404(api_client: TestClient):
    """POST /findings/{id}/explain returns 404 for nonexistent finding."""
    resp = api_client.post("/findings/FND-DOES-NOT-EXIST/explain")
    assert resp.status_code == 404
    assert "not found" in resp.json()["detail"].lower()


def test_api_explain_success(api_client: TestClient):
    """POST /findings/{id}/explain returns 200 with available=True when Ollama responds."""
    # Pick a valid finding from loaded app state
    assert len(app_state.findings) > 0
    valid_id = app_state.findings[0].finding_id

    mock_resp = MagicMock()
    mock_resp.__enter__.return_value = mock_resp
    mock_resp.getcode.return_value = 200
    mock_resp.read.return_value = json.dumps(
        {"response": "Plain English summary from Ollama."}
    ).encode("utf-8")

    with patch("urllib.request.urlopen", return_value=mock_resp):
        resp = api_client.post(f"/findings/{valid_id}/explain")

        assert resp.status_code == 200
        data = resp.json()
        assert data["finding_id"] == valid_id
        assert data["available"] is True
        assert data["generated_by"] == "ollama"
        assert data["explanation"] == "Plain English summary from Ollama."


def test_api_explain_ollama_offline_returns_200_available_false(api_client: TestClient):
    """POST /findings/{id}/explain returns 200 with available=False when Ollama is offline."""
    assert len(app_state.findings) > 0
    valid_id = app_state.findings[0].finding_id

    with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("Connection refused")):
        resp = api_client.post(f"/findings/{valid_id}/explain")

        assert resp.status_code == 200
        data = resp.json()
        assert data["finding_id"] == valid_id
        assert data["available"] is False
        assert "unavailable" in data["explanation"].lower()
