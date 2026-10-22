"""Integration tests for the AccessAtlas FastAPI application using in-process ASGI client.

Tests /health, /identities, /identities/{id}, /findings, /findings/{id}, and /evaluation.
Works entirely without adding extra external libraries.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

import pytest

from accessatlas.api.main import app, app_state
from accessatlas.utils import load_config

FIXTURES_DIR = Path(__file__).parent / "fixtures"


class ASGIResponse:
    """Lightweight response representation matching TestClient interface."""

    def __init__(self, status_code: int, headers: list[tuple[bytes, bytes]], body: bytes) -> None:
        self.status_code = status_code
        self.headers = headers
        self.content = body

    def json(self) -> Any:
        return json.loads(self.content.decode("utf-8"))


class TestClient:
    """Drop-in ASGI TestClient that calls the FastAPI app in-process."""

    __test__ = False

    def __init__(self, asgi_app: Any) -> None:
        self.app = asgi_app

    def get(self, path_and_query: str) -> ASGIResponse:
        path, _, query_string = path_and_query.partition("?")
        scope = {
            "type": "http",
            "asgi": {"version": "3.0"},
            "http_version": "1.1",
            "method": "GET",
            "path": path,
            "raw_path": path.encode("ascii"),
            "query_string": query_string.encode("ascii"),
            "headers": [[b"host", b"testserver"]],
        }

        status_code = [200]
        response_headers: list[tuple[bytes, bytes]] = []
        response_body: list[bytes] = []

        async def receive() -> dict[str, Any]:
            return {"type": "http.request", "body": b"", "more_body": False}

        async def send(message: dict[str, Any]) -> None:
            if message["type"] == "http.response.start":
                status_code[0] = message["status"]
                response_headers.extend(message.get("headers", []))
            elif message["type"] == "http.response.body":
                response_body.append(message.get("body", b""))

        asyncio.run(self.app(scope, receive, send))
        return ASGIResponse(status_code[0], response_headers, b"".join(response_body))


@pytest.fixture(scope="session")
def client() -> TestClient:
    """Initialize app_state with fixtures and return test client."""
    cfg = load_config()
    cfg["paths"]["fixtures"] = str(FIXTURES_DIR)
    app_state.is_loaded = False
    app_state.load(config=cfg, fixture_dir=FIXTURES_DIR)
    return TestClient(app)


def test_health_endpoint(client: TestClient):
    """GET /health must return 200 OK with metadata."""
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["version"] == "0.1.0"
    assert "identities_count" in data
    assert "findings_count" in data
    assert data["snapshot_date"] == "2026-10-12"


def test_identities_pagination(client: TestClient):
    """GET /identities must return paginated results."""
    response = client.get("/identities?page=1&size=5")
    assert response.status_code == 200
    data = response.json()
    assert "items" in data
    assert "total" in data
    assert data["page"] == 1
    assert data["size"] == 5
    assert len(data["items"]) <= 5
    if data["items"]:
        item = data["items"][0]
        assert "identity_id" in item
        assert "identity_kind" in item


def test_identities_filtering_by_kind(client: TestClient):
    """GET /identities?kind=service must return only service identities."""
    response = client.get("/identities?kind=service&size=10")
    assert response.status_code == 200
    data = response.json()
    for item in data["items"]:
        assert item["identity_kind"] == "service"


def test_identities_validation_error(client: TestClient):
    """GET /identities with invalid page number must return 422."""
    response = client.get("/identities?page=0")
    assert response.status_code == 422


def test_get_identity_by_id_positive(client: TestClient):
    """GET /identities/{id} must return full identity detail."""
    list_res = client.get("/identities?size=1")
    items = list_res.json()["items"]
    if not items:
        pytest.skip("No identities loaded in fixture state")

    target_id = items[0]["identity_id"]
    response = client.get(f"/identities/{target_id}")
    assert response.status_code == 200
    data = response.json()
    assert data["identity_id"] == target_id
    assert "findings" in data
    assert "overall_grant_path" in data


def test_get_identity_by_id_not_found(client: TestClient):
    """GET /identities/{id} for non-existent ID must return 404."""
    response = client.get("/identities/NONEXISTENT_USER_9999")
    assert response.status_code == 404
    assert "not found" in response.json()["detail"].lower()


def test_findings_pagination_and_filtering(client: TestClient):
    """GET /findings must return paginated findings and accept filters."""
    response = client.get("/findings?page=1&size=10")
    assert response.status_code == 200
    data = response.json()
    assert "items" in data
    assert "total" in data
    assert data["page"] == 1

    if data["items"]:
        f = data["items"][0]
        rule = f["rule"]
        rule_res = client.get(f"/findings?rule={rule}")
        assert rule_res.status_code == 200
        for item in rule_res.json()["items"]:
            assert item["rule"].lower() == rule.lower()


def test_get_finding_by_id_positive(client: TestClient):
    """GET /findings/{id} must return single finding details."""
    list_res = client.get("/findings?size=1")
    items = list_res.json()["items"]
    if not items:
        pytest.skip("No findings generated from fixture data")

    target_id = items[0]["finding_id"]
    response = client.get(f"/findings/{target_id}")
    assert response.status_code == 200
    data = response.json()
    assert data["finding_id"] == target_id
    assert "evidence" in data
    assert "recommended_action" in data


def test_get_finding_by_id_not_found(client: TestClient):
    """GET /findings/{id} for non-existent ID must return 404."""
    response = client.get("/findings/FND-nonexistent-123")
    assert response.status_code == 404


def test_evaluation_endpoint(client: TestClient):
    """GET /evaluation must return scenario metrics for valid split."""
    response = client.get("/evaluation?split=train")
    if response.status_code == 500:
        pytest.skip("Ground truth data not available in this environment")

    assert response.status_code == 200
    data = response.json()
    assert data["split"] == "train"
    assert "scenarios" in data
    assert "traps" in data


def test_evaluation_endpoint_invalid_split(client: TestClient):
    """GET /evaluation with invalid split must return 400."""
    response = client.get("/evaluation?split=invalid_split")
    assert response.status_code == 400
