"""Tests for the FastAPI web backend using the built-in TestClient."""

from __future__ import annotations

from pathlib import Path

import pytest

fastapi = pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from prodogy.web.server import create_app  # noqa: E402

EXAMPLES = Path(__file__).parent.parent / "examples"


@pytest.fixture(scope="module")
def client() -> TestClient:
    # Allow scanning the whole project tree in tests.
    return TestClient(create_app(allowed_roots=[EXAMPLES.parent]))


def test_health(client):
    r = client.get("/api/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_rules_endpoint(client):
    r = client.get("/api/rules")
    assert r.status_code == 200
    data = r.json()
    assert len(data) >= 11
    assert all({"id", "severity", "category", "rationale"} <= set(d) for d in data)


def test_index_served(client):
    r = client.get("/")
    assert r.status_code == 200
    assert "Prodogy" in r.text


def test_scan_bad_examples(client):
    r = client.post("/api/scan", json={"path": str(EXAMPLES / "bad"), "maintainability": False})
    assert r.status_code == 200
    report = r.json()
    assert report["summary"]["total_findings"] > 0
    ids = {f["rule_id"] for f in report["findings"] if not f["suppressed"]}
    assert "K8S003" in ids
    assert "SECRET001" in ids


def test_scan_missing_path_returns_404(client):
    r = client.post("/api/scan", json={"path": "/nonexistent/xyz", "maintainability": False})
    assert r.status_code == 404


def test_scan_report_is_json_serializable(client):
    r = client.post("/api/scan", json={"path": str(EXAMPLES / "good"), "maintainability": False})
    assert r.status_code == 200
    report = r.json()
    # enums serialized as strings, datetime as ISO string
    assert isinstance(report["generated_at"], str)
    assert report["schema_version"] == "1.0"
