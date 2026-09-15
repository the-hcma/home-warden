"""Tests for GET /health/catalog (app.api.catalog_health_routes)."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from app.api.app import create_app
from app.catalog_checks import CheckResult


def make_client() -> TestClient:
    def _allow_all(username: str, password: str) -> bool:
        return True

    client = TestClient(
        create_app(authenticate_user=_allow_all, session_secret="test-session-secret"),
        base_url="https://testserver",
    )
    # /health/catalog is proxied on #68's self-catalog vhost like any other
    # route, so it now requires a session the same as / -- log in once here
    # so every test below stays focused on the health-check logic itself.
    login = client.post("/auth/login", json={"username": "tester", "password": "irrelevant"})
    assert login.status_code == 200
    return client


def test_health_catalog_requires_session() -> None:
    client = TestClient(create_app(session_secret="test-session-secret"), base_url="https://testserver")
    resp = client.get("/health/catalog")
    assert resp.status_code == 401


def test_health_catalog_host_guard_refused() -> None:
    client = make_client()
    with patch("app.api.catalog_health_routes.enforce_host_guard", return_value=False):
        resp = client.get("/health/catalog")
    assert resp.status_code == 503


def test_health_catalog_missing_catalog_file(tmp_path: Path) -> None:
    client = make_client()
    with (
        patch("app.api.catalog_health_routes.enforce_host_guard", return_value=True),
        patch("app.api.catalog_health_routes.services_json_path", return_value=tmp_path / "missing.json"),
    ):
        resp = client.get("/health/catalog")
    assert resp.status_code == 404


def test_health_catalog_ok(tmp_path: Path) -> None:
    catalog_path = tmp_path / "services.json"
    catalog_path.write_text(json.dumps({"services": [{"name": "svc", "kind": "static"}]}))

    fake_results = [CheckResult("svc", "upstream", "skip", "kind='static', no upstream to probe")]

    client = make_client()
    with (
        patch("app.api.catalog_health_routes.enforce_host_guard", return_value=True),
        patch("app.api.catalog_health_routes.services_json_path", return_value=catalog_path),
        patch("app.api.catalog_health_routes.run_all", return_value=fake_results),
    ):
        resp = client.get("/health/catalog")

    assert resp.status_code == 200
    body = resp.json()
    assert body["healthy"] is True
    assert body["checks"][0]["service"] == "svc"


def test_health_catalog_invalid_json_returns_500(tmp_path: Path) -> None:
    catalog_path = tmp_path / "services.json"
    catalog_path.write_text("{not valid json")

    client = make_client()
    with (
        patch("app.api.catalog_health_routes.enforce_host_guard", return_value=True),
        patch("app.api.catalog_health_routes.services_json_path", return_value=catalog_path),
    ):
        resp = client.get("/health/catalog")

    assert resp.status_code == 500
    assert "invalid JSON" in resp.json()["detail"]


def test_health_catalog_malformed_catalog_shape_returns_500(tmp_path: Path) -> None:
    catalog_path = tmp_path / "services.json"
    catalog_path.write_text(json.dumps({"service": []}))  # typo'd key

    client = make_client()
    with (
        patch("app.api.catalog_health_routes.enforce_host_guard", return_value=True),
        patch("app.api.catalog_health_routes.services_json_path", return_value=catalog_path),
    ):
        resp = client.get("/health/catalog")

    assert resp.status_code == 500
    assert "services" in resp.json()["detail"]


def test_health_catalog_unusable_cloudflare_credentials_returns_500(tmp_path: Path) -> None:
    catalog_path = tmp_path / "services.json"
    catalog_path.write_text(json.dumps({"services": []}))

    client = make_client()
    with (
        patch("app.api.catalog_health_routes.enforce_host_guard", return_value=True),
        patch("app.api.catalog_health_routes.services_json_path", return_value=catalog_path),
        patch(
            "app.api.catalog_health_routes.parse_cloudflare_credentials",
            side_effect=ValueError("no usable Cloudflare credentials"),
        ),
    ):
        resp = client.get("/health/catalog?skip_dns=false")

    assert resp.status_code == 500
    assert "credentials" in resp.json()["detail"]


def test_health_catalog_invalid_settings_returns_500(tmp_path: Path) -> None:
    catalog_path = tmp_path / "services.json"
    catalog_path.write_text(json.dumps({"services": []}))

    client = make_client()
    with (
        patch("app.api.catalog_health_routes.enforce_host_guard", return_value=True),
        patch("app.api.catalog_health_routes.services_json_path", return_value=catalog_path),
        patch("app.api.catalog_health_routes.timeout_seconds", return_value=0),
    ):
        resp = client.get("/health/catalog")

    assert resp.status_code == 500
    assert "timeout" in resp.json()["detail"]


def test_health_catalog_malformed_env_knob_returns_500(tmp_path: Path, monkeypatch) -> None:
    # A malformed ALERT_DAYS env var (int() raises inside the real
    # alert_days() getter, not a mocked return value) must be a clean
    # 500, not an unhandled exception -- the route's actual env-parsing
    # path, not a stand-in for it.
    catalog_path = tmp_path / "services.json"
    catalog_path.write_text(json.dumps({"services": []}))
    monkeypatch.setenv("ALERT_DAYS", "ten")

    client = make_client()
    with (
        patch("app.api.catalog_health_routes.enforce_host_guard", return_value=True),
        patch("app.api.catalog_health_routes.services_json_path", return_value=catalog_path),
    ):
        resp = client.get("/health/catalog")

    assert resp.status_code == 500
    assert "ten" in resp.json()["detail"]


def test_health_catalog_unhealthy_when_any_check_fails(tmp_path: Path) -> None:
    catalog_path = tmp_path / "services.json"
    catalog_path.write_text(json.dumps({"services": []}))

    fake_results = [CheckResult("svc", "cert", "fail", "missing")]

    client = make_client()
    with (
        patch("app.api.catalog_health_routes.enforce_host_guard", return_value=True),
        patch("app.api.catalog_health_routes.services_json_path", return_value=catalog_path),
        patch("app.api.catalog_health_routes.run_all", return_value=fake_results),
    ):
        resp = client.get("/health/catalog")

    assert resp.status_code == 200
    assert resp.json()["healthy"] is False
