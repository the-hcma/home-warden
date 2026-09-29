"""Tests for GET /pki/status (app.api.pki_view_routes)."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from app.api.app import create_app


def make_client() -> TestClient:
    def _allow_all(username: str, password: str) -> bool:
        return True

    client = TestClient(
        create_app(authenticate_user=_allow_all, session_secret="test-session-secret"),
        base_url="https://testserver",
    )
    login = client.post("/auth/login", json={"username": "tester", "password": "irrelevant"})
    assert login.status_code == 200
    return client


def test_pki_status_host_guard_refused() -> None:
    client = make_client()
    with patch("app.api.pki_view_routes.enforce_host_guard", return_value=False):
        resp = client.get("/pki/status")
    assert resp.status_code == 503


def test_pki_status_invalid_catalog_returns_500(tmp_path: Path) -> None:
    catalog = tmp_path / "services.json"
    catalog.write_text('{"service": []}')
    client = make_client()
    with (
        patch("app.api.pki_view_routes.enforce_host_guard", return_value=True),
        patch("app.api.pki_view_routes.services_json_path", return_value=catalog),
    ):
        resp = client.get("/pki/status")
    assert resp.status_code == 500


def test_pki_status_passes_catalog_services_and_store_through(tmp_path: Path) -> None:
    services = [{"name": "wiki", "server_name": "wiki.example.com", "client_cert": {"mode": "required"}}]
    catalog = tmp_path / "services.json"
    catalog.write_text(json.dumps({"services": services}))
    client = make_client()
    with (
        patch("app.api.pki_view_routes.enforce_host_guard", return_value=True),
        patch("app.api.pki_view_routes.services_json_path", return_value=catalog),
        patch("app.api.pki_view_routes.client_pki_store", return_value=tmp_path / "store"),
        patch("app.api.pki_view_routes.load_pki_status", return_value={"status": "ok"}) as load,
    ):
        resp = client.get("/pki/status")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}
    assert load.call_args.args == (tmp_path / "store", services)


def test_pki_status_requires_session() -> None:
    client = TestClient(create_app(session_secret="test-session-secret"), base_url="https://testserver")
    assert client.get("/pki/status").status_code == 401


def test_pki_status_without_a_catalog_still_reports_the_store(tmp_path: Path) -> None:
    client = make_client()
    with (
        patch("app.api.pki_view_routes.enforce_host_guard", return_value=True),
        patch("app.api.pki_view_routes.services_json_path", return_value=tmp_path / "missing.json"),
        patch("app.api.pki_view_routes.client_pki_store", return_value=tmp_path / "store"),
    ):
        resp = client.get("/pki/status")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "not_configured"
    assert body["vhosts"] == []
