"""Tests for GET /dns/records (app.api.dns_view_routes)."""

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


def test_dns_records_requires_session() -> None:
    client = TestClient(create_app(session_secret="test-session-secret"), base_url="https://testserver")
    resp = client.get("/dns/records")
    assert resp.status_code == 401


def test_dns_records_host_guard_refused() -> None:
    client = make_client()
    with patch("app.api.dns_view_routes.enforce_host_guard", return_value=False):
        resp = client.get("/dns/records")
    assert resp.status_code == 503


def test_dns_records_missing_catalog_file_returns_404(tmp_path: Path) -> None:
    client = make_client()
    with (
        patch("app.api.dns_view_routes.enforce_host_guard", return_value=True),
        patch("app.api.dns_view_routes.services_json_path", return_value=tmp_path / "missing.json"),
    ):
        resp = client.get("/dns/records")
    assert resp.status_code == 404


def test_dns_records_invalid_catalog_returns_500(tmp_path: Path) -> None:
    catalog_path = tmp_path / "services.json"
    catalog_path.write_text('{"service": []}')
    client = make_client()
    with (
        patch("app.api.dns_view_routes.enforce_host_guard", return_value=True),
        patch("app.api.dns_view_routes.services_json_path", return_value=catalog_path),
    ):
        resp = client.get("/dns/records")
    assert resp.status_code == 500


def test_dns_records_static_service_is_not_applicable(tmp_path: Path) -> None:
    catalog_path = tmp_path / "services.json"
    catalog_path.write_text(
        json.dumps({"services": [{"name": "svc", "kind": "static", "server_name": "app.example.com"}]})
    )
    client = make_client()
    with (
        patch("app.api.dns_view_routes.enforce_host_guard", return_value=True),
        patch("app.api.dns_view_routes.services_json_path", return_value=catalog_path),
        patch("app.api.dns_view_routes.parse_cloudflare_credentials", return_value=None),
        patch("app.api.dns_view_routes.load_zones_yaml", return_value={}),
    ):
        resp = client.get("/dns/records")
    assert resp.status_code == 200
    entry = resp.json()["services"][0]
    assert entry["local"] == {"status": "not_applicable", "records": None}


def test_dns_records_no_zones_yaml_configured_is_not_configured(tmp_path: Path) -> None:
    catalog_path = tmp_path / "services.json"
    catalog_path.write_text(
        json.dumps(
            {
                "services": [
                    {
                        "name": "svc",
                        "kind": "proxy",
                        "server_name": "app.example.com",
                        "upstream": {"host": "backend.internal", "port": 8080},
                    }
                ]
            }
        )
    )
    client = make_client()
    with (
        patch("app.api.dns_view_routes.enforce_host_guard", return_value=True),
        patch("app.api.dns_view_routes.services_json_path", return_value=catalog_path),
        patch("app.api.dns_view_routes.parse_cloudflare_credentials", return_value=None),
        patch("app.api.dns_view_routes.load_zones_yaml", return_value={}),
    ):
        resp = client.get("/dns/records")
    entry = resp.json()["services"][0]
    assert entry["local"] == {"status": "not_configured", "records": None}
    assert entry["external"] == {"status": "not_configured", "records": None}


def test_dns_records_local_missing_record(tmp_path: Path) -> None:
    catalog_path = tmp_path / "services.json"
    catalog_path.write_text(
        json.dumps(
            {
                "services": [
                    {
                        "name": "svc",
                        "kind": "proxy",
                        "server_name": "app.example.com",
                        "upstream": {"host": "backend.internal", "port": 8080},
                    }
                ]
            }
        )
    )
    client = make_client()
    with (
        patch("app.api.dns_view_routes.enforce_host_guard", return_value=True),
        patch("app.api.dns_view_routes.services_json_path", return_value=catalog_path),
        patch("app.api.dns_view_routes.parse_cloudflare_credentials", return_value=None),
        patch(
            "app.api.dns_view_routes.load_zones_yaml",
            return_value={"domains": [{"domain": "internal", "ttl": 300, "records": {}}]},
        ),
    ):
        resp = client.get("/dns/records")
    entry = resp.json()["services"][0]
    assert entry["local"] == {"status": "missing", "records": None}


def test_dns_records_local_ok(tmp_path: Path) -> None:
    catalog_path = tmp_path / "services.json"
    catalog_path.write_text(
        json.dumps(
            {
                "services": [
                    {
                        "name": "svc",
                        "kind": "proxy",
                        "server_name": "app.example.com",
                        "upstream": {"host": "backend.internal", "port": 8080},
                    }
                ]
            }
        )
    )
    zones_data = {"domains": [{"domain": "internal", "ttl": 300, "records": {"backend.internal": [{"a": "10.0.0.5"}]}}]}
    client = make_client()
    with (
        patch("app.api.dns_view_routes.enforce_host_guard", return_value=True),
        patch("app.api.dns_view_routes.services_json_path", return_value=catalog_path),
        patch("app.api.dns_view_routes.parse_cloudflare_credentials", return_value=None),
        patch("app.api.dns_view_routes.load_zones_yaml", return_value=zones_data),
    ):
        resp = client.get("/dns/records")
    entry = resp.json()["services"][0]
    assert entry["local"] == {"status": "ok", "records": [{"type": "a", "content": "10.0.0.5", "ttl": 300}]}


def test_dns_records_external_ok(tmp_path: Path) -> None:
    catalog_path = tmp_path / "services.json"
    catalog_path.write_text(
        json.dumps({"services": [{"name": "svc", "kind": "static", "server_name": "app.example.com"}]})
    )
    client = make_client()
    with (
        patch("app.api.dns_view_routes.enforce_host_guard", return_value=True),
        patch("app.api.dns_view_routes.services_json_path", return_value=catalog_path),
        patch("app.api.dns_view_routes.parse_cloudflare_credentials", return_value={"x": "y"}),
        patch("app.api.dns_view_routes.load_zones_yaml", return_value={}),
        patch(
            "app.api.dns_view_routes.list_cloudflare_records",
            return_value=[{"type": "A", "content": "203.0.113.10", "ttl": 300, "proxied": False}],
        ),
    ):
        resp = client.get("/dns/records")
    entry = resp.json()["services"][0]
    assert entry["external"] == {
        "status": "ok",
        "records": [{"type": "A", "content": "203.0.113.10", "ttl": 300, "proxied": False}],
    }


def test_dns_records_malformed_cloudflare_credentials_degrades_gracefully(tmp_path: Path) -> None:
    # A bad cloudflare.ini must not 500 the whole page -- local records
    # should still show, external just reports not_configured.
    catalog_path = tmp_path / "services.json"
    catalog_path.write_text(
        json.dumps({"services": [{"name": "svc", "kind": "static", "server_name": "app.example.com"}]})
    )
    client = make_client()
    with (
        patch("app.api.dns_view_routes.enforce_host_guard", return_value=True),
        patch("app.api.dns_view_routes.services_json_path", return_value=catalog_path),
        patch("app.api.dns_view_routes.parse_cloudflare_credentials", side_effect=ValueError("bad ini")),
        patch("app.api.dns_view_routes.load_zones_yaml", return_value={}),
    ):
        resp = client.get("/dns/records")
    assert resp.status_code == 200
    entry = resp.json()["services"][0]
    assert entry["external"] == {"status": "not_configured", "records": None}
