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


def _write_catalog(tmp_path: Path, services: list[dict]) -> Path:
    path = tmp_path / "services.json"
    path.write_text(json.dumps({"services": services}))
    return path


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


def test_dns_records_defaults_missing_service_name(tmp_path: Path) -> None:
    # load_catalog doesn't require a "name" key -- a raw None here would
    # crash the web UI's client-side sort.
    catalog_path = _write_catalog(tmp_path, [{"kind": "static", "server_name": "app.example.com"}])
    client = make_client()
    with (
        patch("app.api.dns_view_routes.enforce_host_guard", return_value=True),
        patch("app.api.dns_view_routes.services_json_path", return_value=catalog_path),
        patch("app.api.dns_view_routes.parse_cloudflare_credentials", return_value=None),
        patch("app.api.dns_view_routes.load_zones_yaml", return_value={}),
    ):
        resp = client.get("/dns/records")
    entry = resp.json()["services"][0]
    assert entry["name"] == "<unnamed>"


def test_dns_records_static_service_is_not_applicable(tmp_path: Path) -> None:
    catalog_path = _write_catalog(tmp_path, [{"name": "svc", "kind": "static", "server_name": "app.example.com"}])
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
    assert entry["local"] == {"status": "not_applicable", "records": None, "detail": None}


def test_dns_records_literal_ip_upstream_host_is_not_applicable(tmp_path: Path) -> None:
    # A literal IP needs no DNS at all -- must not render as "Missing"
    # just because it isn't a key in zones.yml (mirrors
    # check_local_dns's own ipaddress.ip_address(host) guard).
    catalog_path = _write_catalog(
        tmp_path,
        [
            {
                "name": "svc",
                "kind": "proxy",
                "server_name": "app.example.com",
                "upstream": {"host": "10.0.0.5", "port": 8080},
            }
        ],
    )
    zones_data = {"domains": [{"domain": "internal", "ttl": 300, "records": {}}]}
    client = make_client()
    with (
        patch("app.api.dns_view_routes.enforce_host_guard", return_value=True),
        patch("app.api.dns_view_routes.services_json_path", return_value=catalog_path),
        patch("app.api.dns_view_routes.parse_cloudflare_credentials", return_value=None),
        patch("app.api.dns_view_routes.load_zones_yaml", return_value=zones_data),
    ):
        resp = client.get("/dns/records")
    entry = resp.json()["services"][0]
    assert entry["local"] == {"status": "not_applicable", "records": None, "detail": None}


def test_dns_records_no_zones_yaml_configured_is_not_configured(tmp_path: Path) -> None:
    catalog_path = _write_catalog(
        tmp_path,
        [
            {
                "name": "svc",
                "kind": "proxy",
                "server_name": "app.example.com",
                "upstream": {"host": "backend.internal", "port": 8080},
            }
        ],
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
    assert entry["local"] == {"status": "not_configured", "records": None, "detail": None}
    assert entry["external"] == {"status": "not_configured", "records": None, "detail": None}


def test_dns_records_local_missing_record(tmp_path: Path) -> None:
    catalog_path = _write_catalog(
        tmp_path,
        [
            {
                "name": "svc",
                "kind": "proxy",
                "server_name": "app.example.com",
                "upstream": {"host": "backend.internal", "port": 8080},
            }
        ],
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
    assert entry["local"] == {"status": "missing", "records": None, "detail": None}


def test_dns_records_local_present_but_empty_records_is_missing(tmp_path: Path) -> None:
    # An owner key with a literal empty entries list is "representable"
    # per local_records_for_owner's own docstring -- must fold into
    # "missing", not report status=ok with an empty list (which the web
    # UI would otherwise disagree with by rendering it as Missing anyway).
    catalog_path = _write_catalog(
        tmp_path,
        [
            {
                "name": "svc",
                "kind": "proxy",
                "server_name": "app.example.com",
                "upstream": {"host": "backend.internal", "port": 8080},
            }
        ],
    )
    zones_data = {"domains": [{"domain": "internal", "ttl": 300, "records": {"backend.internal": []}}]}
    client = make_client()
    with (
        patch("app.api.dns_view_routes.enforce_host_guard", return_value=True),
        patch("app.api.dns_view_routes.services_json_path", return_value=catalog_path),
        patch("app.api.dns_view_routes.parse_cloudflare_credentials", return_value=None),
        patch("app.api.dns_view_routes.load_zones_yaml", return_value=zones_data),
    ):
        resp = client.get("/dns/records")
    entry = resp.json()["services"][0]
    assert entry["local"] == {"status": "missing", "records": None, "detail": None}


def test_dns_records_local_ok(tmp_path: Path) -> None:
    catalog_path = _write_catalog(
        tmp_path,
        [
            {
                "name": "svc",
                "kind": "proxy",
                "server_name": "app.example.com",
                "upstream": {"host": "backend.internal", "port": 8080},
            }
        ],
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
    assert entry["local"] == {
        "status": "ok",
        "records": [{"type": "a", "content": "10.0.0.5", "ttl": 300}],
        "detail": None,
    }


def test_dns_records_external_ok(tmp_path: Path) -> None:
    catalog_path = _write_catalog(tmp_path, [{"name": "svc", "kind": "static", "server_name": "app.example.com"}])
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
        "detail": None,
    }


def test_dns_records_external_not_applicable_without_server_name(tmp_path: Path) -> None:
    # load_catalog doesn't require server_name -- a service without one
    # has nothing to look up externally.
    catalog_path = _write_catalog(tmp_path, [{"name": "svc", "kind": "static"}])
    client = make_client()
    with (
        patch("app.api.dns_view_routes.enforce_host_guard", return_value=True),
        patch("app.api.dns_view_routes.services_json_path", return_value=catalog_path),
        patch("app.api.dns_view_routes.parse_cloudflare_credentials", return_value={"x": "y"}),
        patch("app.api.dns_view_routes.load_zones_yaml", return_value={}),
        patch("app.api.dns_view_routes.list_cloudflare_records") as mock_list,
    ):
        resp = client.get("/dns/records")
    mock_list.assert_not_called()
    entry = resp.json()["services"][0]
    assert entry["external"] == {"status": "not_applicable", "records": None, "detail": None}


def test_dns_records_external_missing_record(tmp_path: Path) -> None:
    catalog_path = _write_catalog(tmp_path, [{"name": "svc", "kind": "static", "server_name": "app.example.com"}])
    client = make_client()
    with (
        patch("app.api.dns_view_routes.enforce_host_guard", return_value=True),
        patch("app.api.dns_view_routes.services_json_path", return_value=catalog_path),
        patch("app.api.dns_view_routes.parse_cloudflare_credentials", return_value={"x": "y"}),
        patch("app.api.dns_view_routes.load_zones_yaml", return_value={}),
        patch("app.api.dns_view_routes.list_cloudflare_records", return_value=None),
    ):
        resp = client.get("/dns/records")
    entry = resp.json()["services"][0]
    assert entry["external"] == {"status": "missing", "records": None, "detail": None}


def test_dns_records_external_api_error_is_distinct_from_missing(tmp_path: Path) -> None:
    # An auth failure or persistent 5xx must not read as a genuine absent
    # record -- see #122 review.
    catalog_path = _write_catalog(tmp_path, [{"name": "svc", "kind": "static", "server_name": "app.example.com"}])
    client = make_client()
    with (
        patch("app.api.dns_view_routes.enforce_host_guard", return_value=True),
        patch("app.api.dns_view_routes.services_json_path", return_value=catalog_path),
        patch("app.api.dns_view_routes.parse_cloudflare_credentials", return_value={"x": "y"}),
        patch("app.api.dns_view_routes.load_zones_yaml", return_value={}),
        patch("app.api.dns_view_routes.list_cloudflare_records", side_effect=RuntimeError("401 unauthorized")),
    ):
        resp = client.get("/dns/records")
    assert resp.status_code == 200
    entry = resp.json()["services"][0]
    assert entry["external"]["status"] == "error"
    assert entry["external"]["records"] is None
    assert "401" in entry["external"]["detail"]


def test_dns_records_malformed_cloudflare_credentials_degrades_gracefully(tmp_path: Path) -> None:
    # A bad cloudflare.ini must not 500 the whole page -- local records
    # should still show, external just reports not_configured.
    catalog_path = _write_catalog(tmp_path, [{"name": "svc", "kind": "static", "server_name": "app.example.com"}])
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
    assert entry["external"] == {"status": "not_configured", "records": None, "detail": None}
