"""Tests for the /catalog/streams* routes in app.api.catalog_crud_routes (#79)."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from app.api.app import create_app
from app.catalog_crud import GixyResult, NginxTestResult, PreviewResult


def _allow_all(username: str, password: str) -> bool:
    return True


def _preview_result(*, can_apply: bool = True) -> PreviewResult:
    return PreviewResult(
        can_apply=can_apply,
        diff="--- current\n+++ candidate\n",
        gixy=GixyResult(exit_code=0, output="", status="ok"),
        nginx_test=NginxTestResult(
            exit_code=0 if can_apply else 1,
            ok=can_apply,
            output="syntax ok" if can_apply else "syntax failed",
            status="ok" if can_apply else "failed",
        ),
        rendered="# rendered\n",
    )


def _stream(name: str, **overrides) -> dict:
    stream = {"name": name, "listen_port": 8883, "upstream": {"host": "broker.house.internal", "port": 1883}}
    stream.update(overrides)
    return stream


def make_client() -> TestClient:
    client = TestClient(
        create_app(authenticate_user=_allow_all, session_secret="test-session-secret"),
        base_url="https://testserver",
    )
    login = client.post("/auth/login", json={"username": "tester", "password": "irrelevant"})
    assert login.status_code == 200
    return client


@pytest.mark.parametrize(
    ("method", "path", "payload"),
    [
        ("delete", "/catalog/streams/example", None),
        ("get", "/catalog/streams", None),
        ("get", "/catalog/streams/example", None),
        ("post", "/catalog/apply", {"action": "delete", "name": "example", "target": "stream"}),
        ("post", "/catalog/preview", {"action": "delete", "name": "example", "target": "stream"}),
        ("post", "/catalog/streams", {"stream": _stream("example")}),
        ("put", "/catalog/streams/example", {"stream": {"listen_port": 8884}}),
    ],
)
def test_catalog_stream_routes_require_session(method: str, path: str, payload: dict | None) -> None:
    client = TestClient(create_app(session_secret="test-session-secret"), base_url="https://testserver")
    request = getattr(client, method)
    response = request(path, json=payload) if payload is not None else request(path)
    assert response.status_code == 401


def test_catalog_stream_list_host_guard_refused() -> None:
    client = make_client()
    with patch("app.api.catalog_crud_routes.enforce_host_guard", return_value=False):
        response = client.get("/catalog/streams")
    assert response.status_code == 503


def test_catalog_stream_list_returns_streams(tmp_path: Path) -> None:
    catalog_path = tmp_path / "services.json"
    catalog_path.write_text(json.dumps({"services": [], "streams": [_stream("mqtt")]}), encoding="utf-8")

    client = make_client()
    with (
        patch("app.api.catalog_crud_routes.enforce_host_guard", return_value=True),
        patch("app.api.catalog_crud_routes.services_json_path", return_value=catalog_path),
    ):
        response = client.get("/catalog/streams")

    assert response.status_code == 200
    assert [stream["name"] for stream in response.json()["streams"]] == ["mqtt"]


def test_catalog_stream_get_returns_404_for_a_missing_stream(tmp_path: Path) -> None:
    catalog_path = tmp_path / "services.json"
    catalog_path.write_text(json.dumps({"services": [], "streams": [_stream("mqtt")]}), encoding="utf-8")

    client = make_client()
    with (
        patch("app.api.catalog_crud_routes.enforce_host_guard", return_value=True),
        patch("app.api.catalog_crud_routes.services_json_path", return_value=catalog_path),
    ):
        response = client.get("/catalog/streams/missing")

    assert response.status_code == 404


def test_catalog_stream_create_persists_the_new_stream(tmp_path: Path) -> None:
    catalog_path = tmp_path / "services.json"
    catalog_path.write_text(json.dumps({"services": [], "streams": [_stream("mqtt")]}), encoding="utf-8")

    client = make_client()
    with (
        patch("app.api.catalog_crud_routes.enforce_host_guard", return_value=True),
        patch("app.api.catalog_crud_routes.services_json_path", return_value=catalog_path),
        patch("app.api.catalog_crud_routes.render_preview", return_value=_preview_result()),
    ):
        response = client.post("/catalog/streams", json={"stream": _stream("mqtt2", listen_port=8884)})

    assert response.status_code == 200
    assert response.json()["stream"]["name"] == "mqtt2"
    persisted = json.loads(catalog_path.read_text(encoding="utf-8"))
    assert [stream["name"] for stream in persisted["streams"]] == ["mqtt", "mqtt2"]


def test_catalog_stream_create_blocks_when_revalidation_fails(tmp_path: Path) -> None:
    catalog_path = tmp_path / "services.json"
    catalog_path.write_text(json.dumps({"services": [], "streams": [_stream("mqtt")]}), encoding="utf-8")

    client = make_client()
    with (
        patch("app.api.catalog_crud_routes.enforce_host_guard", return_value=True),
        patch("app.api.catalog_crud_routes.services_json_path", return_value=catalog_path),
        patch("app.api.catalog_crud_routes.render_preview", return_value=_preview_result(can_apply=False)),
    ):
        response = client.post("/catalog/streams", json={"stream": _stream("mqtt2", listen_port=8884)})

    assert response.status_code == 409
    persisted = json.loads(catalog_path.read_text(encoding="utf-8"))
    assert [stream["name"] for stream in persisted["streams"]] == ["mqtt"]


def test_catalog_stream_update_persists_changes(tmp_path: Path) -> None:
    catalog_path = tmp_path / "services.json"
    catalog_path.write_text(json.dumps({"services": [], "streams": [_stream("mqtt")]}), encoding="utf-8")

    client = make_client()
    with (
        patch("app.api.catalog_crud_routes.enforce_host_guard", return_value=True),
        patch("app.api.catalog_crud_routes.services_json_path", return_value=catalog_path),
        patch("app.api.catalog_crud_routes.render_preview", return_value=_preview_result()),
    ):
        response = client.put("/catalog/streams/mqtt", json={"stream": {"listen_port": 8884}})

    assert response.status_code == 200
    assert response.json()["stream"]["listen_port"] == 8884
    persisted = json.loads(catalog_path.read_text(encoding="utf-8"))
    assert persisted["streams"][0]["listen_port"] == 8884


def test_catalog_stream_delete_removes_the_stream(tmp_path: Path) -> None:
    catalog_path = tmp_path / "services.json"
    catalog_path.write_text(json.dumps({"services": [], "streams": [_stream("mqtt")]}), encoding="utf-8")

    client = make_client()
    with (
        patch("app.api.catalog_crud_routes.enforce_host_guard", return_value=True),
        patch("app.api.catalog_crud_routes.services_json_path", return_value=catalog_path),
        patch("app.api.catalog_crud_routes.render_preview", return_value=_preview_result()),
    ):
        response = client.delete("/catalog/streams/mqtt")

    assert response.status_code == 200
    persisted = json.loads(catalog_path.read_text(encoding="utf-8"))
    assert persisted["streams"] == []


def test_catalog_stream_delete_returns_404_for_a_missing_stream(tmp_path: Path) -> None:
    catalog_path = tmp_path / "services.json"
    catalog_path.write_text(json.dumps({"services": [], "streams": [_stream("mqtt")]}), encoding="utf-8")

    client = make_client()
    with (
        patch("app.api.catalog_crud_routes.enforce_host_guard", return_value=True),
        patch("app.api.catalog_crud_routes.services_json_path", return_value=catalog_path),
        patch("app.api.catalog_crud_routes.render_preview", return_value=_preview_result()),
    ):
        response = client.delete("/catalog/streams/missing")

    assert response.status_code == 404


def test_catalog_apply_and_preview_support_stream_target(tmp_path: Path) -> None:
    catalog_path = tmp_path / "services.json"
    catalog_path.write_text(json.dumps({"services": [], "streams": [_stream("mqtt")]}), encoding="utf-8")

    client = make_client()
    with (
        patch("app.api.catalog_crud_routes.enforce_host_guard", return_value=True),
        patch("app.api.catalog_crud_routes.services_json_path", return_value=catalog_path),
        patch("app.api.catalog_crud_routes.render_preview", return_value=_preview_result()),
    ):
        preview_response = client.post(
            "/catalog/preview",
            json={"action": "create", "service": _stream("mqtt2", listen_port=8884), "target": "stream"},
        )
        apply_response = client.post(
            "/catalog/apply",
            json={"action": "create", "service": _stream("mqtt2", listen_port=8884), "target": "stream"},
        )

    assert preview_response.status_code == 200
    assert apply_response.status_code == 200
    assert apply_response.json()["stream"]["name"] == "mqtt2"
    persisted = json.loads(catalog_path.read_text(encoding="utf-8"))
    assert [stream["name"] for stream in persisted["streams"]] == ["mqtt", "mqtt2"]
