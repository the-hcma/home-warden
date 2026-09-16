"""Tests for app.api.catalog_crud_routes."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from app.api.app import create_app
from app.catalog_crud import GixyResult, NginxTestResult, PreviewResult
from app.home_warden_config import HomeWardenConfig


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


def _service(name: str, **overrides) -> dict:
    service = {
        "kind": "proxy",
        "name": name,
        "server_name": f"{name}.example.com",
        "upstream": {"host": "backend.example.internal", "path": "/", "port": 8080, "scheme": "http"},
    }
    service.update(overrides)
    return service


def _configure_real_preview(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    def fake_run(command: list[str], **kwargs) -> subprocess.CompletedProcess[str]:
        if command[0] == "sudo":
            return subprocess.CompletedProcess(command, 0, stdout="syntax ok", stderr="")
        return subprocess.CompletedProcess(command, 0, stdout="gixy ok", stderr="")

    monkeypatch.setenv("SCRATCH_DIR", str(tmp_path / "scratch"))
    monkeypatch.setattr("app.catalog_crud.certs_live_dir", lambda: tmp_path / "certs")
    monkeypatch.setattr("app.catalog_crud.load_config", lambda path: HomeWardenConfig())
    monkeypatch.setattr("app.catalog_crud.subprocess.run", fake_run)
    # Force the SCRATCH_DIR fallback rather than whatever setup-service may have
    # installed on the machine running this suite (AGENTS.md: tests must not
    # depend on live infrastructure) -- mirrors test_catalog_crud.py's autouse fixture.
    monkeypatch.setattr("app.catalog_crud.NGINX_PREVIEW_CONF_PATH_FILE", tmp_path / "unused-preview-conf-path")


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
        ("delete", "/catalog/services/example", None),
        ("get", "/catalog/services", None),
        ("get", "/catalog/services/example", None),
        ("post", "/catalog/apply", {"action": "delete", "name": "example"}),
        ("post", "/catalog/preview", {"action": "delete", "name": "example"}),
        ("post", "/catalog/services", {"service": _service("example")}),
        ("put", "/catalog/services/example", {"service": {"server_name": "new.example.com"}}),
    ],
)
def test_catalog_routes_require_session(method: str, path: str, payload: dict | None) -> None:
    client = TestClient(create_app(session_secret="test-session-secret"), base_url="https://testserver")
    request = getattr(client, method)
    response = request(path, json=payload) if payload is not None else request(path)
    assert response.status_code == 401


def test_catalog_list_host_guard_refused() -> None:
    client = make_client()
    with patch("app.api.catalog_crud_routes.enforce_host_guard", return_value=False):
        response = client.get("/catalog/services")
    assert response.status_code == 503


def test_catalog_list_returns_services(tmp_path: Path) -> None:
    catalog_path = tmp_path / "services.json"
    catalog_path.write_text(json.dumps({"services": [_service("one"), _service("two")]}), encoding="utf-8")

    client = make_client()
    with (
        patch("app.api.catalog_crud_routes.enforce_host_guard", return_value=True),
        patch("app.api.catalog_crud_routes.services_json_path", return_value=catalog_path),
    ):
        response = client.get("/catalog/services")

    assert response.status_code == 200
    assert [service["name"] for service in response.json()["services"]] == ["one", "two"]


def test_catalog_get_returns_one_service(tmp_path: Path) -> None:
    catalog_path = tmp_path / "services.json"
    catalog_path.write_text(json.dumps({"services": [_service("one")]}), encoding="utf-8")

    client = make_client()
    with (
        patch("app.api.catalog_crud_routes.enforce_host_guard", return_value=True),
        patch("app.api.catalog_crud_routes.services_json_path", return_value=catalog_path),
    ):
        response = client.get("/catalog/services/one")

    assert response.status_code == 200
    assert response.json()["service"]["server_name"] == "one.example.com"


def test_catalog_get_returns_404_for_a_missing_service(tmp_path: Path) -> None:
    catalog_path = tmp_path / "services.json"
    catalog_path.write_text(json.dumps({"services": [_service("one")]}), encoding="utf-8")

    client = make_client()
    with (
        patch("app.api.catalog_crud_routes.enforce_host_guard", return_value=True),
        patch("app.api.catalog_crud_routes.services_json_path", return_value=catalog_path),
    ):
        response = client.get("/catalog/services/missing")

    assert response.status_code == 404


def test_catalog_update_returns_404_for_a_missing_service(tmp_path: Path) -> None:
    catalog_path = tmp_path / "services.json"
    catalog_path.write_text(json.dumps({"services": [_service("one")]}), encoding="utf-8")

    client = make_client()
    with (
        patch("app.api.catalog_crud_routes.enforce_host_guard", return_value=True),
        patch("app.api.catalog_crud_routes.services_json_path", return_value=catalog_path),
        patch("app.api.catalog_crud_routes.render_preview", return_value=_preview_result()),
    ):
        response = client.put("/catalog/services/missing", json={"service": {"server_name": "missing.example.com"}})

    assert response.status_code == 404


def test_catalog_delete_returns_404_for_a_missing_service(tmp_path: Path) -> None:
    catalog_path = tmp_path / "services.json"
    catalog_path.write_text(json.dumps({"services": [_service("one")]}), encoding="utf-8")

    client = make_client()
    with (
        patch("app.api.catalog_crud_routes.enforce_host_guard", return_value=True),
        patch("app.api.catalog_crud_routes.services_json_path", return_value=catalog_path),
        patch("app.api.catalog_crud_routes.render_preview", return_value=_preview_result()),
    ):
        response = client.delete("/catalog/services/missing")

    assert response.status_code == 404


def test_catalog_preview_returns_structured_preview(tmp_path: Path) -> None:
    catalog_path = tmp_path / "services.json"
    catalog_path.write_text(json.dumps({"services": [_service("one")]}), encoding="utf-8")

    client = make_client()
    with (
        patch("app.api.catalog_crud_routes.enforce_host_guard", return_value=True),
        patch("app.api.catalog_crud_routes.services_json_path", return_value=catalog_path),
        patch("app.api.catalog_crud_routes.render_preview", return_value=_preview_result(can_apply=False)),
    ):
        response = client.post(
            "/catalog/preview",
            json={"action": "update", "name": "one", "service": {"server_name": "preview.example.com"}},
        )

    assert response.status_code == 200
    body = response.json()
    assert body["can_apply"] is False
    assert body["nginx_test"]["status"] == "failed"


def test_catalog_apply_blocks_when_revalidation_fails(tmp_path: Path) -> None:
    catalog_path = tmp_path / "services.json"
    catalog_path.write_text(json.dumps({"services": [_service("one")]}), encoding="utf-8")

    client = make_client()
    with (
        patch("app.api.catalog_crud_routes.enforce_host_guard", return_value=True),
        patch("app.api.catalog_crud_routes.services_json_path", return_value=catalog_path),
        patch("app.api.catalog_crud_routes.render_preview", return_value=_preview_result(can_apply=False)),
    ):
        response = client.post(
            "/catalog/apply",
            json={"action": "update", "name": "one", "service": {"server_name": "blocked.example.com"}},
        )

    assert response.status_code == 409
    assert json.loads(catalog_path.read_text(encoding="utf-8"))["services"][0]["server_name"] == "one.example.com"


def test_catalog_create_blocks_when_revalidation_fails(tmp_path: Path) -> None:
    catalog_path = tmp_path / "services.json"
    catalog_path.write_text(json.dumps({"services": [_service("one")]}), encoding="utf-8")

    client = make_client()
    with (
        patch("app.api.catalog_crud_routes.enforce_host_guard", return_value=True),
        patch("app.api.catalog_crud_routes.services_json_path", return_value=catalog_path),
        patch("app.api.catalog_crud_routes.render_preview", return_value=_preview_result(can_apply=False)),
    ):
        response = client.post("/catalog/services", json={"service": _service("two")})

    assert response.status_code == 409
    persisted = json.loads(catalog_path.read_text(encoding="utf-8"))
    assert [service["name"] for service in persisted["services"]] == ["one"]


def test_catalog_delete_blocks_when_revalidation_fails(tmp_path: Path) -> None:
    catalog_path = tmp_path / "services.json"
    catalog_path.write_text(json.dumps({"services": [_service("one")]}), encoding="utf-8")

    client = make_client()
    with (
        patch("app.api.catalog_crud_routes.enforce_host_guard", return_value=True),
        patch("app.api.catalog_crud_routes.services_json_path", return_value=catalog_path),
        patch("app.api.catalog_crud_routes.render_preview", return_value=_preview_result(can_apply=False)),
    ):
        response = client.delete("/catalog/services/one")

    assert response.status_code == 409
    persisted = json.loads(catalog_path.read_text(encoding="utf-8"))
    assert [service["name"] for service in persisted["services"]] == ["one"]


def test_catalog_update_blocks_when_revalidation_fails(tmp_path: Path) -> None:
    catalog_path = tmp_path / "services.json"
    catalog_path.write_text(json.dumps({"services": [_service("one")]}), encoding="utf-8")

    client = make_client()
    with (
        patch("app.api.catalog_crud_routes.enforce_host_guard", return_value=True),
        patch("app.api.catalog_crud_routes.services_json_path", return_value=catalog_path),
        patch("app.api.catalog_crud_routes.render_preview", return_value=_preview_result(can_apply=False)),
    ):
        response = client.put(
            "/catalog/services/one",
            json={"service": {"server_name": "blocked.example.com"}},
        )

    assert response.status_code == 409
    persisted = json.loads(catalog_path.read_text(encoding="utf-8"))
    assert persisted["services"][0]["server_name"] == "one.example.com"


def test_catalog_create_persists_the_new_service(tmp_path: Path) -> None:
    catalog_path = tmp_path / "services.json"
    catalog_path.write_text(json.dumps({"services": [_service("one")]}), encoding="utf-8")

    client = make_client()
    with (
        patch("app.api.catalog_crud_routes.enforce_host_guard", return_value=True),
        patch("app.api.catalog_crud_routes.services_json_path", return_value=catalog_path),
        patch("app.api.catalog_crud_routes.render_preview", return_value=_preview_result()),
    ):
        response = client.post("/catalog/services", json={"service": _service("two")})

    assert response.status_code == 200
    assert response.json()["service"]["name"] == "two"
    persisted = json.loads(catalog_path.read_text(encoding="utf-8"))
    assert [service["name"] for service in persisted["services"]] == ["one", "two"]


def test_catalog_create_strips_whitespace_before_persisting_and_lookup(tmp_path: Path) -> None:
    catalog_path = tmp_path / "services.json"
    catalog_path.write_text(json.dumps({"services": [_service("one")]}), encoding="utf-8")

    client = make_client()
    with (
        patch("app.api.catalog_crud_routes.enforce_host_guard", return_value=True),
        patch("app.api.catalog_crud_routes.services_json_path", return_value=catalog_path),
        patch("app.api.catalog_crud_routes.render_preview", return_value=_preview_result()),
    ):
        service = _service("two")
        service["name"] = " two "
        service["server_name"] = " two.example.com "
        response = client.post(
            "/catalog/services",
            json={"service": service},
        )

    assert response.status_code == 200
    assert response.json()["service"]["name"] == "two"
    assert response.json()["service"]["server_name"] == "two.example.com"
    persisted = json.loads(catalog_path.read_text(encoding="utf-8"))
    assert persisted["services"][1]["name"] == "two"
    assert persisted["services"][1]["server_name"] == "two.example.com"


def test_catalog_create_rejects_names_that_only_differ_by_whitespace(tmp_path: Path) -> None:
    catalog_path = tmp_path / "services.json"
    catalog_path.write_text(json.dumps({"services": [_service("one")]}), encoding="utf-8")

    client = make_client()
    with (
        patch("app.api.catalog_crud_routes.enforce_host_guard", return_value=True),
        patch("app.api.catalog_crud_routes.services_json_path", return_value=catalog_path),
    ):
        service = _service("two")
        service["name"] = " one "
        service["server_name"] = "two.example.com"
        response = client.post(
            "/catalog/services",
            json={"service": service},
        )

    assert response.status_code == 409
    assert [service["name"] for service in json.loads(catalog_path.read_text(encoding="utf-8"))["services"]] == ["one"]


def test_catalog_create_preview_and_apply_allow_unrelated_service_when_duplicates_already_exist(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    catalog_path = tmp_path / "services.json"
    catalog_path.write_text(
        json.dumps(
            {
                "services": [
                    _service("dup-a", server_name="shared.example.com"),
                    _service("dup-b", server_name="shared.example.com"),
                ]
            }
        ),
        encoding="utf-8",
    )
    _configure_real_preview(monkeypatch, tmp_path)

    client = make_client()
    with (
        patch("app.api.catalog_crud_routes.enforce_host_guard", return_value=True),
        patch("app.api.catalog_crud_routes.services_json_path", return_value=catalog_path),
    ):
        preview_response = client.post("/catalog/preview", json={"action": "create", "service": _service("three")})
        apply_response = client.post("/catalog/apply", json={"action": "create", "service": _service("three")})

    assert preview_response.status_code == 200
    assert apply_response.status_code == 200
    persisted = json.loads(catalog_path.read_text(encoding="utf-8"))
    assert [service["name"] for service in persisted["services"]] == ["dup-a", "dup-b", "three"]


@pytest.mark.parametrize("name_to_delete", ["other", "dup-a"])
def test_catalog_delete_allows_preexisting_duplicates_for_unrelated_and_duplicate_entry_deletes(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    name_to_delete: str,
) -> None:
    catalog_path = tmp_path / "services.json"
    catalog_path.write_text(
        json.dumps(
            {
                "services": [
                    _service("dup-a", server_name="shared.example.com"),
                    _service("dup-b", server_name="shared.example.com"),
                    _service("other"),
                ]
            }
        ),
        encoding="utf-8",
    )
    _configure_real_preview(monkeypatch, tmp_path)

    client = make_client()
    with (
        patch("app.api.catalog_crud_routes.enforce_host_guard", return_value=True),
        patch("app.api.catalog_crud_routes.services_json_path", return_value=catalog_path),
    ):
        response = client.delete(f"/catalog/services/{name_to_delete}")

    assert response.status_code == 200
    persisted = json.loads(catalog_path.read_text(encoding="utf-8"))
    assert [service["name"] for service in persisted["services"]] == [
        service_name for service_name in ["dup-a", "dup-b", "other"] if service_name != name_to_delete
    ]


def test_catalog_apply_persists_the_mutation(tmp_path: Path) -> None:
    catalog_path = tmp_path / "services.json"
    catalog_path.write_text(json.dumps({"services": [_service("one")]}), encoding="utf-8")

    client = make_client()
    with (
        patch("app.api.catalog_crud_routes.enforce_host_guard", return_value=True),
        patch("app.api.catalog_crud_routes.services_json_path", return_value=catalog_path),
        patch("app.api.catalog_crud_routes.render_preview", return_value=_preview_result()),
    ):
        response = client.post(
            "/catalog/apply",
            json={"action": "update", "name": "one", "service": {"server_name": "updated.example.com"}},
        )

    assert response.status_code == 200
    assert json.loads(catalog_path.read_text(encoding="utf-8"))["services"][0]["server_name"] == "updated.example.com"


def test_catalog_delete_removes_the_service(tmp_path: Path) -> None:
    catalog_path = tmp_path / "services.json"
    catalog_path.write_text(json.dumps({"services": [_service("one"), _service("two")]}), encoding="utf-8")

    client = make_client()
    with (
        patch("app.api.catalog_crud_routes.enforce_host_guard", return_value=True),
        patch("app.api.catalog_crud_routes.services_json_path", return_value=catalog_path),
        patch("app.api.catalog_crud_routes.render_preview", return_value=_preview_result()),
    ):
        response = client.delete("/catalog/services/one")

    assert response.status_code == 200
    assert response.json()["deleted_name"] == "one"
    persisted = json.loads(catalog_path.read_text(encoding="utf-8"))
    assert [service["name"] for service in persisted["services"]] == ["two"]


def test_catalog_preview_surfaces_reserved_web_ui_collisions_as_400(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    catalog_path = tmp_path / "services.json"
    catalog_path.write_text(json.dumps({"services": [_service("home-warden-web-ui")]}), encoding="utf-8")
    monkeypatch.setattr("app.catalog_crud.load_config", lambda path: HomeWardenConfig(fqdn="warden.example.com"))

    client = make_client()
    with (
        patch("app.api.catalog_crud_routes.enforce_host_guard", return_value=True),
        patch("app.api.catalog_crud_routes.services_json_path", return_value=catalog_path),
    ):
        response = client.post(
            "/catalog/preview",
            json={"action": "update", "name": "home-warden-web-ui", "service": {"server_name": "new.example.com"}},
        )

    assert response.status_code == 400
    assert "reserved service name" in response.json()["detail"]


def test_catalog_create_rejects_reserved_web_ui_collisions_without_persisting(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    catalog_path = tmp_path / "services.json"
    catalog_path.write_text(json.dumps({"services": [_service("one")]}), encoding="utf-8")
    monkeypatch.setattr("app.catalog_crud.load_config", lambda path: HomeWardenConfig(fqdn="warden.example.com"))

    client = make_client()
    with (
        patch("app.api.catalog_crud_routes.enforce_host_guard", return_value=True),
        patch("app.api.catalog_crud_routes.services_json_path", return_value=catalog_path),
    ):
        response = client.post("/catalog/services", json={"service": _service("home-warden-web-ui")})

    assert response.status_code == 400
    assert "reserved service name" in response.json()["detail"]
    assert [service["name"] for service in json.loads(catalog_path.read_text(encoding="utf-8"))["services"]] == ["one"]


def test_catalog_update_preserves_hidden_fields(tmp_path: Path) -> None:
    catalog_path = tmp_path / "services.json"
    catalog_path.write_text(
        json.dumps(
            {
                "services": [
                    _service(
                        "one",
                        client_cert={"allow_cn": ["alice"], "ca_bundle": "/ca.pem", "mode": "required"},
                        managed_by={"repo": "the-hcma/example"},
                    )
                ]
            }
        ),
        encoding="utf-8",
    )

    client = make_client()
    with (
        patch("app.api.catalog_crud_routes.enforce_host_guard", return_value=True),
        patch("app.api.catalog_crud_routes.services_json_path", return_value=catalog_path),
        patch("app.api.catalog_crud_routes.render_preview", return_value=_preview_result()),
    ):
        response = client.put(
            "/catalog/services/one",
            json={
                "service": {
                    "name": " one-renamed ",
                    "server_name": " updated.example.com ",
                    "upstream": {"port": 9090},
                }
            },
        )

    assert response.status_code == 200
    assert response.json()["service"]["name"] == "one-renamed"
    assert response.json()["service"]["server_name"] == "updated.example.com"
    persisted = json.loads(catalog_path.read_text(encoding="utf-8"))["services"][0]
    assert persisted["name"] == "one-renamed"
    assert persisted["server_name"] == "updated.example.com"
    assert persisted["upstream"]["host"] == "backend.example.internal"
    assert persisted["upstream"]["port"] == 9090
    assert persisted["client_cert"]["allow_cn"] == ["alice"]
    assert persisted["managed_by"]["repo"] == "the-hcma/example"
