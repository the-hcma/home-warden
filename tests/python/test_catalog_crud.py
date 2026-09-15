"""Tests for app.catalog_crud."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

from app.catalog_crud import (
    NGINX_TEST_HELPER,
    CatalogConflictError,
    CatalogValidationError,
    _preview_catalog_conf_path,
    _preview_full_conf_path,
    _run_gixy,
    _run_nginx_test,
    create_service,
    delete_service,
    get_service,
    persist_catalog,
    render_preview,
    update_service,
    validate_service,
)
from app.home_warden_config import HomeWardenConfig


def _proxy_service(name: str, **overrides) -> dict:
    service = {
        "kind": "proxy",
        "name": name,
        "server_name": f"{name}.example.com",
        "upstream": {
            "host": "backend.example.internal",
            "path": "/",
            "port": 8080,
            "scheme": "http",
        },
    }
    service.update(overrides)
    return service


def test_create_service_appends_a_valid_entry() -> None:
    catalog = {"services": [_proxy_service("one")]}

    created = create_service(catalog, _proxy_service("two"))

    assert [service["name"] for service in created["services"]] == ["one", "two"]
    assert [service["name"] for service in catalog["services"]] == ["one"]


def test_create_service_rejects_duplicate_server_name() -> None:
    catalog = {"services": [_proxy_service("one")]}

    with pytest.raises(CatalogConflictError):
        create_service(catalog, _proxy_service("two", server_name="one.example.com"))


def test_create_service_rejects_duplicate_name_after_stripping_whitespace() -> None:
    catalog = {"services": [_proxy_service("one")]}

    with pytest.raises(CatalogConflictError):
        create_service(catalog, _proxy_service(" one ", server_name="two.example.com"))


def test_delete_service_removes_the_named_entry() -> None:
    catalog = {"services": [_proxy_service("one"), _proxy_service("two")]}

    updated = delete_service(catalog, "one")

    assert [service["name"] for service in updated["services"]] == ["two"]


def test_get_service_returns_a_copy() -> None:
    catalog = {"services": [_proxy_service("one")]}

    service = get_service(catalog, "one")
    service["server_name"] = "changed.example.com"

    assert catalog["services"][0]["server_name"] == "one.example.com"


def test_persist_catalog_keeps_original_file_when_replace_fails(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    catalog_path = tmp_path / "services.json"
    catalog_path.write_text(json.dumps({"services": [_proxy_service("one")]}), encoding="utf-8")

    def fake_replace(source: os.PathLike[str] | str, dest: os.PathLike[str] | str) -> None:
        raise OSError("disk full")

    monkeypatch.setattr("app.catalog_crud.os.replace", fake_replace)

    with pytest.raises(OSError):
        persist_catalog({"services": [_proxy_service("two")]}, catalog_path)

    assert json.loads(catalog_path.read_text(encoding="utf-8"))["services"][0]["name"] == "one"
    assert list(tmp_path.glob(".services.json.*.tmp")) == []


def test_persist_catalog_updates_symlink_target_without_replacing_symlink(tmp_path: Path) -> None:
    real_path = tmp_path / "real-services.json"
    link_path = tmp_path / "services.json"
    real_path.write_text(json.dumps({"services": [_proxy_service("one")]}), encoding="utf-8")
    link_path.symlink_to(real_path)

    persist_catalog({"services": [_proxy_service("two")]}, link_path)

    assert link_path.is_symlink()
    assert link_path.resolve() == real_path
    assert json.loads(real_path.read_text(encoding="utf-8"))["services"][0]["name"] == "two"


def test_render_preview_blocks_when_nginx_is_unavailable(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    def fake_run(command: list[str], **kwargs) -> subprocess.CompletedProcess[str]:
        if command[0] == "sudo":
            raise FileNotFoundError("sudo")
        return subprocess.CompletedProcess(command, 0, stdout="gixy ok", stderr="")

    monkeypatch.setenv("SCRATCH_DIR", str(tmp_path / "scratch"))
    monkeypatch.setattr("app.catalog_crud.certs_live_dir", lambda: tmp_path / "certs")
    monkeypatch.setattr("app.catalog_crud.load_config", lambda path: HomeWardenConfig(fqdn="warden.example.com"))
    monkeypatch.setattr("app.catalog_crud.subprocess.run", fake_run)

    current_catalog = {"services": [_proxy_service("one")]}
    candidate_catalog = {"services": [_proxy_service("two")]}

    preview = render_preview(
        candidate_catalog,
        current_catalog=current_catalog,
        current_services_path=tmp_path / "services.json",
    )

    assert preview.can_apply is False
    assert preview.nginx_test.status == "unavailable"
    assert "nginx preview helper unavailable" in preview.nginx_test.output
    assert "server_name warden.example.com;" in preview.rendered


def test_render_preview_surfaces_gixy_findings_without_blocking_apply(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    def fake_run(command: list[str], **kwargs) -> subprocess.CompletedProcess[str]:
        if command[0] == "sudo":
            return subprocess.CompletedProcess(command, 0, stdout="syntax ok", stderr="")
        return subprocess.CompletedProcess(command, 1, stdout="HIGH: suspicious header", stderr="")

    monkeypatch.setenv("SCRATCH_DIR", str(tmp_path / "scratch"))
    monkeypatch.setattr("app.catalog_crud.certs_live_dir", lambda: tmp_path / "certs")
    monkeypatch.setattr("app.catalog_crud.load_config", lambda path: HomeWardenConfig())
    monkeypatch.setattr("app.catalog_crud.subprocess.run", fake_run)

    current_catalog = {"services": [_proxy_service("one")]}
    candidate_catalog = {"services": [_proxy_service("one", server_name="renamed.example.com")]}

    preview = render_preview(
        candidate_catalog,
        current_catalog=current_catalog,
        current_services_path=tmp_path / "services.json",
    )

    assert preview.can_apply is True
    assert preview.gixy.status == "findings"
    assert "suspicious header" in preview.gixy.output
    assert "--- current" in preview.diff
    assert "+        server_name renamed.example.com;" in preview.diff


def test_render_preview_allows_preexisting_duplicates_in_stored_catalog(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    def fake_run(command: list[str], **kwargs) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(command, 0, stdout="ok", stderr="")

    monkeypatch.setenv("SCRATCH_DIR", str(tmp_path / "scratch"))
    monkeypatch.setattr("app.catalog_crud.certs_live_dir", lambda: tmp_path / "certs")
    monkeypatch.setattr("app.catalog_crud.load_config", lambda path: HomeWardenConfig())
    monkeypatch.setattr("app.catalog_crud.subprocess.run", fake_run)

    preview = render_preview(
        {"services": [_proxy_service("candidate-one"), _proxy_service("candidate-two")]},
        current_catalog={"services": [_proxy_service("one"), _proxy_service("two", server_name="one.example.com")]},
        current_services_path=tmp_path / "services.json",
    )

    assert preview.can_apply is True


def test_preview_full_conf_path_uses_installed_marker_when_present(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    installed_conf = tmp_path / "installed-scratch" / "web-ui-preview" / "nginx.conf"
    marker_path = tmp_path / "home-warden-preview-conf-path"
    marker_path.write_text(f"{installed_conf}\n", encoding="utf-8")

    monkeypatch.setenv("SCRATCH_DIR", str(tmp_path / "different-scratch"))
    monkeypatch.setattr("app.catalog_crud.NGINX_PREVIEW_CONF_PATH_FILE", marker_path)

    assert _preview_full_conf_path() == installed_conf


def test_render_preview_uses_the_fixed_preview_conf_path(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    expected_conf = tmp_path / "scratch" / "web-ui-preview" / "nginx.conf"

    def fake_run(command: list[str], **kwargs) -> subprocess.CompletedProcess[str]:
        if command[0] == "sudo":
            assert command == ["sudo", "-n", str(NGINX_TEST_HELPER)]
            assert _preview_full_conf_path() == expected_conf
            assert expected_conf.is_file()
            catalog_conf_text = _preview_catalog_conf_path().read_text(encoding="utf-8")
            assert "server_name candidate.example.com;" in catalog_conf_text
            assert "server_name current.example.com;" not in catalog_conf_text
            assert str(_preview_catalog_conf_path()) in expected_conf.read_text(encoding="utf-8")
            return subprocess.CompletedProcess(command, 0, stdout="syntax ok", stderr="")
        assert command[-1] == str(expected_conf)
        return subprocess.CompletedProcess(command, 0, stdout="gixy ok", stderr="")

    monkeypatch.setenv("SCRATCH_DIR", str(tmp_path / "scratch"))
    monkeypatch.setattr("app.catalog_crud.certs_live_dir", lambda: tmp_path / "certs")
    monkeypatch.setattr("app.catalog_crud.load_config", lambda path: HomeWardenConfig())
    monkeypatch.setattr("app.catalog_crud.subprocess.run", fake_run)

    preview = render_preview(
        {"services": [_proxy_service("candidate")]},
        current_catalog={"services": [_proxy_service("current")]},
        current_services_path=tmp_path / "caller-controlled" / "services.json",
    )

    assert preview.can_apply is True


def test_render_preview_keeps_apply_enabled_when_gixy_errors(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    def fake_run(command: list[str], **kwargs) -> subprocess.CompletedProcess[str]:
        if command[0] == "sudo":
            return subprocess.CompletedProcess(command, 0, stdout="syntax ok", stderr="")
        raise FileNotFoundError("uv")

    monkeypatch.setenv("SCRATCH_DIR", str(tmp_path / "scratch"))
    monkeypatch.setattr("app.catalog_crud.certs_live_dir", lambda: tmp_path / "certs")
    monkeypatch.setattr("app.catalog_crud.load_config", lambda path: HomeWardenConfig())
    monkeypatch.setattr("app.catalog_crud.subprocess.run", fake_run)

    preview = render_preview(
        {"services": [_proxy_service("candidate")]},
        current_catalog={"services": [_proxy_service("current")]},
        current_services_path=tmp_path / "services.json",
    )

    assert preview.can_apply is True
    assert preview.gixy.status == "error"
    assert "gixy unavailable" in preview.gixy.output


def test_render_preview_wraps_candidate_web_ui_name_collisions_as_validation_errors(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr("app.catalog_crud.load_config", lambda path: HomeWardenConfig(fqdn="warden.example.com"))

    with pytest.raises(CatalogValidationError, match="reserved service name"):
        render_preview(
            {"services": [_proxy_service("home-warden-web-ui")]},
            current_catalog={"services": [_proxy_service("candidate")]},
            current_services_path=tmp_path / "services.json",
        )


def test_run_nginx_test_reports_failed_status(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "app.catalog_crud.subprocess.run",
        lambda command, **kwargs: subprocess.CompletedProcess(command, 1, stdout="", stderr="nginx: [emerg] broken"),
    )

    result = _run_nginx_test()

    assert result.ok is False
    assert result.status == "failed"
    assert "nginx: [emerg] broken" in result.output


def test_run_nginx_test_reports_missing_sudo_provisioning(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "app.catalog_crud.subprocess.run",
        lambda command, **kwargs: subprocess.CompletedProcess(
            command, 1, stdout="", stderr="sudo: a password is required"
        ),
    )

    result = _run_nginx_test()

    assert result.ok is False
    assert result.status == "unavailable"
    assert "not provisioned" in result.output


def test_run_nginx_test_reports_timeout_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_run(command: list[str], **kwargs) -> subprocess.CompletedProcess[str]:
        raise subprocess.TimeoutExpired(command[0], 15)

    monkeypatch.setattr("app.catalog_crud.subprocess.run", fake_run)

    result = _run_nginx_test()

    assert result.ok is False
    assert result.status == "failed"
    assert "timed out" in result.output


def test_run_gixy_reports_missing_binary(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    def fake_run(command: list[str], **kwargs) -> subprocess.CompletedProcess[str]:
        raise FileNotFoundError("uv")

    monkeypatch.setattr("app.catalog_crud.subprocess.run", fake_run)

    result = _run_gixy(tmp_path / "candidate.conf")

    assert result.status == "error"
    assert result.exit_code is None
    assert "gixy unavailable" in result.output


def test_run_gixy_reports_unexpected_exit_code(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(
        "app.catalog_crud.subprocess.run",
        lambda command, **kwargs: subprocess.CompletedProcess(command, 7, stdout="", stderr="gixy exploded"),
    )

    result = _run_gixy(tmp_path / "candidate.conf")

    assert result.status == "error"
    assert result.exit_code == 7
    assert "gixy exploded" in result.output


def test_update_service_deep_merges_without_dropping_hidden_fields() -> None:
    catalog = {
        "services": [
            _proxy_service(
                "one",
                client_cert={"allow_cn": ["alice"], "ca_bundle": "/ca.pem", "mode": "required"},
                managed_by={"repo": "the-hcma/example"},
            )
        ]
    }

    updated = update_service(catalog, "one", {"server_name": "new.example.com", "upstream": {"port": 9090}})

    service = updated["services"][0]
    assert service["server_name"] == "new.example.com"
    assert service["upstream"]["host"] == "backend.example.internal"
    assert service["upstream"]["port"] == 9090
    assert service["client_cert"]["allow_cn"] == ["alice"]
    assert service["managed_by"]["repo"] == "the-hcma/example"


def test_update_service_preserves_omitted_optional_fields_and_clears_explicit_nulls() -> None:
    catalog = {
        "services": [
            _proxy_service(
                "one",
                allow_cidrs=["10.0.0.0/24"],
                forward_host_header=True,
                gzip=False,
                websocket=True,
            )
        ]
    }

    omitted = update_service(catalog, "one", {"server_name": "renamed.example.com"})
    assert omitted["services"][0]["allow_cidrs"] == ["10.0.0.0/24"]

    cleared = update_service(catalog, "one", {"allow_cidrs": None})
    assert "allow_cidrs" not in cleared["services"][0]


def test_validate_service_strips_required_string_fields() -> None:
    validated = validate_service(_proxy_service(" service ", kind=" proxy ", server_name=" service.example.com "))

    assert validated["kind"] == "proxy"
    assert validated["name"] == "service"
    assert validated["server_name"] == "service.example.com"


@pytest.mark.parametrize(
    "service, expected",
    [
        ({"kind": "proxy", "name": "broken", "server_name": "broken.example.com"}, "upstream object"),
        ({"kind": "static", "name": "broken", "server_name": "broken.example.com"}, "static object"),
        (_proxy_service("broken", allow_cidrs="10.0.0.0/24"), "list of strings"),
    ],
)
def test_validate_service_rejects_malformed_entries(service: dict, expected: str) -> None:
    with pytest.raises(CatalogValidationError, match=expected):
        validate_service(service)
