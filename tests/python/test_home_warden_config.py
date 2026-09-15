"""Tests for app.home_warden_config."""

from __future__ import annotations

from pathlib import Path

import pytest

from app.home_warden_config import (
    BACKEND_LOOPBACK_HOST,
    BACKEND_LOOPBACK_PORT,
    HomeWardenConfig,
    build_web_ui_catalog_service,
    config_path,
    load_config,
)


def test_build_web_ui_catalog_service_returns_none_when_fqdn_unset() -> None:
    assert build_web_ui_catalog_service(HomeWardenConfig()) is None


def test_build_web_ui_catalog_service_returns_proxy_entry_when_fqdn_set() -> None:
    service = build_web_ui_catalog_service(HomeWardenConfig(fqdn="warden.example.com"))
    assert service == {
        "forward_host_header": True,
        "kind": "proxy",
        "name": "home-warden-web-ui",
        "server_name": "warden.example.com",
        "upstream": {
            "host": BACKEND_LOOPBACK_HOST,
            "path": "/",
            "port": BACKEND_LOOPBACK_PORT,
            "scheme": "http",
        },
    }


def test_config_path_defaults_to_xdg_location(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", "/cfg")
    assert config_path() == Path("/cfg/home-warden/config.toml")


def test_load_config_missing_file_disables_web_ui(tmp_path: Path) -> None:
    assert load_config(tmp_path / "missing.toml") == HomeWardenConfig()


def test_load_config_malformed_toml_disables_web_ui(tmp_path: Path) -> None:
    config_file = tmp_path / "config.toml"
    config_file.write_text("fqdn = [not valid")
    assert load_config(config_file) == HomeWardenConfig()


def test_load_config_reads_valid_fqdn(tmp_path: Path) -> None:
    config_file = tmp_path / "config.toml"
    config_file.write_text('fqdn = "warden.example.com"\n')
    assert load_config(config_file) == HomeWardenConfig(fqdn="warden.example.com")


def test_load_config_treats_empty_fqdn_as_disabled(tmp_path: Path) -> None:
    config_file = tmp_path / "config.toml"
    config_file.write_text('fqdn = "   "\n')
    assert load_config(config_file) == HomeWardenConfig()
