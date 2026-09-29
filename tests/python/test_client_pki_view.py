"""Tests for app.client_pki_view, against a real tiny-pki store."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from app import client_pki_view
from app.client_pki_view import client_cert_vhosts, load_pki_status

_SERVICES = [
    {
        "name": "wiki",
        "server_name": "wiki.example.com",
        "client_cert": {"mode": "required", "allow_cn": ["alice-phone"]},
    },
    {"name": "blog", "server_name": "blog.example.com"},
    {"name": "admin", "server_name": "admin.example.com", "client_cert": {"mode": "optional", "verify_depth": 2}},
]


@pytest.fixture(scope="module")
def store(tmp_path_factory: pytest.TempPathFactory) -> Path:
    path = tmp_path_factory.mktemp("pki") / "store"
    for args in (
        ["init", "--cn", "Test client CA", "--key-type", "ec-p256"],
        ["create", "client", "bob-laptop", "--key-type", "ec-p256"],
        ["create", "client", "alice-phone", "--key-type", "ec-p256"],
        ["revoke", "bob-laptop"],
    ):
        subprocess.run(
            [str(client_pki_view.TINY_PKI), "--store", str(path), *args], check=True, capture_output=True, timeout=60
        )
    return path


def test_a_bad_exit_is_an_error(monkeypatch: pytest.MonkeyPatch, store: Path, tmp_path: Path) -> None:
    monkeypatch.setattr(client_pki_view, "TINY_PKI", _fake_tiny_pki(tmp_path, "echo 'store is locked' >&2; exit 1"))
    status = load_pki_status(store, [], timeout=10)
    assert status["status"] == "error"
    assert status["detail"] == "tiny-pki list ca exited 1: store is locked"


def test_a_missing_tiny_pki_is_an_error(monkeypatch: pytest.MonkeyPatch, store: Path, tmp_path: Path) -> None:
    monkeypatch.setattr(client_pki_view, "TINY_PKI", tmp_path / "missing")
    status = load_pki_status(store, _SERVICES, timeout=10)
    assert status["status"] == "error"
    assert "tiny-pki not found" in status["detail"]
    assert [vhost["name"] for vhost in status["vhosts"]] == ["admin", "wiki"]


def test_a_timeout_is_an_error(monkeypatch: pytest.MonkeyPatch, store: Path) -> None:
    def _timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd="tiny-pki", timeout=3)

    monkeypatch.setattr(client_pki_view.subprocess, "run", _timeout)
    status = load_pki_status(store, [], timeout=3)
    assert status["status"] == "error"
    assert status["detail"] == "tiny-pki list timed out after 3s"


def test_client_cert_vhosts_lists_only_services_that_set_client_cert() -> None:
    assert client_cert_vhosts(_SERVICES) == [
        {
            "name": "admin",
            "server_name": "admin.example.com",
            "mode": "optional",
            "allow_cn": None,
            "verify_depth": 2,
        },
        {
            "name": "wiki",
            "server_name": "wiki.example.com",
            "mode": "required",
            "allow_cn": ["alice-phone"],
            "verify_depth": None,
        },
    ]


def test_json_of_the_wrong_shape_is_an_error(monkeypatch: pytest.MonkeyPatch, store: Path, tmp_path: Path) -> None:
    monkeypatch.setattr(client_pki_view, "TINY_PKI", _fake_tiny_pki(tmp_path, "echo '[]'"))
    status = load_pki_status(store, [], timeout=10)
    assert status["status"] == "error"
    assert status["detail"] == "tiny-pki list ca printed a list, expected a dict"


def test_no_ca_is_not_configured_but_still_lists_vhosts(tmp_path: Path) -> None:
    status = load_pki_status(tmp_path / "store", _SERVICES, timeout=10)
    assert status["status"] == "not_configured"
    assert status["ca"] is None
    assert status["certificates"] == []
    assert [vhost["name"] for vhost in status["vhosts"]] == ["admin", "wiki"]


def test_real_store_reports_ca_crl_and_every_certificate(store: Path) -> None:
    status = load_pki_status(store, _SERVICES, timeout=60)
    assert status["status"] == "revoked"
    assert status["detail"] is None
    assert status["ca"]["cn"] == "Test client CA"
    assert status["ca"]["status"] == "ok"
    assert status["ca"]["days_remaining"] > 3000
    assert status["crl"]["status"] == "ok"
    assert status["crl"]["this_update"] < status["crl"]["next_update"]
    assert [(c["cn"], c["state"], c["health"]) for c in status["certificates"]] == [
        ("alice-phone", "active", "ok"),
        ("bob-laptop", "revoked", "revoked"),
    ]
    bob = status["certificates"][1]
    assert bob["revoked_at"] is not None
    assert bob["reasons"] and bob["reasons"][0].startswith("revoked on ")
    assert status["certificates"][0]["days_remaining"] > 300


def test_real_store_response_names_no_paths(store: Path) -> None:
    text = json.dumps(load_pki_status(store, [], timeout=60))
    assert str(store) not in text
    assert "_path" not in text


def test_serial_with_a_leading_zero_still_matches_its_check_row() -> None:
    checks = {("client", "abc"): {"status": "expiring", "days_remaining": 5, "reasons": ["soon"]}}
    entry = client_pki_view._certificate_entry({"kind": "client", "serial": "0abc", "cn": "x"}, checks)
    assert (entry["health"], entry["days_remaining"]) == ("expiring", 5)


def _fake_tiny_pki(tmp_path: Path, body: str) -> Path:
    script = tmp_path / "tiny-pki"
    script.write_text(f"#!/usr/bin/env bash\n{body}\n")
    script.chmod(0o755)
    return script
