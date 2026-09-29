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
    assert status["detail"] == "tiny-pki list ca exited 1; see the server log"


def test_a_legacy_flat_store_is_an_error_and_is_left_unmigrated(tmp_path: Path) -> None:
    (tmp_path / "ca.crt").write_text("not read\n")
    status = load_pki_status(tmp_path, [], timeout=10)
    assert status["status"] == "error"
    assert "legacy flat layout" in status["detail"]
    assert sorted(path.name for path in tmp_path.iterdir()) == ["ca.crt"]


def test_a_live_superseded_certificate_counts_toward_overall_status(
    monkeypatch: pytest.MonkeyPatch, store: Path, tmp_path: Path
) -> None:
    certs = [
        {"cn": "bob-laptop", "kind": "client", "serial": "0a", "status": "active", "superseded_by": "b"},
        {"cn": "bob-laptop", "kind": "client", "serial": "0b", "status": "active", "superseded_by": None},
    ]
    check = {
        "results": [
            {"kind": "ca", "status": "ok"},
            {"kind": "crl", "status": "ok"},
            {"kind": "client", "serial_number": "a", "status": "expired"},
            {"kind": "client", "serial_number": "b", "status": "ok"},
        ]
    }
    monkeypatch.setattr(client_pki_view, "TINY_PKI", _canned_tiny_pki(tmp_path, certs=certs, check=check))
    status = load_pki_status(store, [], timeout=10)
    assert status["status"] == "expired"
    assert [(c["serial"], c["state"], c["health"]) for c in status["certificates"]] == [
        ("0a", "active", "expired"),
        ("0b", "active", "ok"),
    ]


def test_a_missing_tiny_pki_is_an_error_without_its_path(
    monkeypatch: pytest.MonkeyPatch, store: Path, tmp_path: Path
) -> None:
    monkeypatch.setattr(client_pki_view, "TINY_PKI", tmp_path / "missing")
    status = load_pki_status(store, _SERVICES, timeout=10)
    assert status["status"] == "error"
    assert status["detail"] == "tiny-pki could not be run; see the server log"
    assert [vhost["name"] for vhost in status["vhosts"]] == ["admin", "wiki"]


def test_a_non_executable_tiny_pki_is_an_error(monkeypatch: pytest.MonkeyPatch, store: Path, tmp_path: Path) -> None:
    script = _fake_tiny_pki(tmp_path, "echo '{}'")
    script.chmod(0o644)
    monkeypatch.setattr(client_pki_view, "TINY_PKI", script)
    status = load_pki_status(store, [], timeout=10)
    assert status["status"] == "error"
    assert status["detail"] == "tiny-pki could not be run; see the server log"


def test_a_store_without_a_ca_certificate_is_an_error(tmp_path: Path) -> None:
    (tmp_path / "public").mkdir()
    status = load_pki_status(tmp_path, [], timeout=10)
    assert status["status"] == "error"
    assert status["detail"] == "the store exists but has no CA certificate (ca/ca.crt)"


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


@pytest.mark.parametrize(
    ("certs", "check", "verb"),
    [
        ([None], {"results": []}, "list certs"),
        ([], {"results": [None]}, "check"),
        ([], {}, "check"),
    ],
)
def test_malformed_rows_are_an_error(
    monkeypatch: pytest.MonkeyPatch, store: Path, tmp_path: Path, certs: list, check: dict, verb: str
) -> None:
    monkeypatch.setattr(client_pki_view, "TINY_PKI", _canned_tiny_pki(tmp_path, certs=certs, check=check))
    status = load_pki_status(store, [], timeout=10)
    assert status["status"] == "error"
    assert status["detail"] == f"tiny-pki {verb} printed rows that aren't a list of objects"


def test_no_ca_is_not_configured_but_still_lists_vhosts(tmp_path: Path) -> None:
    status = load_pki_status(tmp_path / "store", _SERVICES, timeout=10)
    assert status["status"] == "not_configured"
    assert status["ca"] is None
    assert status["certificates"] == []
    assert [vhost["name"] for vhost in status["vhosts"]] == ["admin", "wiki"]


def test_real_store_reports_ca_crl_and_every_certificate(store: Path) -> None:
    status = load_pki_status(store, _SERVICES, timeout=60)
    assert status["status"] == "ok"
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


def test_worst_status_ranks_by_tiny_pki_severity() -> None:
    worst = client_pki_view._worst_status
    assert worst(["ok", "ok", "expiring"]) == "expiring"
    assert worst(["ok", "expired", "expiring"]) == "expired"
    assert worst(["ok", None]) == "unknown"
    assert worst([]) == "ok"


def _canned_tiny_pki(tmp_path: Path, *, certs: list, check: dict) -> Path:
    """A tiny-pki that answers `list ca`, `list certs`, and `check` with
    canned JSON; arguments are `--store S --color never <verb> ...`."""
    for name, payload in (("ca", {"cn": "Test client CA"}), ("certs", certs), ("check", check)):
        (tmp_path / f"{name}.json").write_text(json.dumps(payload))
    return _fake_tiny_pki(
        tmp_path,
        f'if [[ "$5" == check ]]; then cat {tmp_path}/check.json; else cat "{tmp_path}/$6.json"; fi',
    )


def _fake_tiny_pki(tmp_path: Path, body: str) -> Path:
    script = tmp_path / "tiny-pki"
    script.write_text(f"#!/usr/bin/env bash\n{body}\n")
    script.chmod(0o755)
    return script
