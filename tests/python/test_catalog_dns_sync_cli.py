"""Tests for app.catalog_dns_sync_cli."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from app.catalog_checks import SyncResult
from app.catalog_dns_sync_cli import main


def _write_credentials(tmp_path: Path) -> Path:
    path = tmp_path / "cloudflare.ini"
    path.write_text("dns_cloudflare_api_token = supersecret\n")
    return path


def test_cli_help_exits_cleanly() -> None:
    proc = subprocess.run(
        [sys.executable, "-m", "app.catalog_dns_sync_cli", "--help"],
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert proc.returncode == 0
    assert "cloudflare" in proc.stdout.lower()


def test_cli_missing_target_exits_2(monkeypatch, capsys) -> None:
    monkeypatch.delenv("DNS_SYNC_TARGET", raising=False)
    monkeypatch.setattr(sys, "argv", ["catalog-dns-sync"])
    assert main() == 2
    assert "--target" in capsys.readouterr().err


def test_cli_host_guard_refused(monkeypatch) -> None:
    monkeypatch.setattr(sys, "argv", ["catalog-dns-sync", "--target", "203.0.113.10"])
    monkeypatch.setattr("app.catalog_dns_sync_cli.enforce_host_guard", lambda caller: False)
    assert main() == 2


def test_cli_missing_catalog_file(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(
        sys,
        "argv",
        ["catalog-dns-sync", "--target", "203.0.113.10", "--services-json", str(tmp_path / "missing.json")],
    )
    monkeypatch.setattr("app.catalog_dns_sync_cli.enforce_host_guard", lambda caller: True)
    assert main() == 2


def test_cli_no_cloudflare_credentials_exits_2(monkeypatch, tmp_path: Path, capsys) -> None:
    catalog_path = tmp_path / "services.json"
    catalog_path.write_text(json.dumps({"services": []}))
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "catalog-dns-sync",
            "--target",
            "203.0.113.10",
            "--services-json",
            str(catalog_path),
            "--cloudflare-credentials",
            str(tmp_path / "missing-cloudflare.ini"),
        ],
    )
    monkeypatch.setattr("app.catalog_dns_sync_cli.enforce_host_guard", lambda caller: True)
    assert main() == 2
    assert "credentials" in capsys.readouterr().err


def test_cli_unusable_cloudflare_credentials_exits_2(monkeypatch, tmp_path: Path, capsys) -> None:
    def _raise_unusable(path):
        raise ValueError("no usable Cloudflare credentials")

    catalog_path = tmp_path / "services.json"
    catalog_path.write_text(json.dumps({"services": []}))
    monkeypatch.setattr(
        sys,
        "argv",
        ["catalog-dns-sync", "--target", "203.0.113.10", "--services-json", str(catalog_path)],
    )
    monkeypatch.setattr("app.catalog_dns_sync_cli.enforce_host_guard", lambda caller: True)
    monkeypatch.setattr("app.catalog_dns_sync_cli.parse_cloudflare_credentials", _raise_unusable)
    assert main() == 2
    assert "credentials" in capsys.readouterr().err


def test_cli_reports_failures_via_exit_code(monkeypatch, tmp_path: Path, capsys) -> None:
    catalog_path = tmp_path / "services.json"
    service = {"name": "svc", "server_name": "app.example.com"}
    catalog_path.write_text(json.dumps({"services": [service]}))
    creds = _write_credentials(tmp_path)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "catalog-dns-sync",
            "--target",
            "203.0.113.10",
            "--services-json",
            str(catalog_path),
            "--cloudflare-credentials",
            str(creds),
        ],
    )
    monkeypatch.setattr("app.catalog_dns_sync_cli.enforce_host_guard", lambda caller: True)
    monkeypatch.setattr(
        "app.catalog_dns_sync_cli.sync_dns_record",
        lambda *a, **kw: SyncResult("svc", "failed", "no Cloudflare zone found for app.example.com"),
    )
    exit_code = main()
    out = json.loads(capsys.readouterr().out)
    assert exit_code == 1
    assert out[0]["status"] == "failed"


def test_cli_exits_0_when_all_noop(monkeypatch, tmp_path: Path, capsys) -> None:
    catalog_path = tmp_path / "services.json"
    service = {"name": "svc", "server_name": "app.example.com"}
    catalog_path.write_text(json.dumps({"services": [service]}))
    creds = _write_credentials(tmp_path)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "catalog-dns-sync",
            "--target",
            "203.0.113.10",
            "--services-json",
            str(catalog_path),
            "--cloudflare-credentials",
            str(creds),
        ],
    )
    monkeypatch.setattr("app.catalog_dns_sync_cli.enforce_host_guard", lambda caller: True)
    monkeypatch.setattr(
        "app.catalog_dns_sync_cli.sync_dns_record",
        lambda *a, **kw: SyncResult("svc", "noop", "A=203.0.113.10 already correct in zone example.com"),
    )
    exit_code = main()
    out = json.loads(capsys.readouterr().out)
    assert exit_code == 0
    assert out[0]["status"] == "noop"


def test_cli_service_filter_limits_to_named_services(monkeypatch, tmp_path: Path, capsys) -> None:
    catalog_path = tmp_path / "services.json"
    services = [
        {"name": "svc-a", "server_name": "a.example.com"},
        {"name": "svc-b", "server_name": "b.example.com"},
    ]
    catalog_path.write_text(json.dumps({"services": services}))
    creds = _write_credentials(tmp_path)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "catalog-dns-sync",
            "--target",
            "203.0.113.10",
            "--services-json",
            str(catalog_path),
            "--cloudflare-credentials",
            str(creds),
            "--service",
            "svc-b",
        ],
    )
    monkeypatch.setattr("app.catalog_dns_sync_cli.enforce_host_guard", lambda caller: True)
    monkeypatch.setattr(
        "app.catalog_dns_sync_cli.sync_dns_record",
        lambda name, *a, **kw: SyncResult(name, "noop", "already correct"),
    )
    main()
    out = json.loads(capsys.readouterr().out)
    assert [r["service"] for r in out] == ["svc-b"]


def test_cli_dns_sync_target_env_default(monkeypatch, tmp_path: Path, capsys) -> None:
    catalog_path = tmp_path / "services.json"
    catalog_path.write_text(json.dumps({"services": []}))
    creds = _write_credentials(tmp_path)
    monkeypatch.setenv("DNS_SYNC_TARGET", "203.0.113.10")
    monkeypatch.setattr(
        sys,
        "argv",
        ["catalog-dns-sync", "--services-json", str(catalog_path), "--cloudflare-credentials", str(creds)],
    )
    monkeypatch.setattr("app.catalog_dns_sync_cli.enforce_host_guard", lambda caller: True)
    assert main() == 0


if __name__ == "__main__":
    import pytest

    raise SystemExit(pytest.main([__file__]))
