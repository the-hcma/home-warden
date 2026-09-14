"""Tests for app.catalog_health_cli."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from app.catalog_health_cli import main


def test_cli_help_exits_cleanly() -> None:
    proc = subprocess.run(
        [sys.executable, "-m", "app.catalog_health_cli", "--help"],
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert proc.returncode == 0
    assert "catalog" in proc.stdout.lower()


def test_cli_host_guard_refused(monkeypatch, capsys) -> None:
    monkeypatch.setattr(sys, "argv", ["catalog-health-check"])
    monkeypatch.setenv("HOME_WARDEN_SKIP_HOST_GUARD", "0")
    monkeypatch.setattr("app.catalog_health_cli.enforce_host_guard", lambda caller: False)
    assert main() == 2


def test_cli_missing_catalog_file(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(sys, "argv", ["catalog-health-check", "--services-json", str(tmp_path / "missing.json")])
    monkeypatch.setattr("app.catalog_health_cli.enforce_host_guard", lambda caller: True)
    assert main() == 2


def test_cli_malformed_catalog_shape_exits_2(monkeypatch, tmp_path: Path, capsys) -> None:
    # Structurally-wrong-but-syntactically-valid JSON (e.g. a typo'd key)
    # must exit 2 with a clear message, not silently validate zero
    # services (exit 0) or crash with an unhandled traceback.
    catalog_path = tmp_path / "services.json"
    catalog_path.write_text(json.dumps({"service": []}))
    monkeypatch.setattr(sys, "argv", ["catalog-health-check", "--services-json", str(catalog_path)])
    monkeypatch.setattr("app.catalog_health_cli.enforce_host_guard", lambda caller: True)
    assert main() == 2
    assert "services" in capsys.readouterr().err


def test_cli_unusable_cloudflare_credentials_exits_2(monkeypatch, tmp_path: Path, capsys) -> None:
    def _raise_unusable(path):
        raise ValueError("no usable Cloudflare credentials")

    catalog_path = tmp_path / "services.json"
    catalog_path.write_text(json.dumps({"services": []}))
    monkeypatch.setattr(sys, "argv", ["catalog-health-check", "--services-json", str(catalog_path)])
    monkeypatch.setattr("app.catalog_health_cli.enforce_host_guard", lambda caller: True)
    monkeypatch.setattr("app.catalog_health_cli.parse_cloudflare_credentials", _raise_unusable)
    assert main() == 2
    assert "credentials" in capsys.readouterr().err


def test_cli_reports_failures_via_exit_code(monkeypatch, tmp_path: Path, capsys) -> None:
    catalog_path = tmp_path / "services.json"
    service = {"name": "svc", "kind": "static", "server_name": "x.example.com"}
    catalog_path.write_text(json.dumps({"services": [service]}))
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "catalog-health-check",
            "--services-json",
            str(catalog_path),
            "--skip-dns",
            "--skip-upstream",
            "--certs-live-dir",
            str(tmp_path / "no-certs-here"),
        ],
    )
    monkeypatch.setattr("app.catalog_health_cli.enforce_host_guard", lambda caller: True)
    exit_code = main()
    out = json.loads(capsys.readouterr().out)
    assert exit_code == 1
    assert out[0]["status"] == "fail"


def test_cli_exits_0_when_all_checks_ok_or_skipped(monkeypatch, tmp_path: Path, capsys) -> None:
    # The documented "Exit: 0 all checks ok/skipped" contract, never
    # directly asserted before -- every other exit-code test proves 1 or 2.
    catalog_path = tmp_path / "services.json"
    service = {"name": "svc", "kind": "static", "server_name": "x.example.com"}
    catalog_path.write_text(json.dumps({"services": [service]}))
    monkeypatch.setattr(
        sys,
        "argv",
        ["catalog-health-check", "--services-json", str(catalog_path), "--skip-cert", "--skip-dns"],
    )
    monkeypatch.setattr("app.catalog_health_cli.enforce_host_guard", lambda caller: True)
    exit_code = main()
    out = json.loads(capsys.readouterr().out)
    assert exit_code == 0
    assert out[0]["status"] == "skip"


def test_cli_invalid_timeout_exits_2(monkeypatch, tmp_path: Path, capsys) -> None:
    catalog_path = tmp_path / "services.json"
    catalog_path.write_text(json.dumps({"services": []}))
    monkeypatch.setattr(
        sys,
        "argv",
        ["catalog-health-check", "--services-json", str(catalog_path), "--timeout", "0"],
    )
    monkeypatch.setattr("app.catalog_health_cli.enforce_host_guard", lambda caller: True)
    assert main() == 2
    assert "timeout" in capsys.readouterr().err
