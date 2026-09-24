"""Tests for app.catalog_register_cli."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from app.catalog_register import RegisterStepResult
from app.catalog_register_cli import main


def _write_credentials(tmp_path: Path) -> Path:
    path = tmp_path / "cloudflare.ini"
    path.write_text("dns_cloudflare_api_token = supersecret\n")
    return path


def _write_catalog(tmp_path: Path) -> Path:
    path = tmp_path / "services.json"
    path.write_text(json.dumps({"services": [{"name": "svc", "kind": "static", "server_name": "app.example.com"}]}))
    return path


def test_cli_help_exits_cleanly() -> None:
    proc = subprocess.run(
        [sys.executable, "-m", "app.catalog_register_cli", "--help"],
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert proc.returncode == 0
    assert "--service" in proc.stdout


def test_cli_missing_target_exits_2(monkeypatch, capsys) -> None:
    monkeypatch.delenv("DNS_SYNC_TARGET", raising=False)
    monkeypatch.setattr(sys, "argv", ["catalog-register", "--service", "svc"])
    assert main() == 2
    assert "--target" in capsys.readouterr().err


def test_cli_non_positive_timeout_exits_2(monkeypatch, capsys) -> None:
    # Without this, a non-positive --timeout reaches socket.settimeout()
    # unvalidated: -1 raises an uncaught ValueError (no JSON plan, no exit
    # 2), and 0 makes the upstream probe non-blocking and misreport a live
    # backend as unreachable -- see run_all's identical guard for the
    # health-check path.
    monkeypatch.setattr(
        sys, "argv", ["catalog-register", "--service", "svc", "--target", "203.0.113.10", "--timeout", "0"]
    )
    assert main() == 2
    assert "--timeout" in capsys.readouterr().err


def test_cli_host_guard_refused(monkeypatch) -> None:
    monkeypatch.setattr(sys, "argv", ["catalog-register", "--service", "svc", "--target", "203.0.113.10"])
    monkeypatch.setattr("app.catalog_register_cli.enforce_host_guard", lambda caller: False)
    assert main() == 2


def test_cli_missing_catalog_file_exits_2(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "catalog-register",
            "--service",
            "svc",
            "--target",
            "203.0.113.10",
            "--services-json",
            str(tmp_path / "missing.json"),
        ],
    )
    monkeypatch.setattr("app.catalog_register_cli.enforce_host_guard", lambda caller: True)
    assert main() == 2


def test_cli_no_cloudflare_credentials_exits_2(monkeypatch, tmp_path: Path, capsys) -> None:
    catalog_path = _write_catalog(tmp_path)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "catalog-register",
            "--service",
            "svc",
            "--target",
            "203.0.113.10",
            "--services-json",
            str(catalog_path),
            "--cloudflare-credentials",
            str(tmp_path / "missing-cloudflare.ini"),
        ],
    )
    monkeypatch.setattr("app.catalog_register_cli.enforce_host_guard", lambda caller: True)
    assert main() == 2
    assert "credentials" in capsys.readouterr().err


def test_cli_reports_failure_via_exit_code(monkeypatch, tmp_path: Path, capsys) -> None:
    catalog_path = _write_catalog(tmp_path)
    creds = _write_credentials(tmp_path)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "catalog-register",
            "--service",
            "svc",
            "--target",
            "203.0.113.10",
            "--services-json",
            str(catalog_path),
            "--cloudflare-credentials",
            str(creds),
        ],
    )
    monkeypatch.setattr("app.catalog_register_cli.enforce_host_guard", lambda caller: True)
    monkeypatch.setattr(
        "app.catalog_register_cli.register_service",
        lambda *a, **kw: [RegisterStepResult("local_dns", "failed", "no record")],
    )
    exit_code = main()
    out = json.loads(capsys.readouterr().out)
    assert exit_code == 1
    assert out[0]["status"] == "failed"


def test_cli_exits_0_when_all_ok_or_skip(monkeypatch, tmp_path: Path, capsys) -> None:
    catalog_path = _write_catalog(tmp_path)
    creds = _write_credentials(tmp_path)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "catalog-register",
            "--service",
            "svc",
            "--target",
            "203.0.113.10",
            "--services-json",
            str(catalog_path),
            "--cloudflare-credentials",
            str(creds),
        ],
    )
    monkeypatch.setattr("app.catalog_register_cli.enforce_host_guard", lambda caller: True)
    monkeypatch.setattr(
        "app.catalog_register_cli.register_service",
        lambda *a, **kw: [
            RegisterStepResult("local_dns", "skip", "static"),
            RegisterStepResult("nginx", "ok", "nginx -t passes"),
        ],
    )
    exit_code = main()
    out = json.loads(capsys.readouterr().out)
    assert exit_code == 0
    assert [r["status"] for r in out] == ["skip", "ok"]


def test_cli_wires_apply_and_service_into_register_service(monkeypatch, tmp_path: Path, capsys) -> None:
    # A swapped wire-up (e.g. apply always False) would silently make
    # --apply a no-op with every other CLI test still passing, since they
    # discard the kwargs register_service was actually called with --
    # capture them here instead of just returning a fixed result.
    catalog_path = _write_catalog(tmp_path)
    creds = _write_credentials(tmp_path)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "catalog-register",
            "--service",
            "svc",
            "--target",
            "203.0.113.10",
            "--services-json",
            str(catalog_path),
            "--cloudflare-credentials",
            str(creds),
            "--apply",
            "--proxied",
        ],
    )
    monkeypatch.setattr("app.catalog_register_cli.enforce_host_guard", lambda caller: True)
    captured: dict = {}

    def _capture(name, catalog, **kw):
        captured["name"] = name
        captured["kwargs"] = kw
        return [RegisterStepResult("nginx", "ok", "nginx -t passes")]

    monkeypatch.setattr("app.catalog_register_cli.register_service", _capture)
    main()
    assert captured["name"] == "svc"
    assert captured["kwargs"]["apply"] is True
    assert captured["kwargs"]["proxied"] is True


def test_cli_target_env_default(monkeypatch, tmp_path: Path, capsys) -> None:
    catalog_path = _write_catalog(tmp_path)
    creds = _write_credentials(tmp_path)
    monkeypatch.setenv("DNS_SYNC_TARGET", "203.0.113.10")
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "catalog-register",
            "--service",
            "svc",
            "--services-json",
            str(catalog_path),
            "--cloudflare-credentials",
            str(creds),
        ],
    )
    monkeypatch.setattr("app.catalog_register_cli.enforce_host_guard", lambda caller: True)
    monkeypatch.setattr(
        "app.catalog_register_cli.register_service", lambda *a, **kw: [RegisterStepResult("nginx", "ok", "ok")]
    )
    assert main() == 0


if __name__ == "__main__":
    import pytest

    raise SystemExit(pytest.main([__file__]))
