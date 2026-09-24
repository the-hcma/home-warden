"""Tests for app.catalog_heal_cli."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from app.catalog_heal import HealStepResult
from app.catalog_heal_cli import main


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
        [sys.executable, "-m", "app.catalog_heal_cli", "--help"], capture_output=True, text=True, timeout=10
    )
    assert proc.returncode == 0
    assert "--apply" in proc.stdout


def test_cli_non_positive_timeout_exits_2(monkeypatch, capsys) -> None:
    monkeypatch.setattr(sys, "argv", ["catalog-heal", "--timeout", "0"])
    assert main() == 2
    assert "--timeout" in capsys.readouterr().err


def test_cli_out_of_range_local_dns_port_exits_2(monkeypatch, capsys) -> None:
    monkeypatch.setattr(sys, "argv", ["catalog-heal", "--local-dns-port", "0"])
    assert main() == 2
    assert "--local-dns-port" in capsys.readouterr().err


def test_cli_host_guard_refused(monkeypatch) -> None:
    monkeypatch.setattr(sys, "argv", ["catalog-heal"])
    monkeypatch.setattr("app.catalog_heal_cli.enforce_host_guard", lambda caller: False)
    assert main() == 2


def test_cli_missing_catalog_file_exits_2(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(sys, "argv", ["catalog-heal", "--services-json", str(tmp_path / "missing.json")])
    monkeypatch.setattr("app.catalog_heal_cli.enforce_host_guard", lambda caller: True)
    assert main() == 2


def test_cli_exits_0_when_nothing_needs_attention(monkeypatch, tmp_path: Path, capsys) -> None:
    catalog_path = _write_catalog(tmp_path)
    creds = _write_credentials(tmp_path)
    monkeypatch.setattr(
        sys,
        "argv",
        ["catalog-heal", "--services-json", str(catalog_path), "--cloudflare-credentials", str(creds)],
    )
    monkeypatch.setattr("app.catalog_heal_cli.enforce_host_guard", lambda caller: True)
    monkeypatch.setattr(
        "app.catalog_heal_cli.heal_catalog",
        lambda *a, **kw: [HealStepResult("svc", "cert", "ok", "valid"), HealStepResult("svc", "dns", "skip", "n/a")],
    )
    exit_code = main()
    out = json.loads(capsys.readouterr().out)
    assert exit_code == 0
    assert [r["action"] for r in out] == ["ok", "skip"]


def test_cli_exits_1_when_something_needs_attention(monkeypatch, tmp_path: Path, capsys) -> None:
    catalog_path = _write_catalog(tmp_path)
    creds = _write_credentials(tmp_path)
    monkeypatch.setattr(
        sys,
        "argv",
        ["catalog-heal", "--services-json", str(catalog_path), "--cloudflare-credentials", str(creds)],
    )
    monkeypatch.setattr("app.catalog_heal_cli.enforce_host_guard", lambda caller: True)
    monkeypatch.setattr(
        "app.catalog_heal_cli.heal_catalog",
        lambda *a, **kw: [HealStepResult("svc", "local_dns", "alert-only", "no record")],
    )
    exit_code = main()
    out = json.loads(capsys.readouterr().out)
    assert exit_code == 1
    assert out[0]["action"] == "alert-only"


def test_cli_wires_apply_and_target_into_heal_catalog(monkeypatch, tmp_path: Path) -> None:
    # A swapped wire-up (e.g. apply always False) would silently make
    # --apply a no-op with every other CLI test still passing, since they
    # discard the kwargs heal_catalog was actually called with -- capture
    # them here instead of just returning a fixed result.
    catalog_path = _write_catalog(tmp_path)
    creds = _write_credentials(tmp_path)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "catalog-heal",
            "--services-json",
            str(catalog_path),
            "--cloudflare-credentials",
            str(creds),
            "--target",
            "203.0.113.10",
            "--apply",
            "--proxied",
        ],
    )
    monkeypatch.setattr("app.catalog_heal_cli.enforce_host_guard", lambda caller: True)
    captured: dict = {}

    def _capture(catalog, **kw):
        captured["kwargs"] = kw
        return [HealStepResult("svc", "cert", "ok", "valid")]

    monkeypatch.setattr("app.catalog_heal_cli.heal_catalog", _capture)
    main()
    assert captured["kwargs"]["apply"] is True
    assert captured["kwargs"]["proxied"] is True
    assert captured["kwargs"]["dns_target"] == "203.0.113.10"


if __name__ == "__main__":
    import pytest

    raise SystemExit(pytest.main([__file__]))
