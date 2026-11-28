"""Tests for app.catalog_dns_sync_cli."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from app.catalog_checks import SyncResult
from app.catalog_dns_sync_cli import main


@pytest.fixture(autouse=True)
def _no_network_snapshot(monkeypatch, tmp_path: Path) -> None:
    # A real (non-dry-run) sync snapshots first (#190); keep these CLI tests off the network.
    monkeypatch.setenv("SCRATCH_DIR", str(tmp_path / "scratch"))
    monkeypatch.setattr(
        "app.catalog_dns_sync_cli.take_snapshot", lambda *a, **kw: {"version": 1, "taken_at": "t", "entries": []}
    )


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


def test_cli_service_filter_unknown_name_exits_2(monkeypatch, tmp_path: Path, capsys) -> None:
    # A misspelled/renamed --service value must fail loudly (exit 2), not
    # silently filter the catalog down to an empty list and exit 0 --
    # every other input error in this module (a bad catalog, missing
    # credentials) already fails loudly the same way.
    catalog_path = tmp_path / "services.json"
    catalog_path.write_text(json.dumps({"services": [{"name": "svc-a", "server_name": "a.example.com"}]}))
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
            "svc-typo",
        ],
    )
    monkeypatch.setattr("app.catalog_dns_sync_cli.enforce_host_guard", lambda caller: True)
    assert main() == 2
    assert "svc-typo" in capsys.readouterr().err


def test_cli_wires_flags_into_sync_dns_record(monkeypatch, tmp_path: Path, capsys) -> None:
    # A swapped wire-up (e.g. proxied=args.dry_run) would silently change
    # live write behavior with every other CLI test still passing, since
    # they all discard the kwargs sync_dns_record was actually called
    # with -- capture them here instead of just returning a fixed result.
    catalog_path = tmp_path / "services.json"
    catalog_path.write_text(json.dumps({"services": [{"name": "svc-a", "server_name": "a.example.com"}]}))
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
            "--proxied",
            "--no-verify-resolution",
            "--max-retries",
            "7",
        ],
    )
    monkeypatch.setattr("app.catalog_dns_sync_cli.enforce_host_guard", lambda caller: True)
    captured: dict = {}

    def _capture(name, *a, **kw):
        captured["args"] = a
        captured["kwargs"] = kw
        return SyncResult(name, "noop", "already correct")

    monkeypatch.setattr("app.catalog_dns_sync_cli.sync_dns_record", _capture)
    main()
    assert captured["kwargs"]["proxied"] is True
    assert captured["kwargs"]["verify_resolution"] is False
    # (service, target, cf_headers, timeout, max_retries) -- max_retries is
    # passed positionally, not as a kwarg.
    assert captured["args"][4] == 7


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


def _dns_only_setup(monkeypatch, tmp_path: Path, extra_args: list[str]) -> list[tuple[str, str]]:
    """Run main() with one catalog service and `extra_args`; returns the (server_name, target) pairs synced."""
    catalog_path = tmp_path / "services.json"
    catalog_path.write_text(json.dumps({"services": [{"name": "svc", "server_name": "app.example.com"}]}))
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
            *extra_args,
        ],
    )
    monkeypatch.setattr("app.catalog_dns_sync_cli.enforce_host_guard", lambda caller: True)
    synced: list[tuple[str, str]] = []

    def fake_sync(name, service, target, *a, **kw):
        synced.append((service["server_name"], target))
        return SyncResult(name, "noop", "already correct")

    monkeypatch.setattr("app.catalog_dns_sync_cli.sync_dns_record", fake_sync)
    return synced


def test_cli_dns_only_names_are_synced_at_the_default_and_their_own_target(monkeypatch, tmp_path: Path, capsys) -> None:
    synced = _dns_only_setup(
        monkeypatch, tmp_path, ["--dns-only", "mail.example.com", "--dns-only", "Relay.Example.com.=203.0.113.99"]
    )
    assert main() == 0
    assert synced == [
        ("app.example.com", "203.0.113.10"),
        ("mail.example.com", "203.0.113.10"),
        ("relay.example.com", "203.0.113.99"),
    ]
    assert [r["service"] for r in json.loads(capsys.readouterr().out)] == [
        "svc",
        "mail.example.com",
        "relay.example.com",
    ]


def test_cli_service_filter_limits_catalog_services_but_not_dns_only_names(monkeypatch, tmp_path: Path) -> None:
    synced = _dns_only_setup(monkeypatch, tmp_path, ["--service", "svc", "--dns-only", "mail.example.com"])
    assert main() == 0
    assert synced == [("app.example.com", "203.0.113.10"), ("mail.example.com", "203.0.113.10")]


def test_cli_dns_only_rejects_bad_names_duplicates_and_catalog_names(monkeypatch, tmp_path: Path, capsys) -> None:
    for args, message in (
        (["--dns-only", "not a host"], "not a fully qualified host name"),
        (["--dns-only", "localhost"], "not a fully qualified host name"),
        (["--dns-only", "mail.example.com="], "nothing after '='"),
        (["--dns-only", "mail.example.com", "--dns-only", "MAIL.example.com"], "given twice"),
        (["--dns-only", "app.example.com"], "already a catalog server_name"),
    ):
        synced = _dns_only_setup(monkeypatch, tmp_path, args)
        assert main() == 2, args
        assert message in capsys.readouterr().err
        assert synced == []


def test_cli_dns_only_names_are_snapshotted_before_writing(monkeypatch, tmp_path: Path) -> None:
    seen: list[list[str]] = []

    def fake_snapshot(services, *a, **kw):
        seen.append([s["server_name"] for s in services])
        return {"version": 1, "taken_at": "t", "entries": []}

    synced = _dns_only_setup(monkeypatch, tmp_path, ["--dns-only", "mail.example.com"])
    monkeypatch.setattr("app.catalog_dns_sync_cli.take_snapshot", fake_snapshot)
    assert main() == 0
    assert seen == [["app.example.com", "mail.example.com"]]
    assert len(synced) == 2


def test_cli_dns_only_names_are_not_reported_as_leftovers(monkeypatch, tmp_path: Path) -> None:
    given: list[list[str]] = []

    def fake_stragglers(services, *a, **kw):
        given.append([s["server_name"] for s in services])
        return []

    _dns_only_setup(monkeypatch, tmp_path, ["--old-target", "203.0.113.7", "--dns-only", "mail.example.com"])
    monkeypatch.setattr("app.catalog_dns_sync_cli.find_stragglers", fake_stragglers)
    assert main() == 0
    assert given == [["app.example.com", "mail.example.com"]]


def test_cli_restore_cannot_be_combined_with_dns_only(monkeypatch, capsys) -> None:
    monkeypatch.setattr(sys, "argv", ["catalog-dns-sync", "--restore", "snap.json", "--dns-only", "mail.example.com"])
    monkeypatch.setattr("app.catalog_dns_sync_cli.enforce_host_guard", lambda caller: True)
    assert main() == 2
    assert "--dns-only" in capsys.readouterr().err
