"""Tests for app.dns_cutover (#190): snapshot, restore, stragglers. Cloudflare is stubbed."""

from __future__ import annotations

import json
import stat
import sys
from pathlib import Path

import pytest

from app.catalog_checks import SyncResult
from app.dns_cutover import find_stragglers, load_snapshot, restore_snapshot, take_snapshot, write_snapshot

HEADERS = {"Authorization": "Bearer x"}
SERVICES = [
    {"name": "a", "server_name": "a.example.com"},
    {"name": "b", "server_name": "b.example.com"},
    {"name": "static-no-name"},
]


def test_take_snapshot_records_current_state(monkeypatch) -> None:
    current = {
        "a.example.com": [{"type": "A", "content": "198.51.100.7", "ttl": 60, "proxied": False}],
        "b.example.com": None,
    }
    monkeypatch.setattr("app.dns_cutover.list_cloudflare_records", lambda d, *a: current[d])
    snap = take_snapshot(SERVICES, HEADERS, 5, 1)
    assert [e["name"] for e in snap["entries"]] == ["a.example.com", "b.example.com"]
    assert snap["entries"][0]["records"][0]["ttl"] == 60
    assert snap["entries"][1]["records"] == []


def test_take_snapshot_propagates_cloudflare_errors(monkeypatch) -> None:
    def boom(*a):
        raise RuntimeError("403")

    monkeypatch.setattr("app.dns_cutover.list_cloudflare_records", boom)
    with pytest.raises(RuntimeError):
        take_snapshot(SERVICES, HEADERS, 5, 1)


def test_write_snapshot_is_private_and_never_overwrites(tmp_path: Path) -> None:
    path = tmp_path / "snaps" / "s.json"
    write_snapshot(path, {"version": 1, "entries": []})
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    with pytest.raises(FileExistsError):
        write_snapshot(path, {"version": 1, "entries": []})


@pytest.mark.parametrize("body", ["not json", "[]", '{"version": 2, "entries": []}', '{"version": 1, "entries": [1]}'])
def test_load_snapshot_rejects_bad_files(tmp_path: Path, body: str) -> None:
    path = tmp_path / "s.json"
    path.write_text(body)
    with pytest.raises(ValueError):
        load_snapshot(path)


def test_snapshot_round_trip(tmp_path: Path) -> None:
    snap = {"version": 1, "taken_at": "t", "entries": [{"service": "a", "name": "a.example.com", "records": []}]}
    path = tmp_path / "s.json"
    write_snapshot(path, snap)
    assert load_snapshot(path) == snap


def test_restore_replays_content_proxied_and_ttl(monkeypatch) -> None:
    calls: list[tuple] = []

    def fake_sync(name, service, target, headers, timeout, retries, **kw):
        calls.append((name, service["server_name"], target, kw))
        return SyncResult(name, "updated", "ok")

    monkeypatch.setattr("app.dns_cutover.sync_dns_record", fake_sync)
    snap = {
        "version": 1,
        "entries": [
            {
                "service": "a",
                "name": "a.example.com",
                "records": [{"content": "198.51.100.7", "ttl": 300, "proxied": True}],
            },
            {"service": "b", "name": "b.example.com", "records": []},
            {"service": "c", "name": "c.example.com", "records": [{"content": "1.1.1.1"}, {"content": "2.2.2.2"}]},
        ],
    }
    results = restore_snapshot(snap, HEADERS, 5, 1, dry_run=True)
    assert [r.status for r in results] == ["updated", "manual", "manual"]
    assert calls == [
        (
            "a",
            "a.example.com",
            "198.51.100.7",
            {"proxied": True, "dry_run": True, "verify_resolution": True, "ttl": 300},
        )
    ]
    assert "delete it by hand" in results[1].detail


def _fake_cf(zone_records: dict[str, list[dict]], pages: int = 1):
    def fake(url, headers, timeout, retries, **kw):
        if "/zones?name=" in url:
            name = url.split("name=")[1]
            return {"result": [{"id": "z1"}]} if name == "example.com" else {"result": []}
        assert "/zones/z1/dns_records?content=198.51.100.7" in url
        page = int(url.split("&page=")[1])
        return {"result": zone_records.get(str(page), []), "result_info": {"total_pages": pages}}

    return fake


def test_find_stragglers_lists_only_non_catalog_records(monkeypatch) -> None:
    recs = {
        "1": [
            {"name": "a.example.com", "type": "A", "content": "198.51.100.7"},
            {"name": "old-wiki.example.com", "type": "A", "content": "198.51.100.7"},
        ],
        "2": [{"name": "vpn.example.com", "type": "A", "content": "198.51.100.7"}],
    }
    monkeypatch.setattr("app.dns_cutover._cf_request", _fake_cf(recs, pages=2))
    out = find_stragglers(SERVICES, "198.51.100.7", HEADERS, 5, 1)
    assert [r["name"] for r in out] == ["old-wiki.example.com", "vpn.example.com"]
    assert out[0]["zone"] == "example.com"


def test_find_stragglers_none(monkeypatch) -> None:
    monkeypatch.setattr("app.dns_cutover._cf_request", _fake_cf({"1": [{"name": "a.example.com"}]}))
    assert find_stragglers(SERVICES, "198.51.100.7", HEADERS, 5, 1) == []


# --- CLI wiring ------------------------------------------------------------------


def _cli_env(monkeypatch, tmp_path: Path, *extra: str) -> None:
    catalog = tmp_path / "services.json"
    catalog.write_text(json.dumps({"services": [SERVICES[0]]}))
    creds = tmp_path / "cf.ini"
    creds.write_text("dns_cloudflare_api_token = t\n")
    monkeypatch.setattr(
        sys,
        "argv",
        ["catalog-dns-sync", "--services-json", str(catalog), "--cloudflare-credentials", str(creds), *extra],
    )
    monkeypatch.setenv("SCRATCH_DIR", str(tmp_path / "scratch"))
    monkeypatch.setattr("app.catalog_dns_sync_cli.enforce_host_guard", lambda caller: True)


def test_cli_snapshots_before_writing(monkeypatch, tmp_path: Path, capsys) -> None:
    from app.catalog_dns_sync_cli import main

    order: list[str] = []
    _cli_env(monkeypatch, tmp_path, "--target", "203.0.113.10")
    monkeypatch.setattr(
        "app.catalog_dns_sync_cli.take_snapshot",
        lambda *a, **kw: order.append("snapshot") or {"version": 1, "taken_at": "t", "entries": []},
    )
    monkeypatch.setattr(
        "app.catalog_dns_sync_cli.sync_dns_record",
        lambda *a, **kw: order.append("sync") or SyncResult("a", "updated", ""),
    )
    assert main() == 0
    assert order == ["snapshot", "sync"]
    assert len(list((tmp_path / "scratch" / "dns-sync-snapshots").glob("*.json"))) == 1
    assert "snapshot written" in capsys.readouterr().err


def test_cli_refuses_to_write_when_snapshot_fails(monkeypatch, tmp_path: Path, capsys) -> None:
    from app.catalog_dns_sync_cli import main

    _cli_env(monkeypatch, tmp_path, "--target", "203.0.113.10")

    def boom(*a, **kw):
        raise RuntimeError("cloudflare down")

    monkeypatch.setattr("app.catalog_dns_sync_cli.take_snapshot", boom)
    synced: list[int] = []
    monkeypatch.setattr("app.catalog_dns_sync_cli.sync_dns_record", lambda *a, **kw: synced.append(1))
    assert main() == 1
    assert synced == []
    assert "refusing to write" in capsys.readouterr().err


def test_cli_dry_run_and_no_snapshot_skip_the_snapshot(monkeypatch, tmp_path: Path) -> None:
    from app.catalog_dns_sync_cli import main

    def boom(*a, **kw):
        raise AssertionError("must not snapshot")

    monkeypatch.setattr("app.catalog_dns_sync_cli.take_snapshot", boom)
    monkeypatch.setattr("app.catalog_dns_sync_cli.sync_dns_record", lambda *a, **kw: SyncResult("a", "noop", ""))
    for flag in ("--dry-run", "--no-snapshot"):
        _cli_env(monkeypatch, tmp_path, "--target", "203.0.113.10", flag)
        assert main() == 0


def test_cli_restore_mode(monkeypatch, tmp_path: Path, capsys) -> None:
    from app.catalog_dns_sync_cli import main

    snap = tmp_path / "s.json"
    snap.write_text(json.dumps({"version": 1, "entries": [{"service": "a", "name": "a.example.com", "records": []}]}))
    _cli_env(monkeypatch, tmp_path, "--restore", str(snap), "--dry-run")
    assert main() == 1  # "manual": nothing was restored for a name that had no record, so not a clean rollback
    assert json.loads(capsys.readouterr().out)[0]["status"] == "manual"


def test_cli_restore_bad_snapshot_exits_2(monkeypatch, tmp_path: Path) -> None:
    from app.catalog_dns_sync_cli import main

    bad = tmp_path / "bad.json"
    bad.write_text("nope")
    _cli_env(monkeypatch, tmp_path, "--restore", str(bad))
    assert main() == 2


def test_cli_reports_stragglers(monkeypatch, tmp_path: Path, capsys) -> None:
    from app.catalog_dns_sync_cli import main

    _cli_env(monkeypatch, tmp_path, "--target", "203.0.113.10", "--dry-run", "--old-target", "198.51.100.7")
    monkeypatch.setattr("app.catalog_dns_sync_cli.sync_dns_record", lambda *a, **kw: SyncResult("a", "noop", ""))
    monkeypatch.setattr(
        "app.catalog_dns_sync_cli.find_stragglers",
        lambda *a: [{"zone": "example.com", "name": "vpn.example.com", "type": "A", "content": "198.51.100.7"}],
    )
    assert main() == 1  # leftovers make the run non-zero
    assert "NOT IN CATALOG" in capsys.readouterr().err


def test_cli_restore_rejects_flags_it_would_ignore(monkeypatch, tmp_path: Path, capsys) -> None:
    from app.catalog_dns_sync_cli import main

    snap = tmp_path / "s.json"
    snap.write_text(json.dumps({"version": 1, "entries": []}))
    for extra in (["--service", "a"], ["--target", "203.0.113.10"], ["--old-target", "198.51.100.7"], ["--proxied"]):
        _cli_env(monkeypatch, tmp_path, "--restore", str(snap), *extra)
        assert main() == 2
    assert "can't be combined" in capsys.readouterr().err


def test_cli_stragglers_use_the_whole_catalog_and_fail_the_run(monkeypatch, tmp_path: Path) -> None:
    from app.catalog_dns_sync_cli import main

    catalog = tmp_path / "full-catalog.json"
    catalog.write_text(json.dumps({"services": SERVICES[:2]}))
    _cli_env(monkeypatch, tmp_path, "--target", "203.0.113.10", "--dry-run", "--old-target", "198.51.100.7")
    monkeypatch.setattr(sys, "argv", [*sys.argv, "--service", "a", "--services-json", str(catalog)])
    monkeypatch.setattr("app.catalog_dns_sync_cli.sync_dns_record", lambda *a, **kw: SyncResult("a", "noop", ""))
    seen: list[list[dict]] = []

    def fake(services, *a):
        seen.append(services)
        return [{"zone": "example.com", "name": "vpn.example.com", "type": "A", "content": "198.51.100.7"}]

    monkeypatch.setattr("app.catalog_dns_sync_cli.find_stragglers", fake)
    assert main() == 1
    assert [s["name"] for s in seen[0]] == ["a", "b"]


@pytest.mark.parametrize(
    "records",
    [
        [{"ttl": 60}],
        [1],
        [{"content": ""}],
        [{"content": "1.1.1.1", "ttl": True}],
        [{"content": "1.1.1.1", "ttl": "60"}],
    ],
)
def test_load_snapshot_rejects_malformed_records(tmp_path: Path, records) -> None:
    path = tmp_path / "s.json"
    path.write_text(json.dumps({"version": 1, "entries": [{"name": "a.example.com", "records": records}]}))
    with pytest.raises(ValueError, match="malformed record"):
        load_snapshot(path)


def test_write_snapshot_leaves_no_temp_file_behind(tmp_path: Path) -> None:
    path = tmp_path / "s.json"
    write_snapshot(path, {"version": 1, "entries": []})
    with pytest.raises(FileExistsError):
        write_snapshot(path, {"version": 1, "entries": []})
    assert [p.name for p in tmp_path.iterdir()] == ["s.json"]


def test_find_stragglers_normalizes_target_and_case(monkeypatch) -> None:
    urls: list[str] = []

    def fake(url, headers, timeout, retries, **kw):
        urls.append(url)
        if "/zones?name=" in url:
            return {"result": [{"id": "z1"}]} if url.endswith("name=example.com") else {"result": []}
        return {"result": [{"name": "A.Example.com", "type": "AAAA"}, {"name": "Vpn.example.com", "type": "AAAA"}]}

    monkeypatch.setattr("app.dns_cutover._cf_request", fake)
    services = [{"server_name": "a.example.com"}, {"server_name": "b.example.com"}]
    out = find_stragglers(services, "2001:0DB8:0:0:0:0:0:1", HEADERS, 5, 1)
    assert [r["name"] for r in out] == ["Vpn.example.com"]
    assert any("content=2001%3Adb8%3A%3A1" in u for u in urls)
    assert sum("/zones?name=example.com" in u for u in urls) == 1  # one zone lookup, not one per service


def test_sync_dns_record_sends_and_compares_ttl(monkeypatch) -> None:
    from app.catalog_checks import sync_dns_record

    writes: list[tuple[str, dict | None]] = []
    existing = {"id": "r1", "type": "A", "content": "203.0.113.10", "proxied": False, "ttl": 1}

    def fake(url, headers, timeout, retries, *, method="GET", data=None):
        if "/zones?name=" in url:
            return {"result": [{"id": "z1", "name_servers": []}]}
        if method in ("PUT", "POST"):
            writes.append((method, data))
            existing.update(data or {})
            return {}
        return {"result": [dict(existing)]}

    monkeypatch.setattr("app.catalog_checks._cf_request", fake)
    svc = {"server_name": "a.example.com"}
    # Same content and proxied flag but a different TTL is an update when a TTL is pinned ...
    r = sync_dns_record("a", svc, "203.0.113.10", HEADERS, 5, 1, ttl=300, verify_resolution=False)
    assert r.status == "updated" and writes == [
        ("PUT", {"type": "A", "name": "a.example.com", "content": "203.0.113.10", "proxied": False, "ttl": 300})
    ]
    # ... and a noop when it matches, and when none is pinned.
    writes.clear()
    existing["ttl"] = 300
    assert sync_dns_record("a", svc, "203.0.113.10", HEADERS, 5, 1, ttl=300).status == "noop"
    assert sync_dns_record("a", svc, "203.0.113.10", HEADERS, 5, 1).status == "noop"
    assert writes == []
