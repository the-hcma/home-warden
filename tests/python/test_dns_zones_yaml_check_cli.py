"""Tests for app.dns_zones_yaml_check_cli."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from app.dns_zones_yaml_check_cli import main

_SOA = "ns1.example.com. hostmaster.example.com. {serial} 16384 2048 1048576 2560"


def test_cli_cname_conflict_blocks_with_exit_2(monkeypatch, tmp_path: Path, capsys) -> None:
    zones_yaml = _zones(
        tmp_path, "zones.yml", 1, "    dns1.example.com:\n      - a: 192.0.2.1\n      - cname: x.example.com.\n"
    )
    monkeypatch.setattr(sys, "argv", ["dns-zones-yaml-check", "--list-zones", str(zones_yaml)])
    assert main() == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "CNAME alongside a records" in captured.err
    assert "[blocks reload]" in captured.err
    assert "1 issue(s) block reload" in captured.err


def test_cli_help_exits_cleanly() -> None:
    proc = subprocess.run(
        [sys.executable, "-m", "app.dns_zones_yaml_check_cli", "--help"],
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert proc.returncode == 0
    assert "zones.yml" in proc.stdout.lower()


def test_cli_well_formed_file_exits_0(monkeypatch, tmp_path: Path, capsys) -> None:
    zones_yaml = tmp_path / "zones.yml"
    zones_yaml.write_text("domains:\n  - domain: example.com\n    ttl: 3600\n    records: {}\n")
    monkeypatch.setattr(sys, "argv", ["dns-zones-yaml-check", str(zones_yaml)])
    assert main() == 0
    assert "OK" in capsys.readouterr().out


def test_cli_list_zones_prints_apexes_on_stdout(monkeypatch, tmp_path: Path, capsys) -> None:
    zones_yaml = tmp_path / "zones.yml"
    zones_yaml.write_text(
        "domains:\n"
        "  - domain: example.com.\n    ttl: 3600\n    records: {}\n"
        "  - domain: 2.0.192.in-addr.arpa\n    ttl: 3600\n    records: {}\n"
    )
    monkeypatch.setattr(sys, "argv", ["dns-zones-yaml-check", "--list-zones", str(zones_yaml)])
    assert main() == 0
    captured = capsys.readouterr()
    assert captured.out.splitlines() == ["example.com", "2.0.192.in-addr.arpa"]
    assert "OK" in captured.err


def test_cli_list_zones_malformed_file_prints_nothing_on_stdout(monkeypatch, tmp_path: Path, capsys) -> None:
    zones_yaml = tmp_path / "zones.yml"
    zones_yaml.write_text("not: [valid, {")
    monkeypatch.setattr(sys, "argv", ["dns-zones-yaml-check", "--list-zones", str(zones_yaml)])
    assert main() == 2
    assert capsys.readouterr().out == ""


def test_cli_lint_warnings_still_exit_0_and_list_zones(monkeypatch, tmp_path: Path, capsys) -> None:
    zones_yaml = _zones(tmp_path, "zones.yml", 1, "    app.example.com:\n      - a: 192.0.2.1\n      - a: 192.0.2.1\n")
    monkeypatch.setattr(sys, "argv", ["dns-zones-yaml-check", "--list-zones", str(zones_yaml)])
    assert main() == 0
    captured = capsys.readouterr()
    assert captured.out.splitlines() == ["example.com"]
    assert "lists a 192.0.2.1 2 times" in captured.err


def test_cli_malformed_file_exits_2(monkeypatch, tmp_path: Path, capsys) -> None:
    zones_yaml = tmp_path / "zones.yml"
    zones_yaml.write_text("not: [valid, {")
    monkeypatch.setattr(sys, "argv", ["dns-zones-yaml-check", str(zones_yaml)])
    assert main() == 2
    assert "dns-zones-yaml-check" in capsys.readouterr().err


def test_cli_missing_file_exits_2(monkeypatch, tmp_path: Path, capsys) -> None:
    monkeypatch.setattr(sys, "argv", ["dns-zones-yaml-check", str(tmp_path / "missing.yml")])
    assert main() == 2
    assert "missing file" in capsys.readouterr().err


def test_cli_previous_flags_a_changed_zone_without_a_serial_bump(monkeypatch, tmp_path: Path, capsys) -> None:
    previous = _zones(tmp_path, "old.yml", 7, "    app.example.com:\n      - a: 192.0.2.1\n")
    current = _zones(tmp_path, "zones.yml", 7, "    app.example.com:\n      - a: 192.0.2.2\n")
    monkeypatch.setattr(sys, "argv", ["dns-zones-yaml-check", "--previous", str(previous), str(current)])
    assert main() == 0
    assert "serial didn't go up (was 7, now 7)" in capsys.readouterr().err


def _zones(tmp_path: Path, name: str, serial: int, owners: str) -> Path:
    path = tmp_path / name
    path.write_text(
        "domains:\n  - domain: example.com\n    ttl: 3600\n    records:\n"
        f"      example.com:\n        - soa: {_SOA.format(serial=serial)}\n"
        + "".join(f"  {line}\n" for line in owners.splitlines())
    )
    return path
