"""Tests for app.dns_zones_yaml_check_cli."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from app.dns_zones_yaml_check_cli import main


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
