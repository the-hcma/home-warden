"""Tests for app.dns_tinydns_convert_cli."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import yaml

from app.dns_tinydns_convert_cli import main


def test_cli_help_exits_cleanly() -> None:
    proc = subprocess.run(
        [sys.executable, "-m", "app.dns_tinydns_convert_cli", "--help"],
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert proc.returncode == 0
    assert "tinydns" in proc.stdout.lower()


def test_cli_missing_input_file_exits_2(monkeypatch, tmp_path: Path, capsys) -> None:
    monkeypatch.setattr(sys, "argv", ["dns-tinydns-convert", str(tmp_path / "missing")])
    assert main() == 2
    assert "missing input file" in capsys.readouterr().err


def test_cli_invalid_tinydns_data_exits_2(monkeypatch, tmp_path: Path, capsys) -> None:
    data_file = tmp_path / "data"
    data_file.write_text("^bad.example.com:x:86400\n")
    monkeypatch.setattr(sys, "argv", ["dns-tinydns-convert", str(data_file)])
    assert main() == 2
    assert "unrecognized tinydns line type" in capsys.readouterr().err


def test_cli_no_soa_lines_exits_2(monkeypatch, tmp_path: Path, capsys) -> None:
    data_file = tmp_path / "data"
    data_file.write_text("+app.example.com:203.0.113.10:86400\n")
    monkeypatch.setattr(sys, "argv", ["dns-tinydns-convert", str(data_file)])
    assert main() == 2
    assert "no zones" in capsys.readouterr().err


def test_cli_writes_zones_yaml_and_pdns_conf(monkeypatch, tmp_path: Path, capsys) -> None:
    data_file = tmp_path / "data"
    data_file.write_text(
        "Zexample.com:ns1.example.com:hostmaster.example.com:1:16384:2048:1048576:2560:3600\n"
        "+app.example.com:203.0.113.10:86400\n"
    )
    outdir = tmp_path / "out"
    monkeypatch.setattr(sys, "argv", ["dns-tinydns-convert", str(data_file), "--outdir", str(outdir)])
    assert main() == 0
    assert "wrote" in capsys.readouterr().out

    zones_yaml = (outdir / "zones.yml").read_text()
    parsed = yaml.safe_load(zones_yaml)
    assert parsed["domains"][0]["domain"] == "example.com"
    # 86400 is an explicit per-line ttl distinct from the zone's own
    # default (3600, from the SOA line) -- must render in the backend's
    # expanded form, not collapse to the zone default.
    assert parsed["domains"][0]["records"]["app.example.com"] == [{"a": {"content": "203.0.113.10", "ttl": 86400}}]

    pdns_conf = (outdir / "pdns.conf").read_text()
    assert "launch=geoip" in pdns_conf
    assert str((outdir / "zones.yml").resolve()) in pdns_conf
    # The auth server must never bind beyond loopback -- per #16's design,
    # the recursor (not this server) answers the real, LAN/public-facing
    # :53. A regression here would expose it, and nothing else asserts
    # this (the CI harness deliberately overrides the port for its own
    # unprivileged smoke test). Both address families must be listed --
    # PowerDNS's own default is local-address=0.0.0.0, :: (every
    # interface); an IPv4-only value here would leave IPv6 at that
    # wildcard default.
    assert "local-address=127.0.0.1, ::1" in pdns_conf
    assert "local-port=853" in pdns_conf


def test_cli_default_outdir_is_cwd(monkeypatch, tmp_path: Path, capsys) -> None:
    data_file = tmp_path / "data"
    data_file.write_text("Zexample.com:ns1.example.com:hostmaster.example.com:1:16384:2048:1048576:2560:3600\n")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(sys, "argv", ["dns-tinydns-convert", str(data_file)])
    assert main() == 0
    assert (tmp_path / "zones.yml").is_file()
    assert (tmp_path / "pdns.conf").is_file()
