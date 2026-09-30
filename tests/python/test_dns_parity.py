"""Tests for app.dns_parity and app.dns_parity_cli (#189). `dig` is stubbed."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from app.dns_parity import compare, expected_queries, parse_dig, parse_server, run_parity
from app.dns_parity_cli import main

DIG_A = """;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1
;; flags: qr aa rd; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1

www.example.com.	300	IN	A	192.0.2.1
"""
DIG_SOA = """;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1
;; flags: qr aa rd; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1

example.com.	3600	IN	SOA	ns1.example.com. admin.example.com. {serial} 7200 900 1209600 3600
"""
DIG_NX = ";; ->>HEADER<<- opcode: QUERY, status: NXDOMAIN, id: 1\n;; flags: qr rd ra; QUERY: 1, ANSWER: 0\n"


def test_parse_server() -> None:
    assert parse_server("192.0.2.1") == ("192.0.2.1", 53)
    assert parse_server("127.0.0.1:853") == ("127.0.0.1", 853)
    assert parse_server("[::1]") == ("::1", 53)
    assert parse_server("[::1]:853") == ("::1", 853)
    assert parse_server("2001:db8::1") == ("2001:db8::1", 53)


def test_parse_dig() -> None:
    a = parse_dig(DIG_A)
    assert a.rcode == "NOERROR" and a.authoritative
    assert ("www.example.com", "A", "192.0.2.1") in a.records
    assert parse_dig(DIG_NX).rcode == "NXDOMAIN"
    with pytest.raises(ValueError):
        parse_dig("garbage")


def test_expected_queries_covers_soa_and_every_type_once() -> None:
    zones = {
        "domains": [
            {
                "domain": "example.com",
                "records": {"www.example.com": [{"a": "192.0.2.1"}, {"txt": "x"}, {"a": "192.0.2.2"}]},
            }
        ]
    }
    assert expected_queries(zones) == [
        ("example.com", "SOA"),
        ("www.example.com", "A"),
        ("www.example.com", "TXT"),
    ]


def test_compare_identical_is_empty() -> None:
    assert compare(parse_dig(DIG_A), parse_dig(DIG_A)) == []


def test_compare_reports_rdata_rcode_and_serial() -> None:
    changed = DIG_A.replace("192.0.2.1", "192.0.2.9")
    diffs = compare(parse_dig(DIG_A), parse_dig(changed))
    assert "only on old: A 192.0.2.1" in diffs and "only on new: A 192.0.2.9" in diffs
    assert any("rcode" in d for d in compare(parse_dig(DIG_A), parse_dig(DIG_NX)))
    serial_diffs = compare(parse_dig(DIG_SOA.format(serial=1)), parse_dig(DIG_SOA.format(serial=2)))
    assert any("serial old=1 new=2" in d for d in serial_diffs)


def test_compare_ttl_only_when_both_authoritative() -> None:
    other_ttl = DIG_A.replace("300", "299")
    assert any(d.startswith("ttl") for d in compare(parse_dig(DIG_A), parse_dig(other_ttl)))
    recursor = other_ttl.replace("qr aa rd", "qr rd ra")
    assert not any(d.startswith("ttl") for d in compare(parse_dig(recursor), parse_dig(recursor.replace("299", "100"))))


def test_run_parity_counts_an_unreachable_server_as_a_difference(monkeypatch) -> None:
    def fake_dig(server, name, rtype, timeout=3):
        if server[0] == "new":
            raise RuntimeError("dig @new failed: timed out")
        return parse_dig(DIG_A)

    monkeypatch.setattr("app.dns_parity.dig", fake_dig)
    findings = run_parity([("www.example.com", "A")], ("old", 53), ("new", 53))
    assert findings[0].differences and "timed out" in findings[0].differences[0]


def test_run_parity_agreement(monkeypatch) -> None:
    monkeypatch.setattr("app.dns_parity.dig", lambda *a, **kw: parse_dig(DIG_A))
    assert run_parity([("www.example.com", "A")], ("o", 53), ("n", 53))[0].differences == []


def test_run_parity_flags_a_record_missing_on_both(monkeypatch) -> None:
    monkeypatch.setattr("app.dns_parity.dig", lambda *a, **kw: parse_dig(DIG_NX))
    q = [("www.example.com", "A")]
    assert run_parity(q, ("o", 53), ("n", 53))[0].differences == []  # a probe: NXDOMAIN on both is fine
    found = run_parity(q, ("o", 53), ("n", 53), must_answer=frozenset(q))
    assert "neither server answers" in found[0].differences[0]


def _zones(tmp_path: Path) -> Path:
    path = tmp_path / "zones.yml"
    path.write_text(
        "domains:\n  - domain: example.com\n    ttl: 300\n    records:\n"
        "      www.example.com:\n        - a: 192.0.2.1\n"
    )
    return path


def test_cli_exit_codes(monkeypatch, tmp_path: Path, capsys) -> None:
    monkeypatch.setattr("app.dns_parity_cli.shutil.which", lambda name: "/usr/bin/dig")
    monkeypatch.setattr("app.dns_parity.dig", lambda *a, **kw: parse_dig(DIG_A))
    argv = [
        "dns-parity",
        "--old",
        "192.0.2.1",
        "--new",
        "192.0.2.2",
        "--zones",
        str(_zones(tmp_path)),
        "--probe",
        "x.example.org/AAAA",
    ]
    monkeypatch.setattr(sys, "argv", argv)
    assert main() == 0
    assert "ok   x.example.org AAAA" in capsys.readouterr().out

    answers = iter([parse_dig(DIG_A), parse_dig(DIG_NX)] * 5)
    monkeypatch.setattr("app.dns_parity.dig", lambda *a, **kw: next(answers))
    assert main() == 1
    assert "DIFF" in capsys.readouterr().out


def test_cli_without_dig_or_zones_exits_2(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(sys, "argv", ["dns-parity", "--old", "a", "--new", "b", "--zones", str(tmp_path / "none.yml")])
    monkeypatch.setattr("app.dns_parity_cli.shutil.which", lambda name: None)
    assert main() == 2
    monkeypatch.setattr("app.dns_parity_cli.shutil.which", lambda name: "/usr/bin/dig")
    assert main() == 2


def test_cli_help_exits_cleanly() -> None:
    proc = subprocess.run(
        [sys.executable, "-m", "app.dns_parity_cli", "--help"], capture_output=True, text=True, timeout=10
    )
    assert proc.returncode == 0 and "--probe" in proc.stdout
