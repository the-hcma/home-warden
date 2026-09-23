"""Tests for app.dns_zone_validate.

The `_real_server` tests actually run pdns_server + dig (per
the-hcma/home-warden#108's "validate by actually running it" mandate) --
skipped, not mocked, where pdns_server/pdnsutil/sqlite3/dig aren't
installed (this repo's own python-test CI job doesn't install PowerDNS;
.github/ci/dns-catalog-validate does). Everything else is a plain unit
test with no live process.
"""

from __future__ import annotations

import gzip
import shutil
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from app.dns_tinydns_convert import RecordValue, Zone
from app.dns_zone_validate import (
    REQUIRED_BINARIES,
    _describe_mismatch,
    _read_schema_sql,
    _start_server_with_retry,
    render_bind_zonefile,
    validate_via_sqlite_backend,
)

_have_real_pdns = all(shutil.which(b) for b in REQUIRED_BINARIES)
requires_real_pdns = pytest.mark.skipif(
    not _have_real_pdns, reason=f"one of {REQUIRED_BINARIES} not on PATH -- install PowerDNS + dnsutils to run"
)

# --- render_bind_zonefile ---------------------------------------------------


def test_render_bind_zonefile_puts_soa_first() -> None:
    zone = Zone(
        apex="example.com",
        ttl=3600,
        records={
            "www.example.com": {"a": [RecordValue("203.0.113.10")]},
            "example.com": {
                "soa": [RecordValue("ns1.example.com. host.example.com. 1 2 3 4 5")],
                "ns": [RecordValue("ns1.example.com.")],
            },
        },
    )
    text = render_bind_zonefile(zone)
    lines = text.splitlines()
    assert lines[0] == "$TTL 3600"
    assert lines[1] == "example.com. IN SOA ns1.example.com. host.example.com. 1 2 3 4 5"


def test_render_bind_zonefile_txt_content_not_double_quoted() -> None:
    # Content already carries its own quotes (dns_tinydns_convert._parse_txt
    # produces it that way) -- the renderer must not add a second layer.
    zone = Zone(apex="example.com", ttl=3600, records={"app.example.com": {"txt": [RecordValue('"hello world"')]}})
    text = render_bind_zonefile(zone)
    assert 'app.example.com. IN TXT "hello world"' in text
    assert '""hello world""' not in text


def test_render_bind_zonefile_multi_value_emits_one_line_each() -> None:
    zone = Zone(
        apex="example.com",
        ttl=3600,
        records={"example.com": {"ns": [RecordValue("ns1.example.com."), RecordValue("ns2.example.com.")]}},
    )
    text = render_bind_zonefile(zone)
    assert "example.com. IN NS ns1.example.com." in text
    assert "example.com. IN NS ns2.example.com." in text


def test_render_bind_zonefile_explicit_ttl_emitted_as_bind_ttl_field() -> None:
    zone = Zone(apex="example.com", ttl=3600, records={"app.example.com": {"a": [RecordValue("203.0.113.10", ttl=60)]}})
    text = render_bind_zonefile(zone)
    assert "app.example.com. 60 IN A 203.0.113.10" in text


# --- validate_via_sqlite_backend: environment errors ------------------------


def test_validate_via_sqlite_backend_missing_binary_raises(tmp_path: Path) -> None:
    zones = {"example.com": Zone(apex="example.com", ttl=3600, records={})}
    with patch("shutil.which", return_value=None):
        with pytest.raises(RuntimeError, match="missing required binaries"):
            validate_via_sqlite_backend(zones, workdir=tmp_path)


def test_validate_via_sqlite_backend_missing_schema_raises(tmp_path: Path) -> None:
    zones = {"example.com": Zone(apex="example.com", ttl=3600, records={})}
    with (
        patch("shutil.which", return_value="/usr/bin/fake"),
        patch("app.dns_zone_validate._find_sqlite_schema", side_effect=RuntimeError("schema.sqlite3.sql missing")),
    ):
        with pytest.raises(RuntimeError, match="schema.sqlite3.sql"):
            validate_via_sqlite_backend(zones, workdir=tmp_path)


# --- _read_schema_sql --------------------------------------------------------


def test_read_schema_sql_plain_file(tmp_path: Path) -> None:
    schema_path = tmp_path / "schema.sqlite3.sql"
    schema_path.write_bytes(b"CREATE TABLE domains (id INTEGER);")
    assert _read_schema_sql(schema_path) == b"CREATE TABLE domains (id INTEGER);"


def test_read_schema_sql_gzip_compressed_file(tmp_path: Path) -> None:
    # Debian/Ubuntu's doc-compression policy commonly ships one of the
    # schema.sqlite3.sql* glob's matches gzipped -- passing the raw
    # (compressed) bytes to sqlite3 would fail before validation starts.
    schema_path = tmp_path / "schema.sqlite3.sql.gz"
    schema_path.write_bytes(gzip.compress(b"CREATE TABLE domains (id INTEGER);"))
    assert _read_schema_sql(schema_path) == b"CREATE TABLE domains (id INTEGER);"


# --- _start_server_with_retry ------------------------------------------------


def test_start_server_with_retry_succeeds_first_try(tmp_path: Path) -> None:
    fake_proc = MagicMock()
    with (
        patch("app.dns_zone_validate._free_udp_port", side_effect=[12345]),
        patch("app.dns_zone_validate.subprocess.Popen", return_value=fake_proc) as mock_popen,
        patch("app.dns_zone_validate._wait_for_server_ready"),
    ):
        proc, port = _start_server_with_retry(tmp_path, "example.com", startup_timeout=1.0, max_attempts=3)
    assert proc is fake_proc
    assert port == 12345
    assert mock_popen.call_count == 1
    fake_proc.terminate.assert_not_called()


def test_start_server_with_retry_retries_on_bind_race(tmp_path: Path) -> None:
    # First port "loses" the TOCTOU race (another process bound it first,
    # simulated here as _wait_for_server_ready never seeing it come up);
    # the second attempt on a fresh port succeeds.
    first_proc, second_proc = MagicMock(), MagicMock()
    with (
        patch("app.dns_zone_validate._free_udp_port", side_effect=[111, 222]),
        patch("app.dns_zone_validate.subprocess.Popen", side_effect=[first_proc, second_proc]),
        patch(
            "app.dns_zone_validate._wait_for_server_ready",
            side_effect=[RuntimeError("did not come up in time"), None],
        ),
    ):
        proc, port = _start_server_with_retry(tmp_path, "example.com", startup_timeout=1.0, max_attempts=3)
    assert proc is second_proc
    assert port == 222
    first_proc.terminate.assert_called_once()
    second_proc.terminate.assert_not_called()


def test_start_server_with_retry_exhausts_attempts_raises(tmp_path: Path) -> None:
    fake_proc = MagicMock()
    with (
        patch("app.dns_zone_validate._free_udp_port", side_effect=[1, 2]),
        patch("app.dns_zone_validate.subprocess.Popen", return_value=fake_proc),
        patch("app.dns_zone_validate._wait_for_server_ready", side_effect=RuntimeError("never came up")),
    ):
        with pytest.raises(RuntimeError, match="never came up"):
            _start_server_with_retry(tmp_path, "example.com", startup_timeout=1.0, max_attempts=2)
    assert fake_proc.terminate.call_count == 2


# --- _describe_mismatch -----------------------------------------------------


def test_describe_mismatch_agreement_returns_none() -> None:
    assert _describe_mismatch("app.example.com", "a", ["203.0.113.10"], ["203.0.113.10"]) is None


def test_describe_mismatch_ignores_trailing_dot_only() -> None:
    assert _describe_mismatch("www.example.com", "cname", ["app.example.com."], ["app.example.com"]) is None


def test_describe_mismatch_real_content_difference_is_reported() -> None:
    result = _describe_mismatch("app.example.com", "a", ["203.0.113.10"], ["198.51.100.1"])
    assert result is not None
    assert "203.0.113.10" in result
    assert "198.51.100.1" in result


def test_describe_mismatch_no_answer_at_all_is_reported() -> None:
    # The record was never served (e.g. a load bug dropped it) -- an
    # empty answer against a non-empty expectation must not be mistaken
    # for agreement.
    result = _describe_mismatch("app.example.com", "a", ["203.0.113.10"], [])
    assert result is not None


# --- validate_via_sqlite_backend: real server -------------------------------


@requires_real_pdns
def test_validate_via_sqlite_backend_real_server_no_mismatches(tmp_path: Path) -> None:
    zones = {
        "example.com": Zone(
            apex="example.com",
            ttl=3600,
            records={
                "example.com": {
                    "soa": [RecordValue("ns1.example.com. host.example.com. 1 16384 2048 1048576 2560")],
                    "ns": [RecordValue("ns1.example.com.")],
                },
                "ns1.example.com": {"a": [RecordValue("203.0.113.1")]},
                "app.example.com": {"a": [RecordValue("203.0.113.10", ttl=60)], "txt": [RecordValue('"hello world"')]},
                "www.example.com": {"cname": [RecordValue("app.example.com.")]},
                "_svc._tcp.example.com": {"srv": [RecordValue("0 100 88 app.example.com.")]},
            },
        )
    }
    mismatches = validate_via_sqlite_backend(zones, workdir=tmp_path)
    assert mismatches == []
