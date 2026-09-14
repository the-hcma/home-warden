"""Tests for app.catalog_checks.

Cert tests generate real, local, ephemeral self-signed certs via openssl
as test fixtures (deterministic, no network/live infra) and exercise
check_cert's actual `cryptography`-based parsing against them. DNS/upstream
network calls are mocked -- see AGENTS.md's Python Conventions ("tests
must not depend on live infrastructure or credentials").
"""

from __future__ import annotations

import email.message
import subprocess
import urllib.error
from pathlib import Path
from unittest.mock import patch

import pytest

from app.catalog_checks import (
    CheckResult,
    _cf_request,
    candidate_zone_names,
    check_cert,
    check_dns,
    check_upstream,
    load_catalog,
    parse_cloudflare_credentials,
    run_all,
)


def make_self_signed_cert(
    cert_dir: Path,
    domain: str,
    *,
    days: int,
    sans: list[str] | None = None,
    leading_general_names: list[str] | None = None,
) -> Path:
    """Generate a real self-signed cert for `domain` under cert_dir/domain/fullchain.pem.

    `leading_general_names` uses openssl's -addext syntax (e.g.
    ["IP:10.0.0.5"], which openssl prints back as "IP Address:10.0.0.5")
    and is placed before the DNS entries in the SAN extension, to exercise
    general-name lists that don't start with "DNS:".
    """
    san_list = sans if sans is not None else [domain]
    domain_dir = cert_dir / domain
    domain_dir.mkdir(parents=True, exist_ok=True)
    cert_path = domain_dir / "fullchain.pem"
    key_path = domain_dir / "privkey.pem"
    general_names = list(leading_general_names or []) + [f"DNS:{s}" for s in san_list]
    san_ext = ",".join(general_names)
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            str(key_path),
            "-out",
            str(cert_path),
            "-days",
            str(days),
            "-subj",
            f"/CN={domain}",
            "-addext",
            f"subjectAltName={san_ext}",
        ],
        check=True,
        capture_output=True,
    )
    return cert_path


# --- load_catalog ---------------------------------------------------------


def test_load_catalog_missing_file(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        load_catalog(tmp_path / "missing.json")


def test_load_catalog_invalid_json(tmp_path: Path) -> None:
    path = tmp_path / "services.json"
    path.write_text("{not valid json")
    with pytest.raises(ValueError, match="invalid JSON"):
        load_catalog(path)


def test_load_catalog_non_object_top_level(tmp_path: Path) -> None:
    # A bare list/string parses as valid JSON but isn't a usable catalog --
    # must fail loudly here, not crash run_all with AttributeError later.
    path = tmp_path / "services.json"
    path.write_text("[]")
    with pytest.raises(ValueError, match="must be an object"):
        load_catalog(path)


def test_load_catalog_missing_services_key(tmp_path: Path) -> None:
    # A typo'd/renamed key ("service" instead of "services") must fail
    # loudly, not silently validate zero services and report healthy.
    path = tmp_path / "services.json"
    path.write_text('{"service": []}')
    with pytest.raises(ValueError, match="services"):
        load_catalog(path)


def test_load_catalog_non_list_services_value(tmp_path: Path) -> None:
    path = tmp_path / "services.json"
    path.write_text('{"services": "oops"}')
    with pytest.raises(ValueError, match="services"):
        load_catalog(path)


def test_load_catalog_ok(tmp_path: Path) -> None:
    path = tmp_path / "services.json"
    path.write_text('{"services": [{"name": "svc"}]}')
    assert load_catalog(path) == {"services": [{"name": "svc"}]}


# --- parse_cloudflare_credentials ---------------------------------------


def test_parse_cloudflare_credentials_token(tmp_path: Path) -> None:
    path = tmp_path / "cloudflare.ini"
    path.write_text("dns_cloudflare_api_token = supersecret\n")
    headers = parse_cloudflare_credentials(path)
    assert headers == {"Authorization": "Bearer supersecret", "Content-Type": "application/json"}


def test_parse_cloudflare_credentials_email_key(tmp_path: Path) -> None:
    path = tmp_path / "cloudflare.ini"
    path.write_text("dns_cloudflare_email = ops@example.com\ndns_cloudflare_api_key = abc123\n")
    headers = parse_cloudflare_credentials(path)
    assert headers == {"X-Auth-Email": "ops@example.com", "X-Auth-Key": "abc123", "Content-Type": "application/json"}


def test_parse_cloudflare_credentials_missing_file(tmp_path: Path) -> None:
    assert parse_cloudflare_credentials(tmp_path / "nope.ini") is None


def test_parse_cloudflare_credentials_comments_and_blanks(tmp_path: Path) -> None:
    path = tmp_path / "cloudflare.ini"
    path.write_text("# comment\n\ndns_cloudflare_api_token = tok\n")
    assert parse_cloudflare_credentials(path) is not None


def test_parse_cloudflare_credentials_present_but_unusable_raises(tmp_path: Path) -> None:
    # A typo'd key: present file, but nothing usable in it -- must not be
    # mistaken for "not configured" (that's the missing-file case, which
    # returns None rather than raising).
    path = tmp_path / "cloudflare.ini"
    path.write_text("dns_cloudflare_api_tokenn = tok\n")
    with pytest.raises(ValueError, match="no usable Cloudflare credentials"):
        parse_cloudflare_credentials(path)


def test_parse_cloudflare_credentials_email_without_key_raises(tmp_path: Path) -> None:
    path = tmp_path / "cloudflare.ini"
    path.write_text("dns_cloudflare_email = ops@example.com\n")
    with pytest.raises(ValueError):
        parse_cloudflare_credentials(path)


# --- candidate_zone_names -------------------------------------------------


def test_candidate_zone_names_order() -> None:
    assert list(candidate_zone_names("a.b.example.com")) == [
        "example.com",
        "b.example.com",
        "a.b.example.com",
    ]


def test_candidate_zone_names_two_labels() -> None:
    assert list(candidate_zone_names("example.com")) == ["example.com"]


# --- check_cert ------------------------------------------------------------


def test_check_cert_no_server_name(tmp_path: Path) -> None:
    result = check_cert("svc", {}, tmp_path, alert_days=10)
    assert result == CheckResult("svc", "cert", "skip", "no server_name on this catalog entry")


def test_check_cert_missing_file(tmp_path: Path) -> None:
    result = check_cert("svc", {"server_name": "app.example.com"}, tmp_path, alert_days=10)
    assert result.status == "fail"
    assert "missing" in result.detail


def test_check_cert_valid(tmp_path: Path) -> None:
    domain = "app.example.com"
    make_self_signed_cert(tmp_path, domain, days=365)
    result = check_cert("svc", {"server_name": domain}, tmp_path, alert_days=10)
    assert result.status == "ok"
    assert "notAfter=" in result.detail


def test_check_cert_expiring_soon(tmp_path: Path) -> None:
    domain = "app.example.com"
    make_self_signed_cert(tmp_path, domain, days=1)
    # alert_days huge relative to a 1-day cert -> always inside the alert window
    result = check_cert("svc", {"server_name": domain}, tmp_path, alert_days=400)
    assert result.status == "fail"
    assert "expires within" in result.detail


def test_check_cert_san_mismatch(tmp_path: Path) -> None:
    domain = "app.example.com"
    make_self_signed_cert(tmp_path, domain, days=365, sans=["other.example.com"])
    result = check_cert("svc", {"server_name": domain}, tmp_path, alert_days=10)
    assert result.status == "fail"
    assert "not covered" in result.detail


def test_check_cert_san_line_with_leading_non_dns_entry(tmp_path: Path) -> None:
    # A SAN list like "IP Address:10.0.0.5, DNS:app.example.com" doesn't
    # start with "DNS:" -- the parser must still find the DNS entry rather
    # than reporting a valid, correctly-issued cert as failing.
    domain = "app.example.com"
    make_self_signed_cert(tmp_path, domain, days=365, sans=[domain], leading_general_names=["IP:10.0.0.5"])
    result = check_cert("svc", {"server_name": domain}, tmp_path, alert_days=10)
    assert result.status == "ok"


# --- check_upstream ----------------------------------------------------------


def test_check_upstream_skip_for_static_kind() -> None:
    result = check_upstream("svc", {"kind": "static"}, timeout=5)
    assert result.status == "skip"


def test_check_upstream_missing_host_port() -> None:
    result = check_upstream("svc", {"kind": "proxy", "upstream": {}}, timeout=5)
    assert result.status == "fail"
    assert "missing" in result.detail


def test_check_upstream_tcp_fail() -> None:
    # Port 1 on loopback: reserved, essentially guaranteed closed/refused.
    service = {"kind": "proxy", "upstream": {"scheme": "http", "host": "127.0.0.1", "port": 1, "path": "/"}}
    result = check_upstream("svc", service, timeout=1)
    assert result.status == "fail"
    assert "TCP connect" in result.detail


def test_check_upstream_ok() -> None:
    service = {"kind": "proxy", "upstream": {"scheme": "http", "host": "10.0.0.5", "port": 8080, "path": "/"}}

    class _FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def getcode(self):
            return 200

    with (
        patch("socket.create_connection") as mock_connect,
        patch("urllib.request.urlopen", return_value=_FakeResponse()),
    ):
        mock_connect.return_value.__enter__ = lambda self: self
        mock_connect.return_value.__exit__ = lambda self, *exc: False
        result = check_upstream("svc", service, timeout=5)

    assert result.status == "ok"
    assert "responded HTTP 200" in result.detail


def test_check_upstream_ipv6_host_bracketed() -> None:
    service = {"kind": "proxy", "upstream": {"scheme": "http", "host": "::1", "port": 7990, "path": "/"}}
    with (
        patch("socket.create_connection"),
        patch("urllib.request.urlopen") as mock_urlopen,
    ):
        mock_urlopen.side_effect = urllib.error.URLError("connection refused")
        check_upstream("svc", service, timeout=1)
    called_req = mock_urlopen.call_args[0][0]
    assert called_req.full_url.startswith("http://[::1]:7990")


def test_check_upstream_non_http_listener_reported_as_fail() -> None:
    # A listener that's up but doesn't speak HTTP (e.g. an "http" catalog
    # entry actually pointed at a TLS port) makes urlopen raise
    # http.client.BadStatusLine, which urllib does NOT wrap in URLError --
    # must be a "fail" result, not an unhandled exception escaping the
    # check (and crashing run_all / the route / the CLI).
    import http.client

    service = {"kind": "proxy", "upstream": {"scheme": "http", "host": "10.0.0.5", "port": 8443, "path": "/"}}
    with (
        patch("socket.create_connection"),
        patch("urllib.request.urlopen") as mock_urlopen,
    ):
        mock_urlopen.side_effect = http.client.BadStatusLine("garbage")
        result = check_upstream("svc", service, timeout=1)
    assert result.status == "fail"
    assert "HTTP probe" in result.detail


# --- _cf_request ---------------------------------------------------------


def _http_error(code: int, reason: str) -> urllib.error.HTTPError:
    return urllib.error.HTTPError("url", code, reason, email.message.Message(), None)


def test_cf_request_max_retries_zero_still_attempts_once() -> None:
    # "Don't retry" (0) must still mean one real attempt, not zero -- a
    # naive range(0) loop leaves last_err unset and crashes instead of
    # either succeeding or raising the real underlying error.
    class _FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def read(self):
            return b'{"result": []}'

    with patch("urllib.request.urlopen", return_value=_FakeResponse()) as mock_urlopen:
        result = _cf_request("https://api.cloudflare.com/x", {}, timeout=5, max_retries=0)
    assert result == {"result": []}
    assert mock_urlopen.call_count == 1


def test_cf_request_4xx_no_retry() -> None:
    with patch("urllib.request.urlopen") as mock_urlopen:
        mock_urlopen.side_effect = _http_error(403, "forbidden")
        with pytest.raises(urllib.error.HTTPError):
            _cf_request("https://api.cloudflare.com/x", {}, timeout=5, max_retries=3)
    assert mock_urlopen.call_count == 1


def test_cf_request_5xx_retries_then_succeeds() -> None:
    class _FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def read(self):
            return b'{"result": ["ok"]}'

    with (
        patch("time.sleep"),
        patch("urllib.request.urlopen") as mock_urlopen,
    ):
        mock_urlopen.side_effect = [
            _http_error(500, "server error"),
            _FakeResponse(),
        ]
        result = _cf_request("https://api.cloudflare.com/x", {}, timeout=5, max_retries=3)
    assert result == {"result": ["ok"]}
    assert mock_urlopen.call_count == 2


def test_cf_request_exhausts_retries_raises_last_error() -> None:
    with (
        patch("time.sleep"),
        patch("urllib.request.urlopen") as mock_urlopen,
    ):
        mock_urlopen.side_effect = _http_error(503, "unavailable")
        with pytest.raises(urllib.error.HTTPError):
            _cf_request("https://api.cloudflare.com/x", {}, timeout=5, max_retries=2)
    assert mock_urlopen.call_count == 2


# --- check_dns ---------------------------------------------------------------


def test_check_dns_no_server_name() -> None:
    result = check_dns("svc", {}, cf_headers={"x": "y"}, timeout=5, max_retries=1)
    assert result.status == "skip"


def test_check_dns_no_credentials() -> None:
    result = check_dns("svc", {"server_name": "app.example.com"}, cf_headers=None, timeout=5, max_retries=1)
    assert result.status == "skip"
    assert "credentials" in result.detail


def test_check_dns_ok() -> None:
    service = {"server_name": "app.example.com"}
    zone_response = {"result": [{"id": "zone123"}]}
    record_response = {"result": [{"type": "A", "content": "203.0.113.10"}]}

    with patch("app.catalog_checks._cf_request", side_effect=[zone_response, record_response]):
        result = check_dns("svc", service, cf_headers={"x": "y"}, timeout=5, max_retries=1)

    assert result.status == "ok"
    assert "A=203.0.113.10" in result.detail


def test_check_dns_no_zone_found() -> None:
    service = {"server_name": "app.example.com"}
    with patch("app.catalog_checks._cf_request", return_value={"result": []}):
        result = check_dns("svc", service, cf_headers={"x": "y"}, timeout=5, max_retries=1)
    assert result.status == "fail"
    assert "no Cloudflare zone found" in result.detail


def test_check_dns_no_records() -> None:
    # Single-label-suffix domain (one candidate zone: "example.com" itself)
    # so the zone-found-but-empty-records path doesn't also need a second
    # candidate's mock responses.
    service = {"server_name": "example.com"}
    with patch(
        "app.catalog_checks._cf_request",
        side_effect=[{"result": [{"id": "zone123"}]}, {"result": []}],
    ):
        result = check_dns("svc", service, cf_headers={"x": "y"}, timeout=5, max_retries=1)
    assert result.status == "fail"
    assert "no A/AAAA/CNAME record" in result.detail


def test_check_dns_falls_back_to_more_specific_nested_zone() -> None:
    # Account holds both example.com and app.example.com as separate
    # zones; the record lives in the nested (more specific) one.
    # candidate_zone_names tries "example.com" first -- it exists but has
    # no record for the domain -- then "app.example.com", which does.
    service = {"server_name": "app.example.com"}
    with patch(
        "app.catalog_checks._cf_request",
        side_effect=[
            {"result": [{"id": "parent-zone"}]},  # zone lookup: example.com found
            {"result": []},  # record lookup in parent-zone: nothing
            {"result": [{"id": "child-zone"}]},  # zone lookup: app.example.com found
            {"result": [{"type": "A", "content": "203.0.113.20"}]},  # record lookup: found
        ],
    ):
        result = check_dns("svc", service, cf_headers={"x": "y"}, timeout=5, max_retries=1)
    assert result.status == "ok"
    assert "zone=app.example.com" in result.detail


# --- run_all -------------------------------------------------------------


def test_run_all_respects_skip_flags(tmp_path: Path) -> None:
    catalog = {"services": [{"name": "svc", "kind": "static", "server_name": "app.example.com"}]}
    results = run_all(
        catalog,
        certs_live_dir=tmp_path,
        alert_days=10,
        cf_headers=None,
        timeout=1,
        max_retries=1,
        skip_cert=True,
        skip_dns=True,
        skip_upstream=False,
    )
    assert len(results) == 1
    assert results[0].dimension == "upstream"


def test_run_all_empty_catalog() -> None:
    results = run_all({}, certs_live_dir=Path("/nonexistent"), alert_days=10, cf_headers=None, timeout=1, max_retries=1)
    assert results == []


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__]))
