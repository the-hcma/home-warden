"""Tests for app.catalog_checks.

Cert tests build real, local, ephemeral self-signed certs directly with
`cryptography` as test fixtures (deterministic, no network/live infra, no
subprocess/openssl dependency -- matching check_cert's own implementation)
and exercise check_cert's actual parsing against them. DNS/upstream
network calls are mocked -- see AGENTS.md's Python Conventions ("tests
must not depend on live infrastructure or credentials").
"""

from __future__ import annotations

import datetime
import email.message
import ipaddress
import subprocess
import urllib.error
from pathlib import Path
from unittest.mock import call, patch

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from app.catalog_checks import (
    CheckResult,
    SyncResult,
    _cf_request,
    _host_resolves,
    _resolve_via_authoritative_ns,
    candidate_zone_names,
    check_cert,
    check_dns,
    check_local_dns,
    check_upstream,
    list_cloudflare_records,
    load_catalog,
    parse_cloudflare_credentials,
    run_all,
    sync_dns_record,
)


def make_self_signed_cert(
    cert_dir: Path,
    domain: str,
    *,
    days: int,
    sans: list[str] | None = None,
    leading_general_names: list[x509.GeneralName] | None = None,
    no_sans: bool = False,
) -> Path:
    """Build a real self-signed cert for `domain` under
    cert_dir/domain/fullchain.pem, purely with `cryptography` -- no
    subprocess/openssl dependency.

    `leading_general_names` (e.g. `[x509.IPAddress(ipaddress.ip_address("10.0.0.5"))]`)
    are placed before the DNS entries in the SAN extension, to exercise
    general-name lists that don't start with a DNS name. `no_sans=True`
    omits the SAN extension entirely.
    """
    san_names = sans if sans is not None else [domain]
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, domain)])
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=days))
    )
    if not no_sans:
        general_names = list(leading_general_names or []) + [x509.DNSName(s) for s in san_names]
        builder = builder.add_extension(x509.SubjectAlternativeName(general_names), critical=False)
    cert = builder.sign(key, hashes.SHA256())

    domain_dir = cert_dir / domain
    domain_dir.mkdir(parents=True, exist_ok=True)
    cert_path = domain_dir / "fullchain.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
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


def test_load_catalog_non_object_service_entry(tmp_path: Path) -> None:
    # A non-object list element would otherwise crash run_all mid-report
    # at service.get("name", ...) instead of failing loudly here.
    path = tmp_path / "services.json"
    path.write_text('{"services": ["not-an-object"]}')
    with pytest.raises(ValueError, match=r"services\[0\] must be an object"):
        load_catalog(path)


def test_load_catalog_flattened_upstream_string(tmp_path: Path) -> None:
    # A hand-edited catalog flattening "upstream" to a bare string --
    # exactly what a renderer-less schema invites -- would otherwise crash
    # check_upstream mid-report at upstream.get("host").
    path = tmp_path / "services.json"
    path.write_text('{"services": [{"name": "x", "kind": "proxy", "upstream": "http://backend:8000"}]}')
    with pytest.raises(ValueError, match=r"services\[0\]\.upstream must be an object"):
        load_catalog(path)


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


def test_check_cert_san_with_leading_non_dns_entry(tmp_path: Path) -> None:
    # A SAN extension mixing general-name types (e.g. IP + DNS) must
    # still find the DNS entry -- get_values_for_type(DNSName) filters by
    # type regardless of ordering, but this pins that contract explicitly.
    domain = "app.example.com"
    ip_entry = x509.IPAddress(ipaddress.ip_address("10.0.0.5"))
    make_self_signed_cert(tmp_path, domain, days=365, sans=[domain], leading_general_names=[ip_entry])
    result = check_cert("svc", {"server_name": domain}, tmp_path, alert_days=10)
    assert result.status == "ok"


def test_check_cert_no_san_extension_reported_as_fail(tmp_path: Path) -> None:
    # A CN-only cert with no SubjectAlternativeName extension at all must
    # not crash check_cert with an unhandled x509.ExtensionNotFound --
    # every other cert fixture in this file adds at least one DNS SAN, so
    # nothing else exercises the except branch that catches this.
    domain = "app.example.com"
    make_self_signed_cert(tmp_path, domain, days=365, no_sans=True)
    result = check_cert("svc", {"server_name": domain}, tmp_path, alert_days=10)
    assert result.status == "fail"
    assert "not covered" in result.detail


def test_check_cert_corrupt_file_reported_as_fail(tmp_path: Path) -> None:
    # A present-but-unparseable "cert" (truncated/corrupt PEM, or someone
    # else's file entirely) must be a "fail" result, not an escaping
    # exception -- the same contract every other failure mode here has.
    domain = "app.example.com"
    cert_dir = tmp_path / domain
    cert_dir.mkdir()
    (cert_dir / "fullchain.pem").write_text("not a certificate\n")
    result = check_cert("svc", {"server_name": domain}, tmp_path, alert_days=10)
    assert result.status == "fail"
    assert "failed to parse" in result.detail


# --- check_upstream ----------------------------------------------------------


def test_check_upstream_skip_for_static_kind() -> None:
    result = check_upstream("svc", {"kind": "static"}, timeout=5)
    assert result.status == "skip"


def test_check_upstream_missing_host_port() -> None:
    result = check_upstream("svc", {"kind": "proxy", "upstream": {}}, timeout=5)
    assert result.status == "fail"
    assert "missing" in result.detail


def test_check_upstream_tcp_fail() -> None:
    # Mocked, not a real connect to a "probably closed" port: an
    # environment where something really is listening on 127.0.0.1:1
    # (a sandboxed/port-forwarded CI runner) would otherwise make this
    # test's outcome depend on the machine it runs on.
    service = {"kind": "proxy", "upstream": {"scheme": "http", "host": "127.0.0.1", "port": 1, "path": "/"}}
    with patch("socket.create_connection", side_effect=OSError("connection refused")):
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


def test_check_upstream_http_error_status_still_counts_as_ok() -> None:
    # Any HTTP response -- even a 5xx -- proves something is listening and
    # answering, which is what this dimension checks for; the response
    # body/status isn't this check's concern.
    service = {"kind": "proxy", "upstream": {"scheme": "http", "host": "10.0.0.5", "port": 8080, "path": "/"}}
    with (
        patch("socket.create_connection"),
        patch("urllib.request.urlopen") as mock_urlopen,
    ):
        mock_urlopen.side_effect = _http_error(502, "bad gateway")
        result = check_upstream("svc", service, timeout=5)
    assert result.status == "ok"
    assert "responded HTTP 502" in result.detail


def test_check_upstream_https_scheme_uses_unverified_context() -> None:
    # The https branch is the only consumer of ssl._create_unverified_context();
    # a regression there should still reach a clean ok/fail result, not raise.
    service = {"kind": "proxy", "upstream": {"scheme": "https", "host": "10.0.0.5", "port": 9090, "path": "/"}}

    class _FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def getcode(self):
            return 200

    with (
        patch("socket.create_connection"),
        patch("urllib.request.urlopen", return_value=_FakeResponse()) as mock_urlopen,
    ):
        result = check_upstream("svc", service, timeout=5)
    assert result.status == "ok"
    assert mock_urlopen.call_args.kwargs["context"] is not None


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


def test_cf_request_forwards_method_and_body() -> None:
    class _FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def read(self):
            return b'{"result": {"id": "rec1"}}'

    with patch("urllib.request.urlopen", return_value=_FakeResponse()) as mock_urlopen:
        result = _cf_request(
            "https://api.cloudflare.com/x",
            {"Authorization": "Bearer tok"},
            timeout=5,
            max_retries=1,
            method="POST",
            data={"type": "A", "name": "app.example.com", "content": "203.0.113.10"},
        )
    assert result == {"result": {"id": "rec1"}}
    sent_req = mock_urlopen.call_args[0][0]
    assert sent_req.get_method() == "POST"
    assert sent_req.data == b'{"type": "A", "name": "app.example.com", "content": "203.0.113.10"}'


# --- _host_resolves ---------------------------------------------------------


def test_host_resolves_found() -> None:
    with patch(
        "subprocess.run", return_value=subprocess.CompletedProcess(args=[], returncode=0, stdout="")
    ) as mock_run:
        assert _host_resolves("backend.example.internal", timeout=5) is True
    assert mock_run.call_args.args[0] == ["getent", "ahosts", "backend.example.internal"]
    assert mock_run.call_args.kwargs["timeout"] == 5


def test_host_resolves_not_found() -> None:
    with patch("subprocess.run", return_value=subprocess.CompletedProcess(args=[], returncode=2, stdout="")):
        assert _host_resolves("backend.example.internal", timeout=5) is False


def test_host_resolves_unexpected_exit_returns_none() -> None:
    with patch("subprocess.run", return_value=subprocess.CompletedProcess(args=[], returncode=3, stdout="")):
        assert _host_resolves("backend.example.internal", timeout=5) is None


def test_host_resolves_getent_missing_returns_none() -> None:
    with patch("subprocess.run", side_effect=FileNotFoundError):
        assert _host_resolves("backend.example.internal", timeout=5) is None


def test_host_resolves_timeout_counts_as_not_resolving() -> None:
    # A resolver that hangs past the check's budget fails nginx too.
    with patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="getent", timeout=5)):
        assert _host_resolves("backend.example.internal", timeout=5) is False


# --- _resolve_via_authoritative_ns ----------------------------------------


def test_resolve_via_authoritative_ns_ok() -> None:
    completed = subprocess.CompletedProcess(args=[], returncode=0, stdout="203.0.113.10\n")
    with patch("subprocess.run", return_value=completed) as mock_run:
        answers = _resolve_via_authoritative_ns("app.example.com", "A", "ns1.example.net", timeout=5)
    assert answers == ["203.0.113.10"]
    assert mock_run.call_args.kwargs["timeout"] == 5
    assert "-p" not in mock_run.call_args.args[0]


def test_resolve_via_authoritative_ns_with_port_adds_dig_flag() -> None:
    completed = subprocess.CompletedProcess(args=[], returncode=0, stdout="10.0.0.5\n")
    with patch("subprocess.run", return_value=completed) as mock_run:
        answers = _resolve_via_authoritative_ns("backend.example.internal", "A", "127.0.0.1", 5, port=853)
    assert answers == ["10.0.0.5"]
    cmd = mock_run.call_args.args[0]
    assert cmd[cmd.index("-p") + 1] == "853"


def test_resolve_via_authoritative_ns_empty_answer() -> None:
    completed = subprocess.CompletedProcess(args=[], returncode=0, stdout="\n")
    with patch("subprocess.run", return_value=completed):
        answers = _resolve_via_authoritative_ns("app.example.com", "A", "ns1.example.net", timeout=5)
    assert answers == []


def test_resolve_via_authoritative_ns_dig_missing_returns_none() -> None:
    # An environment without `dig` installed can't verify -- that's a
    # limitation of the environment, not a DNS failure; callers must not
    # treat this the same as "asked and got no answer" (== []).
    with patch("subprocess.run", side_effect=FileNotFoundError()):
        answers = _resolve_via_authoritative_ns("app.example.com", "A", "ns1.example.net", timeout=5)
    assert answers is None


def test_resolve_via_authoritative_ns_timeout_returns_none() -> None:
    with patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="dig", timeout=5)):
        answers = _resolve_via_authoritative_ns("app.example.com", "A", "ns1.example.net", timeout=5)
    assert answers is None


def test_resolve_via_authoritative_ns_nonzero_exit_returns_none() -> None:
    completed = subprocess.CompletedProcess(args=[], returncode=9, stdout="")
    with patch("subprocess.run", return_value=completed):
        answers = _resolve_via_authoritative_ns("app.example.com", "A", "ns1.example.net", timeout=5)
    assert answers is None


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


def test_check_dns_cf_request_exception_reported_as_fail() -> None:
    # A real Cloudflare auth/4xx failure (or any other _cf_request
    # exception) must be a "fail" result, not an exception escaping
    # check_dns -> run_all -> the route/CLI.
    service = {"server_name": "app.example.com"}
    with patch("app.catalog_checks._cf_request", side_effect=_http_error(403, "forbidden")):
        result = check_dns("svc", service, cf_headers={"x": "y"}, timeout=5, max_retries=1)
    assert result.status == "fail"
    assert "Cloudflare lookup error" in result.detail


def test_check_dns_irrelevant_record_type_is_not_a_match() -> None:
    # A zone answering with only a TXT/MX/NS record for the name is not
    # the same as having an A/AAAA/CNAME pointing at this host -- the
    # record-type filter must actually exclude it, not just happen to
    # (every other test's fixture records are either empty or already
    # A-type, so this is the only test that could catch the filter being
    # dropped or inverted).
    service = {"server_name": "example.com"}
    with patch(
        "app.catalog_checks._cf_request",
        side_effect=[
            {"result": [{"id": "zone123"}]},
            {"result": [{"type": "TXT", "content": "v=spf1 -all"}]},
        ],
    ):
        result = check_dns("svc", service, cf_headers={"x": "y"}, timeout=5, max_retries=1)
    assert result.status == "fail"
    assert "no A/AAAA/CNAME record" in result.detail


# --- check_local_dns --------------------------------------------------------


def test_check_local_dns_skip_for_static_kind() -> None:
    result = check_local_dns("svc", {"kind": "static"}, local_dns_port=853, timeout=5)
    assert result.status == "skip"


def test_check_local_dns_missing_upstream_host_is_fail() -> None:
    result = check_local_dns("svc", {"kind": "proxy", "upstream": {}}, local_dns_port=853, timeout=5)
    assert result.status == "fail"
    assert "missing" in result.detail


def test_check_local_dns_literal_ip_upstream_host_is_skip() -> None:
    service = {"kind": "proxy", "upstream": {"host": "203.0.113.10", "port": 8080}}
    with patch("app.catalog_checks._resolve_via_authoritative_ns") as mock_resolve:
        result = check_local_dns("svc", service, local_dns_port=853, timeout=5)
    mock_resolve.assert_not_called()
    assert result.status == "skip"
    assert "literal IP" in result.detail


def test_check_local_dns_unreachable_is_skip_not_fail() -> None:
    # No local PowerDNS reachable at all (e.g. this host doesn't run one)
    # is an environment limitation, not "the record is missing" -- must
    # not be reported the same way as a real NXDOMAIN.
    service = {"kind": "proxy", "upstream": {"host": "backend.internal", "port": 8080}}
    with patch("app.catalog_checks._resolve_via_authoritative_ns", return_value=None):
        result = check_local_dns("svc", service, local_dns_port=853, timeout=5)
    assert result.status == "skip"


def test_check_local_dns_not_our_zone_is_skip_not_fail() -> None:
    # upstream.host is not required to live in the local PowerDNS zone at
    # all (a backend resolved by the host's real resolver is a valid,
    # common case) -- an empty SOA answer means "not authoritative for
    # this zone," not "record missing," and must not fail the check.
    service = {"kind": "proxy", "upstream": {"host": "backend.internal", "port": 8080}}
    with patch("app.catalog_checks._resolve_via_authoritative_ns", return_value=[]) as mock_resolve:
        result = check_local_dns("svc", service, local_dns_port=853, timeout=5)
    mock_resolve.assert_called_once_with("backend.internal", "SOA", "127.0.0.1", 5, port=853)
    assert result.status == "skip"
    assert "not served by the local PowerDNS zone" in result.detail


def test_check_local_dns_no_record_is_fail() -> None:
    # SOA found (this server is authoritative for the zone) but neither
    # A nor AAAA answers -- a real miss, unlike the not-our-zone case.
    service = {"kind": "proxy", "upstream": {"host": "backend.internal", "port": 8080}}
    with patch(
        "app.catalog_checks._resolve_via_authoritative_ns",
        side_effect=[["ns1.backend.internal."], [], []],
    ) as mock_resolve:
        result = check_local_dns("svc", service, local_dns_port=853, timeout=5)
    assert mock_resolve.call_args_list == [
        call("backend.internal", "SOA", "127.0.0.1", 5, port=853),
        call("backend.internal", "A", "127.0.0.1", 5, port=853),
        call("backend.internal", "AAAA", "127.0.0.1", 5, port=853),
    ]
    assert result.status == "fail"
    assert "no local A/AAAA record" in result.detail


def test_check_local_dns_a_query_none_is_skip_not_fail() -> None:
    # SOA succeeds (zone found) but the A query itself can't be verified
    # (e.g. the local server reloaded/restarted between probes) -- must
    # not be coerced into "record missing" the way `or []` would.
    service = {"kind": "proxy", "upstream": {"host": "backend.internal", "port": 8080}}
    with patch(
        "app.catalog_checks._resolve_via_authoritative_ns",
        side_effect=[["ns1.backend.internal."], None],
    ):
        result = check_local_dns("svc", service, local_dns_port=853, timeout=5)
    assert result.status == "skip"


def test_check_local_dns_aaaa_query_none_is_skip_not_fail() -> None:
    service = {"kind": "proxy", "upstream": {"host": "backend.internal", "port": 8080}}
    with patch(
        "app.catalog_checks._resolve_via_authoritative_ns",
        side_effect=[["ns1.backend.internal."], [], None],
    ):
        result = check_local_dns("svc", service, local_dns_port=853, timeout=5)
    assert result.status == "skip"


def test_check_local_dns_ok() -> None:
    service = {"kind": "proxy", "upstream": {"host": "backend.internal", "port": 8080}}
    with (
        patch(
            "app.catalog_checks._resolve_via_authoritative_ns",
            side_effect=[["ns1.backend.internal."], ["10.0.0.5"], []],
        ),
        patch("app.catalog_checks._host_resolves", return_value=True),
    ):
        result = check_local_dns("svc", service, local_dns_port=853, timeout=5)
    assert result.status == "ok"
    assert "10.0.0.5" in result.detail


def test_check_local_dns_host_cannot_resolve_is_fail() -> None:
    # #139: the authoritative server has the record, but the host's own
    # resolver never asks the local recursor, so nginx couldn't use it.
    service = {"kind": "proxy", "upstream": {"host": "backend.internal", "port": 8080}}
    with (
        patch(
            "app.catalog_checks._resolve_via_authoritative_ns",
            side_effect=[["ns1.backend.internal."], ["10.0.0.5"], []],
        ),
        patch("app.catalog_checks._host_resolves", return_value=False),
    ):
        result = check_local_dns("svc", service, local_dns_port=853, timeout=5)
    assert result.status == "fail"
    assert "this host cannot resolve it" in result.detail
    assert "10.0.0.5" in result.detail


def test_check_local_dns_host_resolution_unknown_is_skip() -> None:
    service = {"kind": "proxy", "upstream": {"host": "backend.internal", "port": 8080}}
    with (
        patch(
            "app.catalog_checks._resolve_via_authoritative_ns",
            side_effect=[["ns1.backend.internal."], ["10.0.0.5"], []],
        ),
        patch("app.catalog_checks._host_resolves", return_value=None),
    ):
        result = check_local_dns("svc", service, local_dns_port=853, timeout=5)
    assert result.status == "skip"
    assert "could not be checked" in result.detail


def test_check_local_dns_aaaa_only_is_ok() -> None:
    # A-only queries would false-fail an IPv6-only backend -- AAAA must
    # also be checked, not just A.
    service = {"kind": "proxy", "upstream": {"host": "backend.internal", "port": 8080}}
    with (
        patch(
            "app.catalog_checks._resolve_via_authoritative_ns",
            side_effect=[["ns1.backend.internal."], [], ["::1"]],
        ),
        patch("app.catalog_checks._host_resolves", return_value=True),
    ):
        result = check_local_dns("svc", service, local_dns_port=853, timeout=5)
    assert result.status == "ok"
    assert "::1" in result.detail


# --- list_cloudflare_records -------------------------------------------


def test_list_cloudflare_records_no_domain_returns_none() -> None:
    assert list_cloudflare_records(None, {"x": "y"}, timeout=5, max_retries=1) is None


def test_list_cloudflare_records_no_credentials_returns_none() -> None:
    assert list_cloudflare_records("app.example.com", None, timeout=5, max_retries=1) is None


def test_list_cloudflare_records_no_zone_found_returns_none() -> None:
    with patch("app.catalog_checks._cf_request", return_value={"result": []}):
        result = list_cloudflare_records("app.example.com", {"x": "y"}, timeout=5, max_retries=1)
    assert result is None


def test_list_cloudflare_records_no_matching_record_returns_none() -> None:
    # candidate_zone_names("app.example.com") tries "example.com" then
    # "app.example.com" -- both must resolve to keep this exercising "zone
    # found, no matching record type" rather than falling through to a
    # StopIteration the broad exception handling used to mask.
    with patch(
        "app.catalog_checks._cf_request",
        side_effect=[
            {"result": [{"id": "zone123"}]},
            {"result": []},
            {"result": [{"id": "zone456"}]},
            {"result": []},
        ],
    ):
        result = list_cloudflare_records("app.example.com", {"x": "y"}, timeout=5, max_retries=1)
    assert result is None


def test_list_cloudflare_records_ok() -> None:
    with patch(
        "app.catalog_checks._cf_request",
        side_effect=[
            {"result": [{"id": "zone123"}]},
            {"result": [{"type": "A", "content": "203.0.113.10", "ttl": 300, "proxied": False}]},
        ],
    ):
        result = list_cloudflare_records("app.example.com", {"x": "y"}, timeout=5, max_retries=1)
    assert result == [{"type": "A", "content": "203.0.113.10", "ttl": 300, "proxied": False}]


def test_list_cloudflare_records_filters_irrelevant_types() -> None:
    with patch(
        "app.catalog_checks._cf_request",
        side_effect=[
            {"result": [{"id": "zone123"}]},
            {
                "result": [
                    {"type": "TXT", "content": "v=spf1 -all", "ttl": 300},
                    {"type": "A", "content": "203.0.113.10", "ttl": 300, "proxied": False},
                ]
            },
        ],
    ):
        result = list_cloudflare_records("app.example.com", {"x": "y"}, timeout=5, max_retries=1)
    assert result == [{"type": "A", "content": "203.0.113.10", "ttl": 300, "proxied": False}]


def test_list_cloudflare_records_propagates_api_errors() -> None:
    # A genuine Cloudflare API error (auth failure, persistent 5xx) must
    # not be swallowed into None -- that would be indistinguishable from
    # a real absent record. Callers (app.api.dns_view_routes) catch this
    # themselves to report a distinct "error" status.
    with (
        patch("app.catalog_checks._cf_request", side_effect=_http_error(500, "server error")),
        pytest.raises(urllib.error.HTTPError),
    ):
        list_cloudflare_records("app.example.com", {"x": "y"}, timeout=5, max_retries=1)


# --- run_all -------------------------------------------------------------


def test_run_all_respects_skip_flags(tmp_path: Path) -> None:
    catalog = {"services": [{"name": "svc", "kind": "static", "server_name": "app.example.com"}]}
    results = run_all(
        catalog,
        certs_live_dir=tmp_path,
        alert_days=10,
        cf_headers=None,
        local_dns_port=853,
        timeout=1,
        max_retries=1,
        skip_cert=True,
        skip_dns=True,
        skip_local_dns=True,
        skip_upstream=False,
    )
    assert len(results) == 1
    assert results[0].dimension == "upstream"


def test_run_all_includes_local_dns_dimension_by_default() -> None:
    # Nothing else in this suite exercises local_dns through run_all --
    # deleting the branch, or dropping its local_dns_port pass-through,
    # must not leave this green.
    catalog = {
        "services": [
            {"name": "svc", "kind": "proxy", "server_name": "app.example.com", "upstream": {"host": "10.0.0.5"}}
        ]
    }
    with patch(
        "app.catalog_checks.check_local_dns", return_value=CheckResult("svc", "local_dns", "ok", "resolves")
    ) as mock_check:
        results = run_all(
            catalog,
            certs_live_dir=Path("/nonexistent"),
            alert_days=10,
            cf_headers=None,
            local_dns_port=853,
            timeout=1,
            max_retries=1,
            skip_cert=True,
            skip_dns=True,
            skip_upstream=True,
        )
    assert [r.dimension for r in results] == ["local_dns"]
    mock_check.assert_called_once_with("svc", catalog["services"][0], local_dns_port=853, timeout=1)


def test_run_all_empty_catalog() -> None:
    results = run_all(
        {},
        certs_live_dir=Path("/nonexistent"),
        alert_days=10,
        cf_headers=None,
        local_dns_port=853,
        timeout=1,
        max_retries=1,
    )
    assert results == []


def test_run_all_rejects_non_positive_timeout() -> None:
    # timeout<=0 reaches socket.settimeout() as an uncaught ValueError
    # (not an OSError) if it isn't caught here first.
    with pytest.raises(ValueError, match="timeout must be positive"):
        run_all(
            {},
            certs_live_dir=Path("/nonexistent"),
            alert_days=10,
            cf_headers=None,
            local_dns_port=853,
            timeout=0,
            max_retries=1,
        )


def test_run_all_rejects_negative_alert_days() -> None:
    # A negative alert_days would otherwise silently make the expiry
    # comparison pass for a cert that's already expired.
    with pytest.raises(ValueError, match="alert_days must be non-negative"):
        run_all(
            {},
            certs_live_dir=Path("/nonexistent"),
            alert_days=-1,
            cf_headers=None,
            local_dns_port=853,
            timeout=5,
            max_retries=1,
        )


def test_run_all_rejects_out_of_range_local_dns_port() -> None:
    # An invalid port makes dig unreachable, which check_local_dns treats
    # as an environment-limitation "skip" -- must not silently degrade
    # the whole dimension to unverified instead of a loud config error.
    with pytest.raises(ValueError, match="local_dns_port must be between 1 and 65535"):
        run_all(
            {},
            certs_live_dir=Path("/nonexistent"),
            alert_days=10,
            cf_headers=None,
            local_dns_port=0,
            timeout=5,
            max_retries=1,
        )


# --- sync_dns_record -------------------------------------------------------


def test_sync_dns_record_no_server_name() -> None:
    result = sync_dns_record("svc", {}, "203.0.113.10", {"x": "y"}, timeout=5, max_retries=1)
    assert result == SyncResult("svc", "skip", "no server_name on this catalog entry")


def test_sync_dns_record_no_credentials() -> None:
    service = {"server_name": "app.example.com"}
    result = sync_dns_record("svc", service, "203.0.113.10", None, timeout=5, max_retries=1)
    assert result.status == "skip"
    assert "credentials" in result.detail


def test_sync_dns_record_no_zone_found() -> None:
    service = {"server_name": "app.example.com"}
    with patch("app.catalog_checks._cf_request", return_value={"result": []}):
        result = sync_dns_record("svc", service, "203.0.113.10", {"x": "y"}, timeout=5, max_retries=1)
    assert result.status == "failed"
    assert "no Cloudflare zone found" in result.detail


def test_sync_dns_record_zone_lookup_exception() -> None:
    service = {"server_name": "app.example.com"}
    with patch("app.catalog_checks._cf_request", side_effect=_http_error(403, "forbidden")):
        result = sync_dns_record("svc", service, "203.0.113.10", {"x": "y"}, timeout=5, max_retries=1)
    assert result.status == "failed"
    assert "Cloudflare lookup error" in result.detail


def test_sync_dns_record_record_lookup_exception() -> None:
    service = {"server_name": "example.com"}
    with patch(
        "app.catalog_checks._cf_request",
        side_effect=[{"result": [{"id": "zone123"}]}, _http_error(500, "server error")],
    ):
        result = sync_dns_record("svc", service, "203.0.113.10", {"x": "y"}, timeout=5, max_retries=1)
    assert result.status == "failed"
    assert "Cloudflare lookup error" in result.detail


def test_sync_dns_record_falls_back_to_more_specific_zone_when_parent_has_no_record() -> None:
    # Account holds both example.com and app.example.com as separate
    # zones; neither has an existing record yet, so the record must be
    # created in the more specific (child) zone -- not the first
    # (parent) zone merely because it happens to exist. Mirrors
    # check_dns's own test_check_dns_falls_back_to_more_specific_nested_zone.
    service = {"server_name": "app.example.com"}
    with (
        patch(
            "app.catalog_checks._cf_request",
            side_effect=[
                {"result": [{"id": "parent-zone", "name_servers": ["ns-parent.example.net"]}]},
                {"result": []},  # no existing record in the parent zone
                {"result": [{"id": "child-zone", "name_servers": ["ns-child.example.net"]}]},
                {"result": []},  # no existing record in the child zone either
                {"result": {"id": "rec1"}},  # POST write
                {"result": [{"type": "A", "content": "203.0.113.10"}]},  # read-back confirm
            ],
        ) as mock_cf,
        patch("app.catalog_checks._resolve_via_authoritative_ns", return_value=["203.0.113.10"]),
    ):
        result = sync_dns_record("svc", service, "203.0.113.10", {"x": "y"}, timeout=5, max_retries=1)
    assert result.status == "created"
    assert "zone app.example.com" in result.detail
    write_call = mock_cf.call_args_list[4]
    assert "zones/child-zone/dns_records" in write_call.args[0]


def test_sync_dns_record_other_type_conflict() -> None:
    service = {"server_name": "app.example.com"}
    with patch(
        "app.catalog_checks._cf_request",
        side_effect=[
            {"result": [{"id": "zone123"}]},
            {"result": [{"id": "rec9", "type": "CNAME", "content": "other.example.com"}]},
        ],
    ):
        result = sync_dns_record("svc", service, "203.0.113.10", {"x": "y"}, timeout=5, max_retries=1)
    assert result.status == "failed"
    assert "different type" in result.detail


def test_sync_dns_record_ignores_non_address_record_types() -> None:
    # An MX/TXT record at the same name is the ordinary case, not a
    # different-type conflict -- only A/AAAA/CNAME are this dimension's
    # concern; the filter that excludes them from `existing` is what this
    # pins.
    service = {"server_name": "example.com"}
    with (
        patch(
            "app.catalog_checks._cf_request",
            side_effect=[
                {"result": [{"id": "zone123", "name_servers": ["ns1.example.net"]}]},
                {"result": [{"id": "mx1", "type": "MX", "content": "mail.example.com"}]},
                {"result": {"id": "rec1"}},
                {"result": [{"type": "A", "content": "203.0.113.10"}]},
            ],
        ),
        patch("app.catalog_checks._resolve_via_authoritative_ns", return_value=["203.0.113.10"]),
    ):
        result = sync_dns_record("svc", service, "203.0.113.10", {"x": "y"}, timeout=5, max_retries=1)
    assert result.status == "created"


def test_sync_dns_record_multiple_same_type_records_refuses_to_pick_one() -> None:
    # A name can legitimately carry several A records (round-robin) --
    # inspecting only the first risks reporting noop while a stale sibling
    # keeps answering, or fixing only one of several.
    service = {"server_name": "example.com"}
    with patch(
        "app.catalog_checks._cf_request",
        side_effect=[
            {"result": [{"id": "zone123"}]},
            {
                "result": [
                    {"id": "r1", "type": "A", "content": "198.51.100.1", "proxied": False},
                    {"id": "r2", "type": "A", "content": "203.0.113.10", "proxied": False},
                ]
            },
        ],
    ):
        result = sync_dns_record("svc", service, "203.0.113.10", {"x": "y"}, timeout=5, max_retries=1)
    assert result.status == "failed"
    assert "multiple existing A records" in result.detail


def test_sync_dns_record_readback_exception_is_failure() -> None:
    service = {"server_name": "example.com"}
    with patch(
        "app.catalog_checks._cf_request",
        side_effect=[
            {"result": [{"id": "zone123"}]},
            {"result": []},
            {"result": {"id": "rec1"}},
            _http_error(500, "server error"),
        ],
    ):
        result = sync_dns_record("svc", service, "203.0.113.10", {"x": "y"}, timeout=5, max_retries=1)
    assert result.status == "failed"
    assert "read-back failed" in result.detail


def test_sync_dns_record_noop_already_correct() -> None:
    service = {"server_name": "app.example.com"}
    with patch(
        "app.catalog_checks._cf_request",
        side_effect=[
            {"result": [{"id": "zone123"}]},
            {"result": [{"id": "rec9", "type": "A", "content": "203.0.113.10", "proxied": False}]},
        ],
    ):
        result = sync_dns_record("svc", service, "203.0.113.10", {"x": "y"}, timeout=5, max_retries=1)
    assert result.status == "noop"


def test_sync_dns_record_dry_run_create() -> None:
    service = {"server_name": "example.com"}
    with patch(
        "app.catalog_checks._cf_request",
        side_effect=[{"result": [{"id": "zone123"}]}, {"result": []}],
    ):
        result = sync_dns_record("svc", service, "203.0.113.10", {"x": "y"}, timeout=5, max_retries=1, dry_run=True)
    assert result.status == "would-create"


def test_sync_dns_record_dry_run_update() -> None:
    service = {"server_name": "app.example.com"}
    with patch(
        "app.catalog_checks._cf_request",
        side_effect=[
            {"result": [{"id": "zone123"}]},
            {"result": [{"id": "rec9", "type": "A", "content": "198.51.100.1", "proxied": False}]},
        ],
    ):
        result = sync_dns_record("svc", service, "203.0.113.10", {"x": "y"}, timeout=5, max_retries=1, dry_run=True)
    assert result.status == "would-update"


def test_sync_dns_record_create_success() -> None:
    # max_retries=3 (not 1) deliberately: proves the create write forwards
    # a hardcoded 1 regardless of the caller's own retry budget (the
    # non-idempotent-POST safety property), while the zone/record/read-back
    # GETs forward the caller's real value.
    service = {"server_name": "example.com"}
    with (
        patch(
            "app.catalog_checks._cf_request",
            side_effect=[
                {"result": [{"id": "zone123", "name_servers": ["ns1.example.net"]}]},
                {"result": []},
                {"result": {"id": "rec1"}},
                {"result": [{"type": "A", "content": "203.0.113.10"}]},
            ],
        ) as mock_cf,
        patch("app.catalog_checks._resolve_via_authoritative_ns", return_value=["203.0.113.10"]),
    ):
        result = sync_dns_record("svc", service, "203.0.113.10", {"x": "y"}, timeout=5, max_retries=3)
    assert result.status == "created"
    assert "203.0.113.10" in result.detail
    write_call = mock_cf.call_args_list[2]
    assert write_call.kwargs["method"] == "POST"
    # Single-attempt invariant: create must always pass max_retries=1 to
    # _cf_request (the 4th positional arg), never the caller's own value --
    # that's what keeps a transient 5xx from ever re-POSTing and risking a
    # duplicate record.
    assert write_call.args[3] == 1
    assert write_call.kwargs["data"] == {
        "type": "A",
        "name": "example.com",
        "content": "203.0.113.10",
        "proxied": False,
    }


def test_sync_dns_record_update_success() -> None:
    service = {"server_name": "app.example.com"}
    with (
        patch(
            "app.catalog_checks._cf_request",
            side_effect=[
                {"result": [{"id": "zone123", "name_servers": ["ns1.example.net"]}]},
                {"result": [{"id": "rec9", "type": "A", "content": "198.51.100.1", "proxied": False}]},
                {"result": {"id": "rec9"}},
                {"result": [{"type": "A", "content": "203.0.113.10"}]},
            ],
        ) as mock_cf,
        patch("app.catalog_checks._resolve_via_authoritative_ns", return_value=["203.0.113.10"]),
    ):
        result = sync_dns_record("svc", service, "203.0.113.10", {"x": "y"}, timeout=5, max_retries=3)
    assert result.status == "updated"
    write_call = mock_cf.call_args_list[2]
    assert write_call.kwargs["method"] == "PUT"
    # Update is idempotent (PUT to a specific record id) -- it forwards the
    # caller's own max_retries, unlike create's hardcoded single attempt.
    assert write_call.args[3] == 3
    assert write_call.kwargs["data"]["content"] == "203.0.113.10"


def test_sync_dns_record_proxied_mismatch_triggers_update_not_noop() -> None:
    # Content already matches but the orange-cloud state doesn't -- must
    # still PUT, not report noop and leave the live record's proxy state
    # wrong with a success status.
    service = {"server_name": "app.example.com"}
    with (
        patch(
            "app.catalog_checks._cf_request",
            side_effect=[
                {"result": [{"id": "zone123", "name_servers": ["ns1.example.net"]}]},
                {"result": [{"id": "rec9", "type": "A", "content": "203.0.113.10", "proxied": False}]},
                {"result": {"id": "rec9"}},
                {"result": [{"type": "A", "content": "203.0.113.10"}]},
            ],
        ) as mock_cf,
        patch("app.catalog_checks._resolve_via_authoritative_ns"),
    ):
        result = sync_dns_record("svc", service, "203.0.113.10", {"x": "y"}, timeout=5, max_retries=1, proxied=True)
    assert result.status == "updated"
    write_call = mock_cf.call_args_list[2]
    assert write_call.kwargs["data"]["proxied"] is True


def test_sync_dns_record_normalizes_noncanonical_ipv6_target() -> None:
    # dig -- and Cloudflare's own stored content -- always report IPv6 in
    # RFC 5952 canonical form; a non-canonical --target must still
    # converge to noop against it instead of "mismatch" forever.
    service = {"server_name": "app.example.com"}
    with patch(
        "app.catalog_checks._cf_request",
        side_effect=[
            {"result": [{"id": "zone123"}]},
            {"result": [{"id": "r1", "type": "AAAA", "content": "2001:db8::1", "proxied": False}]},
        ],
    ):
        result = sync_dns_record("svc", service, "2001:DB8:0000::1", {"x": "y"}, timeout=5, max_retries=1)
    assert result.status == "noop"


def test_sync_dns_record_normalizes_trailing_dot_cname_target() -> None:
    service = {"server_name": "app.example.com"}
    with patch(
        "app.catalog_checks._cf_request",
        side_effect=[
            {"result": [{"id": "zone123"}]},
            {"result": [{"id": "r1", "type": "CNAME", "content": "front.example.net", "proxied": False}]},
        ],
    ):
        result = sync_dns_record("svc", service, "front.example.net.", {"x": "y"}, timeout=5, max_retries=1)
    assert result.status == "noop"


def test_sync_dns_record_create_write_fails() -> None:
    service = {"server_name": "example.com"}
    with patch(
        "app.catalog_checks._cf_request",
        side_effect=[
            {"result": [{"id": "zone123"}]},
            {"result": []},
            _http_error(500, "server error"),
        ],
    ):
        result = sync_dns_record("svc", service, "203.0.113.10", {"x": "y"}, timeout=5, max_retries=1)
    assert result.status == "failed"
    assert "Cloudflare write failed" in result.detail


def test_sync_dns_record_write_succeeds_but_readback_missing() -> None:
    # The write API can return 200 without the record actually being
    # correct yet -- must not report success on that alone.
    service = {"server_name": "example.com"}
    with patch(
        "app.catalog_checks._cf_request",
        side_effect=[
            {"result": [{"id": "zone123", "name_servers": ["ns1.example.net"]}]},
            {"result": []},
            {"result": {"id": "rec1"}},
            {"result": []},
        ],
    ):
        result = sync_dns_record("svc", service, "203.0.113.10", {"x": "y"}, timeout=5, max_retries=1)
    assert result.status == "failed"
    assert "not found on read-back" in result.detail


def test_sync_dns_record_resolution_mismatch_is_failure() -> None:
    # Read-back via the API can look correct while the authoritative
    # nameserver still answers something else -- both checks must pass.
    service = {"server_name": "example.com"}
    with (
        patch(
            "app.catalog_checks._cf_request",
            side_effect=[
                {"result": [{"id": "zone123", "name_servers": ["ns1.example.net"]}]},
                {"result": []},
                {"result": {"id": "rec1"}},
                {"result": [{"type": "A", "content": "203.0.113.10"}]},
            ],
        ),
        patch("app.catalog_checks._resolve_via_authoritative_ns", return_value=["198.51.100.99"]),
    ):
        result = sync_dns_record("svc", service, "203.0.113.10", {"x": "y"}, timeout=5, max_retries=1)
    assert result.status == "failed"
    assert "ns1.example.net answers" in result.detail


def test_sync_dns_record_dig_unavailable_still_succeeds() -> None:
    # No `dig` on this host (or environment can't run it) is a couldn't-
    # verify limitation, not a DNS failure -- must not turn every dig-less
    # host into a false "failed" (see _resolve_via_authoritative_ns's own
    # None-vs-[] contract).
    service = {"server_name": "example.com"}
    with (
        patch(
            "app.catalog_checks._cf_request",
            side_effect=[
                {"result": [{"id": "zone123", "name_servers": ["ns1.example.net"]}]},
                {"result": []},
                {"result": {"id": "rec1"}},
                {"result": [{"type": "A", "content": "203.0.113.10"}]},
            ],
        ),
        patch("app.catalog_checks._resolve_via_authoritative_ns", return_value=None),
    ):
        result = sync_dns_record("svc", service, "203.0.113.10", {"x": "y"}, timeout=5, max_retries=1)
    assert result.status == "created"


def test_sync_dns_record_dig_empty_answer_is_failure() -> None:
    # Distinct from the None case above: dig ran and got a real answer --
    # an empty one -- which is a genuine mismatch, not a skip.
    service = {"server_name": "example.com"}
    with (
        patch(
            "app.catalog_checks._cf_request",
            side_effect=[
                {"result": [{"id": "zone123", "name_servers": ["ns1.example.net"]}]},
                {"result": []},
                {"result": {"id": "rec1"}},
                {"result": [{"type": "A", "content": "203.0.113.10"}]},
            ],
        ),
        patch("app.catalog_checks._resolve_via_authoritative_ns", return_value=[]),
    ):
        result = sync_dns_record("svc", service, "203.0.113.10", {"x": "y"}, timeout=5, max_retries=1)
    assert result.status == "failed"
    assert "answers []" in result.detail


def test_sync_dns_record_cname_dig_answer_trailing_dot_is_normalized() -> None:
    # dig prints CNAME answers as FQDNs with a trailing dot; target never
    # carries one -- a naive exact-string compare would report every
    # correct CNAME write as failed.
    service = {"server_name": "example.com"}
    with (
        patch(
            "app.catalog_checks._cf_request",
            side_effect=[
                {"result": [{"id": "zone123", "name_servers": ["ns1.example.net"]}]},
                {"result": []},
                {"result": {"id": "rec1"}},
                {"result": [{"type": "CNAME", "content": "front.example.net"}]},
            ],
        ),
        patch("app.catalog_checks._resolve_via_authoritative_ns", return_value=["front.example.net."]),
    ):
        result = sync_dns_record("svc", service, "front.example.net", {"x": "y"}, timeout=5, max_retries=1)
    assert result.status == "created"


def test_sync_dns_record_proxied_skips_dig_verification() -> None:
    # A proxied record's authoritative answer is Cloudflare's anycast edge
    # (or nothing), never the origin content just written -- dig
    # verification must be skipped entirely for proxied=True, not just
    # normalized, or every proxied write would report failed.
    service = {"server_name": "example.com"}
    with (
        patch(
            "app.catalog_checks._cf_request",
            side_effect=[
                {"result": [{"id": "zone123", "name_servers": ["ns1.example.net"]}]},
                {"result": []},
                {"result": {"id": "rec1"}},
                {"result": [{"type": "A", "content": "203.0.113.10"}]},
            ],
        ),
        patch("app.catalog_checks._resolve_via_authoritative_ns") as mock_resolve,
    ):
        result = sync_dns_record("svc", service, "203.0.113.10", {"x": "y"}, timeout=5, max_retries=1, proxied=True)
    assert result.status == "created"
    mock_resolve.assert_not_called()


def test_sync_dns_record_verify_resolution_false_skips_dig() -> None:
    service = {"server_name": "example.com"}
    with (
        patch(
            "app.catalog_checks._cf_request",
            side_effect=[
                {"result": [{"id": "zone123", "name_servers": ["ns1.example.net"]}]},
                {"result": []},
                {"result": {"id": "rec1"}},
                {"result": [{"type": "A", "content": "203.0.113.10"}]},
            ],
        ),
        patch("app.catalog_checks._resolve_via_authoritative_ns") as mock_resolve,
    ):
        result = sync_dns_record(
            "svc", service, "203.0.113.10", {"x": "y"}, timeout=5, max_retries=1, verify_resolution=False
        )
    assert result.status == "created"
    mock_resolve.assert_not_called()


def test_sync_dns_record_ipv6_target_selects_aaaa_type() -> None:
    # Proven indirectly: an AAAA record already matching the target is a
    # noop only if the function actually chose record_type="AAAA" -- if
    # it had picked "A" (or "CNAME") this would instead hit the
    # different-type-conflict path.
    service = {"server_name": "app.example.com"}
    with patch(
        "app.catalog_checks._cf_request",
        side_effect=[
            {"result": [{"id": "zone123"}]},
            {"result": [{"id": "r1", "type": "AAAA", "content": "2001:db8::10", "proxied": False}]},
        ],
    ):
        result = sync_dns_record("svc", service, "2001:db8::10", {"x": "y"}, timeout=5, max_retries=1)
    assert result.status == "noop"


def test_sync_dns_record_hostname_target_selects_cname_type() -> None:
    service = {"server_name": "app.example.com"}
    with patch(
        "app.catalog_checks._cf_request",
        side_effect=[
            {"result": [{"id": "zone123"}]},
            {"result": [{"id": "r1", "type": "CNAME", "content": "front.example.net", "proxied": False}]},
        ],
    ):
        result = sync_dns_record("svc", service, "front.example.net", {"x": "y"}, timeout=5, max_retries=1)
    assert result.status == "noop"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__]))
