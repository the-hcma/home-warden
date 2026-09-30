"""Tests for app.cutover_verify / app.cutover_verify_cli (#188) against throwaway local servers."""

from __future__ import annotations

import datetime
import http.client
import http.server
import ssl
import sys
import threading
from collections.abc import Iterator
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from app.cutover_verify import Probe, _describe_cert, compare, failure_kind, probe_vhost
from app.cutover_verify_cli import main


def _self_signed(tmp_path: Path, name: str) -> tuple[Path, Path]:
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=30))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(name)]), critical=False)
        .sign(key, hashes.SHA256())
    )
    crt, pem = tmp_path / f"{name}.crt", tmp_path / f"{name}.key"
    crt.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    pem.write_bytes(
        key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    )
    return crt, pem


class _Server:
    def __init__(self, tmp_path: Path, hsts: bool) -> None:
        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a) -> None:
                pass

            def do_GET(self) -> None:
                if self.server is outer.plain:
                    self.send_response(301)
                    self.send_header("Location", "https://app.example.com/")
                else:
                    self.send_response(200)
                    if hsts:
                        self.send_header("Strict-Transport-Security", "max-age=31536000")
                self.send_header("Content-Length", "0")
                self.end_headers()

        crt, key = _self_signed(tmp_path, "app.example.com")
        self.plain = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        self.tls = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(crt, key)
        self.tls.socket = ctx.wrap_socket(self.tls.socket, server_side=True)
        for srv in (self.plain, self.tls):
            threading.Thread(target=srv.serve_forever, daemon=True).start()

    @property
    def ports(self) -> tuple[int, int]:
        return self.plain.server_address[1], self.tls.server_address[1]

    def close(self) -> None:
        for srv in (self.plain, self.tls):
            srv.shutdown()
            srv.server_close()


@pytest.fixture
def servers(tmp_path: Path) -> Iterator[tuple[_Server, _Server]]:
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    a = _Server(tmp_path / "a", True)
    b = _Server(tmp_path / "b", False)
    yield a, b
    a.close()
    b.close()


def _probe(server: _Server) -> Probe:
    http_port, https_port = server.ports
    return probe_vhost("app.example.com", "127.0.0.1", timeout=5, http_port=http_port, https_port=https_port)


def test_probe_reports_redirect_status_headers_and_tls(servers) -> None:
    a, _ = servers
    p = _probe(a)
    assert p.facts["http.status"] == "301"
    assert p.facts["http.location"] == "https://app.example.com/"
    assert p.facts["https.status"] == "200"
    assert p.facts["https.strict-transport-security"] == "max-age=31536000"
    assert p.facts["tls.verifies"].startswith("no:")  # self-signed, no trusted chain
    assert "tls.notAfter" in p.info and "tls.notAfter" not in p.facts


def test_identical_servers_have_no_differences_and_a_missing_header_is_one(servers) -> None:
    a, b = servers
    assert compare(_probe(a), _probe(a)) == []
    diffs = compare(_probe(a), _probe(b))
    assert any("strict-transport-security" in d for d in diffs)


def test_unreachable_address_is_a_difference_even_when_both_are_down() -> None:
    p = probe_vhost("app.example.com", "127.0.0.1", timeout=1, http_port=1, https_port=1)
    assert p.unreachable == ["127.0.0.1:1 ConnectionRefusedError"]
    diffs = compare(p, p)
    assert "old unreachable: 127.0.0.1:1 ConnectionRefusedError" in diffs and len(diffs) == 2


def test_failure_kind_groups_rejections() -> None:
    assert failure_kind(ssl.SSLError()) == "rejected"
    assert failure_kind(ConnectionResetError()) == "rejected"
    assert failure_kind(http.client.RemoteDisconnected("closed")) == "rejected"
    assert failure_kind(TimeoutError()) == "timeout"
    assert failure_kind(ConnectionRefusedError()) == "ConnectionRefusedError"


def test_unparsable_certificate_is_a_fact_not_a_crash() -> None:
    p = Probe()
    _describe_cert(b"not a certificate", p)
    assert p.facts == {"tls.cert": "unparsable"}


def test_compare_ignores_info() -> None:
    assert compare(Probe({"a": "1"}, {"serial": "x"}), Probe({"a": "1"}, {"serial": "y"})) == []


def test_cli_argument_validation(monkeypatch, tmp_path: Path) -> None:
    base = ["cutover-verify", "--old", "a", "--new", "b", "--services-json", str(tmp_path / "none.json")]
    for extra in (
        ["--old6", "::1"],
        ["--client-cert", "c"],
        ["--client-cert", "/typo.crt", "--client-key", "/typo.key"],
    ):
        monkeypatch.setattr(sys, "argv", base + extra)
        assert main() == 2
    monkeypatch.setattr(sys, "argv", base)  # no catalog, no --host
    assert main() == 2


def test_cli_warns_when_the_catalog_is_unusable_but_hosts_were_given(monkeypatch, tmp_path: Path, capsys) -> None:
    bad = tmp_path / "services.json"
    bad.write_text("{oops")
    monkeypatch.setattr("app.cutover_verify_cli.probe_vhost", lambda *a, **kw: Probe({"x": "1"}))
    monkeypatch.setattr(
        sys,
        "argv",
        ["cutover-verify", "--old", "a", "--new", "b", "--services-json", str(bad), "--host", "h.example.com"],
    )
    assert main() == 0
    assert "WARNING: catalog not used" in capsys.readouterr().err


def test_cli_exit_code_follows_differences(monkeypatch, tmp_path: Path, capsys) -> None:
    catalog = tmp_path / "services.json"
    catalog.write_text('{"services": [{"name": "s", "server_name": "app.example.com", "websocket": true}]}')
    seen: list[bool] = []
    answers = iter([Probe({"x": "1"}), Probe({"x": "1"}), Probe({"x": "1"}), Probe({"x": "2"})])

    def fake_probe(name, addr, **kw):
        seen.append(kw["websocket"])
        return next(answers)

    monkeypatch.setattr("app.cutover_verify_cli.probe_vhost", fake_probe)
    monkeypatch.setattr(sys, "argv", ["cutover-verify", "--old", "a", "--new", "b", "--services-json", str(catalog)])
    assert main() == 0
    assert seen == [True, True]  # websocket flag taken from the catalog
    monkeypatch.setattr(sys, "argv", ["cutover-verify", "--old", "a", "--new", "b", "--services-json", str(catalog)])
    answers = iter([Probe({"x": "1"}), Probe({"x": "2"})])
    assert main() == 1
    assert "DIFF v4 app.example.com" in capsys.readouterr().out
