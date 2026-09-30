"""Tests for app.cutover_preflight and its CLI (#187). Every subprocess and connect is stubbed."""

from __future__ import annotations

import datetime
import subprocess
import sys
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from app.cutover_preflight import Context, _upstream_hostport, parse_conf, run_preflight
from app.cutover_preflight_cli import main

NOW = datetime.datetime(2026, 9, 30, tzinfo=datetime.timezone.utc)

CONF = """
# comment with proxy_pass http://ignored:1;
server {
  listen 443 ssl;
  listen [::]:443 ssl;
  server_name app.example.com www.example.com _;
  ssl_certificate {cert};
  ssl_certificate_key {key};
  location / { proxy_pass http://127.0.0.1:8001; }
  location /v { proxy_pass http://$upstream; }
  location /s { proxy_pass http://unix:/run/x.sock; }
}
"""


def _cert(path: Path, days: int) -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "app.example.com")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(NOW - datetime.timedelta(days=1))
        .not_valid_after(NOW + datetime.timedelta(days=days))
        .sign(key, hashes.SHA256())
    )
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def _proc(rc: int = 0, out: str = "", err: str = "") -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess([], rc, out, err)


@pytest.fixture
def ctx(tmp_path: Path) -> Context:
    cert, key = tmp_path / "fullchain.pem", tmp_path / "privkey.pem"
    _cert(cert, 90)
    key.write_text("k")
    key.chmod(0o640)
    conf = tmp_path / "nginx.conf"
    conf.write_text("x")
    dump = CONF.replace("{cert}", str(cert)).replace("{key}", str(key))
    domains = tmp_path / "certbot-domains"
    domains.write_text("app.example.com\nwww.example.com\n")
    cf, secret = tmp_path / "cloudflare.ini", tmp_path / "session-secret"
    for f in (cf, secret):
        f.write_text("x")
        f.chmod(0o600)
    pki = tmp_path / "pki"
    (pki / "ca").mkdir(parents=True)
    (pki / "ca").chmod(0o700)

    def run(cmd: list[str], timeout: float) -> subprocess.CompletedProcess[str]:
        if "-T" in cmd:
            return _proc(out=dump)
        if cmd[0] == "nginx":
            return _proc(err="nginx version: nginx/1.28.3")
        if cmd[0] == "systemctl":
            return _proc(out="systemd 259 (259-1)")
        if cmd[0] == "ss":
            return _proc(out="LISTEN 0 4096 0.0.0.0:22 0.0.0.0:*\n")
        return _proc()

    return Context(
        nginx_conf=conf,
        repo_dir=tmp_path,
        certbot_domains=domains,
        cloudflare_credentials=cf,
        session_secret=secret,
        pki_store=pki,
        run=run,
        connect=lambda host, port, timeout: True,
        which=lambda name: f"/usr/bin/{name}",
        now=lambda: NOW,
        use_sudo=False,
    )


def _by_name(results, name: str):
    return [r for r in results if r.name == name or r.name.startswith(name)]


def test_parse_conf_ignores_comments_and_wildcards() -> None:
    parsed = parse_conf(CONF.replace("{cert}", "/c").replace("{key}", "/k"))
    assert parsed["server_names"] == {"app.example.com", "www.example.com"}
    assert "http://ignored:1" not in parsed["proxy_pass"]
    assert "[::]:443 ssl" in parsed["listens"]


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("http://127.0.0.1:8001", ("127.0.0.1", 8001)),
        ("https://backend.example.internal/x", ("backend.example.internal", 443)),
        ("http://[::1]:9000/", ("::1", 9000)),
        ("http://$upstream", None),
        ("http://unix:/run/x.sock", None),
        ("backend", None),
    ],
)
def test_upstream_hostport(url: str, expected) -> None:
    assert _upstream_hostport(url) == expected


def test_healthy_host_has_no_failures(ctx: Context) -> None:
    results = run_preflight(ctx)
    assert [r for r in results if r.status == "fail"] == []
    assert _by_name(results, "upstream:127.0.0.1:8001")[0].status == "ok"
    assert _by_name(results, "ipv6")[0].status == "ok"
    assert _by_name(results, "domains")[0].status == "ok"


def test_unreachable_upstream_fails(ctx: Context) -> None:
    ctx.connect = lambda host, port, timeout: False
    assert _by_name(run_preflight(ctx), "upstream:127.0.0.1:8001")[0].status == "fail"


def test_expiring_cert_and_world_readable_key_fail(ctx: Context, tmp_path: Path) -> None:
    _cert(tmp_path / "fullchain.pem", 10)
    (tmp_path / "privkey.pem").chmod(0o644)
    results = run_preflight(ctx)
    assert _by_name(results, "cert:")[0].status == "fail"
    assert _by_name(results, "key:")[0].status == "fail"


def test_missing_tool_and_old_systemd_fail(ctx: Context) -> None:
    ctx.which = lambda name: None if name == "gpg" else f"/usr/bin/{name}"
    base_run = ctx.run
    ctx.run = lambda cmd, t: _proc(out="systemd 255") if cmd[0] == "systemctl" else base_run(cmd, t)
    results = run_preflight(ctx)
    assert _by_name(results, "tool:gpg")[0].status == "fail"
    assert _by_name(results, "systemd-version")[0].status == "fail"


def test_listener_on_443_is_only_a_warning(ctx: Context) -> None:
    base_run = ctx.run
    ctx.run = lambda cmd, t: _proc(out="LISTEN 0 511 0.0.0.0:443 0.0.0.0:*\n") if cmd[0] == "ss" else base_run(cmd, t)
    assert _by_name(run_preflight(ctx), "port:443")[0].status == "warn"


def test_domain_coverage_reports_gaps(ctx: Context) -> None:
    ctx.certbot_domains.write_text("app.example.com\nold.example.com\n")
    ctx.catalog = {"services": [{"name": "a", "server_name": "app.example.com"}, {"server_name": "new.example.com"}]}
    results = run_preflight(ctx)
    assert _by_name(results, "domain:www.example.com")[0].status == "warn"
    assert _by_name(results, "domain:old.example.com")[0].status == "warn"
    assert _by_name(results, "catalog:www.example.com")[0].status == "warn"
    assert _by_name(results, "catalog:new.example.com")[0].status == "fail"


def test_secret_modes_and_missing_files(ctx: Context) -> None:
    ctx.cloudflare_credentials.chmod(0o644)
    ctx.session_secret.unlink()
    (ctx.pki_store / "ca").chmod(0o755)
    by = {r.name: r for r in run_preflight(ctx)}
    assert by["cloudflare.ini"].status == "fail"
    assert by["session-secret"].status == "fail"
    assert by["pki-store"].status == "fail"


def test_no_pki_store_is_a_warning(ctx: Context) -> None:
    (ctx.pki_store / "ca").rmdir()
    assert _by_name(run_preflight(ctx), "pki-store")[0].status == "warn"


def test_nginx_t_failure_stops_conf_dependent_checks(ctx: Context) -> None:
    ctx.run = lambda cmd, t: _proc(rc=1, err="nginx: [emerg] bad\n") if "-T" in cmd else _proc()
    results = run_preflight(ctx)
    assert _by_name(results, "nginx -t")[0].status == "fail"
    assert not _by_name(results, "upstream")


def test_certbot_dry_run_failure_and_skip(ctx: Context) -> None:
    base_run = ctx.run
    ctx.run = lambda cmd, t: _proc(rc=1) if cmd[-1] == "--dry-run" else base_run(cmd, t)
    assert _by_name(run_preflight(ctx), "certbot-dry-run")[0].status == "fail"
    ctx.skip_certbot = True
    assert _by_name(run_preflight(ctx), "certbot-dry-run")[0].status == "warn"


def test_cli_exit_code(monkeypatch, tmp_path: Path, capsys) -> None:
    monkeypatch.setenv("HOME_NGINX_CONF", str(tmp_path / "missing.conf"))
    monkeypatch.setenv("SERVICES_JSON_PATH", str(tmp_path / "none.json"))
    monkeypatch.setattr(sys, "argv", ["cutover-preflight", "--skip-certbot-dry-run", "--no-sudo"])
    assert main() == 1
    assert "FAIL nginx-conf" in capsys.readouterr().out
