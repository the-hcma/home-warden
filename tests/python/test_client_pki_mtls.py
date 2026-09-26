"""End-to-end mTLS against a real nginx with a tiny-pki store (#49).

Drives the tiny-pki CLI the way an operator would (init, create, revoke),
points a throwaway unprivileged nginx at the store's CA certificate and CRL,
and checks that a client certificate is accepted, then rejected once it is
revoked and nginx reloads -- the lifecycle home-warden's client-cert CA has to
support. Skipped when nginx isn't installed, unless HOME_WARDEN_REQUIRE_NGINX=1
(CI's nginx job), where a missing nginx fails instead.
"""

import http.client
import json
import os
import shutil
import socket
import ssl
import subprocess
import sys
import time
from pathlib import Path

import pytest

NGINX = shutil.which("nginx") or ("/usr/sbin/nginx" if Path("/usr/sbin/nginx").is_file() else None)
REQUIRE_NGINX = os.environ.get("HOME_WARDEN_REQUIRE_NGINX") == "1"

pytestmark = pytest.mark.skipif(
    NGINX is None and not REQUIRE_NGINX,
    reason="nginx not on PATH -- install nginx to run the mTLS end-to-end test",
)


def test_client_certificate_accepted_then_rejected_after_revoke(tmp_path: Path) -> None:
    assert NGINX is not None, "HOME_WARDEN_REQUIRE_NGINX=1 but nginx is not installed"
    store = tmp_path / "pki"
    _tiny_pki(store, "init", "--cn", "home-warden test CA", "--key-size", "2048")
    _tiny_pki(store, "create", "server", "localhost", "--san", "localhost", "--san", "127.0.0.1", "--key-size", "2048")
    _tiny_pki(store, "create", "client", "alice", "--key-size", "2048")
    server = _only_entry(store, "servers")
    alice = _only_entry(store, "clients")
    ca_cert = store / "ca" / "ca.crt"
    crl = store / "ca" / "crl.pem"
    assert crl.is_file(), "tiny-pki init should publish an (empty) CRL for nginx's ssl_crl"

    port = _free_port()
    prefix = tmp_path / "nginx"
    conf = _write_nginx_conf(prefix, port, server=server, ca_cert=ca_cert, crl=crl)
    nginx = subprocess.Popen(
        [NGINX, "-p", f"{prefix}/", "-e", str(prefix / "error.log"), "-c", str(conf), "-g", "daemon off;"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    try:
        _wait_for_port(port, nginx)
        assert _get(port, ca_cert, alice) == 200
        assert _get(port, ca_cert, None) == 400

        _tiny_pki(store, "revoke", "alice")
        subprocess.run(
            [NGINX, "-p", f"{prefix}/", "-e", str(prefix / "error.log"), "-c", str(conf), "-s", "reload"],
            check=True,
            timeout=10,
        )
        assert _eventually(lambda: _get(port, ca_cert, alice) == 400), "revoked client still accepted after reload"
        assert "certificate revoked" in (prefix / "error.log").read_text()
    finally:
        nginx.terminate()
        try:
            nginx.wait(timeout=10)
        except subprocess.TimeoutExpired:
            nginx.kill()
            nginx.wait(timeout=10)


def _eventually(predicate, timeout: float = 10.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.2)
    return False


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _get(port: int, ca_cert: Path, client: dict | None) -> int:
    context = ssl.create_default_context(cafile=str(ca_cert))
    if client is not None:
        context.load_cert_chain(client["cert_path"], client["key_path"])
    conn = http.client.HTTPSConnection("localhost", port, context=context, timeout=5)
    try:
        conn.request("GET", "/")
        return conn.getresponse().status
    finally:
        conn.close()


def _only_entry(store: Path, category: str) -> dict:
    listed = json.loads(_tiny_pki(store, "list", category, "--json"))
    entries = listed if isinstance(listed, list) else [listed]
    assert len(entries) == 1, entries
    return entries[0]


def _tiny_pki(store: Path, *args: str) -> str:
    tiny_pki = Path(sys.executable).with_name("tiny-pki")
    result = subprocess.run(
        [str(tiny_pki), "--store", str(store), "--color", "never", *args],
        capture_output=True,
        check=False,
        stdin=subprocess.DEVNULL,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, f"tiny-pki {' '.join(args)} failed:\n{result.stdout}\n{result.stderr}"
    return result.stdout


def _wait_for_port(port: int, nginx: subprocess.Popen) -> None:
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if nginx.poll() is not None:
            stderr = nginx.stderr.read().decode() if nginx.stderr else ""
            pytest.fail(f"nginx exited with {nginx.returncode}:\n{stderr}")
        with socket.socket() as sock:
            sock.settimeout(0.5)
            if sock.connect_ex(("127.0.0.1", port)) == 0:
                return
        time.sleep(0.1)
    pytest.fail(f"nginx did not listen on 127.0.0.1:{port}")


def _write_nginx_conf(prefix: Path, port: int, *, server: dict, ca_cert: Path, crl: Path) -> Path:
    prefix.mkdir()
    conf = prefix / "nginx.conf"
    conf.write_text(
        f"""
worker_processes 1;
pid {prefix}/nginx.pid;
error_log {prefix}/error.log info;
events {{}}
http {{
    access_log off;
    server {{
        listen 127.0.0.1:{port} ssl;
        server_name localhost;
        ssl_certificate {server["cert_path"]};
        ssl_certificate_key {server["key_path"]};
        ssl_client_certificate {ca_cert};
        ssl_crl {crl};
        ssl_verify_client on;
        location / {{
            return 200 "ok\\n";
        }}
    }}
}}
"""
    )
    return conf
