"""End-to-end mTLS against a real nginx with a tiny-pki store (#49).

Drives the tiny-pki CLI the way an operator would (init, create, revoke),
points a throwaway unprivileged nginx at the store's CA certificate and CRL,
and checks the lifecycle home-warden's client-cert CA has to support:

- a client certificate is accepted, then rejected once it is revoked and
  nginx reloads;
- a vhost rendered from the catalog with `client_cert.allow_cn` admits only
  the listed CN, including against a CN that embeds DN syntax
  (`bob,CN=alice`), which tiny-pki issues and nginx prints as
  `...,CN=bob\\,CN=alice`.

Skipped when nginx isn't installed, unless HOME_WARDEN_REQUIRE_NGINX=1
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
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path

import pytest

from app.catalog_render import RenderContext, render_catalog

NGINX = shutil.which("nginx") or ("/usr/sbin/nginx" if Path("/usr/sbin/nginx").is_file() else None)
REQUIRE_NGINX = os.environ.get("HOME_WARDEN_REQUIRE_NGINX") == "1"

pytestmark = pytest.mark.skipif(
    NGINX is None and not REQUIRE_NGINX,
    reason="nginx not on PATH -- install nginx to run the mTLS end-to-end tests",
)


def test_catalog_allow_cn_admits_only_listed_client(tmp_path: Path) -> None:
    store = _init_store(tmp_path)
    for cn in ("alice", "bob", "bob,CN=alice"):
        _tiny_pki(store, "create", "client", cn, "--key-size", "2048")
    clients = {entry["cn"]: entry for entry in _entries(store, "clients")}
    server = _entries(store, "servers")[0]

    live = tmp_path / "live" / "localhost"
    live.mkdir(parents=True)
    shutil.copyfile(server["cert_path"], live / "fullchain.pem")
    shutil.copyfile(server["key_path"], live / "privkey.pem")
    root = tmp_path / "www"
    root.mkdir()
    (root / "index.html").write_text("ok\n")
    catalog = {
        "services": [
            {
                "name": "mtls",
                "kind": "static",
                "server_name": "localhost",
                "static": {"root": str(root)},
                "client_cert": {
                    "mode": "required",
                    "ca_bundle": str(store / "ca" / "ca.crt"),
                    "crl": str(store / "ca" / "crl.pem"),
                    "allow_cn": ["alice"],
                },
            }
        ]
    }
    http_body = render_catalog(catalog, RenderContext(certs_live_dir=tmp_path / "live"))

    with _nginx(tmp_path, http_body) as port:
        ca_cert = store / "ca" / "ca.crt"
        assert _get(port, ca_cert, clients["alice"]) == 200
        assert _get(port, ca_cert, clients["bob"]) == 403
        assert _get(port, ca_cert, clients["bob,CN=alice"]) == 403


def test_client_certificate_accepted_then_rejected_after_revoke(tmp_path: Path) -> None:
    store = _init_store(tmp_path)
    _tiny_pki(store, "create", "client", "alice", "--key-size", "2048")
    server = _entries(store, "servers")[0]
    alice = _entries(store, "clients")[0]
    ca_cert = store / "ca" / "ca.crt"
    crl = store / "ca" / "crl.pem"
    assert crl.is_file(), "tiny-pki init should publish an (empty) CRL for nginx's ssl_crl"

    http_body = f"""
http {{
    server {{
        listen 443 ssl;
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
    with _nginx(tmp_path, http_body) as port:
        assert _get(port, ca_cert, alice) == 200
        assert _get(port, ca_cert, None) == 400

        _tiny_pki(store, "revoke", "alice")
        _nginx_signal(tmp_path, "reload")
        assert _eventually(lambda: _get(port, ca_cert, alice) == 400), "revoked client still accepted after reload"
        assert "certificate revoked" in (tmp_path / "nginx" / "error.log").read_text()


def _entries(store: Path, category: str) -> list[dict]:
    listed = json.loads(_tiny_pki(store, "list", category, "--json"))
    return listed if isinstance(listed, list) else [listed]


def _eventually(predicate: Callable[[], bool], timeout: float = 10.0) -> bool:
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


def _init_store(tmp_path: Path) -> Path:
    store = tmp_path / "pki"
    _tiny_pki(store, "init", "--cn", "home-warden test CA", "--key-size", "2048")
    _tiny_pki(store, "create", "server", "localhost", "--san", "localhost", "--san", "127.0.0.1", "--key-size", "2048")
    return store


@contextmanager
def _nginx(tmp_path: Path, http_body: str) -> Iterator[int]:
    """Run nginx unprivileged on a free loopback port, serving `http_body`
    (an `http {}` block whose `listen 443` lines are moved to that port)."""
    assert NGINX is not None, "HOME_WARDEN_REQUIRE_NGINX=1 but nginx is not installed"
    port = _free_port()
    prefix = tmp_path / "nginx"
    prefix.mkdir()
    body = http_body.replace("listen 443 ssl", f"listen 127.0.0.1:{port} ssl").replace(
        "http {", "http {\n    access_log off;", 1
    )
    (prefix / "nginx.conf").write_text(
        f"worker_processes 1;\npid {prefix}/nginx.pid;\nerror_log {prefix}/error.log info;\nevents {{}}\n{body}\n"
    )
    process = subprocess.Popen(
        [*_nginx_args(tmp_path), "-g", "daemon off;"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    try:
        _wait_for_port(port, process)
        yield port
    finally:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=10)


def _nginx_args(tmp_path: Path) -> list[str]:
    assert NGINX is not None
    prefix = tmp_path / "nginx"
    return [NGINX, "-p", f"{prefix}/", "-e", str(prefix / "error.log"), "-c", str(prefix / "nginx.conf")]


def _nginx_signal(tmp_path: Path, signal: str) -> None:
    subprocess.run([*_nginx_args(tmp_path), "-s", signal], check=True, timeout=10)


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


def _wait_for_port(port: int, process: subprocess.Popen) -> None:
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if process.poll() is not None:
            stderr = process.stderr.read().decode() if process.stderr else ""
            pytest.fail(f"nginx exited with {process.returncode}:\n{stderr}")
        with socket.socket() as sock:
            sock.settimeout(0.5)
            if sock.connect_ex(("127.0.0.1", port)) == 0:
                return
        time.sleep(0.1)
    pytest.fail(f"nginx did not listen on 127.0.0.1:{port}")
