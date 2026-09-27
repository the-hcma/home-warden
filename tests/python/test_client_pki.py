"""home-warden's client-cert CA on tiny-pki (#49), exercised the way an operator would.

Store-level tests drive the tiny-pki CLI (and its public Python API) against a
throwaway store and check the behavior home-warden relies on: a key-free
`public/` directory for nginx, locking between writers, a persisted CRL
lifetime, strict flags, and CN validation.

End-to-end tests point a throwaway unprivileged nginx at the store's
`public/ca.crt` and `public/crl.pem` and check the client lifecycle:

- a client certificate is accepted, then rejected once it is revoked and
  nginx reloads;
- a rotated client keeps working on both certificates until the old serial is
  revoked;
- a vhost rendered from the catalog with `client_cert.allow_cn` admits only
  the listed CN, including against a CN that embeds DN syntax
  (`bob,CN=alice`, issued with tiny-pki's explicit opt-out), which nginx
  prints as `...,CN=bob\\,CN=alice`.

The end-to-end tests skip when nginx isn't installed, unless
HOME_WARDEN_REQUIRE_NGINX=1 (CI's nginx job), where a missing nginx fails.
"""

import datetime
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
from cryptography import x509
from tiny_pki.store import CertificateStore

from app.catalog_render import RenderContext, render_catalog

NGINX = shutil.which("nginx") or ("/usr/sbin/nginx" if Path("/usr/sbin/nginx").is_file() else None)
REQUIRE_NGINX = os.environ.get("HOME_WARDEN_REQUIRE_NGINX") == "1"

requires_nginx = pytest.mark.skipif(
    NGINX is None and not REQUIRE_NGINX,
    reason="nginx not on PATH -- install nginx to run the mTLS end-to-end tests",
)


@requires_nginx
def test_catalog_allow_cn_admits_only_listed_client(tmp_path: Path) -> None:
    store = _init_store(tmp_path)
    _tiny_pki(store, "create", "client", "alice", "--key-size", "2048")
    _tiny_pki(store, "create", "client", "bob", "--key-size", "2048")
    _tiny_pki(store, "create", "client", "bob,CN=alice", "--key-size", "2048", "--allow-dn-special-chars")
    clients = {entry["cn"]: entry for entry in _entries(store, "clients")}
    ca_cert, crl = _public_files(store)
    catalog = {
        "services": [
            {
                "name": "mtls",
                "kind": "static",
                "server_name": "localhost",
                "static": {"root": str(_web_root(tmp_path))},
                "client_cert": {
                    "mode": "required",
                    "ca_bundle": str(ca_cert),
                    "crl": str(crl),
                    "allow_cn": ["alice"],
                },
            }
        ]
    }
    http_body = render_catalog(catalog, RenderContext(certs_live_dir=_live_dir(tmp_path, store), listen_ipv6=False))

    with _nginx(tmp_path, http_body) as port:
        assert _get(port, ca_cert, clients["alice"]) == 200
        assert _get(port, ca_cert, clients["bob"]) == 403
        assert _get(port, ca_cert, clients["bob,CN=alice"]) == 403


@requires_nginx
def test_client_certificate_accepted_then_rejected_after_revoke(tmp_path: Path) -> None:
    store = _init_store(tmp_path)
    _tiny_pki(store, "create", "client", "alice", "--key-size", "2048")
    alice = _entries(store, "clients")[0]
    ca_cert, crl = _public_files(store)
    assert crl.is_file(), "tiny-pki init should publish an (empty) CRL for nginx's ssl_crl"

    with _nginx(tmp_path, _verify_client_http(store)) as port:
        assert _get(port, ca_cert, alice) == 200
        assert _get(port, ca_cert, None) == 400

        _tiny_pki(store, "revoke", "alice")
        _nginx_signal(tmp_path, "reload")
        assert _eventually(lambda: _get(port, ca_cert, alice) == 400), "revoked client still accepted after reload"
        assert "certificate revoked" in (tmp_path / "nginx" / "error.log").read_text()


def test_concurrent_crl_refresh_never_drops_a_revocation(tmp_path: Path) -> None:
    store = _init_store(tmp_path)
    names = [f"device{i}" for i in range(6)]
    for name in names:
        _tiny_pki(store, "create", "client", name, "--key-size", "2048")
    serials = {entry["cn"]: int(entry["serial"], 16) for entry in _entries(store, "clients")}

    writers = [_tiny_pki_popen(store, "revoke", name) for name in names]
    writers += [_tiny_pki_popen(store, "crl") for _ in names]
    for writer in writers:
        _, stderr = writer.communicate(timeout=120)
        assert writer.returncode == 0, stderr

    for crl_path in (store / "ca" / "crl.pem", store / "public" / "crl.pem"):
        crl = x509.load_pem_x509_crl(crl_path.read_bytes())
        missing = [name for name in names if crl.get_revoked_certificate_by_serial_number(serials[name]) is None]
        assert missing == [], f"{crl_path} dropped revocations for {missing}"


def test_crl_lifetime_persists_across_republish(tmp_path: Path) -> None:
    store = _init_store(tmp_path)
    _tiny_pki(store, "create", "client", "alice", "--key-size", "2048")
    _tiny_pki(store, "crl", "--days", "7")
    _tiny_pki(store, "revoke", "alice")

    crl = x509.load_pem_x509_crl(_public_files(store)[1].read_bytes())
    assert crl.next_update_utc is not None
    # lastUpdate is backdated for clock skew, so measure nextUpdate against now.
    remaining = crl.next_update_utc - datetime.datetime.now(datetime.timezone.utc)
    assert datetime.timedelta(days=7) - datetime.timedelta(minutes=5) < remaining <= datetime.timedelta(days=7)


def test_dn_syntax_in_a_client_cn_is_refused_by_default(tmp_path: Path) -> None:
    store = _init_store(tmp_path)
    result = _tiny_pki_run(store, "create", "client", "bob,CN=alice", "--key-size", "2048")
    assert result.returncode != 0
    assert _entries(store, "clients") == []


def test_library_revoke_republishes_the_public_crl(tmp_path: Path) -> None:
    store = _init_store(tmp_path)
    _tiny_pki(store, "create", "client", "alice", "--key-size", "2048")
    serial = int(_entries(store, "clients")[0]["serial"], 16)

    CertificateStore(store).revoke("alice")

    crl = x509.load_pem_x509_crl(_public_files(store)[1].read_bytes())
    assert crl.get_revoked_certificate_by_serial_number(serial) is not None


def test_public_directory_holds_only_the_ca_certificate_and_crl(tmp_path: Path) -> None:
    store = _init_store(tmp_path)
    public = store / "public"
    assert sorted(p.name for p in public.iterdir()) == ["ca.crt", "crl.pem"]
    assert public.stat().st_mode & 0o777 == 0o755
    assert all(p.stat().st_mode & 0o777 == 0o644 for p in public.iterdir())
    assert (store / "ca").stat().st_mode & 0o777 == 0o700
    assert (store / "public" / "ca.crt").read_bytes() == (store / "ca" / "ca.crt").read_bytes()


def test_revoke_dry_run_and_unknown_flags_leave_the_certificate_live(tmp_path: Path) -> None:
    store = _init_store(tmp_path)
    _tiny_pki(store, "create", "client", "alice", "--key-size", "2048")

    _tiny_pki(store, "revoke", "alice", "--dry-run")
    assert _tiny_pki_run(store, "revoke", "alice", "--bogus").returncode != 0

    assert [entry["status"] for entry in _entries(store, "clients")] == ["active"]


@requires_nginx
def test_rotated_client_keeps_access_until_the_old_serial_is_revoked(tmp_path: Path) -> None:
    store = _init_store(tmp_path)
    _tiny_pki(store, "create", "client", "alice", "--key-size", "2048")
    _tiny_pki(store, "create", "client", "alice", "--key-size", "2048", "--keep-previous")
    entries = _entries(store, "clients")
    old = next(entry for entry in entries if entry["superseded_by"])
    new = next(entry for entry in entries if entry["serial"] == old["superseded_by"])
    ca_cert, _ = _public_files(store)

    with _nginx(tmp_path, _verify_client_http(store)) as port:
        assert _get(port, ca_cert, old) == 200
        assert _get(port, ca_cert, new) == 200

        _tiny_pki(store, "revoke", f"0x{old['serial']}")
        _nginx_signal(tmp_path, "reload")
        assert _eventually(lambda: _get(port, ca_cert, old) == 400), "superseded cert still accepted after revoke"
        assert _get(port, ca_cert, new) == 200


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


def _live_dir(tmp_path: Path, store: Path) -> Path:
    server = _entries(store, "servers")[0]
    live = tmp_path / "live"
    (live / "localhost").mkdir(parents=True)
    shutil.copyfile(server["cert_path"], live / "localhost" / "fullchain.pem")
    shutil.copyfile(server["key_path"], live / "localhost" / "privkey.pem")
    return live


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


def _public_files(store: Path) -> tuple[Path, Path]:
    """The key-free copies nginx reads: `public/ca.crt` and `public/crl.pem`."""
    return store / "public" / "ca.crt", store / "public" / "crl.pem"


def _tiny_pki(store: Path, *args: str) -> str:
    result = _tiny_pki_run(store, *args)
    assert result.returncode == 0, f"tiny-pki {' '.join(args)} failed:\n{result.stdout}\n{result.stderr}"
    return result.stdout


def _tiny_pki_argv(store: Path, *args: str) -> list[str]:
    return [str(Path(sys.executable).with_name("tiny-pki")), "--store", str(store), "--color", "never", *args]


def _tiny_pki_popen(store: Path, *args: str) -> subprocess.Popen[str]:
    return subprocess.Popen(
        _tiny_pki_argv(store, *args),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
    )


def _tiny_pki_run(store: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        _tiny_pki_argv(store, *args),
        capture_output=True,
        check=False,
        stdin=subprocess.DEVNULL,
        text=True,
        timeout=60,
    )


def _verify_client_http(store: Path) -> str:
    server = _entries(store, "servers")[0]
    ca_cert, crl = _public_files(store)
    return f"""
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


def _web_root(tmp_path: Path) -> Path:
    root = tmp_path / "www"
    root.mkdir()
    (root / "index.html").write_text("ok\n")
    return root
