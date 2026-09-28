"""scripts/client-pki's device workflow and host guard (#159).

Runs the real wrapper against a throwaway store: `enroll` issues a device's
first certificate and exports a PKCS#12 bundle, `rotate` issues a replacement
while the current one stays valid, and every verb that isn't read-only
refuses to run off the designated host.
"""

import json
import os
import subprocess
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.serialization import pkcs12

REPO = Path(__file__).resolve().parents[2]
CLIENT_PKI = REPO / "scripts" / "client-pki"
PASSWORD = "a-long-enough-bundle-password"


def test_enroll_exports_a_bundle_the_password_opens(tmp_path: Path) -> None:
    store = _init_store(tmp_path)
    result = _client_pki(tmp_path, store, "enroll", "alice-phone", "--password-file", str(_password(tmp_path)))
    _ok(result)
    (serial,) = _active_serials(tmp_path, store, "alice-phone")
    (bundle,) = (store / "bundles").glob("*.p12")
    assert bundle.stat().st_mode & 0o777 == 0o600
    _key, cert, _extra = pkcs12.load_key_and_certificates(bundle.read_bytes(), PASSWORD.encode())
    assert cert is not None and cert.serial_number == int(serial, 16)


def test_enroll_refuses_a_device_that_already_has_a_certificate(tmp_path: Path) -> None:
    store = _init_store(tmp_path)
    password = _password(tmp_path)
    _ok(_client_pki(tmp_path, store, "enroll", "alice-phone", "--password-file", str(password)))
    before = _active_serials(tmp_path, store, "alice-phone")
    result = _client_pki(tmp_path, store, "enroll", "alice-phone", "--password-file", str(password))
    assert result.returncode == 1
    assert "client-pki rotate alice-phone" in result.stderr
    assert _active_serials(tmp_path, store, "alice-phone") == before, "a second enroll must not revoke the first"


def test_enroll_refuses_a_loose_password_file(tmp_path: Path) -> None:
    store = _init_store(tmp_path)
    password = _password(tmp_path)
    password.chmod(0o644)
    result = _client_pki(tmp_path, store, "enroll", "alice-phone", "--password-file", str(password))
    assert result.returncode == 1
    assert "readable by group/other" in result.stderr
    assert _active_serials(tmp_path, store, "alice-phone") == []


def test_legacy_bundle_uses_3des_for_older_devices(tmp_path: Path) -> None:
    store = _init_store(tmp_path)
    _ok(_client_pki(tmp_path, store, "enroll", "alice-phone", "--password-file", str(_password(tmp_path)), "--legacy"))
    (bundle,) = (store / "bundles").glob("*.p12")
    info = subprocess.run(
        ["openssl", "pkcs12", "-in", str(bundle), "-passin", f"pass:{PASSWORD}", "-noout", "-info"],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert "TripleDES" in info.stderr + info.stdout


@pytest.mark.parametrize(
    "args",
    [
        ["backup", "--out", "b.gpg", "--passphrase-file", "p"],
        ["enroll", "alice-phone", "--password-file", "p"],
        ["init", "--cn", "x"],
        ["revoke", "alice-phone"],
        ["rotate", "alice-phone", "--password-file", "p"],
        [],
    ],
)
def test_non_read_only_verbs_refuse_off_the_designated_host(tmp_path: Path, args: list[str]) -> None:
    result = _client_pki(tmp_path, tmp_path / "pki", *args, guard=True)
    assert result.returncode == 1
    assert "no designated host" in result.stderr
    assert not (tmp_path / "pki").exists()


@pytest.mark.parametrize("args", [["check", "--quiet"], ["list", "clients"], ["show", "ca"], ["--version"]])
def test_read_only_verbs_run_off_the_designated_host(tmp_path: Path, args: list[str]) -> None:
    result = _client_pki(tmp_path, tmp_path / "pki", *args, guard=True)
    assert "no designated host" not in result.stderr


def test_rotate_keeps_the_current_certificate_until_it_is_revoked(tmp_path: Path) -> None:
    store = _init_store(tmp_path)
    password = _password(tmp_path)
    _ok(_client_pki(tmp_path, store, "enroll", "alice-phone", "--password-file", str(password)))
    (old,) = _active_serials(tmp_path, store, "alice-phone")

    result = _client_pki(tmp_path, store, "rotate", "alice-phone", "--password-file", str(password))
    _ok(result)
    active = _active_serials(tmp_path, store, "alice-phone")
    assert old in active and len(active) == 2
    (new,) = [serial for serial in active if serial != old]
    assert f"./scripts/client-pki revoke 0x{old}" in result.stdout
    newest = max((store / "bundles").glob("*.p12"), key=lambda p: p.stat().st_mtime_ns)
    _key, cert, _extra = pkcs12.load_key_and_certificates(newest.read_bytes(), PASSWORD.encode())
    assert cert is not None and cert.serial_number == int(new, 16)

    _ok(_client_pki(tmp_path, store, "revoke", f"0x{old}"))
    assert _active_serials(tmp_path, store, "alice-phone") == [new]


def test_rotate_refuses_a_device_that_was_never_enrolled(tmp_path: Path) -> None:
    store = _init_store(tmp_path)
    result = _client_pki(tmp_path, store, "rotate", "bob-laptop", "--password-file", str(_password(tmp_path)))
    assert result.returncode == 1
    assert "client-pki enroll bob-laptop" in result.stderr


def _active_serials(tmp_path: Path, store: Path, cn: str) -> list[str]:
    result = _client_pki(tmp_path, store, "list", "clients", "--json")
    _ok(result)
    entries = json.loads(result.stdout)
    entries = entries if isinstance(entries, list) else [entries]
    return sorted(e["serial"] for e in entries if e["cn"] == cn and e["status"] == "active")


def _client_pki(tmp_path: Path, store: Path, *args: str, guard: bool = False) -> subprocess.CompletedProcess[str]:
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    env = {**os.environ, "HOME": str(home), "HOME_WARDEN_PKI_STORE": str(store)}
    env.pop("HOME_WARDEN_SKIP_HOST_GUARD", None)
    if not guard:
        env["HOME_WARDEN_SKIP_HOST_GUARD"] = "1"
    return subprocess.run([str(CLIENT_PKI), *args], capture_output=True, cwd=tmp_path, env=env, text=True, timeout=120)


def _init_store(tmp_path: Path) -> Path:
    store = tmp_path / "pki"
    _ok(_client_pki(tmp_path, store, "init", "--cn", "device test CA", "--key-size", "2048"))
    return store


def _ok(result: subprocess.CompletedProcess[str]) -> None:
    assert result.returncode == 0, result.stdout + result.stderr


def _password(tmp_path: Path) -> Path:
    path = tmp_path / "bundle-password"
    path.write_text(PASSWORD + "\n")
    path.chmod(0o600)
    return path
