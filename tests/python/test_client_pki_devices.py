"""scripts/client-pki's device workflow and host guard (#159).

Runs the real wrapper against a throwaway store: `enroll` issues a device's
first certificate and exports a PKCS#12 bundle, or signs the device's own CSR
once the operator vouches for its fingerprint, `rotate` issues a replacement
while the current one stays valid, and every verb that isn't read-only
refuses to run off the designated host.
"""

import hashlib
import json
import os
import subprocess
import time
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID

REPO = Path(__file__).resolve().parents[2]
CLIENT_PKI = REPO / "scripts" / "client-pki"
PASSWORD = "a-long-enough-bundle-password"


def test_enroll_accepts_a_fingerprint_in_any_case_with_or_without_colons(tmp_path: Path) -> None:
    store = _init_store(tmp_path)
    csr, key = _device_csr(tmp_path, "bob-laptop")
    plain = _fingerprint(key).lower()
    spaced = " ".join(plain[i : i + 2] for i in range(0, len(plain), 2))
    _ok(_client_pki(tmp_path, store, "enroll", "bob-laptop", "--csr", str(csr), "--fingerprint", spaced))
    assert len(_active_serials(tmp_path, store, "bob-laptop")) == 1


def test_enroll_exports_a_bundle_the_password_opens(tmp_path: Path) -> None:
    store = _init_store(tmp_path)
    result = _client_pki(tmp_path, store, "enroll", "alice-phone", "--password-file", str(_password(tmp_path)))
    _ok(result)
    (serial,) = _active_serials(tmp_path, store, "alice-phone")
    (bundle,) = (store / "bundles").glob("*.p12")
    assert bundle.stat().st_mode & 0o777 == 0o600
    _key, cert, _extra = pkcs12.load_key_and_certificates(bundle.read_bytes(), PASSWORD.encode())
    assert cert is not None and cert.serial_number == int(serial, 16)


@pytest.mark.parametrize("confirmed", [True, False], ids=["signed", "refused"])
def test_enroll_from_a_csr_leaves_no_snapshot_behind(tmp_path: Path, confirmed: bool) -> None:
    store = _init_store(tmp_path)
    csr, key = _device_csr(tmp_path, "bob-laptop")
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    fingerprint = _fingerprint(key) if confirmed else "00" * 32
    result = _client_pki(
        tmp_path,
        store,
        "enroll",
        "bob-laptop",
        "--csr",
        str(csr),
        "--fingerprint",
        fingerprint,
        extra_env={"TMPDIR": str(scratch)},
    )
    assert result.returncode == (0 if confirmed else 1), result.stderr
    assert list(scratch.glob("client-pki-csr.*")) == []


@pytest.mark.parametrize(
    ("fingerprint", "message"),
    [
        ("00" * 32, "does not match --fingerprint"),
        (None, "confirm the CSR's public key with --fingerprint"),
    ],
    ids=["mismatch", "missing-without-terminal"],
)
def test_enroll_from_a_csr_needs_a_confirmed_fingerprint(tmp_path: Path, fingerprint: str | None, message: str) -> None:
    store = _init_store(tmp_path)
    csr, _key = _device_csr(tmp_path, "bob-laptop")
    extra = ["--fingerprint", fingerprint] if fingerprint else []
    result = _client_pki(tmp_path, store, "enroll", "bob-laptop", "--csr", str(csr), *extra)
    assert result.returncode == 1
    assert message in result.stderr
    assert _active_serials(tmp_path, store, "bob-laptop") == []


def test_enroll_from_a_csr_signs_the_device_key_and_stores_none(tmp_path: Path) -> None:
    store = _init_store(tmp_path)
    csr, key = _device_csr(tmp_path, "bob-laptop")
    out = tmp_path / "bob-laptop.crt"
    result = _client_pki(
        tmp_path,
        store,
        "enroll",
        "bob-laptop",
        "--csr",
        str(csr),
        "--fingerprint",
        _fingerprint(key),
        "--out",
        str(out),
    )
    _ok(result)
    assert "public key sha256" in result.stderr, "the operator must see the fingerprint being vouched for"
    assert "public/ca.crt" in result.stdout
    cert = x509.load_pem_x509_certificate(out.read_bytes())
    assert cert.public_key() == key.public_key()
    assert cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == "bob-laptop"
    (serial,) = _active_serials(tmp_path, store, "bob-laptop")
    assert cert.serial_number == int(serial, 16)
    assert list((store / "clients").glob("*.key")) == []
    assert list((store / "bundles").glob("*.p12")) == []


def test_enroll_refuses_a_csr_tiny_pki_would_not_sign(tmp_path: Path) -> None:
    store = _init_store(tmp_path)
    csr, key = _device_csr(tmp_path, "bob-laptop", key=rsa.generate_private_key(public_exponent=65537, key_size=1024))
    result = _client_pki(tmp_path, store, "enroll", "bob-laptop", "--csr", str(csr), "--fingerprint", _fingerprint(key))
    assert result.returncode == 1
    assert "tiny-pki refuses this CSR" in result.stderr
    assert "RSA key is 1024 bits" in result.stderr
    assert _active_serials(tmp_path, store, "bob-laptop") == []


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


def test_enroll_refuses_when_it_cannot_list_the_device(tmp_path: Path) -> None:
    store = _init_store(tmp_path)
    password = _password(tmp_path)
    _ok(_client_pki(tmp_path, store, "enroll", "alice-phone", "--password-file", str(password)))
    before = _active_serials(tmp_path, store, "alice-phone")
    broken = tmp_path / "broken-bin"
    broken.mkdir()
    (broken / "python3").write_text("#!/bin/sh\nexit 1\n")
    (broken / "python3").chmod(0o755)
    path = f"{broken}:{os.environ['PATH']}"
    result = _client_pki(tmp_path, store, "enroll", "alice-phone", "--password-file", str(password), path=path)
    assert result.returncode == 1
    assert "could not list alice-phone's certificates" in result.stderr
    assert _active_serials(tmp_path, store, "alice-phone") == before, "a failed listing must not revoke the device"


@pytest.mark.parametrize(
    "args",
    [
        ["--csr", "device.csr", "--password-file", "p"],
        ["--csr", "device.csr", "--legacy"],
        ["--password-file", "p", "--fingerprint", "AB"],
        ["--password-file", "p", "--out", "x.crt"],
        [],
    ],
    ids=["csr-and-password", "csr-and-legacy", "fingerprint-without-csr", "out-without-csr", "neither"],
)
def test_enroll_rejects_mixed_or_missing_delivery_flags(tmp_path: Path, args: list[str]) -> None:
    store = _init_store(tmp_path)
    (tmp_path / "device.csr").write_text("placeholder\n")
    result = _client_pki(tmp_path, store, "enroll", "bob-laptop", *args)
    assert result.returncode == 2
    assert "usage: client-pki enroll <cn>" in result.stderr


def test_enroll_waits_for_a_concurrent_enroll_and_gives_up(tmp_path: Path) -> None:
    store = _init_store(tmp_path)
    holder = subprocess.Popen(["flock", "--exclusive", str(store / "ca"), "sleep", "10"])
    try:
        time.sleep(0.5)
        result = _client_pki(
            tmp_path,
            store,
            "enroll",
            "alice-phone",
            "--password-file",
            str(_password(tmp_path)),
            extra_env={"CLIENT_PKI_LOCK_TIMEOUT_SEC": "1"},
        )
    finally:
        holder.kill()
        holder.wait()
    assert result.returncode == 1
    assert "another enroll or rotate is running" in result.stderr
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


def test_rotate_from_a_new_csr_keeps_the_current_certificate(tmp_path: Path) -> None:
    store = _init_store(tmp_path)
    first_csr, first_key = _device_csr(tmp_path, "bob-laptop")
    _ok(
        _client_pki(
            tmp_path, store, "enroll", "bob-laptop", "--csr", str(first_csr), "--fingerprint", _fingerprint(first_key)
        )
    )
    (old,) = _active_serials(tmp_path, store, "bob-laptop")

    csr, key = _device_csr(tmp_path, "bob-laptop-next")
    out = tmp_path / "next.crt"
    result = _client_pki(
        tmp_path,
        store,
        "rotate",
        "bob-laptop",
        "--csr",
        str(csr),
        "--fingerprint",
        _fingerprint(key),
        "--out",
        str(out),
    )
    _ok(result)
    active = _active_serials(tmp_path, store, "bob-laptop")
    assert old in active and len(active) == 2
    (new,) = [serial for serial in active if serial != old]
    cert = x509.load_pem_x509_certificate(out.read_bytes())
    assert cert.serial_number == int(new, 16) and cert.public_key() == key.public_key()
    assert f"./scripts/client-pki revoke 0x{old}" in result.stdout


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


def _client_pki(
    tmp_path: Path,
    store: Path,
    *args: str,
    guard: bool = False,
    path: str | None = None,
    extra_env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    env = {**os.environ, "HOME": str(home), "HOME_WARDEN_PKI_STORE": str(store)}
    if path is not None:
        env["PATH"] = path
    env.update(extra_env or {})
    env.pop("HOME_WARDEN_SKIP_HOST_GUARD", None)
    if not guard:
        env["HOME_WARDEN_SKIP_HOST_GUARD"] = "1"
    return subprocess.run(
        [str(CLIENT_PKI), *args],
        capture_output=True,
        cwd=tmp_path,
        env=env,
        stdin=subprocess.DEVNULL,
        text=True,
        timeout=120,
    )


def _device_csr(
    tmp_path: Path, name: str, *, key: ec.EllipticCurvePrivateKey | rsa.RSAPrivateKey | None = None
) -> tuple[Path, ec.EllipticCurvePrivateKey | rsa.RSAPrivateKey]:
    """A CSR as a device would make it; the key stays with the test, never in the store."""
    key = key or ec.generate_private_key(ec.SECP256R1())
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([])).sign(key, hashes.SHA256())
    path = tmp_path / f"{name}.csr"
    path.write_bytes(csr.public_bytes(serialization.Encoding.PEM))
    return path, key


def _fingerprint(key: ec.EllipticCurvePrivateKey | rsa.RSAPrivateKey) -> str:
    spki = key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return ":".join(f"{b:02X}" for b in hashlib.sha256(spki).digest())


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
