"""scripts/client-pki's store protection, encrypted backup, and restore (#158).

Runs the real wrapper against throwaway stores: the permission check that
refuses a store looser than tiny-pki's layout, and a `backup` / `restore`
round trip through `gpg --symmetric` that must keep previously issued
certificates, revocations, and the serial state intact. gpg runs with a
throwaway GNUPGHOME.
"""

import fcntl
import os
import shutil
import subprocess
from pathlib import Path

import pytest
from cryptography import x509

REPO = Path(__file__).resolve().parents[2]
CLIENT_PKI = REPO / "scripts" / "client-pki"

pytestmark = pytest.mark.skipif(shutil.which("gpg") is None, reason="gpg not installed")


def test_backup_refuses_a_dangling_symlink_as_output(tmp_path: Path) -> None:
    store = _init_store(tmp_path)
    target = tmp_path / "redirected.gpg"
    link = tmp_path / "b.gpg"
    link.symlink_to(target)
    result = _client_pki(tmp_path, store, "backup", "--out", str(link), "--passphrase-file", str(_passphrase(tmp_path)))
    assert result.returncode == 1
    assert "refusing to overwrite" in result.stderr
    assert not target.exists()


def test_backup_refuses_a_loose_passphrase_file(tmp_path: Path) -> None:
    store = _init_store(tmp_path)
    passphrase = _passphrase(tmp_path)
    passphrase.chmod(0o644)
    result = _client_pki(
        tmp_path, store, "backup", "--out", str(tmp_path / "b.gpg"), "--passphrase-file", str(passphrase)
    )
    assert result.returncode == 1
    assert "readable by group/other" in result.stderr
    assert not (tmp_path / "b.gpg").exists()


def test_backup_refuses_to_overwrite(tmp_path: Path) -> None:
    store = _init_store(tmp_path)
    out = tmp_path / "b.gpg"
    out.write_text("keep me")
    result = _client_pki(tmp_path, store, "backup", "--out", str(out), "--passphrase-file", str(_passphrase(tmp_path)))
    assert result.returncode == 1
    assert out.read_text() == "keep me"


def test_backup_restore_round_trip_keeps_certificates_revocations_and_serials(tmp_path: Path) -> None:
    store = _init_store(tmp_path)
    _ok(_client_pki(tmp_path, store, "create", "client", "alice", "--key-size", "2048"))
    _ok(_client_pki(tmp_path, store, "create", "client", "bob", "--key-size", "2048"))
    _ok(_client_pki(tmp_path, store, "revoke", "bob"))
    passphrase = _passphrase(tmp_path)
    backup = tmp_path / "b.gpg"
    _ok(_client_pki(tmp_path, store, "backup", "--out", str(backup), "--passphrase-file", str(passphrase)))
    assert backup.stat().st_mode & 0o777 == 0o600
    assert b"BEGIN" not in backup.read_bytes(), "backup must be encrypted, not a plain tar"

    restored = tmp_path / "restored"
    _ok(_client_pki(tmp_path, restored, "restore", "--in", str(backup), "--passphrase-file", str(passphrase)))

    assert _layout(restored) == _layout(store)
    alice_cert = next((restored / "clients").glob("alice-*.crt"))
    verify = subprocess.run(
        ["openssl", "verify", "-CAfile", str(restored / "public" / "ca.crt"), str(alice_cert)],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert verify.returncode == 0, verify.stderr
    bob_serial = x509.load_pem_x509_certificate(next((store / "clients").glob("bob-*.crt")).read_bytes()).serial_number
    crl = x509.load_pem_x509_crl((restored / "public" / "crl.pem").read_bytes())
    assert crl.get_revoked_certificate_by_serial_number(bob_serial) is not None

    _ok(_client_pki(tmp_path, restored, "create", "client", "carol", "--key-size", "2048"))
    serials = [
        x509.load_pem_x509_certificate(p.read_bytes()).serial_number for p in (restored / "clients").glob("*.crt")
    ]
    assert len(serials) == len(set(serials)) == 3


def test_backup_waits_for_the_store_lock_and_gives_up(tmp_path: Path) -> None:
    store = _init_store(tmp_path)
    out = tmp_path / "b.gpg"
    with open(store / "ca" / ".lock", "a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        result = _client_pki(
            tmp_path,
            store,
            "backup",
            "--out",
            str(out),
            "--passphrase-file",
            str(_passphrase(tmp_path)),
            extra_env={"CLIENT_PKI_LOCK_TIMEOUT_SEC": "1"},
        )
    assert result.returncode == 1
    assert not out.exists()


def test_permission_check_accepts_tiny_pkis_own_layout(tmp_path: Path) -> None:
    store = _init_store(tmp_path)
    _ok(_client_pki(tmp_path, store, "create", "client", "alice", "--key-size", "2048"))
    _ok(_client_pki(tmp_path, store, "list", "clients"))


@pytest.mark.parametrize(
    ("relative", "mode", "reason"),
    [
        ("ca/ca.key", 0o644, "accessible by group/other"),
        ("clients", 0o755, "accessible by group/other"),
        ("public", 0o700, "not readable by nginx"),
        ("public/ca.crt", 0o600, "not readable by nginx"),
        ("public/crl.pem", 0o664, "writable by group/other"),
        (".", 0o750, "accessible by group/other"),
    ],
)
def test_permission_check_refuses_a_loosened_store(tmp_path: Path, relative: str, mode: int, reason: str) -> None:
    store = _init_store(tmp_path)
    (store / relative).chmod(mode)
    result = _client_pki(tmp_path, store, "list")
    assert result.returncode == 1
    assert reason in result.stderr
    assert str(store / relative).rstrip("/.") in result.stderr


def test_permission_check_refuses_a_symlink_inside_the_store(tmp_path: Path) -> None:
    store = _init_store(tmp_path)
    key = store / "ca" / "ca.key"
    moved = tmp_path / "elsewhere.key"
    key.rename(moved)
    key.symlink_to(moved)
    result = _client_pki(tmp_path, store, "list")
    assert result.returncode == 1
    assert f"not a regular file or directory: {key}" in result.stderr


def test_permission_check_refuses_a_symlinked_store(tmp_path: Path) -> None:
    store = _init_store(tmp_path)
    link = tmp_path / "pki-link"
    link.symlink_to(store)
    result = _client_pki(tmp_path, link, "list")
    assert result.returncode == 1
    assert "is a symlink" in result.stderr


def test_restore_into_an_existing_empty_directory(tmp_path: Path) -> None:
    store = _init_store(tmp_path)
    passphrase = _passphrase(tmp_path)
    backup = tmp_path / "b.gpg"
    _ok(_client_pki(tmp_path, store, "backup", "--out", str(backup), "--passphrase-file", str(passphrase)))
    target = tmp_path / "target"
    target.mkdir(mode=0o700)
    _ok(_client_pki(tmp_path, target, "restore", "--in", str(backup), "--passphrase-file", str(passphrase)))
    assert _layout(target) == _layout(store)
    assert not list(tmp_path.glob(".client-pki-restore.*"))


def test_restore_refuses_a_ca_key_that_does_not_match(tmp_path: Path) -> None:
    store = _init_store(tmp_path)
    other = tmp_path / "other"
    other.mkdir()
    other_store = _init_store(other)
    (store / "ca" / "ca.key").write_bytes((other_store / "ca" / "ca.key").read_bytes())
    passphrase = _passphrase(tmp_path)
    backup = tmp_path / "b.gpg"
    _ok(_client_pki(tmp_path, store, "backup", "--out", str(backup), "--passphrase-file", str(passphrase)))
    target = tmp_path / "target"
    result = _client_pki(tmp_path, target, "restore", "--in", str(backup), "--passphrase-file", str(passphrase))
    assert result.returncode == 1
    assert "does not hold a usable CA" in result.stderr
    assert not target.exists()
    assert not list(tmp_path.glob(".client-pki-restore.*"))


def test_restore_refuses_a_non_empty_store(tmp_path: Path) -> None:
    store = _init_store(tmp_path)
    passphrase = _passphrase(tmp_path)
    backup = tmp_path / "b.gpg"
    _ok(_client_pki(tmp_path, store, "backup", "--out", str(backup), "--passphrase-file", str(passphrase)))
    before = _layout(store)
    result = _client_pki(tmp_path, store, "restore", "--in", str(backup), "--passphrase-file", str(passphrase))
    assert result.returncode == 1
    assert "not empty" in result.stderr
    assert _layout(store) == before


def test_restore_refuses_a_symlinked_target(tmp_path: Path) -> None:
    store = _init_store(tmp_path)
    passphrase = _passphrase(tmp_path)
    backup = tmp_path / "b.gpg"
    _ok(_client_pki(tmp_path, store, "backup", "--out", str(backup), "--passphrase-file", str(passphrase)))
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "target"
    link.symlink_to(real)
    result = _client_pki(tmp_path, link, "restore", "--in", str(backup), "--passphrase-file", str(passphrase))
    assert result.returncode == 1
    assert "is a symlink" in result.stderr
    assert not any(real.iterdir())
    assert not list(tmp_path.glob(".client-pki-restore.*"))


def test_restore_with_the_wrong_passphrase_leaves_nothing_behind(tmp_path: Path) -> None:
    store = _init_store(tmp_path)
    backup = tmp_path / "b.gpg"
    _ok(_client_pki(tmp_path, store, "backup", "--out", str(backup), "--passphrase-file", str(_passphrase(tmp_path))))
    wrong = tmp_path / "wrong"
    wrong.write_text("not the passphrase\n")
    wrong.chmod(0o600)
    target = tmp_path / "target"
    result = _client_pki(tmp_path, target, "restore", "--in", str(backup), "--passphrase-file", str(wrong))
    assert result.returncode == 1
    assert not target.exists()
    assert not list(tmp_path.glob(".client-pki-restore.*"))


def _client_pki(
    tmp_path: Path, store: Path, *args: str, extra_env: dict[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    gnupg = tmp_path / "gnupg"
    gnupg.mkdir(mode=0o700, exist_ok=True)
    env = {**os.environ, "GNUPGHOME": str(gnupg), "HOME_WARDEN_PKI_STORE": str(store), **(extra_env or {})}
    return subprocess.run([str(CLIENT_PKI), *args], capture_output=True, env=env, text=True, timeout=120)


def _init_store(tmp_path: Path) -> Path:
    store = tmp_path / "pki"
    _ok(_client_pki(tmp_path, store, "init", "--cn", "backup test CA", "--key-size", "2048"))
    return store


def _layout(store: Path) -> dict[str, tuple[int, bytes | None]]:
    return {
        str(p.relative_to(store)): (p.stat().st_mode & 0o777, p.read_bytes() if p.is_file() else None)
        for p in sorted(store.rglob("*"))
        if p.name != ".lock"
    }


def _ok(result: subprocess.CompletedProcess[str]) -> None:
    assert result.returncode == 0, result.stdout + result.stderr


def _passphrase(tmp_path: Path) -> Path:
    path = tmp_path / "passphrase"
    path.write_text("correct horse battery staple\n")
    path.chmod(0o600)
    return path
