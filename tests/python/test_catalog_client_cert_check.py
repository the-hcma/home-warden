"""check_client_cert: the client CA bundle and CRL a gated vhost loads (#160)."""

from __future__ import annotations

import datetime
import os
import subprocess
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from app.catalog_checks import CheckResult, check_client_cert, run_all

REPO_ROOT = Path(__file__).resolve().parents[2]


class _Ca:
    def __init__(self, cn: str, *, days: int = 3650) -> None:
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
        now = datetime.datetime.now(datetime.timezone.utc)
        self.cert = (
            x509.CertificateBuilder()
            .subject_name(self.name)
            .issuer_name(self.name)
            .public_key(self.key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=days))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .sign(self.key, hashes.SHA256())
        )

    def cert_pem(self) -> bytes:
        return self.cert.public_bytes(serialization.Encoding.PEM)

    def crl_pem(self, *, days: float = 30, signing_key: ec.EllipticCurvePrivateKey | None = None) -> bytes:
        now = datetime.datetime.now(datetime.timezone.utc)
        crl = (
            x509.CertificateRevocationListBuilder()
            .issuer_name(self.name)
            .last_update(now - datetime.timedelta(days=1))
            .next_update(now + datetime.timedelta(days=days))
            .sign(signing_key or self.key, hashes.SHA256())
        )
        return crl.public_bytes(serialization.Encoding.PEM)


@pytest.mark.parametrize(
    ("relative", "mode", "expected"),
    [
        ("public", 0o700, "public isn't readable by nginx (mode 0700, needs 0755)"),
        ("public/crl.pem", 0o600, "crl.pem isn't readable by nginx (mode 0600, needs 0644)"),
    ],
)
def test_a_file_nginx_cannot_read_fails(tmp_path: Path, relative: str, mode: int, expected: str) -> None:
    ca = _Ca("Home client CA")
    service = _service(tmp_path, ca.cert_pem(), ca.crl_pem())
    (tmp_path / relative).chmod(mode)
    try:
        result = _check(service)
    finally:
        (tmp_path / relative).chmod(0o755)
    assert result.status == "fail"
    assert expected in result.detail


def test_ca_already_expired_fails(tmp_path: Path) -> None:
    ca = _Ca("Home client CA", days=-1)
    result = _check(_service(tmp_path, ca.cert_pem(), ca.crl_pem()))
    assert result.status == "fail"
    assert "CA CN=Home client CA expired" in result.detail


def test_ca_expiring_within_the_window_fails(tmp_path: Path) -> None:
    ca = _Ca("Home client CA", days=30)
    result = _check(_service(tmp_path, ca.cert_pem(), ca.crl_pem()))
    assert result.status == "fail"
    assert "expires within 60d" in result.detail


def test_crl_expired_fails(tmp_path: Path) -> None:
    ca = _Ca("Home client CA")
    result = _check(_service(tmp_path, ca.cert_pem(), ca.crl_pem(days=-0.5)))
    assert result.status == "fail"
    assert "CRL from CN=Home client CA expired" in result.detail


def test_crl_expiring_within_the_window_fails(tmp_path: Path) -> None:
    ca = _Ca("Home client CA")
    result = _check(_service(tmp_path, ca.cert_pem(), ca.crl_pem(days=3)))
    assert result.status == "fail"
    assert "expires within 7d" in result.detail


def test_crl_not_signed_by_the_ca_fails(tmp_path: Path) -> None:
    ca = _Ca("Home client CA")
    impostor = ec.generate_private_key(ec.SECP256R1())
    result = _check(_service(tmp_path, ca.cert_pem(), ca.crl_pem(signing_key=impostor)))
    assert result.status == "fail"
    assert "isn't signed by a CA in" in result.detail


def test_missing_ca_bundle_fails(tmp_path: Path) -> None:
    service = {
        "name": "svc",
        "client_cert": {"mode": "required", "ca_bundle": str(tmp_path / "absent.crt")},
    }
    result = _check(service)
    assert result == CheckResult("svc", "client_cert", "fail", f"missing: {tmp_path / 'absent.crt'}")


def test_missing_crl_setting_fails(tmp_path: Path) -> None:
    ca_path = _public_file(tmp_path, "ca.crt", _Ca("Home client CA").cert_pem())
    service = {"name": "svc", "client_cert": {"mode": "required", "ca_bundle": str(ca_path)}}
    result = _check(service)
    assert result == CheckResult(
        "svc", "client_cert", "fail", "client_cert.crl is not set, so nginx accepts revoked certificates"
    )


def test_mode_off_is_skipped() -> None:
    assert _check({"name": "svc"}).status == "skip"
    assert _check({"name": "svc", "client_cert": {"mode": "off"}}).status == "skip"


def test_real_tiny_pki_store_is_ok(tmp_path: Path) -> None:
    store = tmp_path / "pki"
    subprocess.run(
        ["uv", "run", "--project", str(REPO_ROOT), "tiny-pki", "--store", str(store), "init", "--cn", "Test CA"],
        check=True,
        capture_output=True,
        env={**os.environ, "NO_COLOR": "1"},
        timeout=120,
    )
    service = {
        "name": "svc",
        "client_cert": {
            "mode": "required",
            "ca_bundle": str(store / "public" / "ca.crt"),
            "crl": str(store / "public" / "crl.pem"),
        },
    }
    result = _check(service)
    assert result == CheckResult("svc", "client_cert", "ok", "1 CA(s), 1 CRL(s) valid")


def test_relative_path_is_refused(tmp_path: Path) -> None:
    service = {"name": "svc", "client_cert": {"mode": "required", "ca_bundle": "conf/pki/public/ca.crt"}}
    result = _check(service)
    assert result.status == "fail"
    assert "is not an absolute path" in result.detail


def test_run_all_includes_client_cert_by_default(tmp_path: Path) -> None:
    ca = _Ca("Home client CA")
    catalog = {"services": [_service(tmp_path, ca.cert_pem(), ca.crl_pem())]}
    results = run_all(
        catalog,
        certs_live_dir=tmp_path,
        alert_days=10,
        cf_headers=None,
        local_dns_port=853,
        timeout=1,
        max_retries=1,
        client_crl_alert_days=31,
        skip_cert=True,
        skip_dns=True,
        skip_local_dns=True,
        skip_upstream=True,
    )
    assert [(r.dimension, r.status) for r in results] == [("client_cert", "fail")]
    assert "expires within 31d" in results[0].detail


def test_run_all_rejects_negative_client_alert_days() -> None:
    with pytest.raises(ValueError, match="client_ca_alert_days and client_crl_alert_days must be non-negative"):
        run_all(
            {},
            certs_live_dir=Path("/nonexistent"),
            alert_days=10,
            cf_headers=None,
            local_dns_port=853,
            timeout=5,
            max_retries=1,
            client_crl_alert_days=-1,
        )


def test_transition_bundle_needs_a_crl_for_every_ca(tmp_path: Path) -> None:
    old, new = _Ca("Home client CA"), _Ca("Home client CA 2")
    bundle = old.cert_pem() + new.cert_pem()
    missing = _check(_service(tmp_path, bundle, old.crl_pem()))
    assert missing.status == "fail"
    assert "no CRL for CA CN=Home client CA 2" in missing.detail

    both = _check(_service(tmp_path, bundle, old.crl_pem() + new.crl_pem()))
    assert both == CheckResult("svc", "client_cert", "ok", "2 CA(s), 2 CRL(s) valid")


def test_transition_bundle_with_a_reused_ca_name_needs_both_crls(tmp_path: Path) -> None:
    old, new = _Ca("Home client CA"), _Ca("Home client CA")
    result = _check(_service(tmp_path, old.cert_pem() + new.cert_pem(), old.crl_pem()))
    assert result.status == "fail"
    assert "no CRL for CA CN=Home client CA" in result.detail

    both = _check(_service(tmp_path, old.cert_pem() + new.cert_pem(), old.crl_pem() + new.crl_pem()))
    assert both == CheckResult("svc", "client_cert", "ok", "2 CA(s), 2 CRL(s) valid")


def test_unparseable_crl_fails(tmp_path: Path) -> None:
    ca = _Ca("Home client CA")
    result = _check(_service(tmp_path, ca.cert_pem(), b"not a crl\n"))
    assert result.status == "fail"
    assert result.detail.startswith("no PEM objects in")


def test_valid_ca_and_crl_is_ok(tmp_path: Path) -> None:
    ca = _Ca("Home client CA")
    result = _check(_service(tmp_path, ca.cert_pem(), ca.crl_pem()))
    assert result == CheckResult("svc", "client_cert", "ok", "1 CA(s), 1 CRL(s) valid")


def _check(service: dict) -> CheckResult:
    return check_client_cert("svc", service, ca_alert_days=60, crl_alert_days=7)


def _public_file(tmp_path: Path, name: str, data: bytes) -> Path:
    public = tmp_path / "public"
    public.mkdir(mode=0o755, exist_ok=True)
    public.chmod(0o755)
    path = public / name
    path.write_bytes(data)
    path.chmod(0o644)
    return path


def _service(tmp_path: Path, ca_pem: bytes, crl_pem: bytes) -> dict:
    ca_path = _public_file(tmp_path, "ca.crt", ca_pem)
    crl_path = _public_file(tmp_path, "crl.pem", crl_pem)
    return {"name": "svc", "client_cert": {"mode": "required", "ca_bundle": str(ca_path), "crl": str(crl_path)}}
