"""Read-only view of the client CA store for GET /pki/status (#161).

Reads the store through tiny-pki's own JSON output (`list ca`, `list
certs`, `check --include-revoked`) rather than its files, so the layout
stays tiny-pki's business. None of those verbs reads the CA key, and this
module never writes: issuing and revoking stay with scripts/client-pki on
the host (the write-action decision in docs/client-pki.md).

Paths tiny-pki reports (certificate and key files, the store itself) are
dropped from the response: the browser has no use for them, and they
name the operator's home directory.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import TypeVar


class PkiViewError(Exception):
    pass


T = TypeVar("T")

# The console script uv installs next to this interpreter (tiny-pki is a
# runtime dependency), so the view doesn't depend on PATH.
TINY_PKI = Path(sys.executable).parent / "tiny-pki"


def client_cert_vhosts(services: list[dict]) -> list[dict]:
    """Every catalog service that sets `client_cert`, with the fields the
    view shows, sorted by name.
    """
    vhosts = []
    for service in services:
        client_cert = service.get("client_cert")
        if not isinstance(client_cert, dict):
            continue
        vhosts.append(
            {
                "name": service.get("name", "<unnamed>"),
                "server_name": service.get("server_name"),
                "mode": client_cert.get("mode"),
                "allow_cn": client_cert.get("allow_cn"),
                "verify_depth": client_cert.get("verify_depth"),
            }
        )
    return sorted(vhosts, key=lambda vhost: str(vhost["name"]))


def load_pki_status(store: Path, services: list[dict], *, timeout: float) -> dict:
    """The CA, its CRL, every certificate the store has issued, and the
    catalog vhosts that use client certificates.

    `status` is `not_configured` when the store has no CA yet (no
    `client-pki init` on this host), `error` when tiny-pki couldn't read
    it, and otherwise tiny-pki's own overall check status (`ok`,
    `expiring`, `expired`, `revoked`, ...).
    """
    result: dict = {
        "status": "not_configured",
        "detail": None,
        "ca": None,
        "crl": None,
        "certificates": [],
        "vhosts": client_cert_vhosts(services),
    }
    if not (store / "ca" / "ca.crt").is_file():
        return result
    try:
        ca = _tiny_pki_json(store, ["list", "ca", "--json"], timeout, dict)
        certs = _tiny_pki_json(store, ["list", "certs", "--json"], timeout, list)
        check = _tiny_pki_json(store, ["check", "--json", "--include-revoked"], timeout, dict, ok_codes=(0, 1, 2))
    except PkiViewError as e:
        return {**result, "status": "error", "detail": str(e)}

    checks = {(row.get("kind"), row.get("serial_number")): row for row in check.get("results") or []}
    ca_check = next((row for row in checks.values() if row.get("kind") == "ca"), {})
    crl_check = next((row for row in checks.values() if row.get("kind") == "crl"), {})
    result.update(
        status=check.get("status", "unknown"),
        ca={
            "cn": ca.get("cn"),
            "fingerprint": ca.get("fingerprint"),
            "expires": ca.get("expires"),
            "days_remaining": ca_check.get("days_remaining"),
            "status": ca_check.get("status", "unknown"),
            "reasons": ca_check.get("reasons") or [],
        },
        crl={
            "this_update": crl_check.get("not_before"),
            "next_update": crl_check.get("not_after"),
            "days_remaining": crl_check.get("days_remaining"),
            "status": crl_check.get("status", "missing"),
            "reasons": crl_check.get("reasons") or [],
        },
        certificates=sorted(
            (_certificate_entry(cert, checks) for cert in certs),
            key=lambda cert: (str(cert["cn"]), str(cert["expires"])),
        ),
    )
    return result


def _certificate_entry(cert: dict, checks: dict) -> dict:
    row = checks.get((cert.get("kind"), _serial_hex(cert.get("serial")))) or {}
    return {
        "cn": cert.get("cn"),
        "kind": cert.get("kind"),
        "serial": cert.get("serial"),
        "fingerprint": cert.get("fingerprint"),
        "expires": cert.get("expires"),
        "days_remaining": row.get("days_remaining"),
        "state": cert.get("status"),
        "health": row.get("status", "unknown"),
        "reasons": row.get("reasons") or [],
        "revoked_at": cert.get("revoked_at"),
        "superseded_by": cert.get("superseded_by"),
    }


def _serial_hex(serial: object) -> str | None:
    """`check` prints serials without leading zeros; `list` keeps them."""
    if not isinstance(serial, str):
        return None
    return serial.lstrip("0") or "0"


def _tiny_pki_json(store: Path, args: list[str], timeout: float, shape: type[T], ok_codes: tuple[int, ...] = (0,)) -> T:
    command = [str(TINY_PKI), "--store", str(store), "--color", "never", *args]
    try:
        proc = subprocess.run(command, capture_output=True, text=True, timeout=timeout, check=False)
    except FileNotFoundError as e:
        raise PkiViewError(f"tiny-pki not found at {TINY_PKI}") from e
    except subprocess.TimeoutExpired as e:
        raise PkiViewError(f"tiny-pki {args[0]} timed out after {timeout:g}s") from e
    if proc.returncode not in ok_codes:
        stderr = proc.stderr.strip().splitlines()
        raise PkiViewError(f"tiny-pki {' '.join(args[:2])} exited {proc.returncode}: {stderr[-1] if stderr else ''}")
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError as e:
        raise PkiViewError(f"tiny-pki {' '.join(args[:2])} printed invalid JSON: {e}") from e
    if not isinstance(data, shape):
        raise PkiViewError(
            f"tiny-pki {' '.join(args[:2])} printed a {type(data).__name__}, expected a {shape.__name__}"
        )
    return data
