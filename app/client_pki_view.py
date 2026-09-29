"""Read-only view of the client CA store for GET /pki/status (#161).

Reads the store through tiny-pki's own JSON output (`list ca`, `list
certs`, `check --include-revoked`) rather than its files, so the layout
stays tiny-pki's business. None of those verbs reads the CA key, and this
module never writes: issuing and revoking stay with scripts/client-pki on
the host (the write-action decision in docs/client-pki.md).

Paths tiny-pki reports (certificate and key files, the store itself) are
dropped from the response: the browser has no use for them, and they
name the operator's home directory. For the same reason an error's
`detail` names no path; the full diagnostic goes to the server log.
"""

from __future__ import annotations

import json
import logging
import subprocess
import sys
from collections.abc import Iterable
from pathlib import Path
from typing import TypeVar

from tiny_pki import Status


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
    it, and otherwise the worst check status (`ok`, `expiring`, `expired`,
    ...) of the CA, the CRL, and the certificates still active -- not
    tiny-pki's own overall status, which with `--include-revoked` reads
    `revoked` as soon as any certificate ever was.
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
        # Reading a legacy flat store makes tiny-pki migrate it, a write
        # this view must not trigger; leave that to scripts/client-pki.
        if (store / "ca.crt").is_file():
            detail = "the store uses tiny-pki's legacy flat layout; run ./scripts/client-pki list ca on the host"
            return {**result, "status": "error", "detail": detail}
        if store.is_dir() and any(store.iterdir()):
            return {**result, "status": "error", "detail": "the store exists but has no CA certificate (ca/ca.crt)"}
        return result
    try:
        ca = _tiny_pki_json(store, ["list", "ca", "--json"], timeout, dict)
        certs = _objects(_tiny_pki_json(store, ["list", "certs", "--json"], timeout, list), "list certs")
        check = _tiny_pki_json(store, ["check", "--json", "--include-revoked"], timeout, dict, ok_codes=(0, 1, 2))
        check_rows = _objects(check.get("results"), "check")
    except PkiViewError as e:
        return {**result, "status": "error", "detail": str(e)}

    checks = {(row.get("kind"), row.get("serial_number")): row for row in check_rows}
    ca_check = next((row for row in checks.values() if row.get("kind") == "ca"), {})
    crl_check = next((row for row in checks.values() if row.get("kind") == "crl"), {})
    certificates = sorted(
        (_certificate_entry(cert, checks) for cert in certs),
        key=lambda cert: (str(cert["cn"]), str(cert["expires"])),
    )
    in_use = [ca_check, crl_check, *(cert for cert in certificates if cert["state"] == "active")]
    result.update(
        status=_worst_status(row.get("status") or row.get("health") for row in in_use),
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
        certificates=certificates,
    )
    return result


_log = logging.getLogger(__name__)


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


def _objects(rows: object, verb: str) -> list[dict]:
    if not isinstance(rows, list) or not all(isinstance(row, dict) for row in rows):
        raise PkiViewError(f"tiny-pki {verb} printed rows that aren't a list of objects")
    return rows


def _serial_hex(serial: object) -> str | None:
    """`check` prints serials without leading zeros; `list` keeps them."""
    if not isinstance(serial, str):
        return None
    return serial.lstrip("0") or "0"


def _worst_status(statuses: Iterable[str | None]) -> str:
    """The most severe of `statuses` by tiny-pki's own ranking; a missing
    or unrecognized one (e.g. no CRL row at all) counts as `unknown`.
    """
    worst = Status.OK
    for value in statuses:
        try:
            status = Status(value)
        except ValueError:
            return "unknown"
        worst = max(worst, status, key=lambda s: s.severity)
    return worst.value


def _tiny_pki_json(store: Path, args: list[str], timeout: float, shape: type[T], ok_codes: tuple[int, ...] = (0,)) -> T:
    command = [str(TINY_PKI), "--store", str(store), "--color", "never", *args]
    try:
        proc = subprocess.run(command, capture_output=True, text=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired as e:
        raise PkiViewError(f"tiny-pki {args[0]} timed out after {timeout:g}s") from e
    except OSError as e:
        _log.warning("running %s failed: %s", TINY_PKI, e)
        raise PkiViewError("tiny-pki could not be run; see the server log") from e
    if proc.returncode not in ok_codes:
        _log.warning("tiny-pki %s exited %d: %s", " ".join(args[:2]), proc.returncode, proc.stderr.strip())
        raise PkiViewError(f"tiny-pki {' '.join(args[:2])} exited {proc.returncode}; see the server log")
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError as e:
        raise PkiViewError(f"tiny-pki {' '.join(args[:2])} printed invalid JSON: {e}") from e
    if not isinstance(data, shape):
        raise PkiViewError(
            f"tiny-pki {' '.join(args[:2])} printed a {type(data).__name__}, expected a {shape.__name__}"
        )
    return data
