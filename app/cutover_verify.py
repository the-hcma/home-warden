"""Compare what two hosts serve for every catalog vhost, without touching DNS (#188).

For each vhost, connect to the old and the new address directly (SNI and `Host` set to the vhost's name,
the equivalent of `curl --resolve`) and compare: `:80` status and redirect, HTTPS status, redirect and
security headers, the TLS protocol, issuer and SANs, whether the certificate verifies, and (with
`--client-cert`) how an mTLS request ends. Certificate serial and `notAfter` are reported but never a
difference (a reissued lineage differs by design), and neither are `Date`/`Server` values.

Only `GET /` is compared, and only the headers in `COMPARED_HEADERS`: this catches a host that serves the wrong
certificate, redirect, TLS or security posture, not a wrong backend behind another path.

An address that can't be reached is always a difference, even when both are down, so a dead pair never
passes as parity. Read-only; every socket has a timeout. Usable after the cutover too.
"""

from __future__ import annotations

import base64
import http.client
import os
import socket
import ssl
from dataclasses import dataclass, field

from cryptography import x509

COMPARED_HEADERS = (
    "strict-transport-security",
    "x-frame-options",
    "x-content-type-options",
    "content-security-policy",
    "referrer-policy",
    "location",
)


class Unreachable(OSError):
    """The TCP connection itself failed (refused, timed out, no route)."""


@dataclass
class Probe:
    """What one address answered for one vhost. `facts` are compared; `info` is shown, never compared."""

    facts: dict[str, str] = field(default_factory=dict)
    info: dict[str, str] = field(default_factory=dict)
    unreachable: list[str] = field(default_factory=list)


@dataclass
class Reply:
    status: int
    headers: dict[str, str]
    tls_version: str | None = None
    peer_der: bytes | None = None


def failure_kind(e: BaseException) -> str:
    """Collapse the many ways a server says "no" into comparable words. With TLS 1.3 a rejected client certificate
    surfaces only after the handshake, as an SSL alert, a reset or a closed connection, depending on timing."""
    if isinstance(e, TimeoutError):
        return "timeout"
    if isinstance(e, (ssl.SSLError, ConnectionResetError, BrokenPipeError, http.client.BadStatusLine)):
        return "rejected"
    return type(e).__name__


def _connect(addr: str, port: int, timeout: float) -> socket.socket:
    family = socket.AF_INET6 if ":" in addr else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((addr, port))
    except OSError as e:
        sock.close()
        raise Unreachable(f"{addr}:{port} {failure_kind(e)}") from e
    return sock


def _tls_context(verify: bool, client_cert: tuple[str, str] | None) -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    if client_cert:
        ctx.load_cert_chain(*client_cert)
    return ctx


def _get(
    name: str,
    addr: str,
    port: int,
    timeout: float,
    *,
    tls: ssl.SSLContext | None,
    headers: dict[str, str] | None = None,
) -> Reply:
    """One `GET /` to `addr:port` (TLS when `tls` is given), always closing what it opened."""
    sock = _connect(addr, port, timeout)
    try:
        wrapped = tls.wrap_socket(sock, server_hostname=name) if tls else sock
    except BaseException:
        sock.close()
        raise
    conn = (
        http.client.HTTPSConnection(name, timeout=timeout) if tls else http.client.HTTPConnection(name, timeout=timeout)
    )
    conn.sock = wrapped
    try:
        conn.request("GET", "/", headers={"Host": name, "Connection": "close", **(headers or {})})
        resp = conn.getresponse()
        version = wrapped.version() if isinstance(wrapped, ssl.SSLSocket) else None
        der = wrapped.getpeercert(binary_form=True) if isinstance(wrapped, ssl.SSLSocket) else None
        return Reply(resp.status, {k.lower(): v for k, v in resp.getheaders()}, version, der)
    finally:
        conn.close()


def _summarize(reply: Reply, prefix: str, facts: dict[str, str]) -> None:
    facts[f"{prefix}.status"] = str(reply.status)
    for header in COMPARED_HEADERS:
        if header in reply.headers:
            facts[f"{prefix}.{header}"] = reply.headers[header]
    # Version disclosure is a difference; the product name alone is not.
    facts[f"{prefix}.server_discloses_version"] = str(any(ch.isdigit() for ch in reply.headers.get("server", "")))


def _describe_cert(der: bytes, p: Probe) -> None:
    try:
        cert = x509.load_der_x509_certificate(der)
        p.facts["tls.issuer"] = cert.issuer.rfc4514_string()
        try:
            san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
            p.facts["tls.san"] = ",".join(sorted(san.get_values_for_type(x509.DNSName)))
        except x509.ExtensionNotFound:
            p.facts["tls.san"] = ""
        p.info["tls.notAfter"] = cert.not_valid_after_utc.isoformat()
        p.info["tls.serial"] = format(cert.serial_number, "x")
    except ValueError:
        p.facts["tls.cert"] = "unparsable"


def probe_vhost(
    name: str,
    addr: str,
    *,
    timeout: float = 5.0,
    client_cert: tuple[str, str] | None = None,
    websocket: bool = False,
    http_port: int = 80,
    https_port: int = 443,
) -> Probe:
    p = Probe()

    def attempt(label: str, port: int, **kw) -> Reply | None:
        try:
            return _get(name, addr, port, timeout, **kw)
        except Unreachable as e:
            if str(e) not in p.unreachable:
                p.unreachable.append(str(e))
        except (OSError, http.client.HTTPException) as e:
            p.facts[f"{label}.error"] = failure_kind(e)
        return None

    # Plain HTTP: status and redirect target (not followed).
    if reply := attempt("http", http_port, tls=None):
        _summarize(reply, "http", p.facts)

    # Does the certificate verify (chain and hostname)? Reported as a fact either way. No request is sent.
    try:
        sock = _connect(addr, https_port, timeout)
        try:
            _tls_context(True, None).wrap_socket(sock, server_hostname=name).close()
            p.facts["tls.verifies"] = "yes"
        except ssl.SSLCertVerificationError as e:
            sock.close()
            p.facts["tls.verifies"] = f"no: {e.verify_message}"
        except (OSError, ssl.SSLError) as e:
            sock.close()
            # A client_cert:required vhost may end the handshake without a client cert; that is a fact too.
            p.facts["tls.verifies"] = f"handshake failed: {failure_kind(e)}"
    except Unreachable as e:
        if str(e) not in p.unreachable:
            p.unreachable.append(str(e))

    # What the server presents whether or not it verifies, and what it answers.
    if reply := attempt("https", https_port, tls=_tls_context(False, None)):
        _summarize(reply, "https", p.facts)
        p.facts["tls.version"] = reply.tls_version or "?"
        if reply.peer_der:
            _describe_cert(reply.peer_der, p)

    if client_cert:
        ctx = _tls_context(False, client_cert)
        if reply := attempt("mtls", https_port, tls=ctx):
            _summarize(reply, "mtls", p.facts)

    if websocket:
        upgrade = {
            "Upgrade": "websocket",
            "Connection": "Upgrade",
            "Sec-WebSocket-Key": base64.b64encode(os.urandom(16)).decode(),
            "Sec-WebSocket-Version": "13",
        }
        if reply := attempt("websocket", https_port, tls=_tls_context(False, client_cert), headers=upgrade):
            p.facts["websocket.status"] = str(reply.status)
    return p


def compare(old: Probe, new: Probe) -> list[str]:
    diffs = [f"old unreachable: {u}" for u in old.unreachable] + [f"new unreachable: {u}" for u in new.unreachable]
    for key in sorted(set(old.facts) | set(new.facts)):
        a, b = old.facts.get(key), new.facts.get(key)
        if a != b:
            diffs.append(f"{key}: old={a!r} new={b!r}")
    return diffs
