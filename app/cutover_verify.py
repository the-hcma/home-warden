"""Compare what two hosts serve for every catalog vhost, without touching DNS (#188).

For each vhost, connect to the old and the new address directly (SNI and `Host` set to the vhost's name,
the equivalent of `curl --resolve`) and compare: `:80` status and redirect, HTTPS status, redirect and
security headers, the TLS protocol, issuer and SANs, whether the certificate verifies, and (with
`--client-cert`) how an mTLS handshake ends. Certificate serial and `notAfter` are reported but never a
difference (a reissued lineage differs by design), and neither are `Date`/`Server` values.

Read-only; every socket has a timeout. Usable after the cutover too, pointing both sides at the public address.
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


@dataclass
class Probe:
    """What one address answered for one vhost. `facts` are compared; `info` is shown, never compared."""

    facts: dict[str, str] = field(default_factory=dict)
    info: dict[str, str] = field(default_factory=dict)


def _connect(addr: str, port: int, timeout: float) -> socket.socket:
    family = socket.AF_INET6 if ":" in addr else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((addr, port))
    except OSError:
        sock.close()
        raise
    return sock


def _request(
    conn: http.client.HTTPConnection, name: str, headers: dict[str, str] | None = None
) -> http.client.HTTPResponse:
    conn.request("GET", "/", headers={"Host": name, "Connection": "close", **(headers or {})})
    return conn.getresponse()


def _summarize(resp: http.client.HTTPResponse, prefix: str, facts: dict[str, str]) -> None:
    facts[f"{prefix}.status"] = str(resp.status)
    for header in COMPARED_HEADERS:
        value = resp.getheader(header)
        if value is not None:
            facts[f"{prefix}.{header}"] = value
    server = resp.getheader("server") or ""
    # Version disclosure is a difference; the product name alone is not.
    facts[f"{prefix}.server_discloses_version"] = str(any(ch.isdigit() for ch in server))


def _tls_context(verify: bool, client_cert: tuple[str, str] | None) -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    if client_cert:
        ctx.load_cert_chain(*client_cert)
    return ctx


def _describe_cert(der: bytes, p: Probe) -> None:
    cert = x509.load_der_x509_certificate(der)
    p.facts["tls.issuer"] = cert.issuer.rfc4514_string()
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        p.facts["tls.san"] = ",".join(sorted(san.get_values_for_type(x509.DNSName)))
    except x509.ExtensionNotFound:
        p.facts["tls.san"] = ""
    p.info["tls.notAfter"] = cert.not_valid_after_utc.isoformat()
    p.info["tls.serial"] = format(cert.serial_number, "x")


def _https_get(
    name: str,
    addr: str,
    port: int,
    timeout: float,
    client_cert: tuple[str, str] | None,
    headers: dict[str, str] | None = None,
) -> tuple[ssl.SSLSocket, http.client.HTTPSConnection, http.client.HTTPResponse]:
    sock = _connect(addr, port, timeout)
    conn = http.client.HTTPSConnection(name, timeout=timeout)
    tls = _tls_context(False, client_cert).wrap_socket(sock, server_hostname=name)
    conn.sock = tls
    return tls, conn, _request(conn, name, headers)


def probe_vhost(
    name: str,
    addr: str,
    *,
    timeout: float = 10.0,
    client_cert: tuple[str, str] | None = None,
    websocket: bool = False,
    http_port: int = 80,
    https_port: int = 443,
) -> Probe:
    p = Probe()
    # Plain HTTP: status and redirect target (not followed).
    try:
        sock = _connect(addr, http_port, timeout)
        conn = http.client.HTTPConnection(name, timeout=timeout)
        conn.sock = sock
        _summarize(_request(conn, name), "http", p.facts)
        conn.close()
    except (OSError, http.client.HTTPException) as e:
        p.facts["http.error"] = type(e).__name__

    # Does the certificate verify (chain and hostname)? Reported as a fact either way.
    try:
        _tls_context(True, None).wrap_socket(_connect(addr, https_port, timeout), server_hostname=name).close()
        p.facts["tls.verifies"] = "yes"
    except ssl.SSLCertVerificationError as e:
        p.facts["tls.verifies"] = f"no: {e.verify_message}"
    except (OSError, ssl.SSLError) as e:
        # A client_cert:required vhost may end the handshake without a client cert; that is a fact too.
        p.facts["tls.verifies"] = f"handshake failed: {type(e).__name__}"

    # What the server presents, whether or not it verifies, and what it answers.
    try:
        sock = _connect(addr, https_port, timeout)
        conn = http.client.HTTPSConnection(name, timeout=timeout)
        tls = _tls_context(False, None).wrap_socket(sock, server_hostname=name)
        conn.sock = tls
        p.facts["tls.version"] = tls.version() or "?"
        der = tls.getpeercert(binary_form=True)
        if der:
            _describe_cert(der, p)
        _summarize(_request(conn, name), "https", p.facts)
        conn.close()
    except (OSError, http.client.HTTPException) as e:
        p.facts["https.error"] = type(e).__name__

    if client_cert:
        try:
            _tls, conn, resp = _https_get(name, addr, https_port, timeout, client_cert)
            _summarize(resp, "mtls", p.facts)
            conn.close()
        except (OSError, http.client.HTTPException) as e:
            p.facts["mtls.error"] = type(e).__name__

    if websocket:
        upgrade = {
            "Upgrade": "websocket",
            "Connection": "Upgrade",
            "Sec-WebSocket-Key": base64.b64encode(os.urandom(16)).decode(),
            "Sec-WebSocket-Version": "13",
        }
        try:
            _tls, conn, resp = _https_get(name, addr, https_port, timeout, client_cert, upgrade)
            p.facts["websocket.status"] = str(resp.status)
            conn.close()
        except (OSError, http.client.HTTPException) as e:
            p.facts["websocket.error"] = type(e).__name__
    return p


def compare(old: Probe, new: Probe) -> list[str]:
    diffs: list[str] = []
    for key in sorted(set(old.facts) | set(new.facts)):
        a, b = old.facts.get(key), new.facts.get(key)
        if a != b:
            diffs.append(f"{key}: old={a!r} new={b!r}")
    return diffs
