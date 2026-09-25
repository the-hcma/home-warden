"""Validate converted DNS zone data by actually running it through a real
`pdns_server` and querying it with `dig` -- per the-hcma/home-warden#108's
"validate by actually running it, not just by generating plausible YAML."

`validate_via_sqlite_backend` is the backend-independent path: it loads
the parsed records into an ephemeral pdns_server (gsqlite3 backend, via
`pdnsutil zone load`), starts it on loopback, and dig-queries every
record. This runs anywhere pdns_server/pdnsutil/dig/sqlite3 are installed
(a developer's own machine included) and proves the *record data* is
DNS-correct -- it does not exercise the actual GeoIP-backend zones.yml
this repo generates, since Homebrew's pdns bottle (used for local dev on
this repo) does not ship the geoip module. The real acceptance test for
the GeoIP YAML shape itself runs in CI, which installs the actual
`pdns-backend-geoip` package -- see .github/ci/dns-catalog-validate.
"""

from __future__ import annotations

import glob
import gzip
import shutil
import socket
import subprocess
import time
from pathlib import Path

from app.dns_tinydns_convert import RecordValue, Zone

REQUIRED_BINARIES = ("pdns_server", "pdnsutil", "sqlite3", "dig")
SCHEMA_SEARCH_PATHS = (
    # Homebrew (macOS, local dev)
    "/opt/homebrew/Cellar/pdns/*/share/doc/pdns/schema.sqlite3.sql",
    "/usr/local/Cellar/pdns/*/share/doc/pdns/schema.sqlite3.sql",
    # Debian/Ubuntu (pdns-backend-sqlite3 package, CI)
    "/usr/share/doc/pdns-backend-sqlite3/schema/schema.sqlite3.sql*",
    "/usr/share/pdns-backend-sqlite3/schema.sqlite3.sql",
    # Ubuntu 26 (pdns-backend-sqlite3 5.0.x)
    "/usr/share/pdns-backend-sqlite3/schema/schema.sqlite3.sql",
)


def render_bind_zonefile(zone: Zone) -> str:
    """Render `zone` as a standard BIND-presentation-format zone file --
    a validation-only intermediate (not part of this repo's shipped
    output, which is GeoIP YAML) that `pdnsutil zone load` can consume
    directly, letting any pdns backend serve the same record data. A
    RecordValue's own explicit ttl (when present) is emitted as BIND's
    optional per-record TTL field; otherwise the record inherits `$TTL`.
    """
    lines = [f"$TTL {zone.ttl}"]
    soa_values = zone.records.get(zone.apex, {}).get("soa")
    if soa_values:
        lines.append(f"{zone.apex}. {_bind_ttl_field(soa_values[0])}IN SOA {soa_values[0].content}")
    for owner in sorted(zone.records):
        for rtype in sorted(zone.records[owner]):
            if owner == zone.apex and rtype == "soa":
                continue
            bind_type = rtype.upper()
            for value in zone.records[owner][rtype]:
                # TXT content already carries its own quotes (see
                # dns_tinydns_convert._parse_txt) -- no extra quoting here.
                lines.append(f"{owner}. {_bind_ttl_field(value)}IN {bind_type} {value.content}")
    return "\n".join(lines) + "\n"


def validate_via_sqlite_backend(
    zones: dict[str, Zone],
    *,
    workdir: Path,
    startup_timeout: float = 5.0,
    query_timeout: float = 3.0,
    max_start_attempts: int = 3,
) -> list[str]:
    """Load every zone into an ephemeral pdns_server + dig-query every
    record it should serve. Returns a list of human-readable mismatch
    descriptions -- empty means every record verified as served
    correctly. Raises RuntimeError for an environment problem (a
    required binary or the sqlite schema file missing, or the server
    never coming up after `max_start_attempts` port picks), which is a
    different failure mode than a mismatch.
    """
    missing = [b for b in REQUIRED_BINARIES if shutil.which(b) is None]
    if missing:
        raise RuntimeError(f"missing required binaries for local DNS validation: {', '.join(missing)}")

    schema_path = _find_sqlite_schema()
    db_path = workdir / "pdns.sqlite3"
    schema_sql = _read_schema_sql(schema_path)
    subprocess.run(["sqlite3", str(db_path)], input=schema_sql, check=True, timeout=startup_timeout)

    conf_path = workdir / "pdns.conf"
    conf_path.write_text(
        "launch=gsqlite3\n"
        f"gsqlite3-database={db_path}\n"
        # Both loopback addresses in the one directive PowerDNS actually
        # has -- an IPv4-only value leaves local-ipv6 at PowerDNS's own
        # default of `::` (every interface), same fix and same reasoning
        # as dns_tinydns_convert.render_pdns_conf.
        "local-address=127.0.0.1, ::1\n"
        "disable-axfr=yes\n"
        # Relative, with cwd=workdir on the server Popen call below --
        # not the absolute workdir path, which can exceed a UNIX domain
        # socket's sun_path length limit (~104-108 bytes) once nested
        # under a long temp/scratch directory.
        "socket-dir=.\n"
        # local-port is passed as a --local-port override per start
        # attempt below, not baked in here, so a retry with a fresh port
        # (see _start_server_with_retry) needs no rewrite of this file.
    )

    for apex, zone in zones.items():
        zonefile_path = workdir / f"{apex}.zone"
        zonefile_path.write_text(render_bind_zonefile(zone))
        subprocess.run(
            ["pdnsutil", f"--config-dir={workdir}", "zone", "load", apex, str(zonefile_path)],
            check=True,
            capture_output=True,
            timeout=startup_timeout,
        )

    probe_apex = next(iter(zones))
    proc, port = _start_server_with_retry(workdir, probe_apex, startup_timeout, max_start_attempts)
    try:
        mismatches: list[str] = []
        for zone in zones.values():
            for owner, type_map in zone.records.items():
                for rtype, values in type_map.items():
                    if rtype == "soa":
                        continue  # SOA content round-trips through pdns's own serial handling; not asserted here.
                    answered = _dig_with_ttl(owner, rtype.upper(), port, timeout=query_timeout)
                    mismatch = _describe_mismatch(owner, rtype, [v.content for v in values], [c for c, _ in answered])
                    if mismatch is not None:
                        mismatches.append(mismatch)
                        continue  # content already wrong; a ttl mismatch on top is just noise.
                    # Every RecordValue with no ttl of its own inherits the
                    # zone default -- that's what must actually be served,
                    # not just what render_bind_zonefile happened to write.
                    expected_ttls = {v.ttl if v.ttl is not None else zone.ttl for v in values}
                    served_ttls = {ttl for _, ttl in answered}
                    if served_ttls != expected_ttls:
                        mismatches.append(
                            f"{owner} {rtype.upper()}: expected ttl(s) {sorted(expected_ttls)}, "
                            f"got {sorted(served_ttls)}"
                        )
        return mismatches
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=startup_timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=startup_timeout)


def _bind_ttl_field(value: RecordValue) -> str:
    return f"{value.ttl} " if value.ttl is not None else ""


def _describe_mismatch(owner: str, rtype: str, expected_values: list[str], answers: list[str]) -> str | None:
    """Compare what a zone claims for owner/rtype against what a live dig
    answered, ignoring only a trailing-dot difference (FQDN presentation
    is not otherwise normalized -- an actual content difference, like the
    TXT-quoting one this module's docstring describes, is exactly what
    this must catch). Returns None when they agree.
    """
    expected = {v.rstrip(".") for v in expected_values}
    got = {a.rstrip(".") for a in answers}
    if expected == got:
        return None
    return f"{owner} {rtype.upper()}: expected {sorted(expected)}, got {sorted(got)}"


def _dig(name: str, rtype: str, port: int, *, timeout: float) -> list[str]:
    """Query 127.0.0.1:port. Before the server has bound its socket, dig
    can hang retrying rather than getting an immediate refusal -- treat a
    timeout the same as "no answer yet" (empty list) rather than letting
    it raise, so _wait_for_server_ready's poll loop can keep retrying.
    """
    try:
        proc = subprocess.run(
            ["dig", "+short", "-p", str(port), "@127.0.0.1", name, rtype],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return []
    return [line.strip() for line in proc.stdout.splitlines() if line.strip()]


def _dig_with_ttl(name: str, rtype: str, port: int, *, timeout: float) -> list[tuple[str, int]]:
    """Like `_dig`, but also captures the served TTL -- `+short` prints
    content only, which would let a record's ttl (the whole point of
    render_zones_yaml's expanded {content, ttl} form, per #108) go
    unverified even though the content check passes. Uses `+noall
    +answer` and parses each answer line's own TTL column rather than
    trusting the zone's declared default.
    """
    try:
        proc = subprocess.run(
            ["dig", "+noall", "+answer", "-p", str(port), "@127.0.0.1", name, rtype],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return []
    results: list[tuple[str, int]] = []
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line or line.startswith(";"):
            continue
        # "<name> <ttl> <class> <type> <rdata...>" -- rdata itself may
        # contain internal whitespace (SRV, a quoted TXT string), so it
        # is never split further than this one boundary.
        parts = line.split(None, 4)
        if len(parts) < 5 or not parts[1].isdigit():
            continue
        results.append((parts[4].strip(), int(parts[1])))
    return results


def _find_sqlite_schema() -> Path:
    for pattern in SCHEMA_SEARCH_PATHS:
        matches = sorted(glob.glob(pattern))
        if matches:
            return Path(matches[-1])
    raise RuntimeError(
        "could not find schema.sqlite3.sql -- install the PowerDNS sqlite3 backend "
        "(pdns-backend-sqlite3 on Debian/Ubuntu, `brew install pdns` on macOS)"
    )


def _free_udp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _read_schema_sql(schema_path: Path) -> bytes:
    """Read the schema SQL, transparently decompressing a `.gz` file --
    Debian/Ubuntu's doc-compression policy commonly ships one of the
    `schema.sqlite3.sql*` glob's matches gzipped. Returns bytes (not a
    file handle) since a GzipFile has no real OS-level fd of its own for
    subprocess to read decompressed data through via `stdin=`; passing
    bytes via `input=` instead works uniformly for both cases.
    """
    raw = schema_path.read_bytes()
    return gzip.decompress(raw) if schema_path.suffix == ".gz" else raw


def _start_server_with_retry(
    workdir: Path, probe_apex: str, startup_timeout: float, max_attempts: int
) -> tuple[subprocess.Popen, int]:
    """Start pdns_server on a freshly OS-assigned port, retrying with a
    new port on failure. `_free_udp_port` necessarily releases its probe
    socket before pdns_server binds the same port (PowerDNS takes a port
    number, not a pre-bound fd) -- a real, if rare, TOCTOU window where
    another process claims it first. A single failed attempt is an
    environment blip worth retrying, not an immediate hard failure.
    """
    last_err: Exception | None = None
    for _ in range(max(1, max_attempts)):
        port = _free_udp_port()
        proc = subprocess.Popen(
            ["pdns_server", f"--config-dir={workdir}", "--daemon=no", "--guardian=no", f"--local-port={port}"],
            cwd=workdir,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            _wait_for_server_ready(port, probe_apex, timeout=startup_timeout)
            return proc, port
        except RuntimeError as e:
            last_err = e
            proc.terminate()
            try:
                proc.wait(timeout=startup_timeout)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=startup_timeout)
    assert last_err is not None
    raise last_err


def _wait_for_server_ready(port: int, probe_name: str, *, timeout: float) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if _dig(probe_name, "SOA", port, timeout=1.0):
            return
        time.sleep(0.2)
    raise RuntimeError(f"pdns_server on 127.0.0.1:{port} did not come up within {timeout}s")
