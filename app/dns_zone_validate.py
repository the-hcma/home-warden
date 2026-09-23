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
import shutil
import socket
import subprocess
import time
from pathlib import Path

from app.dns_tinydns_convert import Zone

REQUIRED_BINARIES = ("pdns_server", "pdnsutil", "sqlite3", "dig")
SCHEMA_SEARCH_PATHS = (
    # Homebrew (macOS, local dev)
    "/opt/homebrew/Cellar/pdns/*/share/doc/pdns/schema.sqlite3.sql",
    "/usr/local/Cellar/pdns/*/share/doc/pdns/schema.sqlite3.sql",
    # Debian/Ubuntu (pdns-backend-sqlite3 package, CI)
    "/usr/share/doc/pdns-backend-sqlite3/schema/schema.sqlite3.sql*",
    "/usr/share/pdns-backend-sqlite3/schema.sqlite3.sql",
)


def render_bind_zonefile(zone: Zone) -> str:
    """Render `zone` as a standard BIND-presentation-format zone file --
    a validation-only intermediate (not part of this repo's shipped
    output, which is GeoIP YAML) that `pdnsutil zone load` can consume
    directly, letting any pdns backend serve the same record data.
    """
    lines = [f"$TTL {zone.ttl}"]
    soa_values = zone.records.get(zone.apex, {}).get("soa")
    if soa_values:
        lines.append(f"{zone.apex}. IN SOA {soa_values[0]}")
    for owner in sorted(zone.records):
        for rtype in sorted(zone.records[owner]):
            if owner == zone.apex and rtype == "soa":
                continue
            bind_type = rtype.upper()
            for value in zone.records[owner][rtype]:
                # TXT content already carries its own quotes (see
                # dns_tinydns_convert._parse_txt) -- no extra quoting here.
                lines.append(f"{owner}. IN {bind_type} {value}")
    return "\n".join(lines) + "\n"


def validate_via_sqlite_backend(
    zones: dict[str, Zone],
    *,
    workdir: Path,
    startup_timeout: float = 5.0,
    query_timeout: float = 3.0,
) -> list[str]:
    """Load every zone into an ephemeral pdns_server + dig-query every
    record it should serve. Returns a list of human-readable mismatch
    descriptions -- empty means every record verified as served
    correctly. Raises RuntimeError for an environment problem (a
    required binary or the sqlite schema file missing, or the server
    never coming up), which is a different failure mode than a mismatch.
    """
    missing = [b for b in REQUIRED_BINARIES if shutil.which(b) is None]
    if missing:
        raise RuntimeError(f"missing required binaries for local DNS validation: {', '.join(missing)}")

    schema_path = _find_sqlite_schema()
    db_path = workdir / "pdns.sqlite3"
    with schema_path.open() as schema_file:
        subprocess.run(["sqlite3", str(db_path)], stdin=schema_file, check=True, timeout=startup_timeout)

    port = _free_udp_port()
    conf_path = workdir / "pdns.conf"
    conf_path.write_text(
        "launch=gsqlite3\n"
        f"gsqlite3-database={db_path}\n"
        "local-address=127.0.0.1\n"
        f"local-port={port}\n"
        "disable-axfr=yes\n"
        # Relative, with cwd=workdir on the server Popen call below --
        # not the absolute workdir path, which can exceed a UNIX domain
        # socket's sun_path length limit (~104-108 bytes) once nested
        # under a long temp/scratch directory.
        "socket-dir=.\n"
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

    proc = subprocess.Popen(
        ["pdns_server", f"--config-dir={workdir}", "--daemon=no", "--guardian=no"],
        cwd=workdir,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        probe_apex = next(iter(zones))
        _wait_for_server_ready(port, probe_apex, timeout=startup_timeout)
        mismatches: list[str] = []
        for zone in zones.values():
            for owner, type_map in zone.records.items():
                for rtype, values in type_map.items():
                    if rtype == "soa":
                        continue  # SOA content round-trips through pdns's own serial handling; not asserted here.
                    answers = _dig(owner, rtype.upper(), port, timeout=query_timeout)
                    mismatch = _describe_mismatch(owner, rtype, values, answers)
                    if mismatch is not None:
                        mismatches.append(mismatch)
        return mismatches
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=startup_timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=startup_timeout)


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


def _wait_for_server_ready(port: int, probe_name: str, *, timeout: float) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if _dig(probe_name, "SOA", port, timeout=1.0):
            return
        time.sleep(0.2)
    raise RuntimeError(f"pdns_server on 127.0.0.1:{port} did not come up within {timeout}s")
