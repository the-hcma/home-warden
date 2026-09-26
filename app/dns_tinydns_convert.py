"""Convert tinydns-format zone data (thehcma/home's `dns/data`) into
PowerDNS GeoIP-backend zone YAML, per the record mapping the-hcma/home#16
already worked out against the real file. See the-hcma/home-warden#108.

Implements exactly the tinydns line types #16 identified as actually used
-- SOA (`Z`), NS with optional glue A (`&`), A+PTR (`=`), A-only (`+`),
TXT (`'`), CNAME (`C`), and SRV via the generic record line (`:` type
`33`, octal-escaped wire rdata) -- and fails loudly on any other line
type rather than silently dropping data.

Each RR is placed under the longest-matching zone apex from the SOA (`Z`)
lines found in the file (mirrors app.catalog_checks.candidate_zone_names'
apex-first walk, but against a known, closed set of zones rather than a
live API).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

GENERIC_SRV_TYPE = "33"


@dataclass
class ParsedRecord:
    owner: str
    rtype: str  # "soa" | "ns" | "a" | "ptr" | "cname" | "txt" | "srv"
    content: str
    ttl: int | None = None
    # True for a record the source never wrote itself -- the PTR tinydns
    # derives from every `=` line. See bucket_into_zones for why that matters.
    implicit: bool = False


@dataclass(frozen=True)
class RecordValue:
    content: str
    # A line's own explicit ttl field, distinct from the zone's default --
    # None means "no per-record override was given," not "ttl is zero."
    ttl: int | None = None


@dataclass
class Zone:
    apex: str
    ttl: int
    # owner -> rtype -> list[RecordValue] (soa/cname are single-valued but
    # still stored as a one-element list; render_zones_yaml unwraps them).
    records: dict[str, dict[str, list[RecordValue]]] = field(default_factory=dict)


def bucket_into_zones(
    records: list[ParsedRecord],
    zone_apexes: list[str],
    dropped: list[ParsedRecord] | None = None,
) -> dict[str, Zone]:
    """Group parsed records under the longest-matching zone apex.

    `zone_apexes` must already be known (from the file's own SOA lines) --
    unlike app.catalog_checks.candidate_zone_names, this never probes an
    external source; it picks the best of a closed, given set. A record
    whose owner matches no known apex is an error: silently dropping it
    would produce a zone file missing data the source file clearly
    intended to serve.

    The one exception is an *implicit* record (the PTR an `=` line derives)
    whose reverse zone the file never defines: tinydns never served it
    authoritatively either, so it is left out rather than failing the whole
    conversion. Each one is appended to `dropped` (when given) so the caller
    can report it.

    Every zone's default ttl comes from its own SOA line -- there is no
    invented fallback constant. tinydns has its own default for a blank
    ttl field, but it isn't necessarily 3600 (an earlier version of this
    function assumed exactly that, unverified); rather than risk migrating
    every ttl-less record in a zone to a wrong, made-up number, a zone
    whose SOA carries no explicit ttl is a loud error here -- the same
    "don't silently invent or drop data" contract this module applies
    everywhere else.
    """
    soa_ttls: dict[str, int | None] = dict.fromkeys(zone_apexes)
    for rec in records:
        if rec.rtype == "soa" and rec.owner in soa_ttls and rec.ttl is not None:
            soa_ttls[rec.owner] = rec.ttl
    zone_default_ttls: dict[str, int] = {apex: ttl for apex, ttl in soa_ttls.items() if ttl is not None}
    missing_ttl = sorted(set(zone_apexes) - zone_default_ttls.keys())
    if missing_ttl:
        raise ValueError(f"zone(s) {missing_ttl} have an SOA line with no explicit ttl -- cannot derive a zone default")

    zones = {apex: Zone(apex=apex, ttl=zone_default_ttls[apex]) for apex in zone_apexes}
    sorted_apexes = sorted(zone_apexes, key=len, reverse=True)

    for rec in records:
        apex = _longest_matching_apex(rec.owner, sorted_apexes)
        if apex is None and rec.implicit:
            if dropped is not None:
                dropped.append(rec)
            continue
        if apex is None:
            raise ValueError(f"no zone apex matches owner {rec.owner!r} (known zones: {zone_apexes})")
        owner_records = zones[apex].records.setdefault(rec.owner, {})
        owner_records.setdefault(rec.rtype, []).append(RecordValue(rec.content, rec.ttl))

    return zones


def parse_tinydns_data(text: str) -> list[ParsedRecord]:
    """Parse tinydns data-file text into a flat list of records, in file
    order. Raises ValueError on any unrecognized line type/shape -- see
    module docstring for why this stays narrow rather than implementing
    the full tinydns-data(5) grammar.
    """
    records: list[ParsedRecord] = []
    for lineno, raw_line in enumerate(text.splitlines(), start=1):
        if not raw_line or raw_line.startswith("#"):
            continue
        try:
            records.extend(_parse_line(raw_line))
        except ValueError as e:
            raise ValueError(f"line {lineno}: {e}") from e
    return records


def render_pdns_conf(zones_yaml_path: str) -> str:
    """Render the pdns.conf snippet pointing at `zones_yaml_path`, per
    the-hcma/home#16's already-validated design: the authoritative
    `pdns_server` listens only on loopback:853 (never the public/LAN
    :53), plain `records:` only (no MaxMind/geo expansions --
    `geoip-database-files=` stays empty), and the *recursor* (unchanged,
    hand-maintained `dns/recursor.conf`) is what actually answers :53,
    forwarding queries for these authoritative zones to loopback:853.

    `local-address` covers both address families as a single
    comma-separated list (PowerDNS's own default is `0.0.0.0, ::`) --
    there is no separate IPv4-only/IPv6-only setting name for the
    authoritative server. Listing only an IPv4 loopback address here
    would leave IPv6 at that wildcard default, reachable on every
    interface on a dual-stack host -- confirmed by actually starting a
    real pdns_server both ways (a plausible-looking `local-ipv6=`
    setting an earlier version of this function tried is rejected
    outright: "Trying to set unknown setting 'local-ipv6'").
    """
    return (
        "# GENERATED by dns-tinydns-convert (the-hcma/home-warden#108) -- do not edit.\n"
        "launch=geoip\n"
        f"geoip-zones-file={zones_yaml_path}\n"
        "geoip-database-files=\n"
        "log-dns-details=yes\n"
        "log-dns-queries=yes\n"
        "loglevel=5\n"
        "local-address=127.0.0.1, ::1\n"
        "local-port=853\n"
    )


def render_zones_yaml(zones: dict[str, Zone]) -> str:
    """Render the PowerDNS GeoIP backend's zones.yml text (a top-level
    `domains:` list, one entry per zone) -- imported lazily so a caller
    that only needs parsing/bucketing (e.g. the sqlite-backend validator)
    doesn't need PyYAML installed.

    Each owner's records are a *list* of single-key `{type: content}`
    dicts -- one list entry per record instance, even when the same type
    repeats (two `ns:` entries stay two list items, never `ns: [a, b]`) --
    per the backend's actual documented schema
    (https://doc.powerdns.com/authoritative/backends/geoip.html), not the
    type-grouped-dict shape an earlier version of this function assumed.
    That assumption was wrong and shipped silently until
    .github/ci/dns-catalog-validate caught it against a real pdns_server
    (the backend answered every query with an empty response, not an
    error) -- exactly the class of mistake that CI job exists to catch.

    A `RecordValue` with its own explicit `ttl` (the tinydns line carried
    one) renders the backend's expanded per-record form
    (`{type: {content: ..., ttl: ...}}`) instead of the plain scalar --
    otherwise a source line's own ttl would silently collapse to the
    zone's single default `ttl:`, changing what's actually served.
    """
    import yaml

    domains = []
    for apex in sorted(zones):
        zone = zones[apex]
        owner_map: dict[str, list[dict[str, object]]] = {}
        for owner in sorted(zone.records):
            entries: list[dict[str, object]] = []
            for rtype in sorted(zone.records[owner]):
                for value in zone.records[owner][rtype]:
                    if value.ttl is not None:
                        entries.append({rtype: {"content": value.content, "ttl": value.ttl}})
                    else:
                        entries.append({rtype: value.content})
            owner_map[owner] = entries
        domains.append({"domain": apex, "ttl": zone.ttl, "records": owner_map})

    header = (
        "# GENERATED by dns-tinydns-convert (the-hcma/home-warden#108) -- do not edit.\n"
        "# Edit this file directly for ongoing changes (it is the source of truth going\n"
        "# forward, per #108); only the initial migration ran the converter.\n"
    )
    return header + yaml.safe_dump({"domains": domains}, sort_keys=False, default_flow_style=False)


def validate_zones_yaml_syntax(path: Path) -> dict:
    """Lightweight, offline check that `path` is well-formed GeoIP-backend
    YAML: valid YAML, a top-level mapping with a non-empty `domains` list,
    each entry a mapping carrying a non-empty string `domain`, plus `ttl`
    and `records`. Returns the parsed document; raises ValueError
    describing the first problem found.

    This is deliberately *not* the real acceptance test -- it catches a
    hand-edit typo/shape mistake (a missing colon, a renamed key) before
    `pdns_control reload` ever sees it, but cannot catch a deeper semantic
    mistake the way spinning up a real pdns_server does (the list-vs-dict
    records shape bug this module shipped with initially, for instance,
    was syntactically valid YAML). For that, see
    app.dns_zone_validate.validate_via_sqlite_backend (local dev/CI) or
    .github/ci/dns-catalog-validate (the real GeoIP-backend acceptance
    test) -- this function is the fast, always-available gate
    scripts/pdns-test-and-reload runs before every live reload, not a
    replacement for either.
    """
    import yaml

    if not path.is_file():
        raise ValueError(f"missing file: {path}")
    try:
        data = yaml.safe_load(path.read_text())
    except OSError as e:
        raise ValueError(f"cannot read {path}: {e}") from e
    except yaml.YAMLError as e:
        raise ValueError(f"invalid YAML in {path}: {e}") from e
    if not isinstance(data, dict):
        raise ValueError(f"{path}: top-level YAML must be a mapping, got {type(data).__name__}")
    domains = data.get("domains")
    if not isinstance(domains, list) or not domains:
        raise ValueError(f"{path}: missing or empty top-level 'domains' list")
    for i, entry in enumerate(domains):
        if not isinstance(entry, dict):
            raise ValueError(f"{path}: domains[{i}] must be a mapping, got {type(entry).__name__}")
        for key in ("domain", "ttl", "records"):
            if key not in entry:
                raise ValueError(f"{path}: domains[{i}] missing required key {key!r}")
        if not isinstance(entry["domain"], str) or not entry["domain"].strip("."):
            raise ValueError(f"{path}: domains[{i}].domain must be a non-empty string")
        if not isinstance(entry["records"], dict):
            raise ValueError(f"{path}: domains[{i}].records must be a mapping")
    return data


def zone_apexes_from_records(records: list[ParsedRecord]) -> list[str]:
    """SOA (`Z`) records define the zones -- collect their owners, in the
    order first seen, so bucketing has a closed set to match against.
    """
    return [rec.owner for rec in records if rec.rtype == "soa"]


def _decode_srv_rdata(field_text: str) -> str:
    data = _decode_tinydns_escapes(field_text)
    if len(data) < 7:
        raise ValueError(f"SRV rdata too short ({len(data)} bytes)")
    priority = (data[0] << 8) | data[1]
    weight = (data[2] << 8) | data[3]
    port = (data[4] << 8) | data[5]
    target, _ = _decode_wire_name(data, 6)
    return f"{priority} {weight} {port} {target}"


def _decode_tinydns_escapes(field_text: str) -> bytes:
    """Decode tinydns's `\\NNN` (exactly 3 octal digits) byte escapes.
    Any other character is its own literal byte -- matches tinydns-data's
    own escaping convention for TXT content and generic-record rdata.
    """
    out = bytearray()
    i, n = 0, len(field_text)
    while i < n:
        if field_text[i] == "\\" and i + 4 <= n and all(c in "01234567" for c in field_text[i + 1 : i + 4]):
            out.append(int(field_text[i + 1 : i + 4], 8))
            i += 4
        else:
            out.append(ord(field_text[i]) & 0xFF)
            i += 1
    return bytes(out)


def _decode_wire_name(data: bytes, offset: int) -> tuple[str, int]:
    """Decode a DNS wire-format name (length-prefixed labels, zero-length
    root label terminator; no compression pointers -- tinydns's generic
    records never emit those) starting at `offset`. Returns (name, the
    offset just past the terminating zero byte).
    """
    labels: list[str] = []
    i = offset
    while True:
        if i >= len(data):
            raise ValueError("truncated wire-format name")
        length = data[i]
        i += 1
        if length == 0:
            break
        if i + length > len(data):
            raise ValueError("truncated wire-format name (label runs past end of rdata)")
        labels.append(data[i : i + length].decode("ascii"))
        i += length
    return ".".join(labels) + ".", i


def _ensure_trailing_dot(name: str) -> str:
    return name if name.endswith(".") else f"{name}."


def _longest_matching_apex(owner: str, sorted_apexes: list[str]) -> str | None:
    for apex in sorted_apexes:
        if owner == apex or owner.endswith(f".{apex}"):
            return apex
    return None


def _optional_ttl(fields: list[str], index: int) -> int | None:
    if len(fields) > index and fields[index]:
        return int(fields[index])
    return None


def _parse_a(fields: list[str]) -> ParsedRecord:
    if len(fields) < 2:
        raise ValueError(f"'+' (A) line needs fqdn:ip, got {fields!r}")
    fqdn, ip = fields[0], fields[1]
    return ParsedRecord(owner=fqdn, rtype="a", content=ip, ttl=_optional_ttl(fields, 2))


def _parse_a_and_ptr(fields: list[str]) -> list[ParsedRecord]:
    if len(fields) < 2:
        raise ValueError(f"'=' (A+PTR) line needs fqdn:ip, got {fields!r}")
    fqdn, ip = fields[0], fields[1]
    ttl = _optional_ttl(fields, 2)
    ptr_owner = _reverse_dns_owner(ip)
    return [
        ParsedRecord(owner=fqdn, rtype="a", content=ip, ttl=ttl),
        ParsedRecord(owner=ptr_owner, rtype="ptr", content=_ensure_trailing_dot(fqdn), ttl=ttl, implicit=True),
    ]


def _parse_cname(fields: list[str]) -> ParsedRecord:
    if len(fields) < 2:
        raise ValueError(f"'C' (CNAME) line needs fqdn:target, got {fields!r}")
    fqdn, target = fields[0], fields[1]
    return ParsedRecord(owner=fqdn, rtype="cname", content=_ensure_trailing_dot(target), ttl=_optional_ttl(fields, 2))


def _parse_generic(fields: list[str]) -> ParsedRecord:
    if len(fields) < 3:
        raise ValueError(f"':' (generic) line needs fqdn:type:rdata, got {fields!r}")
    fqdn, rtype_num, rdata = fields[0], fields[1], fields[2]
    if rtype_num != GENERIC_SRV_TYPE:
        raise ValueError(f"unsupported generic record type {rtype_num!r} for {fqdn!r} (only SRV/33 is handled)")
    return ParsedRecord(owner=fqdn, rtype="srv", content=_decode_srv_rdata(rdata), ttl=_optional_ttl(fields, 3))


def _parse_line(line: str) -> list[ParsedRecord]:
    prefix, rest = line[0], line[1:]
    fields = rest.split(":")

    if prefix == "Z":
        return [_parse_soa(fields)]
    if prefix == "&":
        return _parse_ns(fields)
    if prefix == "=":
        return _parse_a_and_ptr(fields)
    if prefix == "+":
        return [_parse_a(fields)]
    if prefix == "'":
        return [_parse_txt(fields)]
    if prefix == "C":
        return [_parse_cname(fields)]
    if prefix == ":":
        return [_parse_generic(fields)]

    raise ValueError(f"unrecognized tinydns line type {prefix!r}")


def _parse_ns(fields: list[str]) -> list[ParsedRecord]:
    if len(fields) < 3:
        raise ValueError(f"'&' (NS) line needs fqdn:ip:x, got {fields!r}")
    fqdn, ip, nameserver = fields[0], fields[1], fields[2]
    if not nameserver:
        raise ValueError(f"'&' (NS) line for {fqdn!r} has no nameserver hostname")
    ttl = _optional_ttl(fields, 3)
    out = [ParsedRecord(owner=fqdn, rtype="ns", content=_ensure_trailing_dot(nameserver), ttl=ttl)]
    if ip:
        out.append(ParsedRecord(owner=nameserver, rtype="a", content=ip, ttl=ttl))
    return out


def _parse_soa(fields: list[str]) -> ParsedRecord:
    if len(fields) < 8:
        raise ValueError(f"'Z' (SOA) line needs fqdn:mname:rname:ser:ref:ret:exp:min, got {fields!r}")
    fqdn = fields[0]
    mname, rname = _ensure_trailing_dot(fields[1]), _ensure_trailing_dot(fields[2])
    ser, ref, ret, exp, minimum = fields[3], fields[4], fields[5], fields[6], fields[7]
    content = f"{mname} {rname} {ser} {ref} {ret} {exp} {minimum}"
    return ParsedRecord(owner=fqdn, rtype="soa", content=content, ttl=_optional_ttl(fields, 8))


def _parse_txt(fields: list[str]) -> ParsedRecord:
    if len(fields) < 2:
        raise ValueError(f"''' (TXT) line needs fqdn:text, got {fields!r}")
    fqdn, encoded = fields[0], fields[1]
    text = _decode_tinydns_escapes(encoded).decode("utf-8")
    # PowerDNS's TXT `content` always includes the surrounding quotes as
    # literal characters (confirmed by actually running a converted
    # record through a real pdns_server, per #108 -- dig served back
    # `"HOUSE.HCMA"`, not `HOUSE.HCMA`, for a record built from an
    # unquoted content string). Escape backslashes first, then quotes, so
    # an already-escaped backslash doesn't get double-escaped by the
    # quote pass.
    quoted = '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'
    return ParsedRecord(owner=fqdn, rtype="txt", content=quoted, ttl=_optional_ttl(fields, 2))


def _reverse_dns_owner(ipv4: str) -> str:
    octets = ipv4.split(".")
    if len(octets) != 4:
        raise ValueError(f"not a dotted-quad IPv4 address: {ipv4!r}")
    return ".".join(reversed(octets)) + ".in-addr.arpa"
