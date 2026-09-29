"""Lint a PowerDNS GeoIP-backend zones.yml document for record-level
mistakes that are well-formed YAML but wrong DNS. See
the-hcma/home-warden#169.

Runs in two places: dns-tinydns-convert lints the zones.yml it just
rendered (so an import reports what it carried over from the tinydns
data file), and dns-zones-yaml-check lints a hand-edited zones.yml before
scripts/pdns-test-and-reload reloads it. Every finding is a `ZoneIssue`
carrying the fix; only a `blocking` one (a CNAME sharing its owner with
other data, which RFC 1034 section 3.6.2 forbids and resolvers disagree
about) stops a reload -- everything else is reported and served as is.

Expects a document that already passed
app.dns_tinydns_convert.validate_zones_yaml_syntax.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass


@dataclass(frozen=True)
class ZoneIssue:
    subject: str
    problem: str
    fix: str
    blocking: bool = False

    def __str__(self) -> str:
        marker = " [blocks reload]" if self.blocking else ""
        return f"{self.subject}: {self.problem}{marker} -- fix: {self.fix}"


def format_issues(tool: str, issues: list[ZoneIssue], *, note: str = "") -> str:
    """One warning block listing every issue, for printing once at the end
    of a run rather than interleaved with its progress output.
    """
    lines = [f"{tool}: WARNING: {len(issues)} issue(s) need attention{note}:"]
    lines.extend(f"  - {issue}" for issue in issues)
    return "\n".join(lines)


def lint_zones(doc: dict, previous: dict | None = None) -> list[ZoneIssue]:
    """Every issue in `doc`, in zone then owner order.

    `previous` is the last-served version of the same file; when given,
    a zone whose records changed without its SOA serial going up is
    flagged (a server or cache keyed on the serial keeps the old data).
    """
    zones = _collect(doc)
    issues: list[ZoneIssue] = []
    for apex, owners in zones.items():
        issues.extend(_lint_soa(apex, owners))
        for owner, entries in owners.items():
            issues.extend(_lint_owner(apex, owner, entries))
    issues.extend(_lint_address_pairs(zones))
    if previous is not None:
        issues.extend(_lint_serials(zones, _collect(previous)))
    return issues


_SOA_FIELDS = 7


def _collect(doc: dict) -> dict[str, dict[str, list[tuple[str, str]]]]:
    """apex -> owner -> [(rtype, content)], names lowercased without the
    trailing dot. A malformed record entry is kept as rtype "" so
    _lint_owner reports it instead of this raising.
    """
    zones: dict[str, dict[str, list[tuple[str, str]]]] = {}
    for entry in doc.get("domains") or []:
        apex = _name(entry["domain"])
        owners = zones.setdefault(apex, {})
        for owner, records in (entry.get("records") or {}).items():
            entries = owners.setdefault(_name(str(owner)), [])
            for record in records if isinstance(records, list) else [records]:
                entries.append(_record(record))
    return zones


def _ipv4_from_reverse(owner: str) -> str | None:
    labels = owner.removesuffix(".in-addr.arpa").split(".")
    if not owner.endswith(".in-addr.arpa") or len(labels) != 4:
        return None
    return ".".join(reversed(labels))


def _lint_address_pairs(zones: dict[str, dict[str, list[tuple[str, str]]]]) -> list[ZoneIssue]:
    """An A without a PTR, or a PTR without its A, when both sides are
    zones this file serves -- otherwise the other side lives elsewhere
    and isn't this file's to fix. An address with several names only
    needs one PTR, so an A is fine as long as its reverse owner has any.
    """
    apexes = sorted(zones, key=len, reverse=True)
    addresses: dict[str, set[str]] = {}
    pointers: dict[str, set[str]] = {}
    for owners in zones.values():
        for owner, entries in owners.items():
            for rtype, content in entries:
                if rtype == "a":
                    addresses.setdefault(owner, set()).add(content)
                elif rtype == "ptr":
                    pointers.setdefault(owner, set()).add(_name(content))

    issues: list[ZoneIssue] = []
    for owner in sorted(addresses):
        for ip in sorted(addresses[owner]):
            reverse = ".".join(reversed(ip.split("."))) + ".in-addr.arpa"
            reverse_zone = _zone_of(reverse, apexes)
            if reverse_zone is not None and reverse not in pointers:
                issues.append(
                    ZoneIssue(
                        owner,
                        f"A {ip} has no PTR, though its reverse zone {reverse_zone} is served here",
                        f"add `ptr: {owner}.` under {reverse} in zone {reverse_zone}",
                    )
                )
    for owner in sorted(pointers):
        ip = _ipv4_from_reverse(owner)
        if ip is None:
            continue
        for target in sorted(pointers[owner]):
            if _zone_of(target, apexes) is not None and ip not in addresses.get(target, set()):
                issues.append(
                    ZoneIssue(
                        owner,
                        f"PTR points at {target}, which has no A {ip}",
                        f"add `a: {ip}` under {target}, or point the PTR at the name that has it",
                    )
                )
    return issues


def _lint_owner(apex: str, owner: str, entries: list[tuple[str, str]]) -> list[ZoneIssue]:
    issues: list[ZoneIssue] = []
    if owner != apex and not owner.endswith(f".{apex}"):
        issues.append(
            ZoneIssue(
                owner,
                f"is listed under zone {apex} but isn't inside it, so it's never answered",
                f"move it to the zone that contains {owner}, or rename it into {apex}",
            )
        )
    if any(rtype == "" for rtype, _ in entries):
        issues.append(
            ZoneIssue(
                owner,
                "has a record entry that isn't a single `type: content` mapping",
                "write each record as its own list item, e.g. `- a: 192.0.2.1`",
            )
        )
    types = Counter(rtype for rtype, _ in entries if rtype)
    if types["cname"] and types.total() > 1:
        others = sorted(set(types) - {"cname"})
        problem = f"has {types['cname']} CNAMEs" if not others else f"has a CNAME alongside {', '.join(others)} records"
        issues.append(
            ZoneIssue(
                owner,
                f"{problem} (RFC 1034 section 3.6.2 allows a CNAME only on its own)",
                "keep either the single CNAME or the other records at this name, not both",
                blocking=True,
            )
        )
    for (rtype, content), count in sorted(Counter(e for e in entries if e[0]).items()):
        if count > 1:
            issues.append(
                ZoneIssue(owner, f"lists {rtype} {content} {count} times", f"remove the extra {rtype} entries")
            )
    return issues


def _lint_serials(
    zones: dict[str, dict[str, list[tuple[str, str]]]],
    previous: dict[str, dict[str, list[tuple[str, str]]]],
) -> list[ZoneIssue]:
    issues: list[ZoneIssue] = []
    for apex in sorted(zones.keys() & previous.keys()):
        new_serial, old_serial = _serial(zones[apex], apex), _serial(previous[apex], apex)
        if new_serial is None or old_serial is None or new_serial > old_serial:
            continue
        if _without_soa(zones[apex]) != _without_soa(previous[apex]):
            issues.append(
                ZoneIssue(
                    apex,
                    f"records changed but the SOA serial didn't go up (was {old_serial}, now {new_serial})",
                    f"set the serial above {old_serial}, e.g. today's date as YYYYMMDDnn",
                )
            )
    return issues


def _lint_soa(apex: str, owners: dict[str, list[tuple[str, str]]]) -> list[ZoneIssue]:
    issues: list[ZoneIssue] = []
    for owner, entries in owners.items():
        if owner != apex and any(rtype == "soa" for rtype, _ in entries):
            issues.append(ZoneIssue(owner, f"has an SOA but isn't the apex of zone {apex}", "remove this SOA"))
    soas = [content for rtype, content in owners.get(apex, []) if rtype == "soa"]
    if not soas:
        return [
            *issues,
            ZoneIssue(
                apex,
                "zone has no SOA at its apex, so the server won't answer for it",
                f"add `soa: <mname> <rname> <serial> <refresh> <retry> <expire> <minimum>` under {apex}",
            ),
        ]
    if len(soas) > 1:
        issues.append(ZoneIssue(apex, f"zone has {len(soas)} SOA records", "keep exactly one SOA at the apex"))
    fields = soas[0].split()
    if len(fields) != _SOA_FIELDS:
        issues.append(
            ZoneIssue(
                apex,
                f"SOA has {len(fields)} fields, needs {_SOA_FIELDS} (mname rname serial refresh retry expire minimum)",
                "fill in every SOA field; a tinydns Z line with an empty serial leaves one out",
            )
        )
    return issues


def _name(name: str) -> str:
    return name.strip().rstrip(".").lower()


def _record(record: object) -> tuple[str, str]:
    if not isinstance(record, dict) or len(record) != 1:
        return ("", "")
    ((rtype, value),) = record.items()
    if isinstance(value, dict):
        value = value.get("content", "")
    return (str(rtype).lower(), str(value).strip())


def _serial(owners: dict[str, list[tuple[str, str]]], apex: str) -> int | None:
    for rtype, content in owners.get(apex, []):
        fields = content.split()
        if rtype == "soa" and len(fields) == _SOA_FIELDS and fields[2].isdigit():
            return int(fields[2])
    return None


def _without_soa(owners: dict[str, list[tuple[str, str]]]) -> dict[str, list[tuple[str, str]]]:
    return {owner: sorted(e for e in entries if e[0] != "soa") for owner, entries in owners.items()}


def _zone_of(name: str, apexes_longest_first: list[str]) -> str | None:
    for apex in apexes_longest_first:
        if name == apex or name.endswith(f".{apex}"):
            return apex
    return None
