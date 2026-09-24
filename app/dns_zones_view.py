"""Read-only local PowerDNS zones.yml reader for the web UI's DNS view
(#111). Parses the same GeoIP-backend YAML app.dns_tinydns_convert
produces/validates -- this module only reads it for display, it never
writes.
"""

from __future__ import annotations

from pathlib import Path

import yaml


def load_zones_yaml(path: Path) -> dict:
    """Returns {} for a missing file, unreadable/undecodable file, invalid
    YAML, or a non-mapping top level -- the DNS view degrades to "not
    configured" for every service rather than failing the whole page
    when local PowerDNS isn't set up on this host (mirrors #108's own
    opt-in design), or when a hand-edit has broken the file (that's
    `dns-zones-yaml-check`'s job to catch before reload, not this
    read-only view's).
    """
    if not path.is_file():
        return {}
    try:
        data = yaml.safe_load(path.read_text())
    except (yaml.YAMLError, OSError, UnicodeDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def local_records_for_owner(zones_data: dict, owner: str) -> list[dict[str, object]] | None:
    """Return `owner`'s records (flattened to `{type, content, ttl}`,
    resolving each record's own ttl to its zone's default when unset)
    from an already-loaded zones.yml dict, or None if `owner` isn't
    present in any zone -- distinct from an empty list, which would mean
    a real owner entry with zero record types (not something
    render_zones_yaml produces, but representable).
    """
    domains = zones_data.get("domains")
    if not isinstance(domains, list):
        return None
    for zone in domains:
        if not isinstance(zone, dict):
            continue
        records = zone.get("records")
        if not isinstance(records, dict) or owner not in records:
            continue
        entries = records[owner]
        if not isinstance(entries, list):
            continue
        zone_ttl = zone.get("ttl")
        result: list[dict[str, object]] = []
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            for rtype, value in entry.items():
                if isinstance(value, dict):
                    result.append({"type": rtype, "content": value.get("content"), "ttl": value.get("ttl", zone_ttl)})
                else:
                    result.append({"type": rtype, "content": value, "ttl": zone_ttl})
        return result
    return None
