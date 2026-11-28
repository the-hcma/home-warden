"""Sync one Cloudflare name to a set of addresses (#277): round-robin A or AAAA records.

`sync_dns_record` writes one address per name and refuses a name that already has several. This reconciles
the name's records to a set of addresses of one family, and never deletes: a record that is not wanted is
moved (PATCH) onto a wanted address that is missing, and any address still missing is created. A name with
more unwanted records than missing addresses fails and names them, for a human to remove -- or, for a
restore (`allow_extra`), is reported as "manual" after everything else was put back.
"""

from __future__ import annotations

import ipaddress
import urllib.parse

from app.catalog_checks import (
    CF_API_BASE,
    SyncResult,
    _cf_request,
    _resolve_via_authoritative_ns,
    candidate_zone_names,
)


def parse_address_set(targets: list[str]) -> tuple[str, list[str]]:
    """(record type, canonical addresses without duplicates, in the order given). Raises ValueError for a
    name or CNAME target, an empty list, or a mix of IPv4 and IPv6: a set is all A or all AAAA."""
    if not targets:
        raise ValueError("no addresses given")
    addresses: list[str] = []
    versions: set[int] = set()
    for target in targets:
        try:
            parsed = ipaddress.ip_address(target.strip())
        except ValueError:
            raise ValueError(f"{target!r} is not an IP address (a set of addresses cannot hold a host name)") from None
        versions.add(parsed.version)
        if str(parsed) not in addresses:
            addresses.append(str(parsed))
    if len(versions) > 1:
        raise ValueError(f"{', '.join(addresses)}: IPv4 and IPv6 addresses cannot be mixed in one set")
    return ("AAAA" if versions == {6} else "A"), addresses


def sync_dns_address_set(
    name: str,
    service: dict,
    targets: list[str],
    cf_headers: dict[str, str] | None,
    timeout: float,
    max_retries: int,
    *,
    proxied: bool = False,
    dry_run: bool = False,
    verify_resolution: bool = True,
    ttl: int | None = None,
    allow_extra: bool = False,
) -> SyncResult:
    """Reconcile the A/AAAA records of `service["server_name"]` to exactly `targets` (see the module doc).

    Statuses are the ones `sync_dns_record` uses, plus "manual" when `allow_extra` left unwanted records."""
    domain = service.get("server_name")
    if not domain:
        return SyncResult(name, "skip", "no server_name on this catalog entry")
    if cf_headers is None:
        return SyncResult(name, "skip", "no Cloudflare credentials configured")
    try:
        record_type, wanted = parse_address_set(targets)
    except ValueError as e:
        return SyncResult(name, "failed", str(e))

    zone_id: str | None = None
    zone_name = ""
    nameservers: list[str] = []
    rec_url = ""
    existing: list[dict] = []
    try:
        for candidate in candidate_zone_names(domain):
            zone_url = f"{CF_API_BASE}/zones?name={urllib.parse.quote(candidate)}"
            zone_results = _cf_request(zone_url, cf_headers, timeout, max_retries).get("result") or []
            if not zone_results:
                continue
            zone_id = zone_results[0]["id"]
            zone_name = candidate
            nameservers = zone_results[0].get("name_servers") or []
            rec_url = f"{CF_API_BASE}/zones/{zone_id}/dns_records?name={urllib.parse.quote(domain)}"
            rec_data = _cf_request(rec_url, cf_headers, timeout, max_retries)
            existing = [r for r in (rec_data.get("result") or []) if r.get("type") in ("A", "AAAA", "CNAME")]
            if existing:
                break
    except Exception as e:
        return SyncResult(name, "failed", f"Cloudflare lookup error: {e}")
    if zone_id is None:
        return SyncResult(name, "failed", f"no Cloudflare zone found for {domain}")

    other_type = [r for r in existing if r.get("type") != record_type]
    if other_type:
        kinds = ", ".join(f"{r['type']}={r.get('content')}" for r in other_type)
        return SyncResult(
            name,
            "failed",
            f"existing {kinds} record for {domain} has a different type than {record_type} -- "
            "refusing to replace it automatically",
        )
    have = [r for r in existing if r.get("type") == record_type]

    # The first record holding each wanted address stays; every other record is spare (a duplicate or unwanted).
    kept: dict[str, dict] = {}
    spare: list[dict] = []
    for record in have:
        content = record.get("content")
        if content in wanted and content not in kept:
            kept[str(content)] = record
        else:
            spare.append(record)
    missing = [address for address in wanted if address not in kept]
    moves = list(zip(spare, missing))
    creates = missing[len(moves) :]
    leftover = spare[len(moves) :]
    if leftover and not allow_extra:
        extra = ", ".join(str(r.get("content")) for r in leftover)
        return SyncResult(
            name,
            "failed",
            f"{len(leftover)} existing {record_type} record(s) for {domain} are not wanted ({extra}) and there is no "
            "address to move them to -- refusing to delete; remove them by hand",
        )
    retag = [
        r
        for r in kept.values()
        if bool(r.get("proxied", False)) != proxied or (ttl is not None and r.get("ttl") != ttl)
    ]

    steps = (
        [f"move {r.get('content')} -> {address}" for r, address in moves]
        + [f"create {address}" for address in creates]
        + [f"adjust {r.get('content')}" for r in retag]
    )
    left_note = ""
    if leftover:
        left_note = f"; {len(leftover)} other record(s) remain: " + ", ".join(str(r.get("content")) for r in leftover)
    if not steps:
        if leftover:
            return SyncResult(
                name, "manual", f"{record_type}={', '.join(wanted)} present for {domain}{left_note}: delete by hand"
            )
        return SyncResult(name, "noop", f"{record_type}={', '.join(wanted)} already correct in zone {zone_name}")
    if dry_run:
        verb = "would-update" if (moves or retag) else "would-create"
        return SyncResult(
            name, verb, f"{record_type} {domain} -> {', '.join(wanted)} in zone {zone_name}: {'; '.join(steps)}"
        )

    body_extra: dict[str, object] = {"proxied": proxied}
    if ttl is not None:
        body_extra["ttl"] = ttl
    try:
        for record, address in moves:
            url = f"{CF_API_BASE}/zones/{zone_id}/dns_records/{record['id']}"
            _cf_request(url, cf_headers, timeout, max_retries, method="PATCH", data={"content": address, **body_extra})
        for record in retag:
            url = f"{CF_API_BASE}/zones/{zone_id}/dns_records/{record['id']}"
            _cf_request(url, cf_headers, timeout, max_retries, method="PATCH", data=body_extra)
        for address in creates:
            url = f"{CF_API_BASE}/zones/{zone_id}/dns_records"
            data = {"type": record_type, "name": domain, "content": address, **body_extra}
            _cf_request(url, cf_headers, timeout, 1, method="POST", data=data)  # one attempt: a POST is not idempotent
    except Exception as e:
        return SyncResult(name, "failed", f"Cloudflare write failed part way ({'; '.join(steps)}): {e}")

    try:
        confirm = _cf_request(rec_url, cf_headers, timeout, max_retries)
    except Exception as e:
        return SyncResult(name, "failed", f"write accepted but read-back failed: {e}")
    present = {r.get("content") for r in (confirm.get("result") or []) if r.get("type") == record_type}
    absent = [address for address in wanted if address not in present]
    if absent:
        return SyncResult(
            name, "failed", f"write accepted but {record_type}={', '.join(absent)} not found on read-back"
        )

    if verify_resolution and nameservers and not proxied:
        answers = _resolve_via_authoritative_ns(domain, record_type, nameservers[0], timeout)
        if answers is not None:
            answered = {a.rstrip(".") for a in answers}
            not_answered = [address for address in wanted if address not in answered]
            if not_answered:
                return SyncResult(
                    name,
                    "failed",
                    f"write accepted and read back but {nameservers[0]} answers {answers}, "
                    f"missing {', '.join(not_answered)}",
                )

    verb = "updated" if (moves or retag) else "created"
    if leftover:
        return SyncResult(
            name, "manual", f"{verb} {record_type} {domain} -> {', '.join(wanted)}{left_note}: delete by hand"
        )
    return SyncResult(name, verb, f"{verb} {record_type} {domain} -> {', '.join(wanted)} in zone {zone_name}")
