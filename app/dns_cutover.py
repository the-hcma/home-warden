"""Reversible Cloudflare record moves for a host cutover (#190).

`catalog-dns-sync --target <new>` rewrites every catalog record, so before it writes anything the CLI
takes a snapshot of what those records were (`take_snapshot`), and `catalog-dns-sync --restore FILE`
puts them back (`restore_snapshot`). `find_stragglers` lists records in the same zones that still
point at the old target but aren't in the catalog, which a catalog-driven sync would leave behind.

A record the sync *created* (none existed before) is not deleted by a restore: it is reported, and
removing it is left to the operator. The snapshot is what the records were, not a transaction log.
"""

from __future__ import annotations

import datetime
import json
import os
import urllib.parse
from pathlib import Path

from app.catalog_checks import (
    CF_API_BASE,
    SyncResult,
    _cf_request,
    candidate_zone_names,
    list_cloudflare_records,
    sync_dns_record,
)

SNAPSHOT_VERSION = 1
# Hard bound on zone-listing pages, so a huge zone can't turn a report into an unbounded loop.
_MAX_PAGES = 20
_PER_PAGE = 100


def take_snapshot(services: list[dict], cf_headers: dict[str, str], timeout: float, max_retries: int) -> dict:
    """Read every catalog service's current A/AAAA/CNAME records. Raises on a Cloudflare error: a
    snapshot that silently missed a record would make the rollback look safe when it isn't."""
    entries: list[dict] = []
    for service in services:
        domain = service.get("server_name")
        if not domain:
            continue
        records = list_cloudflare_records(domain, cf_headers, timeout, max_retries)
        entries.append({"service": service.get("name", "<unnamed>"), "name": domain, "records": records or []})
    return {
        "version": SNAPSHOT_VERSION,
        "taken_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "entries": entries,
    }


def write_snapshot(path: Path, snapshot: dict) -> None:
    """Write `snapshot` as JSON, mode 0600, refusing to overwrite an existing file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(snapshot, f, indent=2)
        f.write("\n")


def load_snapshot(path: Path) -> dict:
    """Read and shape-check a snapshot file. Raises ValueError (or FileNotFoundError) when unusable."""
    try:
        data = json.loads(path.read_text())
    except json.JSONDecodeError as e:
        raise ValueError(f"{path}: not valid JSON: {e}") from e
    if not isinstance(data, dict) or data.get("version") != SNAPSHOT_VERSION:
        raise ValueError(f"{path}: not a version {SNAPSHOT_VERSION} dns-sync snapshot")
    entries = data.get("entries")
    if not isinstance(entries, list) or not all(
        isinstance(e, dict) and isinstance(e.get("name"), str) and isinstance(e.get("records"), list) for e in entries
    ):
        raise ValueError(f"{path}: malformed snapshot entries")
    return data


def restore_snapshot(
    snapshot: dict,
    cf_headers: dict[str, str],
    timeout: float,
    max_retries: int,
    *,
    dry_run: bool = False,
    verify_resolution: bool = True,
) -> list[SyncResult]:
    """Put each record back to its snapshotted content, proxied flag and TTL, via `sync_dns_record`
    (same read-back and resolution checks as the original write)."""
    results: list[SyncResult] = []
    for entry in snapshot["entries"]:
        service = str(entry.get("service") or entry["name"])
        records = entry["records"]
        if not records:
            results.append(
                SyncResult(service, "skip", f"no record existed for {entry['name']} before the sync; delete it by hand")
            )
            continue
        if len(records) > 1:
            results.append(
                SyncResult(service, "skip", f"{entry['name']} had {len(records)} records; restore them by hand")
            )
            continue
        rec = records[0]
        results.append(
            sync_dns_record(
                service,
                {"server_name": entry["name"]},
                str(rec.get("content")),
                cf_headers,
                timeout,
                max_retries,
                proxied=bool(rec.get("proxied", False)),
                dry_run=dry_run,
                verify_resolution=verify_resolution,
                ttl=rec.get("ttl") if isinstance(rec.get("ttl"), int) else None,
            )
        )
    return results


def find_stragglers(
    services: list[dict], old_target: str, cf_headers: dict[str, str], timeout: float, max_retries: int
) -> list[dict[str, object]]:
    """Records in the catalog services' zones whose content is `old_target` but whose name is not a
    catalog `server_name`: what a cutover would leave pointing at the old host. Read-only; raises on a
    Cloudflare error."""
    catalog_names = {s["server_name"] for s in services if s.get("server_name")}
    zones: dict[str, str] = {}  # zone id -> zone name
    for domain in sorted(catalog_names):
        for candidate in candidate_zone_names(domain):
            data = _cf_request(
                f"{CF_API_BASE}/zones?name={urllib.parse.quote(candidate)}", cf_headers, timeout, max_retries
            )
            found = data.get("result") or []
            if found:
                zones[found[0]["id"]] = candidate
    stragglers: list[dict[str, object]] = []
    for zone_id, zone_name in sorted(zones.items(), key=lambda kv: kv[1]):
        for page in range(1, _MAX_PAGES + 1):
            url = (
                f"{CF_API_BASE}/zones/{zone_id}/dns_records?content={urllib.parse.quote(old_target)}"
                f"&per_page={_PER_PAGE}&page={page}"
            )
            data = _cf_request(url, cf_headers, timeout, max_retries)
            for rec in data.get("result") or []:
                if rec.get("name") not in catalog_names:
                    stragglers.append(
                        {
                            "zone": zone_name,
                            "name": rec.get("name"),
                            "type": rec.get("type"),
                            "content": rec.get("content"),
                        }
                    )
            total_pages = (data.get("result_info") or {}).get("total_pages", 1)
            if page >= total_pages:
                break
    return stragglers
