"""GET /dns/records -- read-only view of local PowerDNS (#108) + external
Cloudflare (#109) DNS records for every catalog service (#111).

Cross-references each service's upstream.host (local) and server_name
(external) against what's actually registered, presenting the same gap
#57's health check already flags as real record data instead of a
pass/fail. Read-only: this route never writes to zones.yml or Cloudflare.
"""

from __future__ import annotations

import ipaddress

from fastapi import APIRouter, HTTPException

from app.catalog_checks import list_cloudflare_records, load_catalog, parse_cloudflare_credentials
from app.catalog_health_settings import (
    cloudflare_credentials_path,
    enforce_host_guard,
    max_retries,
    pdns_zones_yaml_path,
    services_json_path,
    timeout_seconds,
)
from app.dns_zones_view import load_zones_yaml, local_records_for_owner

router = APIRouter(prefix="/dns", tags=["dns"])


@router.get("/records")
def get_dns_records() -> dict:
    if not enforce_host_guard("dns-view-api"):
        raise HTTPException(
            status_code=503,
            detail="this host is not the designated home-warden host (see scripts/lib/host-guard)",
        )

    try:
        catalog = load_catalog(services_json_path())
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e)) from e
    except ValueError as e:
        raise HTTPException(status_code=500, detail=str(e)) from e

    try:
        cf_headers = parse_cloudflare_credentials(cloudflare_credentials_path())
    except ValueError:
        # A malformed cloudflare.ini must not take down the local-records
        # half of this page -- report external records as not configured
        # rather than 500ing the whole view.
        cf_headers = None

    zones_data = load_zones_yaml(pdns_zones_yaml_path())
    timeout = timeout_seconds()
    retries = max_retries()

    services = [
        _service_dns_entry(service, zones_data=zones_data, cf_headers=cf_headers, timeout=timeout, max_retries=retries)
        for service in catalog.get("services") or []
    ]
    return {"services": services}


def _service_dns_entry(
    service: dict, *, zones_data: dict, cf_headers: dict[str, str] | None, timeout: float, max_retries: int
) -> dict:
    # Matches run_all's own service.get("name", "<unnamed>") default --
    # load_catalog doesn't require a "name" key, and a raw None here
    # crashes the web UI's client-side sort.
    name = service.get("name", "<unnamed>")
    server_name = service.get("server_name")
    upstream = service.get("upstream") or {}
    host = upstream.get("host")

    return {
        "name": name,
        "server_name": server_name,
        "upstream_host": host,
        "local": _local_record_set(host, zones_data),
        "external": _external_record_set(server_name, cf_headers, timeout, max_retries),
    }


def _external_record_set(
    domain: str | None, cf_headers: dict[str, str] | None, timeout: float, max_retries: int
) -> dict:
    if not domain:
        return {"status": "not_applicable", "records": None, "detail": None}
    if cf_headers is None:
        return {"status": "not_configured", "records": None, "detail": None}
    try:
        records = list_cloudflare_records(domain, cf_headers, timeout, max_retries)
    except Exception as e:
        # Distinct from "missing" (a genuine absent record) -- an auth
        # failure or a persistent 5xx must not read as a DNS gap.
        return {"status": "error", "records": None, "detail": str(e)}
    if not records:
        return {"status": "missing", "records": None, "detail": None}
    return {"status": "ok", "records": records, "detail": None}


def _local_record_set(host: str | None, zones_data: dict) -> dict:
    if not host:
        return {"status": "not_applicable", "records": None, "detail": None}
    try:
        ipaddress.ip_address(host)
        # A literal IP needs no DNS at all -- mirrors check_local_dns's
        # own guard so this view doesn't contradict #57's semantics.
        return {"status": "not_applicable", "records": None, "detail": None}
    except ValueError:
        pass
    if not zones_data:
        return {"status": "not_configured", "records": None, "detail": None}
    records = local_records_for_owner(zones_data, host)
    if not records:
        # Folds a present-but-empty entries list (representable per
        # local_records_for_owner's own docstring) into "missing" too --
        # there's nothing to show either way, and the two must agree.
        return {"status": "missing", "records": None, "detail": None}
    return {"status": "ok", "records": records, "detail": None}
