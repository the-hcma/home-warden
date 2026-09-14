"""GET /health/catalog -- on-demand cert/DNS/internal-upstream validation.

For the future web UI (the-hcma/home-warden#55) and ad-hoc querying;
scripts/catalog-health-check (app.catalog_health_cli) is the one-shot/timer
equivalent using the same app.catalog_checks logic. Read-only, same as the
CLI -- see app/catalog_checks.py's module docstring for scope/non-goals.
"""

from __future__ import annotations

from dataclasses import asdict

from fastapi import APIRouter, HTTPException, Query

from app.catalog_checks import load_catalog, parse_cloudflare_credentials, run_all
from app.catalog_health_settings import (
    alert_days,
    certs_live_dir,
    cloudflare_credentials_path,
    enforce_host_guard,
    max_retries,
    services_json_path,
    timeout_seconds,
)

router = APIRouter(prefix="/health", tags=["health"])


@router.get("/catalog")
def get_catalog_health(
    skip_cert: bool = Query(False),
    skip_dns: bool = Query(False),
    skip_upstream: bool = Query(False),
) -> dict:
    if not enforce_host_guard("catalog-health-api"):
        raise HTTPException(
            status_code=503,
            detail="this host is not the designated home-warden host (see scripts/lib/host-guard)",
        )

    # One error boundary for the whole load-and-check flow (load_catalog,
    # parse_cloudflare_credentials, run_all -- and, via the arguments
    # evaluated in that same run_all(...) call, the env getters in
    # app.catalog_health_settings) rather than one try per call: the
    # 404/500 contract is decided once for this route, not re-litigated
    # call-by-call as new config inputs are added.
    try:
        catalog = load_catalog(services_json_path())
        cf_headers = None
        if not skip_dns:
            cf_headers = parse_cloudflare_credentials(cloudflare_credentials_path())
        results = run_all(
            catalog,
            certs_live_dir=certs_live_dir(),
            alert_days=alert_days(),
            cf_headers=cf_headers,
            timeout=timeout_seconds(),
            max_retries=max_retries(),
            skip_cert=skip_cert,
            skip_dns=skip_dns,
            skip_upstream=skip_upstream,
        )
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e)) from e
    except ValueError as e:
        raise HTTPException(status_code=500, detail=str(e)) from e

    healthy = not any(r.status == "fail" for r in results)
    return {"healthy": healthy, "checks": [asdict(r) for r in results]}
