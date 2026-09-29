"""GET /pki/status -- read-only view of the client CA (#161): CA and CRL
status, every issued certificate, and the catalog vhosts that require
client certificates. See app.client_pki_view.

Read-only by design: issuing and revoking stay with scripts/client-pki on
the host (docs/client-pki.md, "Web UI").
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException

from app.catalog_checks import load_catalog
from app.catalog_health_settings import client_pki_store, enforce_host_guard, services_json_path, timeout_seconds
from app.client_pki_view import load_pki_status

router = APIRouter(prefix="/pki", tags=["pki"])


@router.get("/status")
def get_pki_status() -> dict:
    if not enforce_host_guard("pki-view-api"):
        raise HTTPException(
            status_code=503,
            detail="this host is not the designated home-warden host (see scripts/lib/host-guard)",
        )
    try:
        services = load_catalog(services_json_path()).get("services") or []
    except FileNotFoundError:
        # The CA status stands on its own; a host with no catalog yet just
        # has no vhosts to list.
        services = []
    except ValueError as e:
        raise HTTPException(status_code=500, detail=str(e)) from e
    return load_pki_status(client_pki_store(), services, timeout=timeout_seconds())
