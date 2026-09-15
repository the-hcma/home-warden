"""Authenticated catalog CRUD + preview/apply routes for the web UI (#69)."""

from __future__ import annotations

from dataclasses import asdict
from typing import Any, Literal

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from app.catalog_crud import (
    CatalogConflictError,
    CatalogNotFoundError,
    CatalogValidationError,
    PreviewResult,
    build_candidate_catalog,
    create_service,
    delete_service,
    get_service,
    list_services,
    load_catalog_file,
    persist_catalog,
    render_preview,
    update_service,
)
from app.catalog_health_settings import enforce_host_guard, services_json_path


class CatalogMutationRequest(BaseModel):
    action: Literal["create", "delete", "update"]
    name: str | None = None
    service: dict[str, Any] | None = None


class ServicePayloadRequest(BaseModel):
    service: dict[str, Any]


router = APIRouter(prefix="/catalog", tags=["catalog"])


@router.post("/apply")
def apply_catalog_mutation(payload: CatalogMutationRequest) -> dict[str, Any]:
    _require_host_guard("catalog-apply-api")
    catalog_path = services_json_path()
    try:
        current_catalog = load_catalog_file(catalog_path)
        candidate_catalog = build_candidate_catalog(
            current_catalog,
            payload.action,
            name=payload.name,
            service=payload.service,
        )
        preview = render_preview(
            candidate_catalog,
            current_catalog=current_catalog,
            current_services_path=catalog_path,
        )
        if not preview.can_apply:
            raise HTTPException(status_code=409, detail=_blocking_apply_detail(preview))
        persist_catalog(candidate_catalog, catalog_path)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except CatalogNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except CatalogConflictError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except CatalogValidationError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc

    return _mutation_response(payload.action, candidate_catalog, payload.name, payload.service, preview)


@router.post("/services")
def create_catalog_service(payload: ServicePayloadRequest) -> dict[str, Any]:
    _require_host_guard("catalog-create-api")
    catalog_path = services_json_path()
    try:
        current_catalog = load_catalog_file(catalog_path)
        candidate_catalog = create_service(current_catalog, payload.service)
        preview = render_preview(
            candidate_catalog,
            current_catalog=current_catalog,
            current_services_path=catalog_path,
        )
        if not preview.can_apply:
            raise HTTPException(status_code=409, detail=_blocking_apply_detail(preview))
        persist_catalog(candidate_catalog, catalog_path)
        created_service = get_service(candidate_catalog, str(payload.service.get("name", "")))
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except CatalogNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except CatalogConflictError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except CatalogValidationError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc

    return {"preview": asdict(preview), "service": created_service}


@router.delete("/services/{name}")
def delete_catalog_service(name: str) -> dict[str, Any]:
    _require_host_guard("catalog-delete-api")
    catalog_path = services_json_path()
    try:
        current_catalog = load_catalog_file(catalog_path)
        candidate_catalog = delete_service(current_catalog, name)
        preview = render_preview(
            candidate_catalog,
            current_catalog=current_catalog,
            current_services_path=catalog_path,
        )
        if not preview.can_apply:
            raise HTTPException(status_code=409, detail=_blocking_apply_detail(preview))
        persist_catalog(candidate_catalog, catalog_path)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except CatalogNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except CatalogConflictError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except CatalogValidationError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc

    return {"deleted_name": name, "preview": asdict(preview)}


@router.get("/services/{name}")
def get_catalog_service(name: str) -> dict[str, Any]:
    _require_host_guard("catalog-get-api")
    catalog_path = services_json_path()
    try:
        catalog = load_catalog_file(catalog_path)
        service = get_service(catalog, name)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except CatalogNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc

    return {"service": service}


@router.get("/services")
def list_catalog_services() -> dict[str, list[dict]]:
    _require_host_guard("catalog-list-api")
    catalog_path = services_json_path()
    try:
        catalog = load_catalog_file(catalog_path)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    return {"services": list_services(catalog)}


@router.post("/preview")
def preview_catalog_mutation(payload: CatalogMutationRequest) -> dict[str, Any]:
    _require_host_guard("catalog-preview-api")
    catalog_path = services_json_path()
    try:
        current_catalog = load_catalog_file(catalog_path)
        candidate_catalog = build_candidate_catalog(
            current_catalog,
            payload.action,
            name=payload.name,
            service=payload.service,
        )
        preview = render_preview(
            candidate_catalog,
            current_catalog=current_catalog,
            current_services_path=catalog_path,
        )
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except CatalogNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except CatalogConflictError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except CatalogValidationError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc

    return asdict(preview)


@router.put("/services/{name}")
def update_catalog_service(name: str, payload: ServicePayloadRequest) -> dict[str, Any]:
    _require_host_guard("catalog-update-api")
    catalog_path = services_json_path()
    try:
        current_catalog = load_catalog_file(catalog_path)
        candidate_catalog = update_service(current_catalog, name, payload.service)
        preview = render_preview(
            candidate_catalog,
            current_catalog=current_catalog,
            current_services_path=catalog_path,
        )
        if not preview.can_apply:
            raise HTTPException(status_code=409, detail=_blocking_apply_detail(preview))
        persist_catalog(candidate_catalog, catalog_path)
        updated_name = payload.service.get("name")
        updated_service = get_service(candidate_catalog, updated_name if isinstance(updated_name, str) else name)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except CatalogNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except CatalogConflictError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except CatalogValidationError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc

    return {"preview": asdict(preview), "service": updated_service}


def _blocking_apply_detail(preview: PreviewResult) -> str:
    if preview.nginx_test.output:
        return preview.nginx_test.output
    return "nginx validation failed; refusing to apply the catalog change"


def _mutation_response(
    action: Literal["create", "delete", "update"],
    candidate_catalog: dict,
    name: str | None,
    service: dict[str, Any] | None,
    preview: PreviewResult,
) -> dict[str, Any]:
    response: dict[str, Any] = {"preview": asdict(preview)}
    if action == "delete":
        response["deleted_name"] = name
        return response

    service_name = service.get("name") if service else None
    target_name = service_name if isinstance(service_name, str) else name or ""
    response["service"] = get_service(candidate_catalog, target_name)
    return response


def _require_host_guard(caller: str) -> None:
    if not enforce_host_guard(caller):
        raise HTTPException(
            status_code=503,
            detail="this host is not the designated home-warden host (see scripts/lib/host-guard)",
        )
