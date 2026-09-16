"""CRUD and preview helpers for the service catalog web UI (#69).

Pure/catalog-focused logic only: no FastAPI imports here. The matching HTTP
surface lives in app.api.catalog_crud_routes.
"""

from __future__ import annotations

import copy
import difflib
import fcntl
import json
import os
import subprocess
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from app.catalog_checks import load_catalog
from app.catalog_health_settings import certs_live_dir, services_json_path
from app.catalog_render import RenderContext, render_catalog
from app.home_warden_config import catalog_with_web_ui_service, config_path, load_config

GIXY_SKIPS = "proxy_buffering_off,proxy_pass_normalized"
GIXY_TIMEOUT_SECONDS = 15
NGINX_PREVIEW_CATALOG_CONF_NAME = "catalog.conf"
NGINX_PREVIEW_CONF_NAME = "nginx.conf"
NGINX_PREVIEW_DIR_NAME = "web-ui-preview"
NGINX_PREVIEW_CONF_PATH_FILE = Path("/usr/local/etc/home-warden-preview-conf-path")
NGINX_TIMEOUT_SECONDS = 15
NGINX_TEST_HELPER = Path("/usr/local/sbin/home-warden-nginx-test-candidate")
REPO_ROOT = Path(__file__).resolve().parent.parent


class CatalogConflictError(ValueError):
    """Raised when a mutation would duplicate a unique service identifier."""


class CatalogNotFoundError(LookupError):
    """Raised when a requested service entry does not exist."""


class CatalogValidationError(ValueError):
    """Raised when a proposed service entry is malformed."""


@dataclass(frozen=True)
class GixyResult:
    exit_code: int | None
    output: str
    status: Literal["error", "findings", "ok"]


@dataclass(frozen=True)
class NginxTestResult:
    exit_code: int | None
    ok: bool
    output: str
    status: Literal["failed", "ok", "unavailable"]


@dataclass(frozen=True)
class PreviewResult:
    can_apply: bool
    diff: str
    gixy: GixyResult
    nginx_test: NginxTestResult
    rendered: str


def build_candidate_catalog(
    catalog: dict,
    action: Literal["create", "delete", "update"],
    *,
    name: str | None = None,
    service: dict | None = None,
    target: Literal["service", "stream"] = "service",
) -> dict:
    if target == "stream":
        if action == "create":
            if service is None:
                raise CatalogValidationError("stream payload is required for create")
            return create_stream(catalog, service)
        if action == "delete":
            if not name:
                raise CatalogValidationError("stream name is required for delete")
            return delete_stream(catalog, name)
        if action == "update":
            if not name:
                raise CatalogValidationError("stream name is required for update")
            if service is None:
                raise CatalogValidationError("stream payload is required for update")
            return update_stream(catalog, name, service)
        raise CatalogValidationError(f"unsupported catalog action {action!r}")

    if action == "create":
        if service is None:
            raise CatalogValidationError("service payload is required for create")
        return create_service(catalog, service)
    if action == "delete":
        if not name:
            raise CatalogValidationError("service name is required for delete")
        return delete_service(catalog, name)
    if action == "update":
        if not name:
            raise CatalogValidationError("service name is required for update")
        if service is None:
            raise CatalogValidationError("service payload is required for update")
        return update_service(catalog, name, service)
    raise CatalogValidationError(f"unsupported catalog action {action!r}")


def create_service(catalog: dict, service: dict) -> dict:
    validated = validate_service(service)
    services = _services(catalog)
    _ensure_unique_identifiers(services, validated)

    updated_catalog = copy.deepcopy(catalog)
    updated_catalog["services"] = [*(copy.deepcopy(entry) for entry in services), validated]
    return updated_catalog


def create_stream(catalog: dict, stream: dict) -> dict:
    validated = validate_stream(stream)
    streams = _streams(catalog)
    _ensure_unique_stream_identifiers(streams, validated)

    updated_catalog = copy.deepcopy(catalog)
    updated_catalog["streams"] = [*(copy.deepcopy(entry) for entry in streams), validated]
    return updated_catalog


def delete_stream(catalog: dict, name: str) -> dict:
    streams = _streams(catalog)
    index = _stream_index(streams, name)

    updated_catalog = copy.deepcopy(catalog)
    updated_catalog["streams"] = [copy.deepcopy(stream) for i, stream in enumerate(streams) if i != index]
    return updated_catalog


def get_stream(catalog: dict, name: str) -> dict:
    streams = _streams(catalog)
    return copy.deepcopy(streams[_stream_index(streams, name)])


def list_streams(catalog: dict) -> list[dict]:
    return [copy.deepcopy(stream) for stream in _streams(catalog)]


def update_stream(catalog: dict, name: str, stream: dict) -> dict:
    streams = _streams(catalog)
    index = _stream_index(streams, name)
    merged = _merge_dicts(streams[index], stream)
    validated = validate_stream(merged)
    _ensure_unique_stream_identifiers(streams, validated, skip_index=index)

    updated_catalog = copy.deepcopy(catalog)
    updated_streams = [copy.deepcopy(entry) for entry in streams]
    updated_streams[index] = validated
    updated_catalog["streams"] = updated_streams
    return updated_catalog


def validate_stream(stream: dict) -> dict:
    if not isinstance(stream, dict):
        raise CatalogValidationError(f"stream entry must be an object, got {type(stream).__name__}")

    candidate = copy.deepcopy(stream)
    candidate["name"] = _required_string(candidate, "name")
    name = candidate["name"]

    listen_port = candidate.get("listen_port")
    if not isinstance(listen_port, int) or isinstance(listen_port, bool) or not (1 <= listen_port <= 65535):
        raise CatalogValidationError(f"stream {name!r} listen_port must be an integer between 1 and 65535")

    upstream = candidate.get("upstream")
    if not isinstance(upstream, dict):
        raise CatalogValidationError(f"stream {name!r} requires an upstream object")

    host = upstream.get("host")
    if not isinstance(host, str) or not host.strip():
        raise CatalogValidationError(f"stream {name!r} upstream.host must be a non-empty string")

    port = upstream.get("port")
    if not isinstance(port, int) or isinstance(port, bool) or not (1 <= port <= 65535):
        raise CatalogValidationError(f"stream {name!r} upstream.port must be an integer between 1 and 65535")

    candidate["upstream"] = {"host": host.strip(), "port": port}
    return candidate


def delete_service(catalog: dict, name: str) -> dict:
    services = _services(catalog)
    index = _service_index(services, name)

    updated_catalog = copy.deepcopy(catalog)
    updated_catalog["services"] = [copy.deepcopy(service) for i, service in enumerate(services) if i != index]
    return updated_catalog


def get_service(catalog: dict, name: str) -> dict:
    services = _services(catalog)
    return copy.deepcopy(services[_service_index(services, name)])


def list_services(catalog: dict) -> list[dict]:
    return [copy.deepcopy(service) for service in _services(catalog)]


def load_catalog_file(path: Path | None = None) -> dict:
    return load_catalog(path or services_json_path())


def persist_catalog(catalog: dict, path: Path | None = None) -> None:
    target_path = path or services_json_path()
    write_path = target_path.resolve() if target_path.is_symlink() else target_path
    write_path.parent.mkdir(parents=True, exist_ok=True)

    fd, temp_name = tempfile.mkstemp(prefix=f".{write_path.name}.", suffix=".tmp", dir=write_path.parent)
    temp_path = Path(temp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as temp_file:
            temp_file.write(json.dumps(catalog, indent=2) + "\n")
            temp_file.flush()
            os.fsync(temp_file.fileno())
        os.replace(temp_path, write_path)
    except Exception:
        try:
            temp_path.unlink()
        except FileNotFoundError:
            pass
        raise


def render_preview(
    catalog: dict,
    *,
    current_catalog: dict | None = None,
    current_services_path: Path | None = None,
) -> PreviewResult:
    current_source = current_catalog if current_catalog is not None else load_catalog_file(current_services_path)

    rendered_current = _render_catalog_text(current_source)
    rendered_candidate = _render_catalog_text(catalog)
    diff = "".join(
        difflib.unified_diff(
            rendered_current.splitlines(keepends=True),
            rendered_candidate.splitlines(keepends=True),
            fromfile="current",
            tofile="candidate",
        )
    )

    with _preview_workspace():
        full_conf = _write_full_nginx_conf(rendered_candidate)
        nginx_result = _run_nginx_test()
        gixy_result = _run_gixy(full_conf)

    return PreviewResult(
        can_apply=nginx_result.ok,
        diff=diff,
        gixy=gixy_result,
        nginx_test=nginx_result,
        rendered=rendered_candidate,
    )


def update_service(catalog: dict, name: str, service: dict) -> dict:
    services = _services(catalog)
    index = _service_index(services, name)
    merged = _merge_dicts(services[index], service)
    validated = validate_service(merged)
    _ensure_unique_identifiers(services, validated, skip_index=index)

    updated_catalog = copy.deepcopy(catalog)
    updated_services = [copy.deepcopy(entry) for entry in services]
    updated_services[index] = validated
    updated_catalog["services"] = updated_services
    return updated_catalog


def validate_service(service: dict) -> dict:
    if not isinstance(service, dict):
        raise CatalogValidationError(f"service entry must be an object, got {type(service).__name__}")

    candidate = copy.deepcopy(service)
    candidate["kind"] = _required_string(candidate, "kind")
    candidate["name"] = _required_string(candidate, "name")
    candidate["server_name"] = _required_string(candidate, "server_name")
    kind = candidate["kind"]
    name = candidate["name"]

    _optional_bool(candidate, "forward_host_header")
    _optional_bool(candidate, "gzip")
    _optional_bool(candidate, "websocket")
    _optional_string_list(candidate, "allow_cidrs")
    _optional_object(candidate, "managed_by")

    client_cert = candidate.get("client_cert")
    if client_cert is not None:
        _validate_client_cert(client_cert, name)

    if kind == "proxy":
        _validate_proxy_service(candidate, name)
    elif kind == "static":
        _validate_static_service(candidate, name)
    else:
        raise CatalogValidationError(f"service {name!r} has unsupported kind {kind!r}")

    return candidate


def _combine_output(stdout: str, stderr: str) -> str:
    return "\n".join(part for part in (stdout.strip(), stderr.strip()) if part)


def _ensure_unique_identifiers(services: list[dict], service: dict, *, skip_index: int | None = None) -> None:
    for index, existing in enumerate(services):
        if skip_index is not None and index == skip_index:
            continue
        if existing.get("name") == service["name"]:
            raise CatalogConflictError(f"service name {service['name']!r} already exists")
        if existing.get("server_name") == service["server_name"]:
            raise CatalogConflictError(f"server_name {service['server_name']!r} already exists")


def _ensure_unique_stream_identifiers(streams: list[dict], stream: dict, *, skip_index: int | None = None) -> None:
    for index, existing in enumerate(streams):
        if skip_index is not None and index == skip_index:
            continue
        if existing.get("name") == stream["name"]:
            raise CatalogConflictError(f"stream name {stream['name']!r} already exists")
        if existing.get("listen_port") == stream["listen_port"]:
            raise CatalogConflictError(f"stream listen_port {stream['listen_port']!r} already exists")


def _merge_dicts(base: dict, updates: dict) -> dict:
    if not isinstance(updates, dict):
        raise CatalogValidationError(f"service update must be an object, got {type(updates).__name__}")

    merged = copy.deepcopy(base)
    for key, value in updates.items():
        if value is None:
            merged.pop(key, None)
            continue
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _merge_dicts(merged[key], value)
            continue
        merged[key] = copy.deepcopy(value)
    return merged


def _optional_bool(service: dict, field: str) -> None:
    value = service.get(field)
    if value is not None and not isinstance(value, bool):
        raise CatalogValidationError(f"service {service.get('name', '<unnamed>')!r} field {field!r} must be a boolean")


def _optional_object(service: dict, field: str) -> None:
    value = service.get(field)
    if value is not None and not isinstance(value, dict):
        raise CatalogValidationError(f"service {service.get('name', '<unnamed>')!r} field {field!r} must be an object")


def _optional_string(service: dict, field: str) -> None:
    value = service.get(field)
    if value is not None and (not isinstance(value, str) or not value.strip()):
        raise CatalogValidationError(
            f"service {service.get('name', '<unnamed>')!r} field {field!r} must be a non-empty string"
        )


def _optional_string_list(service: dict, field: str) -> None:
    value = service.get(field)
    if value is None:
        return
    if not isinstance(value, list) or not all(isinstance(entry, str) and entry.strip() for entry in value):
        raise CatalogValidationError(
            f"service {service.get('name', '<unnamed>')!r} field {field!r} must be a list of strings"
        )


def _render_catalog_text(catalog: dict) -> str:
    config = load_config(config_path())
    try:
        merged_catalog = catalog_with_web_ui_service(catalog, config)
        return render_catalog(merged_catalog, RenderContext(certs_live_dir=certs_live_dir()))
    except (KeyError, TypeError, ValueError) as exc:
        raise CatalogValidationError(f"malformed catalog: {exc!r}") from exc


def _required_string(service: dict, field: str) -> str:
    value = service.get(field)
    if not isinstance(value, str) or not value.strip():
        raise CatalogValidationError(
            f"service {service.get('name', '<unnamed>')!r} field {field!r} must be a non-empty string"
        )
    return value.strip()


def _default_preview_conf_path() -> Path:
    scratch_dir = os.environ.get("SCRATCH_DIR")
    base_dir = Path(scratch_dir) if scratch_dir else Path.home() / "scratch" / "home-warden"
    return base_dir / NGINX_PREVIEW_DIR_NAME / NGINX_PREVIEW_CONF_NAME


def _installed_preview_conf_path() -> Path | None:
    try:
        configured_path = NGINX_PREVIEW_CONF_PATH_FILE.read_text(encoding="utf-8").strip()
    except OSError:
        return None
    if not configured_path:
        return None
    preview_conf = Path(configured_path)
    if not preview_conf.is_absolute():
        return None
    return preview_conf


def _preview_full_conf_path() -> Path:
    return _installed_preview_conf_path() or _default_preview_conf_path()


def _preview_catalog_conf_path() -> Path:
    return _preview_runtime_dir() / NGINX_PREVIEW_CATALOG_CONF_NAME


def _preview_runtime_dir() -> Path:
    return _preview_full_conf_path().parent


@contextmanager
def _preview_workspace() -> Iterator[Path]:
    preview_dir = _preview_runtime_dir()
    preview_dir.mkdir(parents=True, exist_ok=True)

    lock_path = preview_dir / ".lock"
    with lock_path.open("a+", encoding="utf-8") as lock_file:
        fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
        try:
            yield preview_dir
        finally:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)


def _run_gixy(full_conf: Path) -> GixyResult:
    env = os.environ.copy()
    env["GIXY_SKIPS"] = GIXY_SKIPS
    try:
        proc = subprocess.run(
            ["uv", "run", "--group", "lint", "gixy", "-l", "--skips", GIXY_SKIPS, str(full_conf)],
            capture_output=True,
            cwd=REPO_ROOT,
            env=env,
            text=True,
            timeout=GIXY_TIMEOUT_SECONDS,
        )
    except FileNotFoundError as exc:
        return GixyResult(exit_code=None, output=f"gixy unavailable: {exc}", status="error")
    except subprocess.TimeoutExpired:
        return GixyResult(
            exit_code=None,
            output=f"gixy timed out after {GIXY_TIMEOUT_SECONDS}s while linting the candidate config",
            status="error",
        )

    output = _combine_output(proc.stdout, proc.stderr)
    if proc.returncode == 0:
        return GixyResult(exit_code=0, output=output, status="ok")
    if proc.returncode == 1:
        return GixyResult(exit_code=1, output=output, status="findings")
    return GixyResult(exit_code=proc.returncode, output=output or "gixy failed", status="error")


def _run_nginx_test() -> NginxTestResult:
    try:
        proc = subprocess.run(
            ["sudo", "-n", str(NGINX_TEST_HELPER)],
            capture_output=True,
            text=True,
            timeout=NGINX_TIMEOUT_SECONDS,
        )
    except FileNotFoundError as exc:
        return NginxTestResult(
            exit_code=None,
            ok=False,
            output=f"nginx preview helper unavailable: {exc}",
            status="unavailable",
        )
    except subprocess.TimeoutExpired:
        return NginxTestResult(
            exit_code=None,
            ok=False,
            output=f"nginx -t timed out after {NGINX_TIMEOUT_SECONDS}s while validating the candidate config",
            status="failed",
        )

    output = _combine_output(proc.stdout, proc.stderr)
    if proc.returncode != 0 and (
        "a password is required" in output or "not allowed to execute" in output or output.startswith("sudo:")
    ):
        return NginxTestResult(
            exit_code=proc.returncode,
            ok=False,
            output=(
                "nginx preview helper is not provisioned; re-run scripts/setup-service on the designated host.\n"
                f"{output}"
            ),
            status="unavailable",
        )
    return NginxTestResult(
        exit_code=proc.returncode,
        ok=proc.returncode == 0,
        output=output,
        status="ok" if proc.returncode == 0 else "failed",
    )


def _service_index(services: list[dict], name: str) -> int:
    for index, service in enumerate(services):
        if service.get("name") == name:
            return index
    raise CatalogNotFoundError(f"service {name!r} not found")


def _stream_index(streams: list[dict], name: str) -> int:
    for index, stream in enumerate(streams):
        if stream.get("name") == name:
            return index
    raise CatalogNotFoundError(f"stream {name!r} not found")


def _streams(catalog: dict) -> list[dict]:
    streams = catalog.get("streams")
    if streams is None:
        return []
    if not isinstance(streams, list):
        raise ValueError("catalog streams must be a list")
    return streams


def _services(catalog: dict) -> list[dict]:
    services = catalog.get("services")
    if not isinstance(services, list):
        raise ValueError("catalog is missing a top-level services list")
    return services


def _validate_catalog_uniqueness(catalog: dict) -> None:
    seen_names: set[str] = set()
    seen_server_names: set[str] = set()
    for service in _services(catalog):
        name = service.get("name")
        server_name = service.get("server_name")
        if isinstance(name, str):
            if name in seen_names:
                raise CatalogConflictError(f"service name {name!r} already exists")
            seen_names.add(name)
        if isinstance(server_name, str):
            if server_name in seen_server_names:
                raise CatalogConflictError(f"server_name {server_name!r} already exists")
            seen_server_names.add(server_name)


def _validate_client_cert(client_cert: object, service_name: str) -> None:
    if not isinstance(client_cert, dict):
        raise CatalogValidationError(f"service {service_name!r} field 'client_cert' must be an object")

    mode = client_cert.get("mode")
    if mode is not None and mode not in {"off", "optional", "required"}:
        raise CatalogValidationError(
            f"service {service_name!r} client_cert.mode must be 'off', 'optional', or 'required'"
        )

    allow_cn = client_cert.get("allow_cn")
    if allow_cn is not None and (
        not isinstance(allow_cn, list) or not all(isinstance(entry, str) and entry.strip() for entry in allow_cn)
    ):
        raise CatalogValidationError(f"service {service_name!r} client_cert.allow_cn must be a list of strings")

    for field in ("ca_bundle", "crl"):
        value = client_cert.get(field)
        if value is not None and (not isinstance(value, str) or not value.strip()):
            raise CatalogValidationError(f"service {service_name!r} client_cert.{field} must be a non-empty string")

    verify_depth = client_cert.get("verify_depth")
    if verify_depth is not None and (not isinstance(verify_depth, int) or verify_depth < 0):
        raise CatalogValidationError(
            f"service {service_name!r} client_cert.verify_depth must be a non-negative integer"
        )


def _validate_proxy_service(service: dict, service_name: str) -> None:
    upstream = service.get("upstream")
    if not isinstance(upstream, dict):
        raise CatalogValidationError(f"service {service_name!r} kind 'proxy' requires an upstream object")

    host = upstream.get("host")
    if not isinstance(host, str) or not host.strip():
        raise CatalogValidationError(f"service {service_name!r} upstream.host must be a non-empty string")

    port = upstream.get("port")
    if not isinstance(port, int) or not (1 <= port <= 65535):
        raise CatalogValidationError(f"service {service_name!r} upstream.port must be an integer between 1 and 65535")

    path = upstream.get("path")
    if path is not None and (not isinstance(path, str) or not path.startswith("/")):
        raise CatalogValidationError(f"service {service_name!r} upstream.path must be a string starting with '/'")

    scheme = upstream.get("scheme")
    if scheme is not None and scheme not in {"http", "https"}:
        raise CatalogValidationError(f"service {service_name!r} upstream.scheme must be 'http' or 'https'")


def _validate_static_service(service: dict, service_name: str) -> None:
    static = service.get("static")
    if not isinstance(static, dict):
        raise CatalogValidationError(f"service {service_name!r} kind 'static' requires a static object")

    root = static.get("root")
    if not isinstance(root, str) or not root.strip():
        raise CatalogValidationError(f"service {service_name!r} static.root must be a non-empty string")

    listing_path = static.get("listing_path")
    if listing_path is not None and (not isinstance(listing_path, str) or not listing_path.startswith("/")):
        raise CatalogValidationError(f"service {service_name!r} static.listing_path must start with '/'")


def _write_full_nginx_conf(rendered_candidate: str) -> Path:
    rendered_path = _preview_catalog_conf_path()
    full_conf = _preview_full_conf_path()

    _write_text_atomically(rendered_path, rendered_candidate)
    _write_text_atomically(
        full_conf,
        "\n".join(
            [
                "include /etc/nginx/modules-enabled/*.conf;",
                "worker_processes 1;",
                f"error_log {_preview_runtime_dir() / 'nginx-error.log'} warn;",
                f"pid {_preview_runtime_dir() / 'nginx.pid'};",
                "events {",
                "    worker_connections 64;",
                "}",
                f"include {rendered_path};",
                "",
            ]
        ),
    )
    return full_conf


def _write_text_atomically(path: Path, content: str) -> None:
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    temp_path = Path(temp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as temp_file:
            temp_file.write(content)
            temp_file.flush()
            os.fsync(temp_file.fileno())
        os.replace(temp_path, path)
    except Exception:
        try:
            temp_path.unlink()
        except FileNotFoundError:
            pass
        raise
