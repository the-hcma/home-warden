"""Orchestrate one catalog service's local DNS, external DNS, cert, and
final nginx-render validation, in the dependency order a new service
actually needs (see the-hcma/home-warden#110):

  1. local_dns    -- verify the backend's internal name already resolves
                      via local PowerDNS (#108) -- never created here.
  2. upstream     -- verify the backend itself is actually reachable.
  3. external_dns -- create/update the public Cloudflare record (#109).
  4. cert         -- ensure a Let's Encrypt cert covers server_name, via
                      the existing scripts/cert-renewer, unchanged.
  5. nginx        -- final render/`nginx -t`/Gixy-Next validation against
                      the full catalog, via app.catalog_crud.render_preview
                      (the same pipeline the web UI's own catalog edits
                      already use). This module never deploys the
                      rendered output to the live served nginx.conf
                      itself -- see #110's own scope notes.

Each step is a fail-fast precondition for the next -- provisioning, not
auto-healing: a missing local DNS record or an unreachable backend stops
before ever touching external DNS/certs/nginx, and a failure reports what
to fix by hand rather than attempting a repair. `apply=False` (the
default) previews every step without changing anything -- confirm-first,
mirroring app.catalog_checks.sync_dns_record's own `dry_run`.
"""

from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass
from pathlib import Path

from app.catalog_checks import CheckResult, check_local_dns, check_upstream, sync_dns_record
from app.catalog_crud import CatalogNotFoundError, get_service, render_preview


@dataclass
class RegisterStepResult:
    step: str  # "local_dns" | "upstream" | "external_dns" | "cert" | "nginx" | "catalog"
    # "ok" | "skip" | "noop" | "created" | "updated" | "would-create" |
    # "would-update" | "would-apply" | "applied" | "failed" -- always
    # "failed" (never "fail") on any step, so a uniform
    # any(r.status == "failed" for r in results) works across the mixed
    # per-dimension vocabularies below.
    status: str
    detail: str


def register_service(
    name: str,
    catalog: dict,
    *,
    dns_target: str,
    cf_headers: dict[str, str] | None,
    certbot_domains_file: Path,
    cert_renewer: Path,
    services_json_path: Path,
    local_dns_port: int,
    timeout: float,
    max_retries: int,
    apply: bool,
    proxied: bool = False,
    cert_timeout: float = 600.0,
) -> list[RegisterStepResult]:
    results: list[RegisterStepResult] = []

    try:
        service = get_service(catalog, name)
    except CatalogNotFoundError as e:
        return [RegisterStepResult("catalog", "failed", str(e))]

    local_dns = _from_check_result(
        "local_dns", check_local_dns(name, service, local_dns_port=local_dns_port, timeout=timeout)
    )
    results.append(local_dns)
    if local_dns.status == "failed":
        return results

    upstream = _from_check_result("upstream", check_upstream(name, service, timeout))
    results.append(upstream)
    if upstream.status == "failed":
        return results

    dns_result = sync_dns_record(
        name, service, dns_target, cf_headers, timeout, max_retries, proxied=proxied, dry_run=not apply
    )
    external_dns = RegisterStepResult("external_dns", dns_result.status, dns_result.detail)
    results.append(external_dns)
    if external_dns.status == "failed":
        return results

    cert = _ensure_cert(service, certbot_domains_file, cert_renewer, apply=apply, cert_timeout=cert_timeout)
    results.append(cert)
    if cert.status == "failed":
        return results

    results.append(_validate_nginx(catalog, services_json_path))
    return results


def _append_domain(path: Path, domain: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    # A pre-existing file whose last line has no trailing newline (a
    # printf-written file, or an editor that strips the final newline)
    # would otherwise merge with this append into one bogus domain that
    # neither _read_domains nor scripts/cert-renewer's own line reader
    # would ever match again.
    needs_leading_newline = False
    if path.is_file() and path.stat().st_size > 0:
        with path.open("rb") as f:
            f.seek(-1, os.SEEK_END)
            needs_leading_newline = f.read(1) != b"\n"
    with path.open("a", encoding="utf-8") as f:
        if needs_leading_newline:
            f.write("\n")
        f.write(f"{domain}\n")


def _ensure_cert(
    service: dict, certbot_domains_file: Path, cert_renewer: Path, *, apply: bool, cert_timeout: float
) -> RegisterStepResult:
    domain = service.get("server_name")
    if not domain:
        return RegisterStepResult("cert", "skip", "no server_name on this catalog entry")

    already_listed = domain in _read_domains(certbot_domains_file)

    if not apply:
        verb = "already listed" if already_listed else "would add"
        return RegisterStepResult("cert", "would-apply", f"{verb} {domain} in {certbot_domains_file}")

    if not already_listed:
        _append_domain(certbot_domains_file, domain)

    try:
        proc = subprocess.run(
            [str(cert_renewer)],
            capture_output=True,
            text=True,
            timeout=cert_timeout,
            check=False,
            # Without this, an explicit --certbot-domains-file diverging
            # from cert-renewer's own default/env resolution means the
            # domain this step just appended is never the one
            # cert-renewer actually reads -- see #110 review.
            env={**os.environ, "CERTBOT_DOMAINS_FILE": str(certbot_domains_file)},
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        return RegisterStepResult("cert", "failed", f"{cert_renewer} failed to run: {e}")

    if proc.returncode != 0:
        output = "\n".join(part for part in (proc.stdout.strip(), proc.stderr.strip()) if part)
        return RegisterStepResult("cert", "failed", f"cert-renewer failed (exit {proc.returncode}): {output}")
    return RegisterStepResult("cert", "applied", f"cert-renewer completed for {domain}")


def _from_check_result(step: str, result: CheckResult) -> RegisterStepResult:
    # CheckResult spells failure "fail"; RegisterStepResult always spells
    # it "failed" (matching SyncResult) so callers can check one spelling
    # uniformly across every step's result.
    status = "failed" if result.status == "fail" else result.status
    return RegisterStepResult(step, status, result.detail)


def _read_domains(path: Path) -> set[str]:
    if not path.is_file():
        return set()
    domains: set[str] = set()
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        domains.add(line)
    return domains


def _validate_nginx(catalog: dict, services_json_path: Path) -> RegisterStepResult:
    preview = render_preview(catalog, current_catalog=catalog, current_services_path=services_json_path)
    if not preview.can_apply:
        detail = preview.nginx_test.output or preview.gixy.output or "nginx validation failed"
        return RegisterStepResult("nginx", "failed", detail)
    # preview.can_apply reflects nginx -t alone (app.catalog_crud's own
    # gate) -- Gixy-Next is fail-closed per AGENTS.md, so a "findings" or
    # "error" status here must not be folded into an "ok" claim of both
    # passing, even though can_apply itself doesn't see it.
    if preview.gixy.status != "ok":
        detail = preview.gixy.output or f"Gixy-Next status={preview.gixy.status!r}"
        return RegisterStepResult("nginx", "failed", f"nginx -t passed but Gixy-Next did not: {detail}")
    return RegisterStepResult("nginx", "ok", "nginx -t and Gixy-Next both pass against the full catalog")
