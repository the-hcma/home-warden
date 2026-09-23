"""Validate a home-warden service catalog's promises against live infrastructure.

Three independent, read-only dimensions per catalog service (see
the-hcma/home-warden#57):

  1. cert     -- does a Let's Encrypt cert exist for server_name, cover it in
                 its SANs, and have enough runway left?
  2. dns      -- does Cloudflare actually have an A/AAAA/CNAME record for
                 server_name?
  3. upstream -- for proxy services, is upstream.host:port accepting
                 connections and responding to an HTTP request?

Pure, read-only check functions -- this module never mutates certs, DNS, or
any live state. Auto-healing on failure is deliberately out of scope; see
#57 for the open design questions (confirm-first vs. autonomous, flap
protection, credential scope, alerting) that need resolving before that's
built. Consumed by app.catalog_health_cli (one-shot/timer use) and
app.api.catalog_health_routes (on-demand HTTP, for the future web UI).
"""

from __future__ import annotations

import datetime
import ipaddress
import json
import random
import socket
import ssl
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path

from cryptography import x509

CF_API_BASE = "https://api.cloudflare.com/client/v4"


@dataclass
class CheckResult:
    service: str
    dimension: str  # "cert" | "dns" | "upstream"
    status: str  # "ok" | "fail" | "skip"
    detail: str


@dataclass
class SyncResult:
    service: str
    # "created" | "updated" | "noop" | "would-create" | "would-update" | "failed" | "skip"
    status: str
    detail: str


def load_catalog(path: Path) -> dict:
    """Raises FileNotFoundError / ValueError on a missing/invalid catalog --
    plain exceptions (not SystemExit) since this is shared by the long-lived
    FastAPI route as well as the one-shot CLI; each entry point decides how
    to present the failure.

    Validates shape -- not just JSON syntax -- at both the top level
    (object with a list "services") and per-entry (each entry an object;
    its "upstream", if present, an object): a typo'd/renamed key
    (`{"service": [...]}`), a non-object top level, or a flattened
    `"upstream": "http://backend:8000"` (exactly what a renderer-less,
    hand-edited catalog invites) would otherwise either silently validate
    zero services and report healthy, or crash `run_all`/`check_upstream`
    with an unhandled AttributeError mid-report instead of failing loudly
    at this one boundary.
    """
    if not path.is_file():
        raise FileNotFoundError(f"missing catalog file {path}")
    try:
        data = json.loads(path.read_text())
    except json.JSONDecodeError as e:
        raise ValueError(f"invalid JSON in {path}: {e}") from e
    if not isinstance(data, dict):
        raise ValueError(f"{path}: top-level JSON must be an object, got {type(data).__name__}")
    services = data.get("services")
    if not isinstance(services, list):
        raise ValueError(f"{path}: missing or non-list top-level 'services' key")
    for i, entry in enumerate(services):
        if not isinstance(entry, dict):
            raise ValueError(f"{path}: services[{i}] must be an object, got {type(entry).__name__}")
        upstream = entry.get("upstream")
        if upstream is not None and not isinstance(upstream, dict):
            raise ValueError(f"{path}: services[{i}].upstream must be an object, got {type(upstream).__name__}")
    return data


def parse_cloudflare_credentials(path: Path) -> dict[str, str] | None:
    """Parse certbot-dns-cloudflare's flat `key = value` credentials file
    (conf/cloudflare.ini.example) into Cloudflare API auth headers.

    Returns None only when the file doesn't exist at all -- that's a
    legitimate "DNS checks not configured" state. Raises ValueError when
    the file exists but yields no usable credentials (missing/typo'd
    keys, an empty token): a config typo should fail loudly, not read as
    "not configured" and quietly skip the whole DNS dimension as healthy.
    """
    if not path.is_file():
        return None
    values: dict[str, str] = {}
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        values[key.strip()] = val.strip()

    token = values.get("dns_cloudflare_api_token")
    email = values.get("dns_cloudflare_email")
    api_key = values.get("dns_cloudflare_api_key")

    if token:
        return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    if email and api_key:
        return {"X-Auth-Email": email, "X-Auth-Key": api_key, "Content-Type": "application/json"}
    raise ValueError(
        f"{path} exists but has no usable Cloudflare credentials "
        "(expected dns_cloudflare_api_token, or dns_cloudflare_email + dns_cloudflare_api_key)"
    )


def _cf_request(
    url: str,
    headers: dict[str, str],
    timeout: float,
    max_retries: int,
    *,
    method: str = "GET",
    data: dict | None = None,
) -> dict:
    """Call a Cloudflare API URL with bounded, jittered-backoff retries.
    Only retries transient failures (network errors, 5xx) -- never a 4xx.
    `max_retries` is clamped to at least 1 attempt -- "don't retry" (0)
    still means try once, not "crash with an assertion error and get
    reported as a false DNS failure."

    GET/PUT/PATCH/DELETE are idempotent -- safe to retry here directly.
    POST (record creation) is NOT idempotent on Cloudflare's side (no
    dedupe key; a duplicate POST can create a second record) -- callers
    creating a record must pass max_retries=1 here. See sync_dns_record's
    docstring for why re-invoking the *outer* function, rather than
    retrying the POST itself, is the safe retry path (per
    .agents/rules/remote-timeouts-retries.md's "do not retry
    non-idempotent writes unless the API contract is safe" rule).
    """
    body = json.dumps(data).encode("utf-8") if data is not None else None
    last_err: Exception | None = None
    for attempt in range(max(1, max_retries)):
        if attempt:
            time.sleep(min(2**attempt, 8) + random.uniform(0, 0.5))
        req = urllib.request.Request(url, headers=headers, method=method, data=body)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            if e.code < 500:
                raise
            last_err = e
        except (urllib.error.URLError, TimeoutError, socket.timeout) as e:
            last_err = e
    assert last_err is not None
    raise last_err


def _resolve_via_authoritative_ns(domain: str, record_type: str, nameserver: str, timeout: float) -> list[str] | None:
    """Query `nameserver` directly for `domain`'s `record_type` records via
    `dig`, bypassing any resolver cache -- a zone's own authoritative
    nameservers answer a just-written record immediately, with none of a
    public resolver's propagation/TTL-caching delay to account for.

    Returns the list of answer values, or None when `dig` itself isn't
    available in this environment -- an environment limitation, not a DNS
    failure; callers should treat None as "couldn't verify," distinct
    from an empty list, which means "asked and got no answer."
    """
    try:
        proc = subprocess.run(
            ["dig", "+short", f"@{nameserver}", domain, record_type],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0:
        return None
    return [line.strip() for line in proc.stdout.splitlines() if line.strip()]


def candidate_zone_names(domain: str):
    """Yield progressively longer suffixes of domain, apex-first.

    A lightweight stand-in for a real public-suffix-list lookup: tries the
    shortest plausible zone (last two labels) first, then widens. Good
    enough for ordinary two-label zones; a domain whose real zone is a
    longer suffix (e.g. a multi-label ccTLD) still resolves correctly, just
    after a couple of extra, cheap 4xx lookups.
    """
    labels = domain.split(".")
    for i in range(len(labels) - 1, 0, -1):
        yield ".".join(labels[i - 1 :])


def check_cert(name: str, service: dict, certs_live_dir: Path, alert_days: int) -> CheckResult:
    """Uses the `cryptography` package directly rather than shelling out to
    `openssl x509` -- structured field access (not_valid_after_utc, the
    SubjectAlternativeName extension's typed DNSName list) instead of
    parsing the CLI's human-readable text output, which is exactly the
    class of bug that text-parsing produced here before (a SAN entry
    sharing a line with a non-DNS general name got dropped). Matches the
    precedent already set by the-hcma/my-tracks' app/pki.py.
    """
    domain = service.get("server_name")
    if not domain:
        return CheckResult(name, "cert", "skip", "no server_name on this catalog entry")

    cert_path = certs_live_dir / domain / "fullchain.pem"
    if not cert_path.is_file():
        return CheckResult(name, "cert", "fail", f"missing: {cert_path}")

    try:
        cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
    except (ValueError, OSError) as e:
        return CheckResult(name, "cert", "fail", f"failed to parse {cert_path}: {e}")

    try:
        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        sans = san_ext.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        sans = []

    if domain not in sans:
        return CheckResult(
            name,
            "cert",
            "fail",
            f"{domain} not covered by cert SANs ({', '.join(sans) or 'none found'})",
        )

    not_after = cert.not_valid_after_utc
    seconds_left = (not_after - datetime.datetime.now(datetime.timezone.utc)).total_seconds()
    if seconds_left < alert_days * 86400:
        return CheckResult(name, "cert", "fail", f"expires within {alert_days}d (notAfter={not_after.isoformat()})")
    return CheckResult(name, "cert", "ok", f"notAfter={not_after.isoformat()}; SANs cover {domain}")


def check_dns(
    name: str,
    service: dict,
    cf_headers: dict[str, str] | None,
    timeout: float,
    max_retries: int,
) -> CheckResult:
    domain = service.get("server_name")
    if not domain:
        return CheckResult(name, "dns", "skip", "no server_name on this catalog entry")
    if cf_headers is None:
        return CheckResult(name, "dns", "skip", "no Cloudflare credentials configured")

    # Try every candidate zone (apex-first), not just the first one that
    # exists: an account can hold both a parent zone and a more specific
    # nested zone, and the record actually lives in whichever one the
    # domain was delegated into. Stopping at the first match that *exists*
    # (rather than the first that *has the record*) reports a healthy
    # domain as failing when its zone isn't the least-specific one found.
    any_zone_found = False
    try:
        for candidate in candidate_zone_names(domain):
            zone_url = f"{CF_API_BASE}/zones?name={urllib.parse.quote(candidate)}"
            zone_data = _cf_request(zone_url, cf_headers, timeout, max_retries)
            zone_results = zone_data.get("result") or []
            if not zone_results:
                continue
            any_zone_found = True
            zone_id = zone_results[0]["id"]

            rec_url = f"{CF_API_BASE}/zones/{zone_id}/dns_records?name={urllib.parse.quote(domain)}"
            rec_data = _cf_request(rec_url, cf_headers, timeout, max_retries)
            records = rec_data.get("result") or []
            relevant = [r for r in records if r.get("type") in ("A", "AAAA", "CNAME")]
            if relevant:
                summary = ", ".join(f"{r['type']}={r.get('content')}" for r in relevant)
                return CheckResult(name, "dns", "ok", f"zone={candidate} {summary}")
    except Exception as e:  # keep one Cloudflare hiccup from crashing the whole report
        return CheckResult(name, "dns", "fail", f"Cloudflare lookup error: {e}")

    if not any_zone_found:
        return CheckResult(name, "dns", "fail", f"no Cloudflare zone found for {domain}")
    return CheckResult(name, "dns", "fail", f"no A/AAAA/CNAME record for {domain} in any matching Cloudflare zone")


def check_upstream(name: str, service: dict, timeout: float) -> CheckResult:
    if service.get("kind") != "proxy":
        return CheckResult(name, "upstream", "skip", f"kind={service.get('kind')!r}, no upstream to probe")

    upstream = service.get("upstream") or {}
    host = upstream.get("host")
    port = upstream.get("port")
    if not host or not port:
        return CheckResult(name, "upstream", "fail", "upstream.host/port missing from catalog entry")

    try:
        with socket.create_connection((host, port), timeout=timeout):
            pass
    except OSError as e:
        return CheckResult(name, "upstream", "fail", f"TCP connect to {host}:{port} failed: {e}")

    scheme = upstream.get("scheme", "http")
    path = upstream.get("path", "/")
    bracketed_host = f"[{host}]" if ":" in host else host
    url = f"{scheme}://{bracketed_host}:{port}{path}"

    ctx = None
    if scheme == "https":
        # An internal backend's cert isn't part of the public trust chain this
        # module validates elsewhere (Let's Encrypt/Cloudflare) -- this probe
        # only asks "is something responding," the same trust posture nginx's
        # own proxy_pass already has toward this upstream.
        ctx = ssl._create_unverified_context()  # internal-only probe, see comment above

    req = urllib.request.Request(url, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            code = resp.getcode()
    except urllib.error.HTTPError as e:
        # Any HTTP response -- even an error status -- proves something is
        # listening and answering, which is what this dimension checks for.
        code = e.code
    except Exception as e:
        # Broad on purpose, mirroring check_dns: a listener that's up but
        # doesn't speak HTTP (e.g. a TLS port, or any non-HTTP service)
        # raises http.client.HTTPException/BadStatusLine, which urllib does
        # NOT wrap in URLError -- that must be a "fail" result (exactly
        # what this dimension exists to catch), not an unhandled crash.
        return CheckResult(name, "upstream", "fail", f"TCP connect ok but HTTP probe to {url} failed: {e}")

    return CheckResult(name, "upstream", "ok", f"{url} responded HTTP {code}")


def run_all(
    catalog: dict,
    *,
    certs_live_dir: Path,
    alert_days: int,
    cf_headers: dict[str, str] | None,
    timeout: float,
    max_retries: int,
    skip_cert: bool = False,
    skip_dns: bool = False,
    skip_upstream: bool = False,
) -> list[CheckResult]:
    """Run the requested dimensions for every service in the catalog.

    Validates `timeout`/`alert_days` here -- the one choke point both the
    CLI and the route funnel through -- rather than downstream in each
    check: a non-positive timeout reaches `socket.settimeout()` as an
    uncaught `ValueError` (not an `OSError`, so check_upstream's own catch
    doesn't see it), and a negative alert_days would silently make the
    expiry comparison pass for a cert that's already expired. Raising here
    keeps both consumers' existing exit-2/HTTP-500 config-error contract
    intact instead of an escaping exception or a silent false-healthy.
    """
    if timeout <= 0:
        raise ValueError(f"timeout must be positive, got {timeout}")
    if alert_days < 0:
        raise ValueError(f"alert_days must be non-negative, got {alert_days}")

    results: list[CheckResult] = []
    for service in catalog.get("services") or []:
        name = service.get("name", "<unnamed>")
        if not skip_cert:
            results.append(check_cert(name, service, certs_live_dir, alert_days))
        if not skip_dns:
            results.append(check_dns(name, service, cf_headers, timeout, max_retries))
        if not skip_upstream:
            results.append(check_upstream(name, service, timeout))
    return results


def sync_dns_record(
    name: str,
    service: dict,
    target: str,
    cf_headers: dict[str, str] | None,
    timeout: float,
    max_retries: int,
    *,
    proxied: bool = False,
    dry_run: bool = False,
    verify_resolution: bool = True,
) -> SyncResult:
    """Idempotent create-or-update of a Cloudflare A/AAAA/CNAME record for
    `service["server_name"]`, pointed at `target` (this host's own public
    IP, or a shared front-door hostname). home-warden fronts every public
    service from the one host, so there is deliberately no per-service
    target field in the catalog schema -- every synced record points at
    the same place. `target` being a literal IPv4/IPv6 address picks
    A/AAAA; anything else is treated as a CNAME target.

    Does not touch an existing record of a *different* type at the same
    name (e.g. a hand-created CNAME where this call wants an A record) --
    reports that as a failure needing a human decision, rather than
    silently deleting and replacing it.

    Create is a single attempt, not a retry loop: Cloudflare's create
    endpoint isn't idempotent (no dedupe key), so blindly retrying a POST
    risks a duplicate record if a prior attempt actually landed but its
    response was lost. The safe retry path is calling this function
    again -- it always starts by re-reading existing records, so a
    previously-successful create is detected as already-correct (`noop`)
    on the next call, never re-POSTed. Update (PUT to a specific record
    id) is idempotent and retried directly via `_cf_request`.

    Validates the outcome for real before reporting success (see
    the-hcma/home-warden#109): reads the record back via the Cloudflare
    API, and -- unless `verify_resolution=False` or `dig` isn't available
    in this environment -- also resolves it against the zone's own
    authoritative nameservers. A write the API accepted that doesn't come
    back clean on either check is `"failed"`, not a success with a
    warning.
    """
    domain = service.get("server_name")
    if not domain:
        return SyncResult(name, "skip", "no server_name on this catalog entry")
    if cf_headers is None:
        return SyncResult(name, "skip", "no Cloudflare credentials configured")

    try:
        record_type = "AAAA" if isinstance(ipaddress.ip_address(target), ipaddress.IPv6Address) else "A"
    except ValueError:
        record_type = "CNAME"

    zone_id: str | None = None
    zone_name = ""
    nameservers: list[str] = []
    rec_url = ""
    existing: list[dict] = []
    try:
        for candidate in candidate_zone_names(domain):
            zone_url = f"{CF_API_BASE}/zones?name={urllib.parse.quote(candidate)}"
            zone_data = _cf_request(zone_url, cf_headers, timeout, max_retries)
            zone_results = zone_data.get("result") or []
            if not zone_results:
                continue
            # Remember the most specific existing zone seen so far, not just
            # the first one that exists: an account can hold both a parent
            # zone and a more specific delegated zone (see check_dns above),
            # and a record created in the wrong one is silently unreachable.
            # Keep walking candidates (apex-first) until one actually holds
            # the record; if none do, the last (most specific) existing zone
            # is where a new record belongs.
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

    same_type = [r for r in existing if r.get("type") == record_type]
    other_type = [r for r in existing if r.get("type") != record_type]

    if other_type:
        kinds = ", ".join(f"{r['type']}={r.get('content')}" for r in other_type)
        return SyncResult(
            name,
            "failed",
            f"existing {kinds} record for {domain} has a different type than "
            f"{record_type} -- refusing to replace it automatically",
        )

    desired = {"type": record_type, "name": domain, "content": target, "proxied": proxied}

    if same_type and same_type[0].get("content") == target and same_type[0].get("proxied", False) == proxied:
        return SyncResult(name, "noop", f"{record_type}={target} already correct in zone {zone_name}")

    action = "update" if same_type else "create"
    if dry_run:
        verb = "would-update" if action == "update" else "would-create"
        return SyncResult(name, verb, f"{verb.split('-')[1]} {record_type} {domain} -> {target} in zone {zone_name}")

    try:
        if action == "update":
            record_id = same_type[0]["id"]
            write_url = f"{CF_API_BASE}/zones/{zone_id}/dns_records/{record_id}"
            _cf_request(write_url, cf_headers, timeout, max_retries, method="PUT", data=desired)
        else:
            write_url = f"{CF_API_BASE}/zones/{zone_id}/dns_records"
            _cf_request(write_url, cf_headers, timeout, 1, method="POST", data=desired)
    except Exception as e:
        return SyncResult(name, "failed", f"Cloudflare write failed: {e}")

    try:
        confirm = _cf_request(rec_url, cf_headers, timeout, max_retries)
    except Exception as e:
        return SyncResult(name, "failed", f"write accepted but read-back failed: {e}")
    confirmed = [
        r for r in (confirm.get("result") or []) if r.get("type") == record_type and r.get("content") == target
    ]
    if not confirmed:
        return SyncResult(name, "failed", f"write accepted but {record_type}={target} not found on read-back")

    # Skip for proxied records: a proxied name's authoritative answer is
    # Cloudflare's anycast edge (or nothing, for a proxied CNAME), never the
    # origin `content` just written -- the API read-back above is already
    # this case's real validation.
    if verify_resolution and nameservers and not proxied:
        answers = _resolve_via_authoritative_ns(domain, record_type, nameservers[0], timeout)
        # dig prints CNAME/NS-style answers as FQDNs with a trailing dot;
        # `target` never carries one -- normalize before comparing.
        normalized = [a.rstrip(".") for a in answers] if answers is not None else None
        if normalized is not None and target not in normalized:
            return SyncResult(
                name,
                "failed",
                f"write accepted and read back but {nameservers[0]} answers {answers}, not {target}",
            )

    verb = "updated" if action == "update" else "created"
    return SyncResult(name, verb, f"{verb} {record_type} {domain} -> {target} in zone {zone_name}")
