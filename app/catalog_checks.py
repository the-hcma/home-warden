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

CF_API_BASE = "https://api.cloudflare.com/client/v4"


@dataclass
class CheckResult:
    service: str
    dimension: str  # "cert" | "dns" | "upstream"
    status: str  # "ok" | "fail" | "skip"
    detail: str


def load_catalog(path: Path) -> dict:
    """Raises FileNotFoundError / ValueError on a missing/invalid catalog --
    plain exceptions (not SystemExit) since this is shared by the long-lived
    FastAPI route as well as the one-shot CLI; each entry point decides how
    to present the failure.

    Validates top-level shape (object with a list "services"), not just
    JSON syntax -- a typo'd/renamed key (`{"service": [...]}`) or a
    non-object top level would otherwise either silently validate zero
    services and report healthy, or crash `run_all` with an unhandled
    AttributeError instead of failing loudly at this boundary.
    """
    if not path.is_file():
        raise FileNotFoundError(f"missing catalog file {path}")
    try:
        data = json.loads(path.read_text())
    except json.JSONDecodeError as e:
        raise ValueError(f"invalid JSON in {path}: {e}") from e
    if not isinstance(data, dict):
        raise ValueError(f"{path}: top-level JSON must be an object, got {type(data).__name__}")
    if not isinstance(data.get("services"), list):
        raise ValueError(f"{path}: missing or non-list top-level 'services' key")
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


def _cf_request(url: str, headers: dict[str, str], timeout: float, max_retries: int) -> dict:
    """GET a Cloudflare API URL with bounded, jittered-backoff retries.
    Only retries transient failures (network errors, 5xx) -- never a 4xx.
    `max_retries` is clamped to at least 1 attempt -- "don't retry" (0)
    still means try once, not "crash with an assertion error and get
    reported as a false DNS failure."
    """
    last_err: Exception | None = None
    for attempt in range(max(1, max_retries)):
        if attempt:
            time.sleep(min(2**attempt, 8) + random.uniform(0, 0.5))
        req = urllib.request.Request(url, headers=headers)
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


def check_cert(name: str, service: dict, certs_live_dir: Path, alert_days: int, timeout: float) -> CheckResult:
    domain = service.get("server_name")
    if not domain:
        return CheckResult(name, "cert", "skip", "no server_name on this catalog entry")

    cert_path = certs_live_dir / domain / "fullchain.pem"
    if not cert_path.is_file():
        return CheckResult(name, "cert", "fail", f"missing: {cert_path}")

    try:
        proc = subprocess.run(
            [
                "openssl",
                "x509",
                "-in",
                str(cert_path),
                "-noout",
                "-enddate",
                "-ext",
                "subjectAltName",
                "-checkend",
                str(alert_days * 86400),
            ],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return CheckResult(name, "cert", "fail", f"openssl timed out after {timeout}s")

    # -checkend sets returncode 1 when the cert will lapse within the window;
    # any other nonzero code is a real parse/read error, not an expiry signal.
    if proc.returncode not in (0, 1):
        return CheckResult(name, "cert", "fail", f"openssl error: {proc.stderr.strip()}")

    enddate = ""
    sans: list[str] = []
    for line in proc.stdout.splitlines():
        stripped = line.strip()
        if stripped.startswith("notAfter="):
            enddate = stripped[len("notAfter=") :]
            continue
        # DNS names can share a line with other general-name types (e.g.
        # "IP Address:10.0.0.5, DNS:app.example.com") -- scan every
        # comma-separated entry on every line, don't require the whole
        # line to start with "DNS:", and accumulate rather than overwrite
        # in case openssl ever wraps the SAN list across lines.
        for part in stripped.split(","):
            part = part.strip()
            if part.startswith("DNS:"):
                sans.append(part[len("DNS:") :])

    if domain not in sans:
        return CheckResult(
            name,
            "cert",
            "fail",
            f"{domain} not covered by cert SANs ({', '.join(sans) or 'none found'})",
        )
    if proc.returncode == 1:
        return CheckResult(name, "cert", "fail", f"expires within {alert_days}d (notAfter={enddate})")
    return CheckResult(name, "cert", "ok", f"notAfter={enddate}; SANs cover {domain}")


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
    """Run the requested dimensions for every service in the catalog."""
    results: list[CheckResult] = []
    for service in catalog.get("services") or []:
        name = service.get("name", "<unnamed>")
        if not skip_cert:
            results.append(check_cert(name, service, certs_live_dir, alert_days, timeout))
        if not skip_dns:
            results.append(check_dns(name, service, cf_headers, timeout, max_retries))
        if not skip_upstream:
            results.append(check_upstream(name, service, timeout))
    return results
