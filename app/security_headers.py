"""Baseline security response headers for the home-warden web UI (#76).

Defense-in-depth on top of #55/#68's existing guarantees (loopback-only
backend, mandatory nginx TLS termination, HttpOnly/Secure/SameSite=Strict
session cookie): none of these headers are load-bearing for an app that's
already single-origin, vanilla-DOM, and never renders third-party or
user-supplied HTML, but they're cheap and standard, and HSTS in particular
reinforces the "never reachable except through nginx's TLS" story against a
misconfigured or downgraded connection.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable

from starlette.requests import Request
from starlette.responses import Response

# One year, plus subdomains -- home-warden's own vhost story (#55/#68) is
# always HTTPS-only, so there's no legitimate plain-HTTP fallback to protect.
HSTS_VALUE = "max-age=31536000; includeSubDomains"
# Single-origin static assets (web/, #67) with no third-party scripts, no
# inline event handlers, and no embedding, so a strict default-src plus an
# explicit frame-ancestors covers this app's actual surface. style-src and
# img-src need explicit 'unsafe-inline'/data: allowances: app/api/static
# /index.html ships its CSS as an inline <style> block and its favicon as a
# data: URI, both of which a bare default-src 'self' would silently block
# (breaking the UI, not just tightening it).
CSP_VALUE = "default-src 'self'; frame-ancestors 'none'; style-src 'self' 'unsafe-inline'; img-src 'self' data:"

SECURITY_HEADERS: dict[str, str] = {
    "Content-Security-Policy": CSP_VALUE,
    "Referrer-Policy": "same-origin",
    "Strict-Transport-Security": HSTS_VALUE,
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
}


async def add_security_headers(request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
    response = await call_next(request)
    for name, value in SECURITY_HEADERS.items():
        response.headers.setdefault(name, value)
    return response
