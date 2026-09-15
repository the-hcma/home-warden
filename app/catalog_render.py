"""Render a home-warden service catalog (services.json) into nginx config.

Turns the schema documented in services.json.example into nginx config text
via `crossplane.build()` -- output this repo's own `nginx -t` (and, since
#50, `scripts/nginx-security-lint`/Gixy-Next) can validate. See
the-hcma/home-warden#54.

Deliberately narrow in scope for this first landing: it renders `http {}`
server blocks (proxy + static kinds) and `stream {}` blocks from the
catalog, plus the shared TLS/access-control template every vhost gets. It
does *not* flip the switch on migrating the live thehcma/home conf to
catalog-driven generation -- that's an operator-reviewed follow-up once
this output has been diffed against the real conf (#54's "Migrate the live
conf" scope note). `background_units` is informational-only bookkeeping
(per services.json.example's notes) and is never consumed here.

Known fidelity gaps from #45/#54's validation pass, and how this module
resolves each:

- IPv6 literal upstream hosts need bracket notation in the constructed URL
  -- `_upstream_url`/`_stream_upstream_address` bracket any host containing
  a ':' (a literal IPv6 address; hostnames never contain colons).
- Static exact-match root location: every `kind: static` server always gets
  a `location = /` block (serve index.html, else 404) ahead of its general
  root location -- a fixed renderer convention, not a new schema field, per
  #54's "lean on... a documented convention" option.
- CRL: `client_cert.crl`, when present, becomes `ssl_crl <path>;`.
- allow_cn: becomes a `map $ssl_client_s_dn $allow_<name>_cn { ... }` block
  plus an `if` gate in the service's location -- exactly the mapping
  services.json.example's notes already document.
- Legacy/redundant blocks: this renderer never emits anything beyond what
  the catalog + this module's fixed template describe -- no historical
  cruft carries over, and that's a deliberate, documented property of
  catalog-driven generation (not an accident to review away later).
- Security validation (#50): scripts/render-catalog's own validate step
  runs scripts/nginx-security-lint against its rendered output, in
  addition to `nginx -t` -- see that script's docstring.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

DEFAULT_CLIENT_MAX_BODY_SIZE = "10m"
DEFAULT_SSL_PROTOCOLS = "TLSv1.2 TLSv1.3"


@dataclass
class RenderContext:
    """Shared template settings applied to every vhost -- deliberately NOT
    part of the catalog schema (see services.json.example's top-level
    `_notes`): a catalog entry describes *what* to serve, this describes
    *how* every vhost is secured/tuned.
    """

    certs_live_dir: Path
    client_max_body_size: str = DEFAULT_CLIENT_MAX_BODY_SIZE
    server_tokens_off: bool = True
    ssl_protocols: str = DEFAULT_SSL_PROTOCOLS


def build_catalog_config(catalog: dict, ctx: RenderContext) -> list[dict]:
    """Build the crossplane payload (a list of top-level directive dicts)
    for the full catalog: an http-level `server_tokens off;` (#50's
    Gixy-Next version_disclosure fix, applied once here rather than
    per-vhost), one `map` per service with an `allow_cn` allowlist, one
    `server` per proxy/static service (all inside `http`), plus one
    `server` per `streams` entry (inside `stream`, only emitted when the
    catalog actually has any).

    The first service's `server` block is marked `default_server` -- with
    multiple https vhosts and no explicit default, nginx silently falls
    back to whichever `server` was defined first anyway; naming that
    choice explicitly (what Gixy-Next's `default_server_flag` check flags
    as missing) makes it a documented renderer property instead of an
    accident of catalog ordering.
    """
    services = catalog.get("services") or []
    streams = catalog.get("streams") or []

    http_block: list[dict] = []
    if ctx.server_tokens_off:
        http_block.append(_directive("server_tokens", args=["off"]))
    for service in services:
        allow_cn_map = _build_allow_cn_map(service)
        if allow_cn_map is not None:
            http_block.append(allow_cn_map)
    for i, service in enumerate(services):
        http_block.append(_build_server_block(service, ctx, is_default_server=(i == 0)))

    payload = [_directive("http", block=http_block)]
    if streams:
        payload.append(_directive("stream", block=[_build_stream_server_block(s) for s in streams]))
    return payload


def render_catalog(catalog: dict, ctx: RenderContext) -> str:
    """Render `catalog` to nginx config text. Import crossplane lazily --
    it's a `lint`/render-only dependency, not needed by every consumer of
    this package (e.g. the catalog-health CLI/routes)."""
    import crossplane

    return crossplane.build(build_catalog_config(catalog, ctx), header=True) + "\n"


def _allow_cidr_directives(allow_cidrs: list[str] | None) -> list[dict]:
    if not allow_cidrs:
        return []
    directives = [_directive("allow", args=[cidr]) for cidr in allow_cidrs]
    directives.append(_directive("deny", args=["all"]))
    return directives


def _allow_cn_map_name(service: dict) -> str:
    return f"allow_{_safe_ident(service.get('name', 'service'))}_cn"


def _build_allow_cn_map(service: dict) -> dict | None:
    allow_cn = (service.get("client_cert") or {}).get("allow_cn")
    if not allow_cn:
        return None
    map_block = [_directive("default", args=["0"])]
    for cn in allow_cn:
        map_block.append(_directive(f"~^CN={_escape_map_pattern(cn)}(,|$)", args=["1"]))
    return _directive("map", args=["$ssl_client_s_dn", f"${_allow_cn_map_name(service)}"], block=map_block)


def _build_server_block(service: dict, ctx: RenderContext, *, is_default_server: bool = False) -> dict:
    # static's content is a set of sibling server-level location/root
    # blocks (an exact-match "/", the general root, an optional listing
    # location); proxy's content is a single `location / { proxy_pass ...; }`.
    # Only the latter needs an explicit wrapping location.
    kind = service.get("kind")
    if kind == "static":
        content_directives = _static_location_directives(service)
    elif kind == "proxy":
        content_directives = [_directive("location", args=["/"], block=_proxy_location_directives(service, ctx))]
    else:
        raise ValueError(f"unsupported service kind {kind!r} for {service.get('name', '<unnamed>')!r}")

    domain = service["server_name"]
    cert_dir = ctx.certs_live_dir / domain
    listen_args = ["443", "ssl", "default_server"] if is_default_server else ["443", "ssl"]
    block = [
        _directive("listen", args=listen_args),
        _directive("server_name", args=[domain]),
        _directive("ssl_certificate", args=[str(cert_dir / "fullchain.pem")]),
        _directive("ssl_certificate_key", args=[str(cert_dir / "privkey.pem")]),
        _directive("ssl_protocols", args=ctx.ssl_protocols.split()),
        _directive("client_max_body_size", args=[ctx.client_max_body_size]),
        *_allow_cidr_directives(service.get("allow_cidrs")),
        *_client_cert_directives(service),
    ]
    if service.get("gzip") is False:
        block.append(_directive("gzip", args=["off"]))
    block.extend(content_directives)
    return _directive("server", block=block)


def _build_stream_server_block(stream: dict) -> dict:
    upstream = stream["upstream"]
    address = _stream_upstream_address(upstream)
    return _directive(
        "server",
        block=[
            _directive("listen", args=[str(stream["listen_port"])]),
            _directive("proxy_pass", args=[address]),
        ],
    )


def _client_cert_directives(service: dict) -> list[dict]:
    client_cert = service.get("client_cert")
    if not client_cert or client_cert.get("mode", "off") == "off":
        return []
    mode = client_cert["mode"]
    directives = [
        _directive("ssl_client_certificate", args=[client_cert["ca_bundle"]]),
        _directive("ssl_verify_client", args=[mode]),
    ]
    if client_cert.get("verify_depth") is not None:
        directives.append(_directive("ssl_verify_depth", args=[str(client_cert["verify_depth"])]))
    if client_cert.get("crl"):
        directives.append(_directive("ssl_crl", args=[client_cert["crl"]]))
    return directives


def _directive(name: str, *, args: list[str] | None = None, block: list[dict] | None = None) -> dict:
    stmt: dict = {"directive": name, "args": args or []}
    if block is not None:
        stmt["block"] = block
    return stmt


def _escape_map_pattern(value: str) -> str:
    # $ssl_client_s_dn's RFC2253-ish DN string is comma-separated
    # ("CN=alice,O=example") -- a CN value containing a regex metacharacter
    # would otherwise corrupt the map's `~` regex pattern.
    return "".join(f"\\{c}" if c in ".*+?^$()[]{}|\\" else c for c in value)


def _proxy_location_directives(service: dict, ctx: RenderContext) -> list[dict]:
    del ctx  # unused for now; kept for a consistent per-kind signature
    directives = [_directive("proxy_pass", args=[_upstream_url(service["upstream"])])]

    allow_cn = (service.get("client_cert") or {}).get("allow_cn")
    if allow_cn:
        # crossplane's builder wraps `if` args in "(" ")" itself (see its
        # `build()`): passing already-parenthesized args here would double
        # them up and get the whole condition mis-quoted as one token.
        map_var = f"${_allow_cn_map_name(service)}"
        directives.append(_directive("if", args=[map_var, "=", "0"], block=[_directive("return", args=["403"])]))

    if service.get("forward_host_header"):
        directives.append(_directive("proxy_set_header", args=["Host", "$host"]))

    if service.get("websocket"):
        directives.extend(
            [
                _directive("proxy_http_version", args=["1.1"]),
                _directive("proxy_set_header", args=["Upgrade", "$http_upgrade"]),
                _directive("proxy_set_header", args=["Connection", "upgrade"]),
                _directive("proxy_buffering", args=["off"]),
            ]
        )
    return directives


def _safe_ident(name: str) -> str:
    return "".join(c if c.isalnum() else "_" for c in name)


def _static_location_directives(service: dict) -> list[dict]:
    static = service["static"]
    root = static["root"]
    directives = [_directive("root", args=[root])]
    listing_path = static.get("listing_path")
    if listing_path:
        directives.append(
            _directive(
                "location",
                args=[listing_path],
                block=[_directive("root", args=[root]), _directive("autoindex", args=["on"])],
            )
        )
    directives.insert(
        0,
        _directive(
            "location",
            args=["=", "/"],
            block=[
                _directive("root", args=[root]),
                # open_file_cache avoids a fresh stat() per request for the
                # try_files lookup below (Gixy-Next's try_files_is_evil_too).
                _directive("open_file_cache", args=["max=1000", "inactive=20s"]),
                _directive("try_files", args=["/index.html", "=404"]),
            ],
        ),
    )
    return directives


def _stream_upstream_address(upstream: dict) -> str:
    host = upstream["host"]
    bracketed = f"[{host}]" if ":" in host else host
    return f"{bracketed}:{upstream['port']}"


def _upstream_url(upstream: dict) -> str:
    scheme = upstream.get("scheme", "http")
    host = upstream["host"]
    bracketed = f"[{host}]" if ":" in host else host
    path = upstream.get("path", "/")
    return f"{scheme}://{bracketed}:{upstream['port']}{path}"
