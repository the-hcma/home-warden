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
  plus an `if` gate applied at the server level -- kind-agnostic, so it
  enforces the CN allowlist for static as well as proxy vhosts, not just
  the location a particular kind happens to wrap its content in.
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
    for i, service in enumerate(services):
        allow_cn_map = _build_allow_cn_map(service, i)
        if allow_cn_map is not None:
            http_block.append(allow_cn_map)
    for i, service in enumerate(services):
        http_block.append(_build_server_block(service, ctx, index=i, is_default_server=(i == 0)))

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


# The catalog schema's client_cert.mode values ('off'/'optional'/'required',
# see services.json.example's _notes) are operator-facing wording, not raw
# nginx syntax: nginx's ssl_verify_client directive takes on/off/optional
# (never the schema's 'required' verbatim, and 'optional_no_ca' is
# deliberately never offered by the schema -- see #49).
_SSL_VERIFY_CLIENT_MODES = {"required": "on", "optional": "optional"}


def _allow_cidr_directives(allow_cidrs: list[str] | None) -> list[dict]:
    if not allow_cidrs:
        return []
    directives = [_directive("allow", args=[cidr]) for cidr in allow_cidrs]
    directives.append(_directive("deny", args=["all"]))
    return directives


def _allow_cn_gate_directives(service: dict, index: int) -> list[dict]:
    allow_cn = (service.get("client_cert") or {}).get("allow_cn")
    if not allow_cn:
        return []
    # crossplane's builder wraps `if` args in "(" ")" itself (see its
    # `build()`): passing already-parenthesized args here would double
    # them up and get the whole condition mis-quoted as one token. `if` is
    # valid directly in `server` context, so this applies uniformly to
    # every kind (not just proxy, where a location-scoped `if` would also
    # work) -- keeping enforcement kind-agnostic instead of only wiring it
    # into one location handler.
    map_var = f"${_allow_cn_map_name(service, index)}"
    return [_directive("if", args=[map_var, "=", "0"], block=[_directive("return", args=["403"])])]


def _allow_cn_map_name(service: dict, index: int) -> str:
    # Prefixing with the service's position in the catalog guarantees
    # uniqueness regardless of name collisions after sanitization
    # (`_safe_ident` collapses every non-alphanumeric character to `_`, so
    # e.g. "web-app" and "web.app", or two services that both omit `name`,
    # would otherwise sanitize to the same identifier and redeclare the
    # same nginx map variable -- either a config the assembled nginx
    # rejects outright, or a silent CN-allowlist mixup between vhosts).
    return f"allow_{index}_{_safe_ident(service.get('name', 'service'))}_cn"


def _build_allow_cn_map(service: dict, index: int) -> dict | None:
    allow_cn = (service.get("client_cert") or {}).get("allow_cn")
    if not allow_cn:
        return None
    map_block = [_directive("default", args=["0"])]
    for cn in allow_cn:
        # $ssl_client_s_dn is RFC 2253 form with RDNs printed in *reverse*
        # of the certificate subject's order (OpenSSL's XN_FLAG_DN_REV),
        # so CN is not reliably the first (or last) attribute -- anchoring
        # the pattern at the string start (`^CN=...`) misses any subject
        # where CN isn't emitted first. Match CN as any comma-delimited
        # RDN instead: preceded by start-of-string or a comma, followed by
        # a comma or end-of-string. The `(?<!\\)` negative lookbehind on
        # the leading comma rejects a comma that RFC 2253 escaped as part
        # of a *value* (e.g. subject "/CN=evil/OU=x,CN=alice" prints as
        # "OU=x\,CN=alice,CN=evil") -- without it, that escaped comma would
        # read as an RDN separator and let a cert whose real CN is "evil"
        # match the "alice" allowlist entry.
        #
        # This still can't distinguish a genuine "CN=alice" RDN from a
        # second, duplicate "CN=alice" RDN elsewhere in the same subject
        # (multiple CN attributes are legal in an X.509 name) -- that's a
        # CA issuance-policy concern (home-warden#49's tooling doesn't
        # exist yet to enforce single-CN subjects), not something a
        # regex over the flattened DN string can fully close.
        #
        # Backslash count: nginx's config-file lexer (ngx_conf_read_token)
        # collapses a literal `\\` pair to a single backslash *even in
        # unquoted tokens* (this map key isn't quoted -- it has no
        # whitespace/braces/semicolons for crossplane's builder to quote
        # it over), before the argument ever reaches pcre2_compile(). To
        # have PCRE see the two backslash characters `\\` it needs for a
        # literal-backslash lookbehind, the rendered *file* must contain
        # four backslash characters here, i.e. this Python string needs
        # two real backslashes (`\\` written twice) per escaped position.
        map_block.append(_directive(f"~(?:^|(?<!\\\\\\\\),)CN={_escape_map_pattern(cn)}(?:,|$)", args=["1"]))
    return _directive("map", args=["$ssl_client_s_dn", f"${_allow_cn_map_name(service, index)}"], block=map_block)


def _build_server_block(service: dict, ctx: RenderContext, *, index: int, is_default_server: bool = False) -> dict:
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

    if service.get("extra_location_blocks"):
        # Not yet implemented (see services.json.example note 16): fail
        # loudly rather than silently drop the operator's declared
        # location-block escape hatch (a rendered vhost with no trace of
        # it looks correct while quietly missing the intended directives).
        raise ValueError(
            f"extra_location_blocks is not yet supported by the renderer (service {service.get('name', '<unnamed>')!r})"
        )

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
        *_allow_cn_gate_directives(service, index),
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
    if not client_cert:
        return []
    mode = client_cert.get("mode", "off")
    # ca_bundle/crl/allow_cn only ever do anything once ssl_verify_client is
    # emitted -- declaring any of them while mode is "off" (explicitly, or
    # by omission, since "off" is the documented default) is never a valid
    # configuration and is a strong signal of a typo (a missing/mis-cased
    # `mode` key, or a misspelled `client_cert`/`clientCert` outer key)
    # rather than an intentional staged-mTLS state, so fail loud instead of
    # silently rendering a public vhost with no client-cert gate at all.
    has_cert_material = any(client_cert.get(k) for k in ("ca_bundle", "crl", "allow_cn"))
    if mode == "off":
        if has_cert_material:
            raise ValueError(
                "client_cert.mode is 'off' (or missing) but ca_bundle/crl/allow_cn is set for service "
                f"{service.get('name', '<unnamed>')!r} -- set mode to 'optional' or 'required', or drop them"
            )
        return []
    if mode not in _SSL_VERIFY_CLIENT_MODES:
        raise ValueError(f"unsupported client_cert.mode {mode!r} for service {service.get('name', '<unnamed>')!r}")
    if client_cert.get("allow_cn") and mode != "required":
        # The server-level allow_cn gate (`_allow_cn_gate_directives`) 403s
        # any request whose $ssl_client_s_dn doesn't match the allowlist --
        # including a request with no client cert at all, since the map's
        # `default 0` catches an empty $ssl_client_s_dn too. With
        # mode: "optional", that silently upgrades the declared optionality
        # to a de facto "required": nginx accepts an anonymous request past
        # ssl_verify_client, but the gate still rejects it. There's no
        # signal in the rendered config that the two disagree, so fail
        # loud here rather than let the deployed behavior surprise an
        # operator who genuinely wanted "verify a cert if presented, but
        # anonymous access is still fine for anyone not on the allowlist".
        raise ValueError(
            "client_cert.allow_cn requires mode: 'required' for service "
            f"{service.get('name', '<unnamed>')!r} -- with mode: 'optional', the CN gate would still "
            "403 every cert-less request, silently upgrading 'optional' to 'required'"
        )
    directives = [
        _directive("ssl_client_certificate", args=[client_cert["ca_bundle"]]),
        _directive("ssl_verify_client", args=[_SSL_VERIFY_CLIENT_MODES[mode]]),
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
