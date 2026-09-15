"""Tests for app.catalog_render.

Covers the known fidelity gaps #45/#54's validation pass identified (IPv6
bracket notation, static exact-match root location, CRL, allow_cn), plus a
crossplane.parse() round-trip on every rendered config -- the same
directive-context/argument validation nginx itself does, giving a real
syntax check without needing a local nginx binary. See #54.
"""

from __future__ import annotations

import json
from pathlib import Path

import crossplane
import pytest

from app.catalog_render import RenderContext, build_catalog_config, render_catalog

EXAMPLE_CATALOG_PATH = Path(__file__).resolve().parent.parent.parent / "services.json.example"


def _parse_ok(rendered: str, tmp_path: Path) -> None:
    conf_path = tmp_path / "nginx.conf"
    conf_path.write_text(rendered)
    result = crossplane.parse(str(conf_path), combine=True)
    assert result["status"] == "ok", result.get("errors")


def _proxy_service(name: str = "svc", **overrides) -> dict:
    service = {
        "name": name,
        "server_name": f"{name}.example.com",
        "kind": "proxy",
        "upstream": {"scheme": "http", "host": "backend.internal", "port": 8080, "path": "/"},
    }
    service.update(overrides)
    return service


def test_allow_cidrs_render_allow_then_deny_all(tmp_path: Path) -> None:
    catalog = {"services": [_proxy_service(allow_cidrs=["10.0.0.0/24", "192.168.1.0/24"])]}
    rendered = render_catalog(catalog, RenderContext(certs_live_dir=tmp_path))
    assert "allow 10.0.0.0/24;" in rendered
    assert "allow 192.168.1.0/24;" in rendered
    assert "deny all;" in rendered
    _parse_ok(rendered, tmp_path)


def test_allow_cn_builds_map_block_and_if_gate(tmp_path: Path) -> None:
    catalog = {
        "services": [
            _proxy_service(
                client_cert={
                    "mode": "required",
                    "ca_bundle": "/tmp/ca.pem",
                    "allow_cn": ["alice"],
                }
            )
        ]
    }
    rendered = render_catalog(catalog, RenderContext(certs_live_dir=tmp_path))
    assert "map $ssl_client_s_dn $allow_svc_cn {" in rendered
    assert "~^CN=alice(,|$) 1;" in rendered
    assert "if ($allow_svc_cn = 0) {" in rendered
    assert "return 403;" in rendered
    _parse_ok(rendered, tmp_path)


def test_allow_cn_pattern_escapes_regex_metacharacters(tmp_path: Path) -> None:
    catalog = {
        "services": [
            _proxy_service(client_cert={"mode": "required", "ca_bundle": "/tmp/ca.pem", "allow_cn": ["bob (admin)"]})
        ]
    }
    rendered = render_catalog(catalog, RenderContext(certs_live_dir=tmp_path))
    assert r"bob \(admin\)" in rendered
    _parse_ok(rendered, tmp_path)


def test_crl_renders_ssl_crl_directive(tmp_path: Path) -> None:
    catalog = {
        "services": [
            _proxy_service(
                client_cert={"mode": "optional", "ca_bundle": "/tmp/ca.pem", "crl": "/tmp/ca.crl", "verify_depth": 2}
            )
        ]
    }
    rendered = render_catalog(catalog, RenderContext(certs_live_dir=tmp_path))
    assert "ssl_client_certificate /tmp/ca.pem;" in rendered
    assert "ssl_verify_client optional;" in rendered
    assert "ssl_verify_depth 2;" in rendered
    assert "ssl_crl /tmp/ca.crl;" in rendered
    _parse_ok(rendered, tmp_path)


def test_client_cert_mode_required_maps_to_ssl_verify_client_on(tmp_path: Path) -> None:
    # The schema's client_cert.mode is 'off'/'optional'/'required' (operator
    # wording); nginx's ssl_verify_client only accepts on/off/optional --
    # 'required' verbatim is an invalid value that fails `nginx -t`.
    catalog = {"services": [_proxy_service(client_cert={"mode": "required", "ca_bundle": "/tmp/ca.pem"})]}
    rendered = render_catalog(catalog, RenderContext(certs_live_dir=tmp_path))
    assert "ssl_verify_client on;" in rendered
    assert "ssl_verify_client required;" not in rendered
    _parse_ok(rendered, tmp_path)


def test_example_catalog_renders_and_parses(tmp_path: Path) -> None:
    catalog = json.loads(EXAMPLE_CATALOG_PATH.read_text())
    rendered = render_catalog(catalog, RenderContext(certs_live_dir=tmp_path))
    _parse_ok(rendered, tmp_path)


def test_default_server_flag_only_on_first_service(tmp_path: Path) -> None:
    catalog = {"services": [_proxy_service(name="a"), _proxy_service(name="b")]}
    rendered = render_catalog(catalog, RenderContext(certs_live_dir=tmp_path))
    listen_lines = [line for line in rendered.splitlines() if line.strip().startswith("listen ")]
    assert sum(1 for line in listen_lines if line.strip() == "listen 443 ssl default_server;") == 1
    assert sum(1 for line in listen_lines if line.strip() == "listen 443 ssl;") == 1
    _parse_ok(rendered, tmp_path)


def test_forward_host_header_and_websocket_directives(tmp_path: Path) -> None:
    catalog = {"services": [_proxy_service(forward_host_header=True, websocket=True)]}
    rendered = render_catalog(catalog, RenderContext(certs_live_dir=tmp_path))
    assert "proxy_set_header Host $host;" in rendered
    assert "proxy_http_version 1.1;" in rendered
    assert "proxy_set_header Upgrade $http_upgrade;" in rendered
    assert "proxy_set_header Connection upgrade;" in rendered
    assert "proxy_buffering off;" in rendered
    _parse_ok(rendered, tmp_path)


def test_gzip_off_only_when_explicitly_false(tmp_path: Path) -> None:
    catalog = {"services": [_proxy_service(name="a", gzip=False), _proxy_service(name="b")]}
    rendered = render_catalog(catalog, RenderContext(certs_live_dir=tmp_path))
    assert rendered.count("gzip off;") == 1
    _parse_ok(rendered, tmp_path)


def test_ipv6_stream_upstream_gets_bracket_notation(tmp_path: Path) -> None:
    catalog = {
        "streams": [
            {"name": "s", "listen_port": 1883, "upstream": {"host": "2001:db8::2", "port": 1883}},
        ],
    }
    rendered = render_catalog(catalog, RenderContext(certs_live_dir=tmp_path))
    assert "proxy_pass [2001:db8::2]:1883;" in rendered
    _parse_ok(rendered, tmp_path)


def test_ipv6_upstream_host_gets_bracket_notation(tmp_path: Path) -> None:
    catalog = {"services": [_proxy_service(upstream={"scheme": "http", "host": "2001:db8::1", "port": 8080})]}
    rendered = render_catalog(catalog, RenderContext(certs_live_dir=tmp_path))
    assert "proxy_pass http://[2001:db8::1]:8080/;" in rendered
    _parse_ok(rendered, tmp_path)


def test_ipv4_upstream_host_is_not_bracketed(tmp_path: Path) -> None:
    catalog = {"services": [_proxy_service(upstream={"scheme": "http", "host": "10.0.0.5", "port": 8080})]}
    rendered = render_catalog(catalog, RenderContext(certs_live_dir=tmp_path))
    assert "proxy_pass http://10.0.0.5:8080/;" in rendered
    assert "[10.0.0.5]" not in rendered


def test_static_service_gets_exact_match_root_before_general_location(tmp_path: Path) -> None:
    catalog = {
        "services": [
            {
                "name": "static-svc",
                "server_name": "static.example.com",
                "kind": "static",
                "static": {"root": "/srv/example", "listing_path": "/listing/"},
            }
        ]
    }
    rendered = render_catalog(catalog, RenderContext(certs_live_dir=tmp_path))
    exact_idx = rendered.index("location = / {")
    general_root_idx = rendered.index("root /srv/example;", exact_idx + 1)
    listing_idx = rendered.index("location /listing/ {")
    assert exact_idx < general_root_idx < listing_idx
    assert "try_files /index.html =404;" in rendered
    assert "open_file_cache max=1000 inactive=20s;" in rendered
    assert "autoindex on;" in rendered
    _parse_ok(rendered, tmp_path)


def test_static_service_without_listing_path_has_no_autoindex(tmp_path: Path) -> None:
    catalog = {
        "services": [
            {
                "name": "static-svc",
                "server_name": "static.example.com",
                "kind": "static",
                "static": {"root": "/srv/example"},
            }
        ]
    }
    rendered = render_catalog(catalog, RenderContext(certs_live_dir=tmp_path))
    assert "autoindex" not in rendered
    _parse_ok(rendered, tmp_path)


def test_server_tokens_off_by_default_and_omittable(tmp_path: Path) -> None:
    catalog = {"services": [_proxy_service()]}
    rendered = render_catalog(catalog, RenderContext(certs_live_dir=tmp_path))
    assert "server_tokens off;" in rendered
    _parse_ok(rendered, tmp_path)

    rendered_without = render_catalog(catalog, RenderContext(certs_live_dir=tmp_path, server_tokens_off=False))
    assert not any(line.strip().startswith("server_tokens") for line in rendered_without.splitlines())
    _parse_ok(rendered_without, tmp_path)


def test_unsupported_kind_raises_value_error(tmp_path: Path) -> None:
    catalog = {"services": [_proxy_service(kind="not-a-real-kind")]}
    with pytest.raises(ValueError, match="unsupported service kind"):
        build_catalog_config(catalog, RenderContext(certs_live_dir=tmp_path))
