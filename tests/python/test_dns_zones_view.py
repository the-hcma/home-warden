"""Tests for app.dns_zones_view."""

from __future__ import annotations

from pathlib import Path

from app.dns_zones_view import load_zones_yaml, local_records_for_owner

# --- load_zones_yaml ---------------------------------------------------


def test_load_zones_yaml_missing_file_is_empty_dict(tmp_path: Path) -> None:
    assert load_zones_yaml(tmp_path / "missing.yml") == {}


def test_load_zones_yaml_invalid_yaml_is_empty_dict(tmp_path: Path) -> None:
    path = tmp_path / "zones.yml"
    path.write_text("not: [valid, {")
    assert load_zones_yaml(path) == {}


def test_load_zones_yaml_undecodable_bytes_is_empty_dict(tmp_path: Path) -> None:
    # path.read_text() raises UnicodeDecodeError before yaml.safe_load
    # ever runs -- must degrade the same as invalid YAML, not 500 the
    # route.
    path = tmp_path / "zones.yml"
    path.write_bytes(b"\xff\xfe\x00")
    assert load_zones_yaml(path) == {}


def test_load_zones_yaml_non_mapping_top_level_is_empty_dict(tmp_path: Path) -> None:
    path = tmp_path / "zones.yml"
    path.write_text("- just\n- a\n- list\n")
    assert load_zones_yaml(path) == {}


def test_load_zones_yaml_ok(tmp_path: Path) -> None:
    path = tmp_path / "zones.yml"
    path.write_text("domains:\n  - domain: example.com\n    ttl: 3600\n    records: {}\n")
    data = load_zones_yaml(path)
    assert data["domains"][0]["domain"] == "example.com"


# --- local_records_for_owner --------------------------------------------


def test_local_records_for_owner_not_found() -> None:
    zones_data = {"domains": [{"domain": "example.com", "ttl": 3600, "records": {}}]}
    assert local_records_for_owner(zones_data, "backend.example.com") is None


def test_local_records_for_owner_present_but_empty_entries_list() -> None:
    # Representable (an owner key with a literal empty list), distinct
    # from the owner simply not being a key at all -- callers (the
    # /dns/records route) fold this into "missing" the same as a
    # not-found owner, since there's nothing to show either way.
    zones_data = {"domains": [{"domain": "example.com", "ttl": 3600, "records": {"backend.example.com": []}}]}
    assert local_records_for_owner(zones_data, "backend.example.com") == []


def test_local_records_for_owner_malformed_domains_is_not_found() -> None:
    assert local_records_for_owner({"domains": "oops"}, "backend.example.com") is None


def test_local_records_for_owner_plain_scalar_uses_zone_default_ttl() -> None:
    zones_data = {
        "domains": [
            {
                "domain": "example.com",
                "ttl": 3600,
                "records": {"backend.example.com": [{"a": "10.0.0.5"}]},
            }
        ]
    }
    result = local_records_for_owner(zones_data, "backend.example.com")
    assert result == [{"type": "a", "content": "10.0.0.5", "ttl": 3600}]


def test_local_records_for_owner_expanded_form_uses_own_ttl() -> None:
    zones_data = {
        "domains": [
            {
                "domain": "example.com",
                "ttl": 3600,
                "records": {"backend.example.com": [{"a": {"content": "10.0.0.5", "ttl": 60}}]},
            }
        ]
    }
    result = local_records_for_owner(zones_data, "backend.example.com")
    assert result == [{"type": "a", "content": "10.0.0.5", "ttl": 60}]


def test_local_records_for_owner_multiple_record_types() -> None:
    zones_data = {
        "domains": [
            {
                "domain": "example.com",
                "ttl": 3600,
                "records": {
                    "backend.example.com": [
                        {"a": "10.0.0.5"},
                        {"aaaa": "::1"},
                    ]
                },
            }
        ]
    }
    result = local_records_for_owner(zones_data, "backend.example.com")
    assert result == [
        {"type": "a", "content": "10.0.0.5", "ttl": 3600},
        {"type": "aaaa", "content": "::1", "ttl": 3600},
    ]


def test_local_records_for_owner_searches_multiple_zones() -> None:
    zones_data = {
        "domains": [
            {"domain": "example.com", "ttl": 3600, "records": {}},
            {
                "domain": "internal.example.com",
                "ttl": 300,
                "records": {"backend.internal.example.com": [{"a": "10.0.0.9"}]},
            },
        ]
    }
    result = local_records_for_owner(zones_data, "backend.internal.example.com")
    assert result == [{"type": "a", "content": "10.0.0.9", "ttl": 300}]
