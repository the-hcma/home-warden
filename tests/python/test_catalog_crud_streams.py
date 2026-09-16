"""Tests for the stream (TCP passthrough) CRUD support in app.catalog_crud (#79)."""

from __future__ import annotations

import pytest

from app.catalog_crud import (
    CatalogConflictError,
    CatalogNotFoundError,
    CatalogValidationError,
    build_candidate_catalog,
    create_stream,
    delete_stream,
    get_stream,
    list_streams,
    update_stream,
    validate_stream,
)


def _stream(name: str, **overrides) -> dict:
    stream = {
        "name": name,
        "listen_port": 8883,
        "upstream": {"host": "broker.house.internal", "port": 1883},
    }
    stream.update(overrides)
    return stream


def test_create_stream_appends_a_valid_entry() -> None:
    catalog = {"services": [], "streams": [_stream("mqtt")]}

    created = create_stream(catalog, _stream("mqtt2", listen_port=8884))

    assert [stream["name"] for stream in created["streams"]] == ["mqtt", "mqtt2"]
    assert [stream["name"] for stream in catalog["streams"]] == ["mqtt"]


def test_create_stream_tolerates_a_missing_streams_key() -> None:
    catalog = {"services": []}

    created = create_stream(catalog, _stream("mqtt"))

    assert [stream["name"] for stream in created["streams"]] == ["mqtt"]
    assert "streams" not in catalog


def test_create_stream_rejects_duplicate_name() -> None:
    catalog = {"streams": [_stream("mqtt")]}

    with pytest.raises(CatalogConflictError):
        create_stream(catalog, _stream("mqtt", listen_port=9999))


def test_create_stream_rejects_duplicate_listen_port() -> None:
    catalog = {"streams": [_stream("mqtt")]}

    with pytest.raises(CatalogConflictError):
        create_stream(catalog, _stream("mqtt2", listen_port=8883))


def test_delete_stream_removes_the_named_entry() -> None:
    catalog = {"streams": [_stream("mqtt"), _stream("mqtt2", listen_port=8884)]}

    updated = delete_stream(catalog, "mqtt")

    assert [stream["name"] for stream in updated["streams"]] == ["mqtt2"]


def test_delete_stream_raises_not_found_for_a_missing_name() -> None:
    catalog = {"streams": [_stream("mqtt")]}

    with pytest.raises(CatalogNotFoundError):
        delete_stream(catalog, "missing")


def test_get_stream_returns_a_copy() -> None:
    catalog = {"streams": [_stream("mqtt")]}

    fetched = get_stream(catalog, "mqtt")
    fetched["listen_port"] = 1

    assert catalog["streams"][0]["listen_port"] == 8883


def test_get_stream_raises_not_found_for_a_missing_name() -> None:
    catalog = {"streams": [_stream("mqtt")]}

    with pytest.raises(CatalogNotFoundError):
        get_stream(catalog, "missing")


def test_list_streams_returns_all_entries() -> None:
    catalog = {"streams": [_stream("mqtt"), _stream("mqtt2", listen_port=8884)]}

    assert [stream["name"] for stream in list_streams(catalog)] == ["mqtt", "mqtt2"]


def test_list_streams_tolerates_a_missing_streams_key() -> None:
    assert list_streams({"services": []}) == []


def test_update_stream_merges_fields() -> None:
    catalog = {"streams": [_stream("mqtt")]}

    updated = update_stream(catalog, "mqtt", {"upstream": {"port": 1884}})

    assert updated["streams"][0]["upstream"] == {"host": "broker.house.internal", "port": 1884}


def test_update_stream_raises_not_found_for_a_missing_name() -> None:
    catalog = {"streams": [_stream("mqtt")]}

    with pytest.raises(CatalogNotFoundError):
        update_stream(catalog, "missing", {"listen_port": 8884})


def test_update_stream_rejects_collision_with_another_entry() -> None:
    catalog = {"streams": [_stream("mqtt"), _stream("mqtt2", listen_port=8884)]}

    with pytest.raises(CatalogConflictError):
        update_stream(catalog, "mqtt2", {"listen_port": 8883})


def test_validate_stream_accepts_a_valid_entry() -> None:
    validated = validate_stream(_stream("mqtt"))

    assert validated["name"] == "mqtt"
    assert validated["upstream"] == {"host": "broker.house.internal", "port": 1883}


def test_validate_stream_strips_required_string_fields() -> None:
    validated = validate_stream(_stream(" mqtt ", upstream={"host": " broker.house.internal ", "port": 1883}))

    assert validated["name"] == "mqtt"
    assert validated["upstream"]["host"] == "broker.house.internal"


@pytest.mark.parametrize(
    ("overrides", "expected"),
    [
        ({"name": ""}, "must be a non-empty string"),
        ({"listen_port": 0}, "listen_port must be an integer"),
        ({"listen_port": 65536}, "listen_port must be an integer"),
        ({"listen_port": "8883"}, "listen_port must be an integer"),
        ({"upstream": "not-an-object"}, "requires an upstream object"),
        ({"upstream": {"port": 1883}}, "upstream.host must be a non-empty string"),
        ({"upstream": {"host": "", "port": 1883}}, "upstream.host must be a non-empty string"),
        ({"upstream": {"host": "broker", "port": 0}}, "upstream.port must be an integer"),
        ({"upstream": {"host": "broker", "port": "1883"}}, "upstream.port must be an integer"),
    ],
)
def test_validate_stream_rejects_malformed_entries(overrides: dict, expected: str) -> None:
    stream = _stream("mqtt")
    stream.update(overrides)

    with pytest.raises(CatalogValidationError, match=expected):
        validate_stream(stream)


def test_build_candidate_catalog_dispatches_stream_actions() -> None:
    catalog = {"streams": [_stream("mqtt")]}

    created = build_candidate_catalog(catalog, "create", service=_stream("mqtt2", listen_port=8884), target="stream")
    assert [stream["name"] for stream in created["streams"]] == ["mqtt", "mqtt2"]

    deleted = build_candidate_catalog(catalog, "delete", name="mqtt", target="stream")
    assert deleted["streams"] == []

    updated = build_candidate_catalog(
        catalog, "update", name="mqtt", service={"listen_port": 8885}, target="stream"
    )
    assert updated["streams"][0]["listen_port"] == 8885


def test_build_candidate_catalog_stream_requires_payloads() -> None:
    catalog = {"streams": [_stream("mqtt")]}

    with pytest.raises(CatalogValidationError):
        build_candidate_catalog(catalog, "create", target="stream")
    with pytest.raises(CatalogValidationError):
        build_candidate_catalog(catalog, "delete", target="stream")
    with pytest.raises(CatalogValidationError):
        build_candidate_catalog(catalog, "update", name="mqtt", target="stream")
