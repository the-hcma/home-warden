"""app.dns_address_set: sync one name to several addresses without ever deleting a record.

A small in-memory Cloudflare stands in for the API: zones, records, and the three calls the sync makes.
"""

from __future__ import annotations

import pytest

from app import dns_address_set
from app.dns_address_set import parse_address_set, sync_dns_address_set


class FakeCloudflare:
    def __init__(self, records: list[dict]) -> None:
        self.records = [
            {"id": f"r{i}", "name": "mail.example.com", "proxied": False, "ttl": 300, **r}
            for i, r in enumerate(records)
        ]
        self.calls: list[tuple[str, str, dict]] = []
        self.total_pages = 1

    def __call__(self, url, headers, timeout, max_retries, *, method="GET", data=None):
        data = data or {}
        self.calls.append((method, url, data))
        if "/zones?name=" in url:
            return (
                {"result": [{"id": "z1", "name_servers": ["ns1.example.net"]}]}
                if "example.com" in url
                else {"result": []}
            )
        if method == "GET" and "/dns_records?name=" in url:
            return {"result": [dict(r) for r in self.records], "result_info": {"total_pages": self.total_pages}}
        if method == "PATCH":
            record = next(r for r in self.records if url.endswith("/" + r["id"]))
            record.update(data)
            return {"result": record}
        if method == "POST":
            record = {"id": f"r{len(self.records)}", "name": "mail.example.com", "ttl": 300, **data}
            self.records.append(record)
            return {"result": record}
        raise AssertionError(f"unexpected call {method} {url}")

    def writes(self) -> list[tuple[str, dict]]:
        return [(m, d) for m, _, d in self.calls if m in ("PATCH", "POST")]

    def contents(self) -> list[str]:
        return sorted(r["content"] for r in self.records)


@pytest.fixture
def cloudflare(monkeypatch):
    def install(records: list[dict], dig=None):
        fake = FakeCloudflare(records)
        monkeypatch.setattr(dns_address_set, "_cf_request", fake)
        monkeypatch.setattr(dns_address_set, "_resolve_via_authoritative_ns", lambda *a, **kw: dig)
        return fake

    return install


def test_a_different_record_type_at_the_name_is_refused(cloudflare) -> None:
    fake = cloudflare([{"type": "CNAME", "content": "other.example.net"}])
    result = _sync(["192.0.2.30", "192.0.2.9"])
    assert result.status == "failed" and "different type" in result.detail
    assert fake.writes() == []


def test_a_duplicate_of_a_wanted_address_is_named_as_a_duplicate_and_not_deleted(cloudflare) -> None:
    fake = cloudflare([{"type": "A", "content": "192.0.2.9"}, {"type": "A", "content": "192.0.2.9"}])
    result = _sync(["192.0.2.9"])
    assert result.status == "failed"
    assert "192.0.2.9 (duplicate)" in result.detail and "refusing to delete" in result.detail
    assert fake.writes() == []


def test_a_kept_record_whose_ttl_or_proxy_flag_differs_is_adjusted_with_one_patch(cloudflare) -> None:
    fake = cloudflare([{"type": "A", "content": "192.0.2.10", "proxied": True, "ttl": 60}])
    result = _sync(["192.0.2.10"], ttl=300, verify_resolution=False)
    assert result.status == "updated", result.detail
    assert fake.writes() == [("PATCH", {"proxied": False, "ttl": 300})]
    assert fake.records[0]["ttl"] == 300 and fake.records[0]["proxied"] is False


def test_a_listing_that_grows_a_second_page_after_the_write_is_a_failure(cloudflare, monkeypatch) -> None:
    fake = cloudflare([{"type": "A", "content": "192.0.2.10"}])
    original = fake.__call__

    def second_page_after_write(url, headers, timeout, max_retries, *, method="GET", data=None):
        result = original(url, headers, timeout, max_retries, method=method, data=data)
        if method == "GET" and "/dns_records?name=" in url and fake.writes():
            result = {**result, "result_info": {"total_pages": 2}}
        return result

    monkeypatch.setattr(dns_address_set, "_cf_request", second_page_after_write)
    result = _sync(["192.0.2.30", "192.0.2.9"], verify_resolution=False)
    assert result.status == "failed" and "now has more than 100 records" in result.detail


@pytest.mark.parametrize("info", [{"total_pages": 1}, {"total_pages": None}, {}, None])
def test_a_missing_or_single_page_count_is_a_complete_listing(info) -> None:
    assert dns_address_set._truncated({"result": [{"id": "r0"}], "result_info": info}) is False


@pytest.mark.parametrize("info", [{"total_pages": None}, {}, None])
def test_a_full_page_without_a_page_count_is_treated_as_truncated(info) -> None:
    full = [{"id": f"r{i}"} for i in range(100)]
    assert dns_address_set._truncated({"result": full, "result_info": info}) is True
    assert dns_address_set._truncated({"result": full[:99], "result_info": info}) is False


def test_an_ipv6_scope_identifier_is_refused() -> None:
    with pytest.raises(ValueError, match="scope identifier"):
        parse_address_set(["2001:db8::1", "2001:db8::2%eth0"])


@pytest.mark.parametrize("info", [{"total_pages": 2}, {"total_pages": "many"}, {"total_pages": [3]}])
def test_a_multi_page_or_unreadable_page_count_counts_as_truncated(info) -> None:
    assert dns_address_set._truncated({"result": [], "result_info": info}) is True


def test_a_name_already_holding_the_set_is_a_noop_and_writes_nothing(cloudflare) -> None:
    fake = cloudflare([{"type": "A", "content": "192.0.2.30"}, {"type": "A", "content": "192.0.2.9"}])
    result = _sync(["192.0.2.9", "192.0.2.30"])
    assert result.status == "noop"
    assert fake.writes() == []


def test_a_read_back_missing_an_address_is_a_failure(cloudflare, monkeypatch) -> None:
    fake = cloudflare([{"type": "A", "content": "192.0.2.10"}])
    original = fake.__call__

    def drop_post(url, headers, timeout, max_retries, *, method="GET", data=None):
        result = original(url, headers, timeout, max_retries, method=method, data=data)
        if method == "POST":
            fake.records.pop()
        return result

    monkeypatch.setattr(dns_address_set, "_cf_request", drop_post)
    result = _sync(["192.0.2.30", "192.0.2.9"], verify_resolution=False)
    assert result.status == "failed" and "not found on read-back" in result.detail


def test_a_read_back_that_still_shows_an_unwanted_record_is_a_failure(cloudflare, monkeypatch) -> None:
    fake = cloudflare([{"type": "A", "content": "192.0.2.10"}])
    original = fake.__call__

    def keep_old(url, headers, timeout, max_retries, *, method="GET", data=None):
        result = original(url, headers, timeout, max_retries, method=method, data=data)
        if method == "GET" and "/dns_records?name=" in url and fake.writes():
            result = {**result, "result": [*result["result"], {"type": "A", "content": "192.0.2.10", "id": "old"}]}
        return result

    monkeypatch.setattr(dns_address_set, "_cf_request", keep_old)
    result = _sync(["192.0.2.30", "192.0.2.9"], verify_resolution=False)
    assert result.status == "failed" and "not exactly" in result.detail


def test_a_truncated_listing_is_never_reconciled(cloudflare) -> None:
    fake = cloudflare([{"type": "A", "content": "192.0.2.10"}])
    fake.total_pages = 2
    result = _sync(["192.0.2.30", "192.0.2.9"])
    assert result.status == "failed" and "partial list" in result.detail
    assert fake.writes() == []


def test_a_wanted_address_that_already_exists_is_kept_not_rewritten(cloudflare) -> None:
    fake = cloudflare([{"type": "A", "content": "192.0.2.9"}])
    result = _sync(["192.0.2.30", "192.0.2.9"], verify_resolution=False)
    assert result.status == "created"
    assert [(m, d["content"]) for m, d in fake.writes()] == [("POST", "192.0.2.30")]


def test_an_authoritative_answer_missing_an_address_is_a_failure(cloudflare) -> None:
    cloudflare([{"type": "A", "content": "192.0.2.10"}], dig=["192.0.2.30"])
    result = _sync(["192.0.2.30", "192.0.2.9"])
    assert result.status == "failed" and "missing 192.0.2.9" in result.detail


def test_an_authoritative_answer_that_still_includes_an_unwanted_address_is_a_failure(cloudflare) -> None:
    cloudflare([{"type": "A", "content": "192.0.2.10"}], dig=["192.0.2.30", "192.0.2.9", "192.0.2.10"])
    result = _sync(["192.0.2.30", "192.0.2.9"])
    assert result.status == "failed" and "also answers 192.0.2.10" in result.detail


def test_dry_run_reports_the_steps_and_writes_nothing(cloudflare) -> None:
    fake = cloudflare([{"type": "A", "content": "192.0.2.10"}])
    result = _sync(["192.0.2.30", "192.0.2.9"], dry_run=True)
    assert result.status == "would-update"
    assert "move 192.0.2.10 -> 192.0.2.30" in result.detail and "create 192.0.2.9" in result.detail
    assert fake.writes() == []


def test_mixed_families_in_the_request_fail_before_any_call(cloudflare) -> None:
    fake = cloudflare([])
    result = _sync(["192.0.2.1", "2001:db8::1"])
    assert result.status == "failed" and "cannot be mixed" in result.detail
    assert fake.calls == []


def test_more_unwanted_records_than_addresses_to_move_them_to_fails_and_deletes_nothing(cloudflare) -> None:
    fake = cloudflare(
        [
            {"type": "A", "content": "192.0.2.10"},
            {"type": "A", "content": "192.0.2.11"},
            {"type": "A", "content": "192.0.2.12"},
        ]
    )
    result = _sync(["192.0.2.30", "192.0.2.9"])
    assert result.status == "failed"
    assert "192.0.2.12" in result.detail and "refusing to delete" in result.detail
    assert fake.writes() == []


def test_nothing_exists_so_both_addresses_are_created(cloudflare) -> None:
    fake = cloudflare([])
    result = _sync(["192.0.2.30", "192.0.2.9"], verify_resolution=False)
    assert result.status == "created", result.detail
    assert fake.contents() == ["192.0.2.30", "192.0.2.9"]
    assert [m for m, _ in fake.writes()] == ["POST", "POST"]


def test_one_existing_record_is_moved_and_the_second_address_created(cloudflare) -> None:
    fake = cloudflare([{"type": "A", "content": "192.0.2.10"}], dig=["192.0.2.30", "192.0.2.9"])
    result = _sync(["192.0.2.30", "192.0.2.9"])
    assert result.status == "updated", result.detail
    assert fake.contents() == ["192.0.2.30", "192.0.2.9"]
    assert [m for m, _ in fake.writes()] == ["PATCH", "POST"]


def test_parse_address_set_normalizes_dedupes_and_keeps_order() -> None:
    assert parse_address_set(["192.0.2.10", "192.0.2.9", "192.0.2.10"]) == ("A", ["192.0.2.10", "192.0.2.9"])
    assert parse_address_set(["2001:DB8::1"]) == ("AAAA", ["2001:db8::1"])


@pytest.mark.parametrize("bad", [[], ["mail.example.net"], ["192.0.2.1", "2001:db8::1"], ["192.0.2.999"]])
def test_parse_address_set_rejects_names_mixed_families_and_nothing(bad) -> None:
    with pytest.raises(ValueError):
        parse_address_set(bad)


def test_restore_mode_allows_extra_records_in_the_read_back_and_the_answer(cloudflare) -> None:
    cloudflare(
        [{"type": "A", "content": "192.0.2.30"}, {"type": "A", "content": "192.0.2.9"}], dig=["192.0.2.10", "192.0.2.9"]
    )
    result = _sync(["192.0.2.10"], allow_extra=True)
    assert result.status == "manual"


def test_restore_mode_dry_run_reports_the_records_it_would_leave(cloudflare) -> None:
    fake = cloudflare([{"type": "A", "content": "192.0.2.30"}, {"type": "A", "content": "192.0.2.9"}])
    result = _sync(["192.0.2.10"], allow_extra=True, dry_run=True)
    assert result.status == "manual"
    assert "would-update" in result.detail and "would have to be deleted by hand" in result.detail
    assert fake.writes() == []


def test_restore_mode_puts_back_ttl_and_proxy_on_a_kept_record_and_reports_the_other(cloudflare) -> None:
    fake = cloudflare(
        [
            {"type": "A", "content": "192.0.2.10", "proxied": True, "ttl": 60},
            {"type": "A", "content": "192.0.2.9"},
        ]
    )
    result = _sync(["192.0.2.10"], allow_extra=True, ttl=300, verify_resolution=False)
    assert result.status == "manual"
    assert fake.writes() == [("PATCH", {"proxied": False, "ttl": 300})]
    assert "192.0.2.9" in result.detail


def test_restore_mode_puts_the_original_back_and_reports_the_extra_record(cloudflare) -> None:
    fake = cloudflare([{"type": "A", "content": "192.0.2.30"}, {"type": "A", "content": "192.0.2.9"}])
    result = _sync(["192.0.2.10"], allow_extra=True, ttl=300, verify_resolution=False)
    assert result.status == "manual"
    assert "192.0.2.9" in result.detail or "192.0.2.30" in result.detail
    assert "192.0.2.10" in fake.contents() and len(fake.contents()) == 2
    assert [m for m, _ in fake.writes()] == ["PATCH"]


def _sync(targets, **kwargs):
    return sync_dns_address_set(
        "mail", {"server_name": "mail.example.com"}, targets, {"Authorization": "x"}, 5.0, 1, **kwargs
    )
