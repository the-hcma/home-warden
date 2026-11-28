"""wait_for_authoritative_answer and the two sync functions that report a failed write only after it gave up (#281)."""

from __future__ import annotations

import pytest

from app import catalog_checks, dns_address_set
from app.catalog_checks import SyncResult, sync_dns_record, wait_for_authoritative_answer
from app.dns_address_set import sync_dns_address_set


def test_a_late_answer_is_waited_for(monkeypatch) -> None:
    resolver = _Resolver([["192.0.2.10"], ["192.0.2.10"], ["192.0.2.30"]])
    answers, attempts = wait_for_authoritative_answer(resolver, lambda found: "192.0.2.30" in found)
    assert answers == ["192.0.2.30"] and attempts == 3


def test_a_later_good_answer_still_wins_after_a_query_that_got_no_answer(monkeypatch) -> None:
    resolver = _Resolver([["192.0.2.10"], None, ["192.0.2.30"]])
    answers, attempts = wait_for_authoritative_answer(resolver, lambda found: "192.0.2.30" in found)
    assert answers == ["192.0.2.30"] and attempts == 3


def test_a_query_that_gets_no_answer_after_a_disagreeing_one_does_not_turn_into_a_pass(monkeypatch) -> None:
    monkeypatch.setenv("DNS_SYNC_ANSWER_TRIES", "3")
    resolver = _Resolver([["192.0.2.10"], None, None])
    answers, attempts = wait_for_authoritative_answer(resolver, lambda found: "192.0.2.30" in found)
    assert answers == ["192.0.2.10"] and attempts == 3


def test_an_answer_that_never_agrees_stops_at_the_configured_tries(monkeypatch) -> None:
    monkeypatch.setenv("DNS_SYNC_ANSWER_TRIES", "4")
    resolver = _Resolver([["192.0.2.10"]])
    answers, attempts = wait_for_authoritative_answer(resolver, lambda found: "192.0.2.30" in found)
    assert answers == ["192.0.2.10"] and attempts == 4 and resolver.calls == 4


def test_no_answer_at_all_ends_the_wait_at_once(monkeypatch) -> None:
    resolver = _Resolver([None])
    answers, attempts = wait_for_authoritative_answer(resolver, lambda found: True)
    assert answers is None and attempts == 1


def test_sync_dns_address_set_fails_only_after_the_tries_and_says_so(monkeypatch) -> None:
    monkeypatch.setenv("DNS_SYNC_ANSWER_TRIES", "2")
    monkeypatch.setattr(dns_address_set, "_cf_request", _cloudflare("192.0.2.10"))
    resolver = _Resolver([["192.0.2.10"]])
    monkeypatch.setattr(dns_address_set, "_resolve_via_authoritative_ns", resolver)
    result = sync_dns_address_set("app", {"server_name": "app.example.com"}, ["192.0.2.30"], {"x": "y"}, 5.0, 1)
    assert result.status == "failed" and "checked 2 time(s)" in result.detail
    assert "dig +short app.example.com A @ns1.example.net" in result.detail and "--dry-run" not in result.detail


def test_sync_dns_address_set_succeeds_when_the_nameserver_catches_up(monkeypatch) -> None:
    monkeypatch.setattr(dns_address_set, "_cf_request", _cloudflare("192.0.2.10"))
    resolver = _Resolver([["192.0.2.10"], ["192.0.2.30"]])
    monkeypatch.setattr(dns_address_set, "_resolve_via_authoritative_ns", resolver)
    result = sync_dns_address_set("app", {"server_name": "app.example.com"}, ["192.0.2.30"], {"x": "y"}, 5.0, 1)
    assert isinstance(result, SyncResult) and result.status == "updated", result.detail
    assert resolver.calls == 2


def test_sync_dns_record_fails_only_after_the_tries_and_says_so(monkeypatch) -> None:
    monkeypatch.setenv("DNS_SYNC_ANSWER_TRIES", "3")
    monkeypatch.setattr(catalog_checks, "_cf_request", _cloudflare("192.0.2.10"))
    resolver = _Resolver([["192.0.2.10"]])
    monkeypatch.setattr(catalog_checks, "_resolve_via_authoritative_ns", resolver)
    result = sync_dns_record("app", {"server_name": "app.example.com"}, "192.0.2.30", {"x": "y"}, 5.0, 1)
    assert result.status == "failed"
    assert "checked 3 time(s)" in result.detail
    assert "dig +short app.example.com A @ns1.example.net" in result.detail
    assert "--dry-run" not in result.detail
    assert resolver.calls == 3


def test_sync_dns_record_reports_the_old_answer_when_later_queries_get_none(monkeypatch) -> None:
    monkeypatch.setenv("DNS_SYNC_ANSWER_TRIES", "3")
    monkeypatch.setattr(catalog_checks, "_cf_request", _cloudflare("192.0.2.10"))
    monkeypatch.setattr(catalog_checks, "_resolve_via_authoritative_ns", _Resolver([["192.0.2.10"], None, None]))
    result = sync_dns_record("app", {"server_name": "app.example.com"}, "192.0.2.30", {"x": "y"}, 5.0, 1)
    assert result.status == "failed" and "192.0.2.10" in result.detail


def test_sync_dns_record_succeeds_when_the_nameserver_catches_up(monkeypatch) -> None:
    monkeypatch.setattr(catalog_checks, "_cf_request", _cloudflare("192.0.2.10"))
    resolver = _Resolver([["192.0.2.10"], ["192.0.2.10"], ["192.0.2.30"]])
    monkeypatch.setattr(catalog_checks, "_resolve_via_authoritative_ns", resolver)
    result = sync_dns_record("app", {"server_name": "app.example.com"}, "192.0.2.30", {"x": "y"}, 5.0, 1)
    assert result.status == "updated", result.detail
    assert resolver.calls == 3


@pytest.mark.parametrize(("value", "expected"), [("0", 1), ("x", 5), ("-3", 1), ("7", 7)])
def test_the_tries_setting_is_bounded_and_forgiving(monkeypatch, value: str, expected: int) -> None:
    monkeypatch.setenv("DNS_SYNC_ANSWER_TRIES", value)
    assert catalog_checks._answer_tries() == expected


class _Resolver:
    """Answers each call from `script`, repeating the last entry."""

    def __init__(self, script: list[list[str] | None]) -> None:
        self.script = script
        self.calls = 0

    def __call__(self, *args, **kwargs):
        answer = self.script[min(self.calls, len(self.script) - 1)]
        self.calls += 1
        return answer


def _cloudflare(record_ip: str):
    """A one-zone Cloudflare holding a single A record; a PATCH or POST changes it. Returns the stub."""
    state = {"records": [{"id": "r0", "type": "A", "name": "app.example.com", "content": record_ip, "proxied": False}]}

    def request(url, headers, timeout, max_retries, *, method="GET", data=None):
        if "/zones?name=" in url:
            return {"result": [{"id": "z1", "name_servers": ["ns1.example.net"]}]}
        if method == "PATCH":
            state["records"][0].update(data or {})
            return {"result": state["records"][0]}
        return {"result": [dict(r) for r in state["records"]]}

    return request
