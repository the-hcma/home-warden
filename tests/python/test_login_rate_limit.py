"""Unit tests for the in-process login rate limiter (#76).

Route-level throttling behavior (429 + Retry-After, per-IP isolation) is
covered in tests/python/test_auth_routes.py; this file pins the limiter's
own backoff math and TTL eviction directly, since driving those precisely
through the HTTP layer would require dozens of near-duplicate requests.
"""

from __future__ import annotations

from app.login_rate_limit import LoginRateLimiter


class _FakeClock:
    def __init__(self) -> None:
        self._now = 0.0

    def __call__(self) -> float:
        return self._now

    def advance(self, seconds: float) -> None:
        self._now += seconds


def test_backoff_doubles_per_failure_past_the_threshold() -> None:
    clock = _FakeClock()
    limiter = LoginRateLimiter(base_backoff_seconds=1.0, failure_threshold=5, max_backoff_seconds=60.0, clock=clock)

    for _ in range(5):
        limiter.record_failure("1.2.3.4")
    assert limiter.seconds_until_allowed("1.2.3.4") == 0.0  # still under threshold

    limiter.record_failure("1.2.3.4")  # 6th failure: 1st over-threshold -> 1s
    assert limiter.seconds_until_allowed("1.2.3.4") == 1.0

    clock.advance(1.0)  # elapse the 1s block before the next failure
    limiter.record_failure("1.2.3.4")  # 7th failure: 2nd over-threshold -> 2s
    assert limiter.seconds_until_allowed("1.2.3.4") == 2.0


def test_backoff_is_capped_at_max_backoff_seconds() -> None:
    clock = _FakeClock()
    limiter = LoginRateLimiter(base_backoff_seconds=1.0, failure_threshold=1, max_backoff_seconds=10.0, clock=clock)

    # 10 failures past the threshold of 1 would be 2**9 = 512s uncapped.
    for _ in range(11):
        limiter.record_failure("1.2.3.4")
        clock.advance(limiter.seconds_until_allowed("1.2.3.4") or 0.0)

    assert limiter.seconds_until_allowed("1.2.3.4") <= 10.0


def test_record_success_clears_the_block() -> None:
    clock = _FakeClock()
    limiter = LoginRateLimiter(base_backoff_seconds=1.0, failure_threshold=1, clock=clock)

    limiter.record_failure("1.2.3.4")
    limiter.record_failure("1.2.3.4")
    assert limiter.seconds_until_allowed("1.2.3.4") > 0.0

    limiter.record_success("1.2.3.4")
    assert limiter.seconds_until_allowed("1.2.3.4") == 0.0


def test_stale_entry_expires_after_the_ttl_and_restarts_the_count() -> None:
    clock = _FakeClock()
    limiter = LoginRateLimiter(base_backoff_seconds=1.0, entry_ttl_seconds=900.0, failure_threshold=1, clock=clock)

    limiter.record_failure("1.2.3.4")
    limiter.record_failure("1.2.3.4")
    assert limiter.seconds_until_allowed("1.2.3.4") > 0.0

    clock.advance(900.0 + 1.0)
    # A single failure after the TTL must not immediately re-block: the
    # stale entry should have been evicted, restarting the failure count
    # rather than continuing to accumulate from where it left off.
    limiter.record_failure("1.2.3.4")
    assert limiter.seconds_until_allowed("1.2.3.4") == 0.0


def test_stale_entries_are_evicted_and_do_not_grow_unbounded() -> None:
    # A key that fails once and is never seen again must not keep its
    # entry forever -- that's the actual memory bound against a flood of
    # one-off/rotating source keys.
    clock = _FakeClock()
    limiter = LoginRateLimiter(entry_ttl_seconds=60.0, failure_threshold=100, clock=clock)

    for i in range(50):
        limiter.record_failure(f"10.0.0.{i}")
    assert len(limiter._entries) == 50  # internal state assertion

    clock.advance(61.0)
    limiter.record_failure("10.0.0.999")  # any activity sweeps stale entries
    assert len(limiter._entries) == 1  # only the fresh key remains
