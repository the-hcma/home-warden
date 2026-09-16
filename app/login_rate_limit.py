"""In-process rate limiting for `POST /auth/login` (#76).

A single-process, single-host service doesn't need a shared datastore for
this -- an in-memory, per-source-key sliding backoff is enough. Deliberately
keyed by source IP (not username): the whole point of throttling a login
endpoint is to slow down credential guessing, and a per-username lockout
would hand an attacker a free denial-of-service against a legitimate
operator just by spraying wrong passwords at their username from anywhere.
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from time import monotonic

# Failed attempts allowed before any backoff kicks in -- generous enough
# that a legitimate operator mistyping a password a couple of times never
# notices, but small enough to blunt a fast automated guesser.
DEFAULT_FAILURE_THRESHOLD = 5
# Delay applied on the first throttled attempt once the threshold is
# crossed; doubles per additional failure (capped by max_backoff_seconds).
DEFAULT_BASE_BACKOFF_SECONDS = 1.0
DEFAULT_MAX_BACKOFF_SECONDS = 60.0
# An entry with no activity in this long is treated as fresh on its next
# failure, bounding memory growth from one-off/rotating source IPs instead
# of requiring a background sweep.
DEFAULT_ENTRY_TTL_SECONDS = 15 * 60


class _Entry:
    __slots__ = ("blocked_until", "failures", "last_seen")

    def __init__(self) -> None:
        self.blocked_until = 0.0
        self.failures = 0
        self.last_seen = 0.0


class LoginRateLimiter:
    """Per-key exponential backoff after repeated login failures.

    Thread-safe: FastAPI runs sync route handlers (like the PAM-backed
    login route this guards) in a worker thread pool, not just the event
    loop, so concurrent requests can call in from different threads.
    """

    def __init__(
        self,
        *,
        base_backoff_seconds: float = DEFAULT_BASE_BACKOFF_SECONDS,
        entry_ttl_seconds: float = DEFAULT_ENTRY_TTL_SECONDS,
        failure_threshold: int = DEFAULT_FAILURE_THRESHOLD,
        max_backoff_seconds: float = DEFAULT_MAX_BACKOFF_SECONDS,
        clock: Callable[[], float] = monotonic,
    ) -> None:
        self._base_backoff_seconds = base_backoff_seconds
        self._clock = clock
        self._entries: dict[str, _Entry] = {}
        self._entry_ttl_seconds = entry_ttl_seconds
        self._failure_threshold = failure_threshold
        self._lock = threading.Lock()
        self._max_backoff_seconds = max_backoff_seconds

    def record_failure(self, key: str) -> None:
        with self._lock:
            now = self._clock()
            entry = self._entries.get(key)
            if entry is None or now - entry.last_seen > self._entry_ttl_seconds:
                entry = _Entry()
                self._entries[key] = entry
            entry.last_seen = now
            entry.failures += 1
            if entry.failures > self._failure_threshold:
                # Bound the exponent itself, not just the resulting backoff:
                # entry.failures is attacker-controlled (unauthenticated
                # requests keep incrementing it), and 2 ** huge_exponent
                # raises OverflowError converting to float long before
                # min(...) below ever gets a chance to clamp the value.
                exponent = min(entry.failures - self._failure_threshold - 1, 63)
                backoff = self._base_backoff_seconds * (2**exponent)
                entry.blocked_until = now + min(backoff, self._max_backoff_seconds)
            self._evict_stale(now)

    def record_success(self, key: str) -> None:
        with self._lock:
            self._entries.pop(key, None)

    def seconds_until_allowed(self, key: str) -> float:
        """Returns 0.0 if an attempt is allowed right now, otherwise how
        many seconds the caller must wait before trying again."""
        with self._lock:
            now = self._clock()
            entry = self._entries.get(key)
            if entry is None:
                return 0.0
            if now - entry.last_seen > self._entry_ttl_seconds:
                del self._entries[key]
                return 0.0
            remaining = entry.blocked_until - now
            return remaining if remaining > 0 else 0.0

    def _evict_stale(self, now: float) -> None:
        # Called with self._lock already held. A key that fails once and is
        # never seen again would otherwise keep its _Entry for the process
        # lifetime -- record_success only clears the one key that just
        # succeeded, and seconds_until_allowed only evicts a key that's
        # actually queried again. Sweeping here (bounded by however often
        # failures happen) is what actually bounds _entries' size against a
        # flood of one-off/rotating source keys.
        stale = [
            stale_key
            for stale_key, stale_entry in self._entries.items()
            if now - stale_entry.last_seen > self._entry_ttl_seconds
        ]
        for stale_key in stale:
            del self._entries[stale_key]
