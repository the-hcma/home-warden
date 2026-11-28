"""Shared pytest settings."""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _no_answer_delay(monkeypatch: pytest.MonkeyPatch) -> None:
    # The authoritative-answer check after a DNS write retries with a delay (DNS_SYNC_ANSWER_DELAY_S): no test sleeps.
    # The attempt count is pinned too, to a value other than the built-in default (5) so that a test can tell the pin is
    # in place, and an operator's environment cannot change what the tests expect; a test that needs another value
    # sets it in its own body.
    monkeypatch.setenv("DNS_SYNC_ANSWER_DELAY_S", "0")
    monkeypatch.setenv("DNS_SYNC_ANSWER_TRIES", "7")
