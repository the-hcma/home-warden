"""Shared pytest settings."""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _no_answer_delay(monkeypatch: pytest.MonkeyPatch) -> None:
    # The authoritative-answer check after a DNS write retries with a delay (DNS_SYNC_ANSWER_DELAY_S); no test sleeps.
    monkeypatch.setenv("DNS_SYNC_ANSWER_DELAY_S", "0")
