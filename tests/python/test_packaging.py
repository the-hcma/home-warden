"""Smoke test for the uv/pytest/ruff project skeleton itself.

Confirms `app`/`config` are actually importable as the packaged project,
not just present as directories, so a packaging regression (e.g. a bad
[tool.hatch.build] entry) fails CI here rather than silently in whatever
feature test notices it first.
"""

from __future__ import annotations

import importlib


def test_app_package_importable() -> None:
    assert importlib.import_module("app") is not None


def test_config_package_importable() -> None:
    assert importlib.import_module("config") is not None
