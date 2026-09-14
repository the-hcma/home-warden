"""Smoke test for the uv/pytest/ruff project skeleton itself.

Placeholder until real Python code lands (the-hcma/home-warden#57) --
confirms `app`/`config` are actually importable as the packaged project,
not just present as directories, so a packaging regression fails CI here
rather than silently in whatever feature PR notices it first.
"""

from __future__ import annotations

import importlib


def test_app_package_importable() -> None:
    assert importlib.import_module("app") is not None


def test_config_package_importable() -> None:
    assert importlib.import_module("config") is not None
