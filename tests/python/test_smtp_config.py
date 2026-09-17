"""Tests for app.smtp_config."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from app.home_warden_config import HomeWardenConfig, load_config
from app.smtp_config import (
    SmtpConfig,
    SmtpConfigStorageError,
    SmtpConfigUpdate,
    delete_smtp_config,
    load_smtp_config,
    save_smtp_config,
    smtp_send_ready,
)


def _update(**overrides) -> SmtpConfigUpdate:
    defaults = {
        "from_address": "alerts@example.com",
        "host": "smtp.example.com",
        "mail_domain": "example.com",
        "password": "s3cret",
        "port": 587,
        "username": "alerts",
    }
    defaults.update(overrides)
    return SmtpConfigUpdate(**defaults)


def test_load_smtp_config_returns_none_when_unset(tmp_path: Path) -> None:
    assert load_smtp_config(tmp_path / "config.toml") is None


def test_save_and_load_round_trips(tmp_path: Path) -> None:
    path = tmp_path / "config.toml"
    saved = save_smtp_config(_update(), path)

    assert saved == SmtpConfig(
        from_address="alerts@example.com",
        host="smtp.example.com",
        mail_domain="example.com",
        password="s3cret",
        port=587,
        username="alerts",
    )
    assert load_smtp_config(path) == saved


def test_save_smtp_config_is_chmod_600(tmp_path: Path) -> None:
    path = tmp_path / "config.toml"
    save_smtp_config(_update(), path)
    assert (path.stat().st_mode & 0o777) == 0o600


def test_save_smtp_config_preserves_other_top_level_keys(tmp_path: Path) -> None:
    path = tmp_path / "config.toml"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text('fqdn = "warden.example.com"\n')

    save_smtp_config(_update(), path)

    assert 'fqdn = "warden.example.com"' in path.read_text()
    assert load_smtp_config(path) is not None
    # Regression: a naive rewrite that only round-trips through this
    # module's own reader (not home_warden_config's) could silently
    # corrupt the fqdn value another loader depends on.
    assert load_config(path) == HomeWardenConfig(fqdn="warden.example.com")


def test_save_smtp_config_none_password_keeps_existing(tmp_path: Path) -> None:
    path = tmp_path / "config.toml"
    save_smtp_config(_update(password="original"), path)

    resaved = save_smtp_config(_update(password=None, host="smtp2.example.com"), path)

    assert resaved.password == "original"
    assert resaved.host == "smtp2.example.com"


def test_save_smtp_config_empty_string_password_clears_it(tmp_path: Path) -> None:
    path = tmp_path / "config.toml"
    save_smtp_config(_update(password="original"), path)

    resaved = save_smtp_config(_update(password=""), path)

    assert resaved.password == ""


def test_delete_smtp_config_removes_table_but_keeps_fqdn(tmp_path: Path) -> None:
    path = tmp_path / "config.toml"
    path.write_text('fqdn = "warden.example.com"\n')
    save_smtp_config(_update(), path)

    delete_smtp_config(path)

    assert load_smtp_config(path) is None
    assert 'fqdn = "warden.example.com"' in path.read_text()


def test_delete_smtp_config_on_missing_file_is_a_noop(tmp_path: Path) -> None:
    delete_smtp_config(tmp_path / "config.toml")  # must not raise


def test_toml_string_values_are_escaped(tmp_path: Path) -> None:
    # A password containing a quote and a backslash must round-trip exactly,
    # not corrupt the rendered TOML file into something tomllib can't parse.
    path = tmp_path / "config.toml"
    tricky = 'p@ss"w\\ord'
    save_smtp_config(_update(password=tricky), path)

    reloaded = load_smtp_config(path)
    assert reloaded is not None
    assert reloaded.password == tricky


def test_toml_string_values_escape_arbitrary_control_characters(tmp_path: Path) -> None:
    # Regression: only \n \t \r were escaped -- any other control
    # character (vertical tab, ESC, ...) wrote an invalid TOML file that
    # tomllib itself couldn't parse back, silently "losing" the settings
    # (and fqdn alongside them) on the very next read.
    path = tmp_path / "config.toml"
    tricky = "line1\x0bline2\x1bend"  # vertical tab + ESC
    save_smtp_config(_update(password=tricky), path)

    reloaded = load_smtp_config(path)
    assert reloaded is not None
    assert reloaded.password == tricky


def test_write_toml_dict_is_never_briefly_world_readable(tmp_path: Path) -> None:
    # Regression: write_text() then chmod() leaves a real window (and, on
    # a crash between the two calls, a permanent state) where this file --
    # now holding a relay password -- sits at the process umask's default
    # mode rather than operator-only. Same pattern app/home_warden_auth.py
    # already avoids for the session secret.
    path = tmp_path / "config.toml"
    original_umask = os.umask(0o022)  # a typical default, deliberately loose
    try:
        save_smtp_config(_update(), path)
    finally:
        os.umask(original_umask)

    assert (path.stat().st_mode & 0o777) == 0o600


def test_smtp_send_ready_requires_host_domain_and_from_address() -> None:
    assert smtp_send_ready(None) is False
    assert smtp_send_ready(SmtpConfig()) is False
    assert smtp_send_ready(SmtpConfig(from_address="a@b.com", host="smtp.example.com", mail_domain="b.com")) is True


def test_load_smtp_config_gracefully_degrades_on_malformed_file(tmp_path: Path) -> None:
    # Reads stay lenient (matches home_warden_config.load_config's own
    # precedent for this file) -- only writes must refuse.
    path = tmp_path / "config.toml"
    path.write_text("fqdn = warden.example.com\n")  # unquoted string -- invalid TOML

    assert load_smtp_config(path) is None


def test_save_smtp_config_refuses_to_overwrite_malformed_file(tmp_path: Path) -> None:
    path = tmp_path / "config.toml"
    original = "fqdn = warden.example.com\n"  # unquoted string -- invalid TOML
    path.write_text(original)

    with pytest.raises(SmtpConfigStorageError):
        save_smtp_config(_update(), path)

    # Must not have been overwritten -- a partial/guessed rewrite here
    # would permanently drop the fqdn key this module doesn't own.
    assert path.read_text() == original


def test_save_smtp_config_refuses_to_write_unsupported_value_type(tmp_path: Path) -> None:
    # Regression: a config.toml that parses cleanly but holds a type this
    # writer can't re-serialize (a float, an array, a date, ...) used to
    # raise a bare TypeError out of save_smtp_config -- an untranslated
    # 500 at the route layer instead of the same 409-refuse-to-overwrite
    # contract every other unwritable-file case gets.
    path = tmp_path / "config.toml"
    original = "alert_days = 1.5\n"  # a float -- valid TOML, unsupported by this writer
    path.write_text(original)

    with pytest.raises(SmtpConfigStorageError):
        save_smtp_config(_update(), path)

    assert path.read_text() == original


def test_delete_smtp_config_refuses_to_overwrite_malformed_file(tmp_path: Path) -> None:
    path = tmp_path / "config.toml"
    original = "fqdn = warden.example.com\n"
    path.write_text(original)

    with pytest.raises(SmtpConfigStorageError):
        delete_smtp_config(path)

    assert path.read_text() == original


def test_smtp_send_ready_requires_password_when_username_set() -> None:
    incomplete = SmtpConfig(
        from_address="a@b.com",
        host="smtp.example.com",
        mail_domain="b.com",
        username="alerts",
    )
    assert smtp_send_ready(incomplete) is False

    complete = SmtpConfig(
        from_address="a@b.com",
        host="smtp.example.com",
        mail_domain="b.com",
        password="s3cret",
        username="alerts",
    )
    assert smtp_send_ready(complete) is True
