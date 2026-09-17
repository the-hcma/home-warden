"""Tests for app.smtp_config."""

from __future__ import annotations

from pathlib import Path

from app.home_warden_config import HomeWardenConfig, load_config
from app.smtp_config import (
    SmtpConfig,
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


def test_smtp_send_ready_requires_host_domain_and_from_address() -> None:
    assert smtp_send_ready(None) is False
    assert smtp_send_ready(SmtpConfig()) is False
    assert smtp_send_ready(SmtpConfig(from_address="a@b.com", host="smtp.example.com", mail_domain="b.com")) is True


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
