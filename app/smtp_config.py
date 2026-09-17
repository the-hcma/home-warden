"""SMTP settings storage in home-warden's config.toml (#57's alerting design).

Adopts the *shape* of the-hcma/domesti-bot's SMTP settings feature
(app/smtp_store.py) -- operator-configurable relay, tested-before-saved,
friendly errors -- but not its storage mechanism: domesti-bot persists
settings in a SQLite table with a Fernet-encrypted password column, which
assumes infrastructure (a database, a managed encryption key) home-warden
doesn't have and isn't taking on just for this. Instead, SMTP settings join
a new [smtp] table in the existing config.toml (already home-warden's
"general config surface", already chmod 600), with the password protected
by that same file permission -- the same plaintext-at-rest-behind-file-
permissions trust model this repo already uses for conf/cloudflare.ini's
Cloudflare API token.
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass
from pathlib import Path

from app.home_warden_config import config_path

SMTP_TABLE = "smtp"
DEFAULT_PORT = 25

_CONFIG_HEADER = "# home-warden web UI config."


class SmtpConfigStorageError(RuntimeError):
    """Raised when config.toml exists but can't be parsed, on a write.

    A read-modify-write must never silently rewrite a file it failed to
    read: home_warden_config.load_config's fqdn (or any other top-level
    key this module doesn't own) would otherwise be dropped permanently
    the moment an operator saves SMTP settings against a malformed file.
    """


@dataclass(frozen=True)
class SmtpConfig:
    from_address: str = ""
    host: str = ""
    mail_domain: str = ""
    password: str = ""
    port: int = DEFAULT_PORT
    username: str = ""


@dataclass(frozen=True)
class SmtpConfigUpdate:
    """Draft values for a save. `password=None` means "keep the currently
    stored password" (mirrors domesti-bot's draft-password contract) --
    the web UI never re-sends a password it didn't just receive from the
    operator, so a blank field must not silently clear a working relay
    credential.
    """

    from_address: str
    host: str
    mail_domain: str
    password: str | None
    port: int
    username: str


def delete_smtp_config(path: Path | None = None) -> None:
    """Remove the [smtp] table, leaving any other config.toml keys intact."""
    resolved = config_path(path)
    data = _read_toml_dict_for_write(resolved)
    if SMTP_TABLE not in data:
        return
    del data[SMTP_TABLE]
    _write_toml_dict(resolved, data)


def load_smtp_config(path: Path | None = None) -> SmtpConfig | None:
    """Return stored SMTP settings, or None when the [smtp] table is absent."""
    resolved = config_path(path)
    data = _read_toml_dict(resolved)
    table = data.get(SMTP_TABLE)
    if not isinstance(table, dict):
        return None
    return SmtpConfig(
        from_address=_str(table, "from_address"),
        host=_str(table, "host"),
        mail_domain=_str(table, "mail_domain"),
        password=_str(table, "password"),
        port=_int(table, "port", DEFAULT_PORT),
        username=_str(table, "username"),
    )


def save_smtp_config(update: SmtpConfigUpdate, path: Path | None = None) -> SmtpConfig:
    """Upsert the [smtp] table, preserving every other top-level config.toml key."""
    resolved = config_path(path)
    data = _read_toml_dict_for_write(resolved)

    password = update.password
    if password is None:
        existing = data.get(SMTP_TABLE)
        password = _str(existing, "password") if isinstance(existing, dict) else ""

    config = SmtpConfig(
        from_address=update.from_address.strip(),
        host=update.host.strip(),
        mail_domain=update.mail_domain.strip(),
        password=password,
        port=update.port,
        username=update.username.strip(),
    )
    data[SMTP_TABLE] = {
        "from_address": config.from_address,
        "host": config.host,
        "mail_domain": config.mail_domain,
        "password": config.password,
        "port": config.port,
        "username": config.username,
    }
    _write_toml_dict(resolved, data)
    return config


def smtp_send_ready(config: SmtpConfig | None) -> bool:
    """True when stored SMTP settings are sufficient to actually send mail."""
    if config is None:
        return False
    if not config.host.strip() or not config.from_address.strip() or not config.mail_domain.strip():
        return False
    if not config.username.strip():
        return True
    return bool(config.password.strip())


def _dump_toml(data: dict[str, object]) -> str:
    """Minimal TOML writer for this file's bounded shape: top-level scalars
    (today: `fqdn`) plus at most one level of table nesting (`[smtp]`).
    Regenerates the file from scratch rather than patching text in place --
    simpler and safer than a partial-text editor for a file this repo fully
    owns the shape of, at the cost of not preserving hand-added comments
    across a save.
    """
    lines = [_CONFIG_HEADER, ""]
    scalars = {key: value for key, value in data.items() if not isinstance(value, dict)}
    tables = {key: value for key, value in data.items() if isinstance(value, dict)}

    for key, value in scalars.items():
        lines.append(f"{key} = {_toml_scalar(value)}")

    for table_name, table in tables.items():
        if not table:
            continue
        lines.append("")
        lines.append(f"[{table_name}]")
        for key, value in table.items():
            lines.append(f"{key} = {_toml_scalar(value)}")

    lines.append("")
    return "\n".join(lines)


def _int(table: dict[str, object], key: str, default: int) -> int:
    value = table.get(key, default)
    # bool is an int subclass in Python -- exclude it so a stray
    # `port = true` in a hand-edited file doesn't silently read as 1.
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    return default


def _read_toml_dict(path: Path) -> dict[str, object]:
    """Lenient read for GET-style consumers (this module's own
    load_smtp_config): a malformed file degrades to "nothing configured"
    rather than an error, matching home_warden_config.load_config's
    existing precedent for this same file.
    """
    if not path.is_file():
        return {}
    try:
        with path.open("rb") as config_file:
            data = tomllib.load(config_file)
    except (OSError, tomllib.TOMLDecodeError, UnicodeDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def _read_toml_dict_for_write(path: Path) -> dict[str, object]:
    """Strict read for the read-modify-write save/delete path -- a file
    that exists but fails to parse must never be silently overwritten
    (see SmtpConfigStorageError). Only a genuinely absent file starts
    from {}.
    """
    if not path.is_file():
        return {}
    try:
        with path.open("rb") as config_file:
            data = tomllib.load(config_file)
    except (OSError, tomllib.TOMLDecodeError, UnicodeDecodeError) as exc:
        raise SmtpConfigStorageError(
            f"{path} exists but could not be parsed as TOML -- refusing to overwrite it: {exc}"
        ) from exc
    if not isinstance(data, dict):
        raise SmtpConfigStorageError(
            f"{path} does not contain a TOML table at its top level -- refusing to overwrite it"
        )
    return data


def _str(table: dict[str, object], key: str) -> str:
    value = table.get(key, "")
    return value if isinstance(value, str) else ""


def _toml_scalar(value: object) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, str):
        return _toml_string(value)
    raise TypeError(f"unsupported TOML scalar type: {type(value).__name__}")


def _toml_string(value: str) -> str:
    # Basic TOML string escaping, in the order that matters: the escape
    # marker itself first, then the characters it would otherwise flag.
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    escaped = escaped.replace("\n", "\\n").replace("\t", "\\t").replace("\r", "\\r")
    return f'"{escaped}"'


def _write_toml_dict(path: Path, data: dict[str, object]) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.write_text(_dump_toml(data), encoding="utf-8")
    path.chmod(0o600)
