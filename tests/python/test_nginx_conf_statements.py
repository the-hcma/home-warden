"""scripts/lib/nginx-conf-statements: split an `nginx -T` dump into statements the
way nginx's lexer does, so directive scans see what nginx sees.
"""

import subprocess
from pathlib import Path

LIB = Path(__file__).resolve().parents[2] / "scripts" / "lib" / "nginx-conf-statements"


def test_backslash_escapes_keep_a_quote_or_terminator_inside_the_token() -> None:
    assert _statements('return 200 "say \\"hi\\"; ok";\nroot /srv/a\\;b;\n') == [
        'return 200 "say \\"hi\\"; ok"',
        "root /srv/a\\;b",
    ]


def test_hash_starts_a_comment_only_at_a_token_boundary() -> None:
    assert _statements("# listen [::]:80;\nroot /srv/site#1; # trailing ssl_crl /x;\nindex a.html;\n") == [
        "root /srv/site#1",
        "index a.html",
    ]


def test_quoted_hash_does_not_hide_the_next_directive() -> None:
    assert _statements('return 200 "a # b"; listen [::]:443 ssl;\n') == ['return 200 "a # b"', "listen [::]:443 ssl"]


def test_quoted_terminators_stay_inside_the_token() -> None:
    assert _statements("root \"/home/op/a{b\";\nalias '/home/op/c;d}';\n") == [
        'root "/home/op/a{b"',
        "alias '/home/op/c;d}'",
    ]


def test_statements_split_at_braces_and_semicolons_not_lines() -> None:
    dump = "http {\n  server { listen 443 ssl;\n    ssl_crl\n        /srv/pki/crl.pem;\n  }\n}\n"
    assert _statements(dump) == ["http", "server", "listen 443 ssl", "ssl_crl /srv/pki/crl.pem"]


def test_variable_braces_stay_inside_the_token() -> None:
    assert _statements("root /srv/${host}/www;\nset $x ${y}z;\n") == ["root /srv/${host}/www", "set $x ${y}z"]


def _statements(dump: str) -> list[str]:
    result = subprocess.run(
        ["bash", "-c", 'source "$1"; shift; nginx_conf_statements "$@"', "bash", str(LIB), dump],
        capture_output=True,
        check=True,
        text=True,
        timeout=10,
    )
    return result.stdout.splitlines()
