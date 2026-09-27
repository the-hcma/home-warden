"""scripts/lib/nginx-sandbox-binds: which served-conf paths home-warden.service's
sandbox binds back in (#148).

A file republished by rename (a CRL, a client CA bundle) must be bound by its
directory: a single-file bind pins the old inode, so nginx would keep reading
the stale file across reloads.
"""

import subprocess
from pathlib import Path

import pytest

LIB = Path(__file__).resolve().parents[2] / "scripts" / "lib" / "nginx-sandbox-binds"
COVERED = ["/home/op/home/nginx/server", "/home/op/work/home-warden/conf", "/home/op/scratch/home-warden"]


def test_ca_bundles_and_crl_bind_their_directory() -> None:
    binds, _ = _resolve(
        "ssl_client_certificate /home/op/pki/ca/ca.crt;\n"
        "ssl_crl /home/op/pki/ca/crl.pem;\n"
        "ssl_trusted_certificate /home/op/chains/upstream.pem;\n"
    )
    assert binds == ["-/home/op/chains", "-/home/op/pki/ca"]


def test_comments_are_ignored_but_a_hash_inside_a_path_is_literal() -> None:
    binds, stderr = _resolve(
        "#root /home/op/commented-out;\n"
        "ssl_crl /home/op/pki/ca/crl.pem; # ssl_crl /home/op/other/crl.pem;\n"
        "root /home/op/site#1;\n"
    )
    assert binds == ["-/home/op/pki/ca"]
    assert "not exposing /home/op/site#1 (from root)" in stderr


def test_covered_directories_are_not_bound_again() -> None:
    binds, _ = _resolve("ssl_crl /home/op/work/home-warden/conf/pki/ca/crl.pem;\n")
    assert binds == []


def test_crl_beside_a_private_key_falls_back_to_a_file_bind() -> None:
    binds, stderr = _resolve(
        "ssl_crl /home/op/pki/ca/crl.pem;\nssl_client_certificate /home/op/pki/pub/ca.crt;\n",
        stub_key_dirs=["/home/op/pki/ca"],
    )
    assert binds == ["-/home/op/pki/ca/crl.pem", "-/home/op/pki/pub"]
    assert "binding /home/op/pki/ca/crl.pem (from ssl_crl) as a single file" in stderr


def test_crl_directly_in_a_home_directory_is_refused() -> None:
    binds, stderr = _resolve("ssl_crl /home/op/crl.pem;\n")
    assert binds == []
    assert "not exposing /home/op (from ssl_crl)" in stderr


@pytest.mark.parametrize(
    ("name", "pem_label", "expected"),
    [
        ("crl.pem", "X509 CRL", False),
        ("ca.key", "", True),
        ("bundle.p12", "", True),
        ("sub/key.pem", "PRIVATE KEY", True),
        ("ec.pem", "EC PRIVATE KEY", True),
        ("enc.pem", "ENCRYPTED PRIVATE KEY", True),
    ],
)
def test_dir_holds_private_key(tmp_path: Path, name: str, pem_label: str, expected: bool) -> None:
    (tmp_path / name).parent.mkdir(parents=True, exist_ok=True)
    (tmp_path / name).write_text(_pem_begin(pem_label) if pem_label else "")
    assert _holds_private_key(tmp_path) is expected


def test_directives_spanning_lines_or_after_a_brace_are_found() -> None:
    binds, _ = _resolve("server { root /home/op/www;\n    ssl_crl\n        /home/op/pki/ca/crl.pem;\n}\n")
    assert binds == ["-/home/op/pki/ca", "-/home/op/www"]


def test_hidden_directory_is_refused() -> None:
    binds, stderr = _resolve("ssl_crl /home/op/.pki/crl.pem;\n")
    assert binds == []
    assert "not exposing /home/op/.pki (from ssl_crl)" in stderr


def test_missing_dir_holds_no_private_key(tmp_path: Path) -> None:
    assert _holds_private_key(tmp_path / "absent") is False


def test_other_file_directives_bind_just_the_file() -> None:
    binds, _ = _resolve(
        "ssl_certificate /home/op/tls/site/fullchain.pem;\n"
        "ssl_certificate_key /home/op/tls/site/privkey.pem;\n"
        "auth_basic_user_file /home/op/auth/htpasswd;\n"
    )
    assert binds == ["-/home/op/auth/htpasswd", "-/home/op/tls/site/fullchain.pem", "-/home/op/tls/site/privkey.pem"]


def test_paths_outside_home_and_variables_are_ignored() -> None:
    binds, stderr = _resolve("ssl_crl /etc/nginx/crl.pem;\nroot /home/op/www/$host;\n")
    assert binds == []
    assert stderr == ""


def test_reload_watch_dirs_cover_crl_and_client_ca_only() -> None:
    dirs, stderr = _watch_dirs(
        "ssl_crl /home/op/pki/ca/crl.pem;\n"
        'ssl_client_certificate "/home/op/pki/ca/ca.crt";\n'
        "ssl_client_certificate /etc/nginx/client-ca/ca.crt;\n"
        "ssl_trusted_certificate /home/op/chains/upstream.pem;\n"
        "ssl_certificate /home/op/tls/site/fullchain.pem;\n"
    )
    assert dirs == ["/etc/nginx/client-ca", "/home/op/pki/ca"]
    assert stderr == ""


def test_reload_watch_dirs_find_directives_spanning_lines_or_after_a_brace() -> None:
    dirs, _ = _watch_dirs(
        "server { ssl_crl /home/op/pki/ca/crl.pem;\n    ssl_client_certificate\n        /srv/pki/ca.crt;\n}\n"
    )
    assert dirs == ["/home/op/pki/ca", "/srv/pki"]


def test_reload_watch_dirs_skip_only_exactly_watched_dirs() -> None:
    dirs, _ = _watch_dirs(
        "ssl_crl /home/op/home/nginx/server/crl.pem;\nssl_crl /home/op/home/nginx/server/pki/crl.pem;\n"
    )
    assert dirs == ["/home/op/home/nginx/server/pki"]


def test_reload_watch_dirs_warn_on_paths_systemd_would_misparse() -> None:
    dirs, stderr = _watch_dirs(
        'ssl_crl "/home/op/my pki/crl.pem";\nssl_crl /home/op/$host/crl.pem;\nssl_crl crl.pem;\n'
    )
    assert dirs == []
    assert stderr.count("not watching") == 3


def test_root_alias_and_glob_include_bind_directories() -> None:
    binds, _ = _resolve(
        "root /home/op/www/site/;\nalias /home/op/www/files;\ninclude /home/op/snippets/*.conf;\n"
        "include /home/op/snippets-one/extra.conf;\n"
    )
    assert binds == [
        "-/home/op/snippets",
        "-/home/op/snippets-one/extra.conf",
        "-/home/op/www/files",
        "-/home/op/www/site",
    ]


def _holds_private_key(directory: Path) -> bool:
    result = subprocess.run(
        ["bash", "-c", 'source "$1"; dir_holds_private_key "$2"', "bash", str(LIB), str(directory)],
        capture_output=True,
        timeout=10,
    )
    return result.returncode == 0


def _pem_begin(label: str) -> str:
    # Assembled at runtime: literal key headers in source trip gitleaks' private-key rule.
    dashes = "-" * 5
    return f"{dashes}BEGIN {label}{dashes}\n"


def _resolve(dump: str, stub_key_dirs: list[str] | None = None) -> tuple[list[str], str]:
    stub = " ".join(f'"{d}"' for d in stub_key_dirs or [])
    script = (
        'source "$1"; shift; '
        f'dir_holds_private_key() {{ local d; for d in {stub}; do [[ "$1" == "$d" ]] && return 0; done; return 1; }}; '
        'resolve_nginx_extra_read_paths "$@"'
    )
    result = subprocess.run(
        ["bash", "-c", script, "bash", str(LIB), dump, *COVERED],
        capture_output=True,
        check=True,
        text=True,
        timeout=10,
    )
    return result.stdout.split(), result.stderr


def _watch_dirs(dump: str) -> tuple[list[str], str]:
    result = subprocess.run(
        [
            "bash",
            "-c",
            'source "$1"; shift; resolve_nginx_reload_watch_dirs "$@"',
            "bash",
            str(LIB),
            dump,
            "/home/op/home/nginx/server/",
        ],
        capture_output=True,
        check=True,
        text=True,
        timeout=10,
    )
    return result.stdout.splitlines(), result.stderr
