"""scripts/lib/nginx-sandbox-binds: which served-conf paths home-warden.service's
sandbox binds back in (#148).

A file republished by rename (a CRL, a client CA bundle) must be bound by its
directory: a single-file bind pins the old inode, so nginx would keep reading
the stale file across reloads.
"""

import subprocess
from pathlib import Path

LIB = Path(__file__).resolve().parents[2] / "scripts" / "lib" / "nginx-sandbox-binds"
COVERED = ["/home/op/home/nginx/server", "/home/op/work/home-warden/conf", "/home/op/scratch/home-warden"]


def test_ca_bundles_and_crl_bind_their_directory() -> None:
    binds, _ = _resolve(
        "ssl_client_certificate /home/op/pki/ca/ca.crt;\n"
        "ssl_crl /home/op/pki/ca/crl.pem;\n"
        "ssl_trusted_certificate /home/op/chains/upstream.pem;\n"
    )
    assert binds == ["-/home/op/chains", "-/home/op/pki/ca"]


def test_covered_directories_are_not_bound_again() -> None:
    binds, _ = _resolve("ssl_crl /home/op/work/home-warden/conf/pki/ca/crl.pem;\n")
    assert binds == []


def test_crl_directly_in_a_home_directory_is_refused() -> None:
    binds, stderr = _resolve("ssl_crl /home/op/crl.pem;\n")
    assert binds == []
    assert "not exposing /home/op (from ssl_crl)" in stderr


def test_hidden_directory_is_refused() -> None:
    binds, stderr = _resolve("ssl_crl /home/op/.pki/crl.pem;\n")
    assert binds == []
    assert "not exposing /home/op/.pki (from ssl_crl)" in stderr


def test_other_file_directives_bind_just_the_file() -> None:
    binds, _ = _resolve(
        "ssl_certificate /home/op/tls/site/fullchain.pem;\n"
        "ssl_certificate_key /home/op/tls/site/privkey.pem;\n"
        "auth_basic_user_file /home/op/auth/htpasswd;\n"
    )
    assert binds == ["-/home/op/auth/htpasswd", "-/home/op/tls/site/fullchain.pem", "-/home/op/tls/site/privkey.pem"]


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


def test_paths_outside_home_and_variables_are_ignored() -> None:
    binds, stderr = _resolve("ssl_crl /etc/nginx/crl.pem;\nroot /home/op/www/$host;\n")
    assert binds == []
    assert stderr == ""


def _resolve(dump: str) -> tuple[list[str], str]:
    result = subprocess.run(
        ["bash", "-c", 'source "$1"; shift; resolve_nginx_extra_read_paths "$@"', "bash", str(LIB), dump, *COVERED],
        capture_output=True,
        check=True,
        text=True,
        timeout=10,
    )
    return result.stdout.split(), result.stderr
