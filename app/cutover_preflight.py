"""Read-only readiness check for a host that is about to take over the front door (#187).

Nothing here changes the host: it reads the served nginx config, certificates, secrets' file modes,
`certbot-domains` and the catalog, and tries TCP connects to every `proxy_pass` upstream. Each check yields
ok / warn / fail with what to fix; only `fail` makes `cutover-preflight` exit non-zero.

`cert-renewer --dry-run` is opt-in (`--certbot-dry-run`), not part of the default run: it talks to Let's Encrypt
staging and is host-guarded, so it can't run before the host is pinned. It changes nothing on the host: a lineage
with no renewal config (certs copied in) is reported and skipped, not moved (#199).
`scripts/cutover-assess preflight` (the temporary shell version from #192) covers the same ground for a host
without `uv`.
"""

from __future__ import annotations

import datetime
import os
import re
import shutil
import socket
import stat
import subprocess
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from cryptography import x509

_TOOLS = ("nginx", "dig", "uv", "gpg", "openssl")
_MIN_SYSTEMD = 259
_MIN_NGINX = (1, 28)
_PORTS = (80, 443, 853)
_CERT_MIN_DAYS = 30


@dataclass
class Result:
    name: str
    status: str  # "ok" | "warn" | "fail"
    detail: str


Runner = Callable[[list[str], float], subprocess.CompletedProcess[str]]
Connector = Callable[[str, int, float], bool]


def default_runner(cmd: list[str], timeout: float) -> subprocess.CompletedProcess[str]:
    """Run `cmd`; a missing binary or a timeout becomes a non-zero result, so one broken check can't
    replace the whole report with a traceback."""
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
    except FileNotFoundError:
        return subprocess.CompletedProcess(cmd, 127, "", f"{cmd[0]}: not found")
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(cmd, 124, "", f"{cmd[0]}: timed out after {timeout:.0f}s")


def default_connector(host: str, port: int, timeout: float) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


@dataclass
class Context:
    nginx_conf: Path
    repo_dir: Path
    scratch_dir: Path
    certbot_domains: Path
    cloudflare_credentials: Path
    session_secret: Path
    pki_store: Path
    run: Runner = default_runner
    connect: Connector = default_connector
    which: Callable[[str], str | None] = shutil.which
    # cert-renewer runs ${CERTBOT:-/usr/bin/certbot} and refuses anything else, so check that path, not PATH
    # (a snap install is on PATH as /snap/bin/certbot but not at /usr/bin/certbot).
    certbot: str = "/usr/bin/certbot"
    is_executable: Callable[[str], bool] = lambda path: os.access(path, os.X_OK)
    now: Callable[[], datetime.datetime] = lambda: datetime.datetime.now(datetime.timezone.utc)
    use_sudo: bool = True
    certbot_dry_run: bool = False
    timeout: float = 5.0
    catalog: dict = field(default_factory=dict)


def _strip_comments(text: str) -> str:
    """nginx starts a comment at a `#` that begins a token, so `…$request_uri#x;` and a `#` inside a quoted
    string or regex keep their directive intact."""
    return re.sub(r"(?m)(^|\s)#.*$", r"\1", text)


def parse_conf(dump: str) -> dict[str, set[str]]:
    """Pull the directives a cutover cares about out of `nginx -T` output."""
    text = _strip_comments(dump)

    def grab(pattern: str) -> set[str]:
        return {m.group(1).strip() for m in re.finditer(pattern, text)}

    server_names: set[str] = set()
    for raw in grab(r"\bserver_name\s+([^;]+);"):
        server_names.update(n for n in raw.split() if re.fullmatch(r"[A-Za-z0-9.-]+\.[A-Za-z]+", n))
    upstreams: set[str] = set()
    groups: set[str] = set()
    for m in re.finditer(r"\bupstream\s+(\S+)\s*\{([^}]*)\}", text):
        groups.add(m.group(1))
        upstreams.update(f"tcp://{srv}" for srv in re.findall(r"\bserver\s+([^\s;]+)", m.group(2)))
    proxy_pass = grab(r"\bproxy_pass\s+([^;\s]+)\s*;")
    # `proxy_pass http://backend;` naming an upstream group is checked through that group's servers
    proxy_pass = {u for u in proxy_pass if u.partition("://")[2].split("/", 1)[0] not in groups}
    return {
        "server_names": server_names,
        "proxy_pass": proxy_pass | upstreams,
        "certs": grab(r"\bssl_certificate\s+([^;\s]+)\s*;"),
        "keys": grab(r"\bssl_certificate_key\s+([^;\s]+)\s*;"),
        "listens": grab(r"\blisten\s+([^;]+);"),
    }


def _upstream_hostport(url: str) -> tuple[str, int] | None:
    """(host, port) of a `proxy_pass` target, or None for one we can't check (variables, unix sockets).
    A scheme-less `host:port` is a `stream {}` proxy_pass."""
    if "$" in url or url.startswith("unix:"):
        return None
    scheme, sep, rest = url.partition("://")
    if not sep:
        scheme, rest = "", url
    if rest.startswith("unix:"):  # proxy_pass http://unix:/run/x.sock:/uri
        return None
    hostport = rest.split("/", 1)[0]
    default_port = {"https": 443, "http": 80}.get(scheme)
    try:
        if hostport.startswith("["):  # [v6]:port
            host, _, tail = hostport[1:].partition("]")
            port_s = tail[1:] if tail.startswith(":") else ""
        else:
            host, _, port_s = hostport.partition(":")
        port = int(port_s) if port_s else default_port
    except ValueError:
        return None
    return (host, port) if host and port else None


def _sudo(ctx: Context, cmd: list[str]) -> list[str]:
    return ["sudo", *cmd] if ctx.use_sudo else cmd


def _mode_issue(path: Path, forbid: int) -> str | None:
    try:
        mode = stat.S_IMODE(path.stat().st_mode)
    except OSError as e:
        return f"{path}: {e.strerror or e}"
    return f"{path} has mode {mode:04o}, expected no access for {forbid:03o}" if mode & forbid else None


def check_tools(ctx: Context) -> list[Result]:
    out = [
        Result(f"tool:{t}", "ok" if ctx.which(t) else "fail", "present" if ctx.which(t) else f"{t} not installed")
        for t in _TOOLS
    ]
    if ctx.is_executable(ctx.certbot):
        out.append(Result("tool:certbot", "ok", ctx.certbot))
    else:
        detail = f"{ctx.certbot} is not executable; cert-renewer needs it there (set CERTBOT or symlink it)"
        out.append(Result("tool:certbot", "fail", detail))
    if ctx.which("nginx"):
        proc = ctx.run(["nginx", "-v"], ctx.timeout)
        m = re.search(r"nginx/(\d+)\.(\d+)", proc.stderr + proc.stdout)
        if m and (int(m.group(1)), int(m.group(2))) < _MIN_NGINX:
            out.append(Result("nginx-version", "warn", f"{m.group(0)} is older than {_MIN_NGINX[0]}.{_MIN_NGINX[1]}"))
        elif m:
            out.append(Result("nginx-version", "ok", m.group(0)))
    if ctx.which("systemctl"):
        m = re.search(r"systemd (\d+)", ctx.run(["systemctl", "--version"], ctx.timeout).stdout)
        if m and int(m.group(1)) < _MIN_SYSTEMD:
            detail = (
                f"systemd {m.group(1)} < {_MIN_SYSTEMD}: machine-id ConditionHost needs {_MIN_SYSTEMD}+; "
                "the hostname guard still works"
            )
            out.append(Result("systemd-version", "warn", detail))
        elif m:
            out.append(Result("systemd-version", "ok", f"systemd {m.group(1)}"))
    return out


def check_ports(ctx: Context) -> list[Result]:
    if not ctx.which("ss"):
        return [Result("ports", "warn", "ss not found; could not check 80/443/853")]
    listening = ctx.run(["ss", "--listening", "--numeric", "--tcp"], ctx.timeout).stdout
    out = []
    for port in _PORTS:
        busy = re.search(rf"[:.]{port}\s", listening) is not None
        out.append(
            Result(
                f"port:{port}",
                "warn" if busy else "ok",
                "already has a listener (fine only if it is home-warden or pdns)" if busy else "free",
            )
        )
    return out


def check_conf(ctx: Context) -> tuple[list[Result], dict[str, set[str]]]:
    if not ctx.nginx_conf.is_file():
        return [Result("nginx-conf", "fail", f"served conf not readable: {ctx.nginx_conf}")], {}
    out = []
    # -p as scripts/nginx-test-and-reload does, so relative paths resolve the way the service's do
    proc = ctx.run(_sudo(ctx, ["nginx", "-p", f"{ctx.scratch_dir}/", "-T", "-c", str(ctx.nginx_conf)]), 30)
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout).strip().splitlines()[-1:] or ["nginx -T failed"]
        return [Result("nginx -t", "fail", detail[0])], {}
    out.append(Result("nginx -t", "ok", "config valid"))
    lint = ctx.run(
        ["env", f"HOME_NGINX_CONF={ctx.nginx_conf}", str(ctx.repo_dir / "scripts" / "nginx-security-lint")], 300
    )
    out.append(
        Result("gixy", "ok", "no findings")
        if lint.returncode == 0
        else Result("gixy", "fail", "Gixy-Next findings (run scripts/nginx-security-lint)")
    )
    return out, parse_conf(proc.stdout)


def check_upstreams(ctx: Context, conf: dict[str, set[str]]) -> list[Result]:
    out = []
    for url in sorted(conf.get("proxy_pass", ())):
        hp = _upstream_hostport(url)
        if hp is None:
            out.append(Result(f"upstream:{url}", "warn", "dynamic or unix upstream, not checked"))
        elif ctx.connect(hp[0], hp[1], ctx.timeout):
            out.append(Result(f"upstream:{hp[0]}:{hp[1]}", "ok", "reachable from this host"))
        else:
            out.append(
                Result(
                    f"upstream:{hp[0]}:{hp[1]}", "fail", "unreachable from this host; move the app or fix the address"
                )
            )
    return out


def check_certs(ctx: Context, conf: dict[str, set[str]]) -> list[Result]:
    out = []
    deadline = ctx.now() + datetime.timedelta(days=_CERT_MIN_DAYS)
    for path_s in sorted(conf.get("certs", ())):
        path = Path(path_s)
        try:
            cert = x509.load_pem_x509_certificate(path.read_bytes())
        except (OSError, ValueError) as e:
            out.append(Result(f"cert:{path}", "fail", f"not readable/parsable: {e}"))
            continue
        if cert.not_valid_after_utc < deadline:
            out.append(
                Result(f"cert:{path}", "fail", f"expires {cert.not_valid_after_utc:%Y-%m-%d} (< {_CERT_MIN_DAYS} days)")
            )
        else:
            out.append(Result(f"cert:{path}", "ok", f"valid until {cert.not_valid_after_utc:%Y-%m-%d}"))
    for path_s in sorted(conf.get("keys", ())):
        issue = _mode_issue(Path(path_s), 0o007)
        out.append(
            Result(f"key:{path_s}", "fail", issue) if issue else Result(f"key:{path_s}", "ok", "not world-accessible")
        )
    return out


def check_domains(ctx: Context, conf: dict[str, set[str]]) -> list[Result]:
    out = []
    try:
        domains = {
            line.strip()
            for line in ctx.certbot_domains.read_text().splitlines()
            if line.strip() and not line.strip().startswith("#")
        }
    except OSError:
        return [Result("certbot-domains", "fail", f"{ctx.certbot_domains} missing")]
    served = conf.get("server_names", set())
    for d in sorted(served - domains):
        out.append(Result(f"domain:{d}", "warn", "served by nginx but not in certbot-domains (cert not managed here)"))
    for d in sorted(domains - served):
        out.append(Result(f"domain:{d}", "warn", "in certbot-domains but not served by the conf"))
    catalog_names = {s["server_name"] for s in ctx.catalog.get("services") or [] if s.get("server_name")}
    if ctx.catalog:
        for d in sorted(served - catalog_names):
            out.append(Result(f"catalog:{d}", "warn", "vhost not in services.json; catalog checks won't cover it"))
        for d in sorted(catalog_names - domains):
            out.append(Result(f"catalog:{d}", "fail", "in services.json but not in certbot-domains"))
    if not out:
        out.append(Result("domains", "ok", "certbot-domains, served vhosts and catalog agree"))
    return out


def check_secrets(ctx: Context) -> list[Result]:
    out = []
    # cloudflare.ini drives cert issuance; the session secret belongs to the opt-in web UI and is created on demand.
    for label, path, missing in (
        ("cloudflare.ini", ctx.cloudflare_credentials, "fail"),
        ("session-secret", ctx.session_secret, "warn"),
    ):
        if not path.exists():
            out.append(Result(label, missing, f"{path} missing"))
            continue
        issue = _mode_issue(path, 0o077)
        out.append(Result(label, "fail", issue) if issue else Result(label, "ok", "present, owner-only"))
    ca_dir = ctx.pki_store / "ca"
    if ca_dir.exists():
        issue = _mode_issue(ca_dir, 0o077)
        out.append(Result("pki-store", "fail", issue) if issue else Result("pki-store", "ok", "ca/ is owner-only"))
    else:
        out.append(
            Result(
                "pki-store",
                "warn",
                f"no CA at {ctx.pki_store}; restore it (client-pki restore) if vhosts use client_cert",
            )
        )
    return out


def check_certbot_dry_run(ctx: Context) -> list[Result]:
    if not ctx.certbot_dry_run:
        return [
            Result(
                "certbot-dry-run",
                "warn",
                "not run (opt in with --certbot-dry-run; needs a pinned host and talks to LE staging)",
            )
        ]
    proc = ctx.run([str(ctx.repo_dir / "scripts" / "cert-renewer"), "--dry-run"], 900)
    return [
        Result(
            "certbot-dry-run",
            "ok" if proc.returncode == 0 else "fail",
            "cert-renewer --dry-run " + ("passed" if proc.returncode == 0 else "failed"),
        )
    ]


def run_preflight(ctx: Context) -> list[Result]:
    results = check_tools(ctx) + check_ports(ctx)
    conf_results, conf = check_conf(ctx)
    results += conf_results
    if conf:
        results += check_upstreams(ctx, conf) + check_certs(ctx, conf) + check_domains(ctx, conf)
        if any("[::]" in listen for listen in conf.get("listens", ())):
            results.append(Result("ipv6", "ok", "conf has [::] listens; setup-service adds the matching sockets"))
    results += check_secrets(ctx)
    results += check_certbot_dry_run(ctx)
    return results
