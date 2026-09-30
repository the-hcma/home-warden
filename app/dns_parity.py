"""Compare what two DNS servers answer for every record in a zones.yml (#189).

Used before moving DNS to a replacement server (and by #175's rollout): for each owner/type in
`zones.yml` (plus each zone's SOA, plus any extra `--probe` names such as a public name that must
forward, or one that must be NXDOMAIN), ask both servers and compare the response code, the AA flag,
the record set and, when both answers are authoritative, the TTLs. A TTL via a recursor is a cache
countdown, so it is not compared there.

Read-only. Every `dig` has a short timeout and a single try, per `.cursor/rules/remote-timeouts-retries.mdc`.
"""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass, field

_STATUS_RE = re.compile(r"status:\s*(\w+)")
_FLAGS_RE = re.compile(r"flags:\s*([a-z ]*);")


@dataclass(frozen=True)
class Answer:
    rcode: str
    flags: frozenset[str]
    records: frozenset[tuple[str, str, str]]  # (owner, type, rdata)
    ttls: dict[tuple[str, str, str], int] = field(default_factory=dict, compare=False, hash=False)

    @property
    def authoritative(self) -> bool:
        return "aa" in self.flags


@dataclass
class Finding:
    name: str
    rtype: str
    differences: list[str]


def parse_server(spec: str, default_port: int = 53) -> tuple[str, int]:
    """`HOST`, `HOST:PORT`, `[V6]` or `[V6]:PORT` -> (host, port)."""
    if spec.startswith("["):
        host, _, rest = spec[1:].partition("]")
        return host, int(rest[1:]) if rest.startswith(":") else default_port
    if spec.count(":") == 1:
        host, _, port = spec.partition(":")
        return host, int(port)
    return spec, default_port


def parse_dig(output: str) -> Answer:
    """Parse `dig +noall +comments +answer` output."""
    rcode_m = _STATUS_RE.search(output)
    flags_m = _FLAGS_RE.search(output)
    if not rcode_m:
        raise ValueError("no status line in dig output")
    records: set[tuple[str, str, str]] = set()
    ttls: dict[tuple[str, str, str], int] = {}
    for line in output.splitlines():
        if not line.strip() or line.startswith(";"):
            continue
        parts = line.split(None, 4)
        if len(parts) < 5 or not parts[1].isdigit():
            continue
        owner, ttl, _cls, rtype, rdata = parts
        key = (owner.lower().rstrip("."), rtype.upper(), " ".join(rdata.split()))
        records.add(key)
        ttls[key] = int(ttl)
    return Answer(rcode_m.group(1), frozenset((flags_m.group(1) if flags_m else "").split()), frozenset(records), ttls)


def dig(server: tuple[str, int], name: str, rtype: str, timeout: int = 3) -> Answer:
    host, port = server
    proc = subprocess.run(
        [
            "dig",
            "+noall",
            "+comments",
            "+answer",
            f"+time={timeout}",
            "+tries=1",
            "-p",
            str(port),
            f"@{host}",
            name,
            rtype,
        ],
        capture_output=True,
        text=True,
        timeout=timeout * 2 + 5,
        check=False,
    )
    if proc.returncode != 0 or "status:" not in proc.stdout:
        raise RuntimeError(f"dig @{host} -p {port} {name} {rtype} failed: {(proc.stdout + proc.stderr).strip()[:200]}")
    return parse_dig(proc.stdout)


def expected_queries(zones_data: dict) -> list[tuple[str, str]]:
    """Every (owner, TYPE) zones.yml serves, plus each zone's SOA, in file order, de-duplicated."""
    seen: set[tuple[str, str]] = set()
    out: list[tuple[str, str]] = []

    def add(item: tuple[str, str]) -> None:
        if item not in seen:
            seen.add(item)
            out.append(item)

    for zone in zones_data.get("domains") or []:
        if not isinstance(zone, dict):
            continue
        if zone.get("domain"):
            add((str(zone["domain"]), "SOA"))
        records = zone.get("records")
        if not isinstance(records, dict):
            continue
        for owner, entries in records.items():
            for entry in entries or []:
                if isinstance(entry, dict):
                    for rtype in entry:
                        add((str(owner), str(rtype).upper()))
    return out


def _serial(answer: Answer) -> str | None:
    for _owner, rtype, rdata in sorted(answer.records):
        if rtype == "SOA":
            fields = rdata.split()
            if len(fields) >= 3:
                return fields[2]
    return None


def compare(old: Answer, new: Answer) -> list[str]:
    diffs: list[str] = []
    if old.rcode != new.rcode:
        diffs.append(f"rcode old={old.rcode} new={new.rcode}")
    if old.authoritative != new.authoritative:
        diffs.append(f"AA flag old={old.authoritative} new={new.authoritative}")
    for rec in sorted(old.records - new.records):
        diffs.append(f"only on old: {rec[1]} {rec[2]}")
    for rec in sorted(new.records - old.records):
        diffs.append(f"only on new: {rec[1]} {rec[2]}")
    if old.authoritative and new.authoritative:
        for rec in sorted(old.records & new.records):
            if old.ttls.get(rec) != new.ttls.get(rec):
                diffs.append(f"ttl {rec[1]} old={old.ttls.get(rec)} new={new.ttls.get(rec)}")
    old_serial, new_serial = _serial(old), _serial(new)
    if old_serial and new_serial and old_serial != new_serial:
        diffs.append(f"SOA serial old={old_serial} new={new_serial} (server left behind?)")
    return diffs


def run_parity(
    queries: list[tuple[str, str]],
    old: tuple[str, int],
    new: tuple[str, int],
    timeout: int = 3,
    *,
    must_answer: frozenset[tuple[str, str]] = frozenset(),
) -> list[Finding]:
    """One Finding per query, with an empty `differences` list when the servers agree. A server that can't be
    asked counts as a difference, never as agreement, and so does an empty answer on both servers for a
    query in `must_answer` (a record zones.yml says exists): both missing it is not parity."""
    findings: list[Finding] = []
    for name, rtype in queries:
        try:
            old_answer = dig(old, name, rtype, timeout)
            new_answer = dig(new, name, rtype, timeout)
        except (RuntimeError, ValueError, subprocess.TimeoutExpired) as e:
            findings.append(Finding(name, rtype, [str(e)]))
            continue
        diffs = compare(old_answer, new_answer)
        if not diffs and (name, rtype) in must_answer and not old_answer.records:
            diffs.append(f"neither server answers {rtype} for {name} (rcode {old_answer.rcode})")
        findings.append(Finding(name, rtype, diffs))
    return findings
