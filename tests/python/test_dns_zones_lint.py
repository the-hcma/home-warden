"""Tests for app.dns_zones_lint."""

from __future__ import annotations

from app.dns_zones_lint import ZoneIssue, format_issues, lint_zones

_SOA = "ns1.example.com. hostmaster.example.com. 2026092901 16384 2048 1048576 2560"
_REVERSE_SOA = "ns1.example.com. hostmaster.example.com. 1 16384 2048 1048576 2560"


def test_a_record_with_a_ptr_elsewhere_for_its_address_is_fine() -> None:
    doc = _doc(
        {"app.example.com": [{"a": "192.0.2.7"}], "alias.example.com": [{"a": "192.0.2.7"}]},
        reverse={"7.2.0.192.in-addr.arpa": [{"ptr": "app.example.com."}]},
    )
    assert lint_zones(doc) == []


def test_a_record_without_ptr_in_a_local_reverse_zone_is_flagged() -> None:
    doc = _doc({"app.example.com": [{"a": "192.0.2.7"}]}, reverse={})
    (issue,) = lint_zones(doc)
    assert issue.subject == "app.example.com"
    assert "A 192.0.2.7 has no PTR" in issue.problem
    assert "`ptr: app.example.com.` under 7.2.0.192.in-addr.arpa" in issue.fix
    assert not issue.blocking


def test_a_record_without_ptr_is_fine_when_the_reverse_zone_is_elsewhere() -> None:
    assert lint_zones(_doc({"app.example.com": [{"a": "198.51.100.7"}]})) == []


def test_clean_document_has_no_issues() -> None:
    doc = _doc(
        {"app.example.com": [{"a": "192.0.2.7"}], "www.example.com": [{"cname": "app.example.com."}]},
        reverse={"7.2.0.192.in-addr.arpa": [{"ptr": "app.example.com."}]},
    )
    assert lint_zones(doc) == []


def test_cname_alongside_other_data_blocks_reload() -> None:
    doc = _doc({"dns1.example.com": [{"a": "198.51.100.1"}, {"cname": "other.example.com."}]})
    (issue,) = lint_zones(doc)
    assert issue.subject == "dns1.example.com"
    assert "CNAME alongside a records" in issue.problem
    assert "RFC 1034" in issue.problem
    assert issue.blocking


def test_cname_at_the_apex_conflicts_with_the_soa() -> None:
    doc = _doc({"example.com": [{"soa": _SOA}, {"cname": "elsewhere.example.net."}]}, apex_soa=False)
    assert any(issue.blocking and "CNAME alongside soa" in issue.problem for issue in lint_zones(doc))


def test_changed_zone_without_a_serial_bump_is_flagged() -> None:
    previous = _doc({"app.example.com": [{"a": "198.51.100.7"}]})
    current = _doc({"app.example.com": [{"a": "198.51.100.8"}]})
    (issue,) = lint_zones(current, previous)
    assert issue.subject == "example.com"
    assert "serial didn't go up (was 2026092901, now 2026092901)" in issue.problem


def test_duplicate_records_are_flagged() -> None:
    doc = _doc({"app.example.com": [{"a": "198.51.100.7"}, {"a": {"content": "198.51.100.7", "ttl": 60}}]})
    (issue,) = lint_zones(doc)
    assert "lists a 198.51.100.7 2 times" in issue.problem


def test_format_issues_is_one_block_with_every_issue() -> None:
    issues = [ZoneIssue("a.example.com", "p1", "f1"), ZoneIssue("b.example.com", "p2", "f2", blocking=True)]
    text = format_issues("tool", issues, note=" in zones.yml")
    assert text.splitlines() == [
        "tool: WARNING: 2 issue(s) need attention in zones.yml:",
        "  - a.example.com: p1 -- fix: f1",
        "  - b.example.com: p2 [blocks reload] -- fix: f2",
    ]


def test_malformed_record_entry_is_flagged() -> None:
    (issue,) = lint_zones(_doc({"app.example.com": [{"a": "198.51.100.7", "txt": '"x"'}]}))
    assert "isn't a single `type: content` mapping" in issue.problem


def test_malformed_entry_next_to_a_cname_is_not_a_cname_conflict() -> None:
    issues = lint_zones(_doc({"www.example.com": [{"cname": "x.example.com."}, {"a": "192.0.2.1", "txt": '"x"'}]}))
    assert [issue.problem for issue in issues] == ["has a record entry that isn't a single `type: content` mapping"]
    assert not any(issue.blocking for issue in issues)


def test_missing_soa_is_flagged() -> None:
    (issue,) = lint_zones(_doc({"app.example.com": [{"a": "198.51.100.7"}]}, apex_soa=False))
    assert issue.subject == "example.com"
    assert "no SOA at its apex" in issue.problem


def test_multiple_cnames_block_reload() -> None:
    doc = _doc({"www.example.com": [{"cname": "a.example.com."}, {"cname": "b.example.com."}]})
    (issue,) = lint_zones(doc)
    assert "has 2 CNAMEs" in issue.problem
    assert issue.blocking


def test_owner_outside_its_zone_is_flagged() -> None:
    (issue,) = lint_zones(_doc({"app.example.net": [{"a": "198.51.100.7"}]}))
    assert issue.subject == "app.example.net"
    assert "isn't inside it" in issue.problem


def test_ptr_to_a_local_name_without_that_a_is_flagged() -> None:
    doc = _doc(
        {"app.example.com": [{"a": "192.0.2.8"}]},
        reverse={
            "7.2.0.192.in-addr.arpa": [{"ptr": "app.example.com."}],
            "8.2.0.192.in-addr.arpa": [{"ptr": "app.example.com."}],
        },
    )
    (issue,) = lint_zones(doc)
    assert issue.subject == "7.2.0.192.in-addr.arpa"
    assert "has no A 192.0.2.7" in issue.problem


def test_ptr_to_a_name_outside_the_served_zones_is_fine() -> None:
    doc = _doc({}, reverse={"7.2.0.192.in-addr.arpa": [{"ptr": "host.example.net."}]})
    assert lint_zones(doc) == []


def test_serial_bump_or_unchanged_zone_is_fine() -> None:
    previous = _doc({"app.example.com": [{"a": "198.51.100.7"}]})
    bumped = _doc({"app.example.com": [{"a": "198.51.100.8"}]}, soa=_SOA.replace("2026092901", "2026092902"))
    assert lint_zones(bumped, previous) == []
    assert lint_zones(previous, previous) == []


def test_soa_away_from_the_apex_is_flagged() -> None:
    doc = _doc({"sub.example.com": [{"soa": _SOA}]})
    (issue,) = lint_zones(doc)
    assert issue.subject == "sub.example.com"
    assert "isn't the apex" in issue.problem


def test_soa_with_a_missing_field_is_flagged() -> None:
    doc = _doc({}, soa="ns1.example.com. hostmaster.example.com.  16384 2048 1048576 2560")
    (issue,) = lint_zones(doc)
    assert "SOA has 6 fields, needs 7" in issue.problem
    assert "empty serial" in issue.fix


def _doc(
    records: dict,
    *,
    apex_soa: bool = True,
    reverse: dict | None = None,
    soa: str = _SOA,
) -> dict:
    zone_records = {"example.com.": [{"soa": soa}], **records} if apex_soa else dict(records)
    domains = [{"domain": "example.com", "ttl": 3600, "records": zone_records}]
    if reverse is not None:
        reverse_records = {"2.0.192.in-addr.arpa": [{"soa": _REVERSE_SOA}], **reverse}
        domains.append({"domain": "2.0.192.in-addr.arpa", "ttl": 3600, "records": reverse_records})
    return {"domains": domains}
