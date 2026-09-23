"""Tests for app.dns_tinydns_convert.

No live infra/network needed -- pure text-in, structured-data-out parsing
and YAML rendering, per AGENTS.md's Python conventions. Domains/IPs use
RFC 2606/5737 documentation values (example.com, 203.0.113.0/24), not
real thehcma/home data, per .cursor/rules/no-private-infra.mdc.
"""

from __future__ import annotations

import yaml

from app.dns_tinydns_convert import (
    ParsedRecord,
    RecordValue,
    Zone,
    bucket_into_zones,
    parse_tinydns_data,
    render_zones_yaml,
    zone_apexes_from_records,
)

# --- parse_tinydns_data: individual line types ----------------------------


def test_parse_soa() -> None:
    line = "Zexample.com:ns1.example.com:hostmaster.example.com:1:16384:2048:1048576:2560:3600"
    records = parse_tinydns_data(line)
    assert records == [
        ParsedRecord(
            owner="example.com",
            rtype="soa",
            content="ns1.example.com. hostmaster.example.com. 1 16384 2048 1048576 2560",
            ttl=3600,
        )
    ]


def test_parse_soa_no_ttl() -> None:
    line = "Zexample.com:ns1.example.com:hostmaster.example.com:1:16384:2048:1048576:2560"
    records = parse_tinydns_data(line)
    assert records[0].ttl is None


def test_parse_ns_without_glue() -> None:
    line = "&example.com::ns1.example.com:86400"
    records = parse_tinydns_data(line)
    assert records == [ParsedRecord(owner="example.com", rtype="ns", content="ns1.example.com.", ttl=86400)]


def test_parse_ns_with_glue_a() -> None:
    line = "&example.com:203.0.113.1:ns1.example.com:86400"
    records = parse_tinydns_data(line)
    assert records == [
        ParsedRecord(owner="example.com", rtype="ns", content="ns1.example.com.", ttl=86400),
        ParsedRecord(owner="ns1.example.com", rtype="a", content="203.0.113.1", ttl=86400),
    ]


def test_parse_ns_missing_hostname_raises() -> None:
    line = "&example.com:203.0.113.1:"
    try:
        parse_tinydns_data(line)
        raise AssertionError("expected ValueError")
    except ValueError as e:
        assert "nameserver hostname" in str(e)


def test_parse_a_and_ptr() -> None:
    line = "=app.example.com:203.0.113.2:86400"
    records = parse_tinydns_data(line)
    assert records == [
        ParsedRecord(owner="app.example.com", rtype="a", content="203.0.113.2", ttl=86400),
        ParsedRecord(owner="2.113.0.203.in-addr.arpa", rtype="ptr", content="app.example.com.", ttl=86400),
    ]


def test_parse_a_only() -> None:
    line = "+web.example.com:203.0.113.5:86400"
    records = parse_tinydns_data(line)
    assert records == [ParsedRecord(owner="web.example.com", rtype="a", content="203.0.113.5", ttl=86400)]


def test_parse_cname() -> None:
    line = "Cwww.example.com:web.example.com:86400"
    records = parse_tinydns_data(line)
    assert records == [ParsedRecord(owner="www.example.com", rtype="cname", content="web.example.com.", ttl=86400)]


def test_parse_cname_target_already_has_trailing_dot() -> None:
    line = "Cwww.example.com:web.example.com.:86400"
    records = parse_tinydns_data(line)
    assert records[0].content == "web.example.com."


def test_parse_txt_plain() -> None:
    line = "'_kerberos.example.com:EXAMPLE.COM:86400"
    records = parse_tinydns_data(line)
    assert records == [ParsedRecord(owner="_kerberos.example.com", rtype="txt", content='"EXAMPLE.COM"', ttl=86400)]


def test_parse_txt_octal_escape() -> None:
    # \072 = octal 72 = decimal 58 = ':' -- a literal colon inside TXT
    # content must survive the encode/decode round trip even though ':'
    # is the tinydns field delimiter everywhere else.
    line = r"'app.example.com:v=spf1\072 -all:86400"
    records = parse_tinydns_data(line)
    assert records[0].content == '"v=spf1: -all"'


def test_parse_txt_escapes_internal_quote() -> None:
    # \042 = octal 42 = decimal 34 = '"' -- an internal quote must be
    # escaped in the rendered content, not left to terminate the string
    # early.
    line = r"'app.example.com:say \042hi\042:86400"
    records = parse_tinydns_data(line)
    assert records[0].content == '"say \\"hi\\""'


def test_parse_txt_escapes_literal_backslash() -> None:
    # \134 = octal 134 = decimal 92 = '\' -- a literal backslash byte in
    # the decoded text must itself be escaped in the quoted content.
    # Order matters here (escape backslashes before quotes, or an
    # already-escaped backslash gets double-escaped by the quote pass) --
    # every other TXT test enters via an octal escape that decodes to a
    # non-backslash byte, so none of them exercise this branch at all.
    line = r"'app.example.com:a\134b:86400"
    records = parse_tinydns_data(line)
    expected = '"' + "a" + "\\\\" + "b" + '"'
    assert records[0].content == expected


def test_render_zones_yaml_preserves_txt_backslash_escaping_round_trip() -> None:
    # Same case as test_parse_txt_escapes_literal_backslash, carried all
    # the way through bucket_into_zones + render_zones_yaml + a real YAML
    # parse -- pins that the escaping survives the full pipeline, not
    # just the parse step.
    text = "\n".join(
        [
            "Zexample.com:ns1.example.com:hostmaster.example.com:1:16384:2048:1048576:2560:3600",
            r"'app.example.com:a\134b:86400",
        ]
    )
    records = parse_tinydns_data(text)
    apexes = zone_apexes_from_records(records)
    zones = bucket_into_zones(records, apexes)
    parsed = yaml.safe_load(render_zones_yaml(zones))
    txt_entry = next(
        v for entry in parsed["domains"][0]["records"]["app.example.com"] for k, v in entry.items() if k == "txt"
    )
    content = txt_entry["content"] if isinstance(txt_entry, dict) else txt_entry
    assert content == '"' + "a" + "\\\\" + "b" + '"'


def test_parse_srv() -> None:
    # 0 100 88 -> priority=0 weight=100 port=88, target ipa.example.com.
    # Wire rdata: 2-byte prio, 2-byte weight, 2-byte port, then
    # length-prefixed labels "ipa" "example" "com" + root.
    rdata = "\\000\\000\\000\\144\\000\\130\\003ipa\\007example\\003com\\000"
    line = f"_ldap._tcp.example.com:33:{rdata}:86400"
    line = ":" + line
    records = parse_tinydns_data(line)
    assert records == [
        ParsedRecord(owner="_ldap._tcp.example.com", rtype="srv", content="0 100 88 ipa.example.com.", ttl=86400)
    ]


def test_parse_srv_label_length_exceeds_remaining_rdata_raises() -> None:
    # A length byte of 5 promises 5 more bytes, but only "ab" (2) remain
    # before the rdata ends -- must fail loudly, not silently slice a
    # truncated/garbage label into the emitted target name (Python slicing
    # doesn't raise past the end of a bytes object on its own).
    rdata = "\\000\\000\\000\\000\\000\\000\\005ab"
    line = f":app.example.com:33:{rdata}:86400"
    try:
        parse_tinydns_data(line)
        raise AssertionError("expected ValueError")
    except ValueError as e:
        assert "truncated wire-format name" in str(e)


def test_parse_generic_unsupported_type_raises() -> None:
    line = ":app.example.com:15:\\000\\012mail:86400"  # type 15 = MX, not handled
    try:
        parse_tinydns_data(line)
        raise AssertionError("expected ValueError")
    except ValueError as e:
        assert "unsupported generic record type" in str(e)


def test_parse_unrecognized_line_type_raises() -> None:
    try:
        parse_tinydns_data("^app.example.com:some.target:86400")  # bare PTR, not in #16's scope
        raise AssertionError("expected ValueError")
    except ValueError as e:
        assert "unrecognized tinydns line type" in str(e)


def test_parse_error_includes_line_number() -> None:
    text = "+ok.example.com:203.0.113.5:86400\n^bad.example.com:x:86400\n"
    try:
        parse_tinydns_data(text)
        raise AssertionError("expected ValueError")
    except ValueError as e:
        assert "line 2" in str(e)


def test_parse_skips_comments_and_blank_lines() -> None:
    text = "# a comment\n\n+ok.example.com:203.0.113.5:86400\n"
    records = parse_tinydns_data(text)
    assert len(records) == 1


# --- zone_apexes_from_records / bucket_into_zones -------------------------


def test_zone_apexes_from_records() -> None:
    text = (
        "Zexample.com:ns1.example.com:hostmaster.example.com:1:16384:2048:1048576:2560:3600\n"
        "Z113.0.203.in-addr.arpa:ns1.example.com:hostmaster.example.com:1:16384:2048:1048576:2560:3600\n"
    )
    records = parse_tinydns_data(text)
    assert zone_apexes_from_records(records) == ["example.com", "113.0.203.in-addr.arpa"]


def test_bucket_into_zones_places_records_under_matching_apex() -> None:
    records = [
        ParsedRecord(owner="example.com", rtype="soa", content="soa-content", ttl=3600),
        ParsedRecord(owner="web.example.com", rtype="a", content="203.0.113.5", ttl=86400),
        ParsedRecord(owner="2.113.0.203.in-addr.arpa", rtype="ptr", content="app.example.com.", ttl=86400),
    ]
    zones = bucket_into_zones(records, ["example.com", "113.0.203.in-addr.arpa"])
    assert zones["example.com"].records["web.example.com"]["a"] == [RecordValue("203.0.113.5", 86400)]
    assert zones["113.0.203.in-addr.arpa"].records["2.113.0.203.in-addr.arpa"]["ptr"] == [
        RecordValue("app.example.com.", 86400)
    ]


def test_bucket_into_zones_picks_longest_matching_apex() -> None:
    # A record for app.sub.example.com must land in the more specific
    # sub.example.com zone, not the broader example.com one.
    records = [ParsedRecord(owner="app.sub.example.com", rtype="a", content="203.0.113.10", ttl=None)]
    zones = bucket_into_zones(records, ["example.com", "sub.example.com"])
    assert "app.sub.example.com" in zones["sub.example.com"].records
    assert zones["example.com"].records == {}


def test_bucket_into_zones_apex_itself_matches() -> None:
    records = [ParsedRecord(owner="example.com", rtype="txt", content="hello", ttl=None)]
    zones = bucket_into_zones(records, ["example.com"])
    assert zones["example.com"].records["example.com"]["txt"] == [RecordValue("hello")]


def test_bucket_into_zones_unmatched_owner_raises() -> None:
    records = [ParsedRecord(owner="app.unrelated.com", rtype="a", content="203.0.113.10", ttl=None)]
    try:
        bucket_into_zones(records, ["example.com"])
        raise AssertionError("expected ValueError")
    except ValueError as e:
        assert "no zone apex matches" in str(e)


def test_bucket_into_zones_soa_ttl_sets_zone_default_ttl() -> None:
    records = [ParsedRecord(owner="example.com", rtype="soa", content="soa-content", ttl=7200)]
    zones = bucket_into_zones(records, ["example.com"])
    assert zones["example.com"].ttl == 7200


def test_bucket_into_zones_preserves_multiple_record_types_for_same_owner() -> None:
    # #16's own documented oddity: a name can carry an A record (from NS
    # glue) and later a CNAME too -- both must survive, not overwrite.
    records = [
        ParsedRecord(owner="app.example.com", rtype="a", content="203.0.113.1", ttl=86400),
        ParsedRecord(owner="app.example.com", rtype="cname", content="alias.example.com.", ttl=86400),
    ]
    zones = bucket_into_zones(records, ["example.com"])
    owner_records = zones["example.com"].records["app.example.com"]
    assert owner_records["a"] == [RecordValue("203.0.113.1", 86400)]
    assert owner_records["cname"] == [RecordValue("alias.example.com.", 86400)]


def test_bucket_into_zones_preserves_per_record_ttl_distinct_from_zone_default() -> None:
    # A source line's own ttl must survive onto its RecordValue even when
    # it differs from the zone's SOA-derived default -- it must not
    # silently collapse to that default (the bug #108's real-pdns_server
    # CI check surfaced: every record answered with the SOA's ttl instead
    # of its own).
    records = [
        ParsedRecord(owner="example.com", rtype="soa", content="soa-content", ttl=3600),
        ParsedRecord(owner="app.example.com", rtype="a", content="203.0.113.10", ttl=60),
    ]
    zones = bucket_into_zones(records, ["example.com"])
    assert zones["example.com"].ttl == 3600
    assert zones["example.com"].records["app.example.com"]["a"] == [RecordValue("203.0.113.10", 60)]


def test_bucket_into_zones_no_explicit_ttl_leaves_record_value_ttl_none() -> None:
    records = [ParsedRecord(owner="app.example.com", rtype="a", content="203.0.113.10", ttl=None)]
    zones = bucket_into_zones(records, ["example.com"])
    assert zones["example.com"].records["app.example.com"]["a"] == [RecordValue("203.0.113.10", None)]


# --- render_zones_yaml ------------------------------------------------------


def test_render_zones_yaml_round_trips_and_has_expected_shape() -> None:
    zones = {
        "example.com": Zone(
            apex="example.com",
            ttl=3600,
            records={
                "example.com": {
                    "soa": [RecordValue("ns1.example.com. hostmaster.example.com. 1 16384 2048 1048576 2560")]
                },
                "web.example.com": {"a": [RecordValue("203.0.113.5")]},
            },
        )
    }
    text = render_zones_yaml(zones)
    parsed = yaml.safe_load(text)
    assert parsed["domains"] == [
        {
            "domain": "example.com",
            "ttl": 3600,
            "records": {
                "example.com": [{"soa": "ns1.example.com. hostmaster.example.com. 1 16384 2048 1048576 2560"}],
                "web.example.com": [{"a": "203.0.113.5"}],
            },
        }
    ]


def test_render_zones_yaml_repeated_type_is_separate_list_entries() -> None:
    # The backend's real schema (confirmed by actually running a
    # converted zone through it, see #108) wants two separate {ns: ...}
    # list entries for two NS records -- never a single ns: [a, b] value.
    zones = {
        "example.com": Zone(
            apex="example.com",
            ttl=3600,
            records={"example.com": {"ns": [RecordValue("ns1.example.com."), RecordValue("ns2.example.com.")]}},
        )
    }
    parsed = yaml.safe_load(render_zones_yaml(zones))
    assert parsed["domains"][0]["records"]["example.com"] == [
        {"ns": "ns1.example.com."},
        {"ns": "ns2.example.com."},
    ]


def test_render_zones_yaml_cname_is_a_plain_string_value() -> None:
    zones = {
        "example.com": Zone(
            apex="example.com", ttl=3600, records={"www.example.com": {"cname": [RecordValue("web.example.com.")]}}
        )
    }
    parsed = yaml.safe_load(render_zones_yaml(zones))
    assert parsed["domains"][0]["records"]["www.example.com"] == [{"cname": "web.example.com."}]


def test_render_zones_yaml_per_record_ttl_uses_expanded_form() -> None:
    # A RecordValue with its own explicit ttl must render the backend's
    # expanded {content, ttl} form, not silently collapse to the zone's
    # single default ttl -- the actual bug this pins.
    zones = {
        "example.com": Zone(
            apex="example.com",
            ttl=3600,
            records={"app.example.com": {"a": [RecordValue("203.0.113.10", ttl=60)]}},
        )
    }
    parsed = yaml.safe_load(render_zones_yaml(zones))
    assert parsed["domains"][0]["records"]["app.example.com"] == [{"a": {"content": "203.0.113.10", "ttl": 60}}]


def test_render_zones_yaml_no_explicit_ttl_uses_plain_scalar_form() -> None:
    zones = {
        "example.com": Zone(
            apex="example.com", ttl=3600, records={"app.example.com": {"a": [RecordValue("203.0.113.10")]}}
        )
    }
    parsed = yaml.safe_load(render_zones_yaml(zones))
    assert parsed["domains"][0]["records"]["app.example.com"] == [{"a": "203.0.113.10"}]


def test_render_zones_yaml_has_generated_header_comment() -> None:
    zones = {"example.com": Zone(apex="example.com", ttl=3600, records={})}
    text = render_zones_yaml(zones)
    assert text.startswith("# GENERATED by dns-tinydns-convert")


def test_render_zones_yaml_multiple_zones_sorted_by_apex() -> None:
    zones = {
        "z.example.com": Zone(apex="z.example.com", ttl=3600, records={}),
        "a.example.com": Zone(apex="a.example.com", ttl=3600, records={}),
    }
    parsed = yaml.safe_load(render_zones_yaml(zones))
    assert [d["domain"] for d in parsed["domains"]] == ["a.example.com", "z.example.com"]


# --- end-to-end: parse -> bucket -> render ---------------------------------


def test_end_to_end_conversion() -> None:
    # Deliberately mixes both ttl paths: most lines carry no explicit ttl
    # (inherit the zone's SOA-derived default, rendered as a plain
    # scalar), while app.example.com's `=` line gives an explicit ttl=60
    # distinct from the zone default (3600) -- proving a source line's
    # own ttl survives into the expanded {content, ttl} form rather than
    # silently collapsing to the zone default (the bug #108's real-
    # pdns_server CI check surfaced).
    text = "\n".join(
        [
            "Zexample.com:ns1.example.com:hostmaster.example.com:1:16384:2048:1048576:2560:3600",
            "&example.com:203.0.113.1:ns1.example.com",
            "=app.example.com:203.0.113.2:60",
            "Cwww.example.com:app.example.com",
            "'_kerberos.example.com:EXAMPLE.COM",
            "Z113.0.203.in-addr.arpa:ns1.example.com:hostmaster.example.com:1:16384:2048:1048576:2560:3600",
            "&113.0.203.in-addr.arpa::ns1.example.com",
        ]
    )
    records = parse_tinydns_data(text)
    apexes = zone_apexes_from_records(records)
    zones = bucket_into_zones(records, apexes)
    parsed = yaml.safe_load(render_zones_yaml(zones))

    domains_by_name = {d["domain"]: d for d in parsed["domains"]}
    assert set(domains_by_name) == {"example.com", "113.0.203.in-addr.arpa"}

    forward = domains_by_name["example.com"]["records"]
    apex_soa_entry = next(v for entry in forward["example.com"] for k, v in entry.items() if k == "soa")
    apex_soa = apex_soa_entry["content"] if isinstance(apex_soa_entry, dict) else apex_soa_entry
    assert apex_soa.startswith("ns1.example.com. hostmaster.example.com.")
    assert {"ns": "ns1.example.com."} in forward["example.com"]
    assert forward["ns1.example.com"] == [{"a": "203.0.113.1"}]
    assert forward["app.example.com"] == [{"a": {"content": "203.0.113.2", "ttl": 60}}]
    assert forward["www.example.com"] == [{"cname": "app.example.com."}]
    assert forward["_kerberos.example.com"] == [{"txt": '"EXAMPLE.COM"'}]

    reverse = domains_by_name["113.0.203.in-addr.arpa"]["records"]
    assert reverse["2.113.0.203.in-addr.arpa"] == [{"ptr": {"content": "app.example.com.", "ttl": 60}}]
    assert {"ns": "ns1.example.com."} in reverse["113.0.203.in-addr.arpa"]
