"""The most important tests in the repo: the scope engine decides what may be touched."""

from __future__ import annotations

import logging

import pytest

from bounty_pilot.scope import OutOfScopeError, Scope, ScopeError, extract_host, parse_rule


def mk(in_scope, out_of_scope=(), program="p"):
    return Scope.from_dict({"program": program, "in_scope": list(in_scope),
                            "out_of_scope": list(out_of_scope)})


# ---- wildcard / exact domain matching ----------------------------------------------
class TestDomains:
    def test_exact_domain_matches_only_itself(self):
        s = mk(["example.com"])
        assert s.is_allowed("example.com")
        assert not s.is_allowed("www.example.com")
        assert not s.is_allowed("evilexample.com")

    def test_wildcard_matches_subdomains_at_any_depth(self):
        s = mk(["*.example.com"])
        assert s.is_allowed("www.example.com")
        assert s.is_allowed("a.b.c.example.com")

    def test_wildcard_does_not_match_apex(self):
        assert not mk(["*.example.com"]).is_allowed("example.com")

    @pytest.mark.parametrize("host", [
        "evilexample.com",            # suffix without a dot boundary
        "example.com.evil.net",       # rule name as a prefix
        "example.com-evil.net",
        "notexample.com",
        "example.co",
    ])
    def test_lookalikes_never_match(self, host):
        s = mk(["*.example.com", "example.com"])
        assert not s.is_allowed(host)

    def test_case_insensitive_and_trailing_dot(self):
        s = mk(["*.Example.COM"])
        assert s.is_allowed("WWW.EXAMPLE.com.")

    def test_idn_hosts_are_normalized(self):
        s = mk(["*.example.com"])
        assert s.is_allowed("bücher.example.com")

    def test_default_deny(self):
        s = mk(["*.example.com"])
        assert not s.is_allowed("unrelated.org")
        d = s.check("unrelated.org")
        assert not d.allowed and "in_scope" in d.reason


# ---- out-of-scope always wins --------------------------------------------------------
class TestPrecedence:
    def test_exact_out_beats_wildcard_in(self):
        s = mk(["*.example.com"], ["admin.example.com"])
        assert s.is_allowed("www.example.com")
        assert not s.is_allowed("admin.example.com")

    def test_wildcard_out_beats_wildcard_in(self):
        s = mk(["*.example.com"], ["*.internal.example.com"])
        assert not s.is_allowed("db.internal.example.com")
        assert not s.is_allowed("a.b.internal.example.com")
        assert s.is_allowed("public.example.com")

    def test_exact_out_does_not_exclude_children(self):
        # Documented behaviour: exclude the subtree explicitly with a wildcard rule as well.
        s = mk(["*.example.com"], ["admin.example.com"])
        assert s.is_allowed("x.admin.example.com")
        s2 = mk(["*.example.com"], ["admin.example.com", "*.admin.example.com"])
        assert not s2.is_allowed("x.admin.example.com")

    def test_out_of_scope_ip_beats_in_scope_cidr(self):
        s = mk(["203.0.113.0/24"], ["203.0.113.99"])
        assert s.is_allowed("203.0.113.5")
        assert not s.is_allowed("203.0.113.99")

    def test_out_of_scope_cidr_carves_hole(self):
        s = mk(["10.0.0.0/16"], ["10.0.5.0/24"])
        assert s.is_allowed("10.0.4.1")
        assert not s.is_allowed("10.0.5.200")

    def test_same_entry_in_both_lists_is_blocked(self):
        assert not mk(["example.com"], ["example.com"]).is_allowed("example.com")

    def test_reason_names_the_out_of_scope_rule(self):
        d = mk(["*.example.com"], ["admin.example.com"]).check("admin.example.com")
        assert not d.allowed and d.rule == "admin.example.com" and "out_of_scope" in d.reason


# ---- CIDR / IPs ---------------------------------------------------------------------
class TestNetworks:
    def test_cidr_boundaries(self):
        s = mk(["203.0.113.0/24"])
        assert s.is_allowed("203.0.113.0")
        assert s.is_allowed("203.0.113.255")
        assert not s.is_allowed("203.0.112.255")
        assert not s.is_allowed("203.0.114.0")

    def test_single_ip_rule(self):
        s = mk(["198.51.100.7"])
        assert s.is_allowed("198.51.100.7")
        assert not s.is_allowed("198.51.100.8")

    def test_ipv6(self):
        s = mk(["2001:db8::/48"])
        assert s.is_allowed("2001:db8::1")
        assert s.is_allowed("[2001:db8:0:1::5]")
        assert not s.is_allowed("2001:db9::1")

    def test_ipv4_mapped_ipv6_is_normalized(self):
        assert mk(["10.0.0.0/24"]).is_allowed("::ffff:10.0.0.5")

    def test_domain_rules_never_match_ips_and_vice_versa(self):
        assert not mk(["example.com"]).is_allowed("203.0.113.5")
        assert not mk(["203.0.113.0/24"]).is_allowed("example.com")

    def test_ip_in_url_with_port(self):
        assert mk(["203.0.113.0/24"]).is_allowed("http://203.0.113.10:8080/admin")

    def test_ipv4_and_ipv6_do_not_cross_match(self):
        assert not mk(["10.0.0.0/24"]).is_allowed("2001:db8::1")

    @pytest.mark.parametrize("host", ["2130706433", "0x7f.0.0.1", "0177.0.0.1"])
    def test_obfuscated_ip_forms_do_not_slip_through(self, host):
        assert not mk(["127.0.0.0/24", "*.example.com"]).is_allowed(host)


# ---- URL / target parsing -----------------------------------------------------------
class TestParsing:
    @pytest.mark.parametrize("raw,expected", [
        ("https://WWW.Example.com:8443/a/b?c=d#e", "www.example.com"),
        ("www.example.com/path", "www.example.com"),
        ("www.example.com:80", "www.example.com"),
        ("  www.example.com  ", "www.example.com"),
        ("http://[2001:db8::1]:80/", "2001:db8::1"),
    ])
    def test_extract_host(self, raw, expected):
        assert extract_host(raw) == expected

    @pytest.mark.parametrize("raw", [
        "", "   ", None, 123,
        "http://evil.com\\@good.example.com",   # backslash confusion
        "http://good.example.com@evil.com",     # userinfo confusion
        "http://evil.com@good.example.com",
        "good.example.com\nevil.com",           # embedded newline
        "good.example.com evil.com",            # embedded space
        "http://good.example.com:99999",        # invalid port
        "*.example.com",                        # a wildcard is not a target
        "a..example.com",
        "-bad.example.com",
        "fe80::1%eth0",
    ])
    def test_ambiguous_targets_are_blocked(self, raw):
        s = mk(["*.example.com"])
        assert extract_host(raw) is None
        assert not s.is_allowed(raw)

    def test_url_tricks_resolve_to_the_real_host(self):
        s = mk(["*.example.com"])
        assert not s.is_allowed("http://evil.com/?x=www.example.com")
        assert not s.is_allowed("http://evil.com#.example.com")
        assert not s.is_allowed("http://evil.com/.example.com")
        assert s.is_allowed("http://www.example.com/?next=http://evil.com")


# ---- validation of scope definitions ------------------------------------------------
class TestValidation:
    @pytest.mark.parametrize("bad", ["*", "*.com", "*.", "foo.*.example.com", "*example.com",
                                     "203.0.113.0/33", "0.0.0.0/0", "10.0.0.0/8", "::/0",
                                     "203.0.113.5/24", "", "   ", 5, "http://[bad"])
    def test_bad_rules_rejected(self, bad):
        with pytest.raises(ScopeError):
            parse_rule(bad)

    def test_ip_wildcard_rejected(self):
        with pytest.raises(ScopeError):
            parse_rule("*.10.0.0.1")

    @pytest.mark.parametrize("data", [
        None, [], "x", {},
        {"program": "p"},
        {"program": "p", "in_scope": []},
        {"program": "p", "in_scope": "example.com"},
        {"program": "bad name!", "in_scope": ["example.com"]},
        {"program": "", "in_scope": ["example.com"]},
        {"program": "p", "in_scope": ["example.com"], "out_of_scope": "x"},
    ])
    def test_bad_scope_documents_rejected(self, data):
        with pytest.raises(ScopeError):
            Scope.from_dict(data)

    def test_invalid_yaml(self):
        with pytest.raises(ScopeError):
            Scope.from_yaml("a: [unclosed")

    def test_url_style_rule_is_reduced_to_host(self):
        r = parse_rule("https://www.example.com/some/path")
        assert r.kind == "domain" and r.domain == "www.example.com"

    def test_minimum_cidr_size_boundary(self):
        assert parse_rule("10.0.0.0/16").kind == "network"
        assert parse_rule("2001:db8::/48").kind == "network"

    def test_load_from_file(self, tmp_path):
        p = tmp_path / "s.yaml"
        p.write_text("program: x\nin_scope: ['*.example.com']\n", encoding="utf-8")
        assert Scope.load(p).is_allowed("a.example.com")


# ---- helpers used by the pipeline ---------------------------------------------------
class TestHelpers:
    def test_require_returns_host_or_raises(self):
        s = mk(["*.example.com"], ["admin.example.com"])
        assert s.require("https://www.example.com/x") == "www.example.com"
        with pytest.raises(OutOfScopeError):
            s.require("admin.example.com")
        with pytest.raises(OutOfScopeError):
            s.require("evil.org")

    def test_filter_keeps_order_dedups_and_drops_non_strings(self):
        s = mk(["*.example.com"])
        got = s.filter(["b.example.com", "evil.org", "a.example.com", "b.example.com", None, 5])
        assert got == ["b.example.com", "a.example.com"]

    def test_blocked_targets_are_audited_and_logged(self, caplog):
        s = mk(["*.example.com"], ["admin.example.com"])
        with caplog.at_level(logging.WARNING, logger="bounty_pilot.scope"):
            s.is_allowed("admin.example.com")
            s.is_allowed("evil.org")
            s.is_allowed("ok.example.com")
        assert set(s.blocked) == {"admin.example.com", "evil.org"}
        assert "SCOPE BLOCK" in caplog.text and "evil.org" in caplog.text

    def test_seed_domains(self):
        s = mk(["*.example.com", "other.org", "203.0.113.0/24"], ["other.org"])
        assert s.seed_domains() == ["example.com"]

    def test_explicit_hosts(self):
        s = mk(["www.example.com", "*.example.com", "198.51.100.7", "203.0.113.0/24"],
               ["198.51.100.7"])
        assert s.explicit_hosts() == ["www.example.com"]
