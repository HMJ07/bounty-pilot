"""Scope engine: the single most safety-critical component of bounty-pilot.

Every target (hostname, URL or IP) is checked here *before* any network request is made
by any tool wrapper. The rules are deliberately simple and conservative:

1. Anything that cannot be parsed unambiguously is BLOCKED.
2. ``out_of_scope`` always wins over ``in_scope``.
3. Anything that does not match an ``in_scope`` rule is BLOCKED (default deny).

Rule syntax (the same for ``in_scope`` and ``out_of_scope``):

* ``example.com``      exact host only (NOT its subdomains)
* ``*.example.com``    any subdomain at any depth (NOT the apex ``example.com``)
* ``203.0.113.7``      a single IP address
* ``203.0.113.0/24``   a CIDR network (IPv4 or IPv6)

Ports, paths and schemes are ignored: scope is decided on the host only.
"""

from __future__ import annotations

import ipaddress
import logging
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

import yaml

log = logging.getLogger("bounty_pilot.scope")

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network

# Whitespace, backslashes and control characters make URL parsing ambiguous between
# libraries and browsers (e.g. "http://evil.com\@good.com"), so they are refused outright.
_FORBIDDEN = re.compile(r"[\s\\\x00-\x1f\x7f]")
_LABEL = re.compile(r"^(?!-)[a-z0-9_-]{1,63}(?<!-)$")
_PROGRAM = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")

MIN_IPV4_PREFIX = 16
MIN_IPV6_PREFIX = 48
_MAX_AUDIT = 10_000


class ScopeError(ValueError):
    """The scope definition is invalid."""


class OutOfScopeError(Exception):
    """An operation was attempted against something that is not in scope."""


def _normalize_ip(ip: IPAddress) -> IPAddress:
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    return ip


def extract_host(raw: object) -> str | None:
    """Return the normalized host of a hostname/URL/IP string, or None if ambiguous/invalid."""
    if not isinstance(raw, str):
        return None
    s = raw.strip()
    if not s or _FORBIDDEN.search(s) or "%" in s:
        return None
    try:
        return str(_normalize_ip(ipaddress.ip_address(s)))
    except ValueError:
        pass
    try:
        parts = urlsplit(s if "://" in s else "//" + s)
        host = parts.hostname
        _ = parts.port  # raises ValueError on a malformed port
    except ValueError:
        return None
    if "@" in parts.netloc or not host:
        return None  # userinfo tricks ("good.com@evil.com") are never trusted
    host = host.rstrip(".").lower()
    if not host:
        return None
    try:
        host.encode("ascii")
    except UnicodeEncodeError:
        try:
            host = host.encode("idna").decode("ascii")
        except UnicodeError:
            return None
    try:
        return str(_normalize_ip(ipaddress.ip_address(host)))
    except ValueError:
        pass
    if not all(_LABEL.match(label) for label in host.split(".")):
        return None
    return host


def _as_ip(host: str) -> IPAddress | None:
    try:
        return _normalize_ip(ipaddress.ip_address(host))
    except ValueError:
        return None


@dataclass(frozen=True)
class Rule:
    """One parsed scope entry."""

    raw: str
    kind: str  # "domain" | "wildcard" | "network"
    domain: str = ""
    network: IPNetwork | None = None

    def matches(self, host: str) -> bool:
        ip = _as_ip(host)
        if self.kind == "network":
            return ip is not None and self.network is not None and (
                ip.version == self.network.version and ip in self.network
            )
        if ip is not None:
            return False  # domain rules never match IP literals
        if self.kind == "domain":
            return host == self.domain
        return host.endswith("." + self.domain)  # wildcard: strict subdomains only


def parse_rule(raw: object) -> Rule:
    if not isinstance(raw, str) or not raw.strip():
        raise ScopeError(f"scope entries must be non-empty strings, got {raw!r}")
    s = raw.strip().lower()
    if s.startswith("*."):
        base = extract_host(s[2:])
        if base is None or _as_ip(base) is not None or "." not in base:
            raise ScopeError(
                f"invalid wildcard {raw!r}: must look like '*.example.com' "
                "(at least a registrable domain after '*.')"
            )
        return Rule(raw=raw.strip(), kind="wildcard", domain=base)
    if "*" in s:
        raise ScopeError(f"unsupported wildcard placement in {raw!r}; only a leading '*.' is allowed")
    if "/" in s and "://" not in s:
        try:
            net = ipaddress.ip_network(s, strict=True)
        except ValueError as exc:
            raise ScopeError(f"invalid CIDR {raw!r}: {exc}") from exc
        floor = MIN_IPV4_PREFIX if net.version == 4 else MIN_IPV6_PREFIX
        if net.prefixlen < floor:
            raise ScopeError(
                f"CIDR {raw!r} is too broad (minimum /{floor}); "
                "list narrower ranges to avoid an accidental huge scope"
            )
        return Rule(raw=raw.strip(), kind="network", network=net)
    host = extract_host(s)
    if host is None:
        raise ScopeError(f"cannot parse scope entry {raw!r}")
    ip = _as_ip(host)
    if ip is not None:
        net = ipaddress.ip_network(f"{ip}/{ip.max_prefixlen}")
        return Rule(raw=raw.strip(), kind="network", network=net)
    return Rule(raw=raw.strip(), kind="domain", domain=host)


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str
    host: str | None = None
    rule: str | None = None

    def __bool__(self) -> bool:  # pragma: no cover - trivial
        return self.allowed


@dataclass
class Scope:
    program: str
    in_scope: list[Rule]
    out_of_scope: list[Rule] = field(default_factory=list)
    platform: str = ""
    notes: str = ""
    blocked: dict[str, str] = field(default_factory=dict)

    # ---- construction -------------------------------------------------------------
    @classmethod
    def from_dict(cls, data: object) -> Scope:
        if not isinstance(data, dict):
            raise ScopeError("scope file must be a YAML mapping")
        program = str(data.get("program", "")).strip()
        if not _PROGRAM.match(program):
            raise ScopeError(
                "'program' is required and may only contain letters, digits, '.', '_' and '-' "
                "(max 64 chars, must start with a letter or digit)"
            )
        raw_in = data.get("in_scope")
        if not isinstance(raw_in, list) or not raw_in:
            raise ScopeError("'in_scope' must be a non-empty list")
        raw_out = data.get("out_of_scope") or []
        if not isinstance(raw_out, list):
            raise ScopeError("'out_of_scope' must be a list")
        return cls(
            program=program,
            in_scope=[parse_rule(r) for r in raw_in],
            out_of_scope=[parse_rule(r) for r in raw_out],
            platform=str(data.get("platform", "") or ""),
            notes=str(data.get("notes", "") or ""),
        )

    @classmethod
    def from_yaml(cls, text: str) -> Scope:
        try:
            data = yaml.safe_load(text)
        except yaml.YAMLError as exc:
            raise ScopeError(f"invalid YAML: {exc}") from exc
        return cls.from_dict(data)

    @classmethod
    def load(cls, path: str | Path) -> Scope:
        return cls.from_yaml(Path(path).read_text(encoding="utf-8"))

    # ---- decisions ----------------------------------------------------------------
    def check(self, target: object) -> Decision:
        host = extract_host(target)
        if host is None:
            return self._block(str(target), Decision(False, "unparseable or ambiguous target"))
        for rule in self.out_of_scope:
            if rule.matches(host):
                return self._block(
                    str(target), Decision(False, f"matches out_of_scope rule '{rule.raw}'", host, rule.raw)
                )
        for rule in self.in_scope:
            if rule.matches(host):
                return Decision(True, f"matches in_scope rule '{rule.raw}'", host, rule.raw)
        return self._block(str(target), Decision(False, "not covered by any in_scope rule", host))

    def is_allowed(self, target: object) -> bool:
        return self.check(target).allowed

    def require(self, target: object) -> str:
        """Return the normalized host or raise OutOfScopeError."""
        d = self.check(target)
        if not d.allowed:
            raise OutOfScopeError(f"{target!r} blocked: {d.reason}")
        assert d.host is not None
        return d.host

    def filter(self, targets: Iterable[object]) -> list[str]:
        """Keep only allowed targets (original strings preserved, order preserved, deduped)."""
        seen: set[str] = set()
        out: list[str] = []
        for t in targets:
            if not isinstance(t, str) or t in seen:
                continue
            seen.add(t)
            if self.is_allowed(t):
                out.append(t)
        return out

    def seed_domains(self) -> list[str]:
        """Domains that passive enumeration may start from (wildcard bases / exact domains).

        A wildcard base such as ``example.com`` (from ``*.example.com``) is used only as a
        *seed name* for passive sources; nothing is contacted unless a discovered host passes
        ``check`` afterwards.
        """
        seeds: list[str] = []
        for rule in self.in_scope:
            if rule.kind in ("domain", "wildcard") and rule.domain not in seeds:
                if rule.kind == "wildcard" or self.is_allowed(rule.domain):
                    seeds.append(rule.domain)
        return seeds

    def explicit_hosts(self) -> list[str]:
        """Exact in-scope domains and single IPs that may be probed directly."""
        hosts: list[str] = []
        for rule in self.in_scope:
            if rule.kind == "domain":
                cand = rule.domain
            elif rule.kind == "network" and rule.network is not None and (
                rule.network.num_addresses == 1
            ):
                cand = str(rule.network.network_address)
            else:
                continue
            if cand not in hosts and self.is_allowed(cand):
                hosts.append(cand)
        return hosts

    # ---- audit --------------------------------------------------------------------
    def _block(self, target: str, decision: Decision) -> Decision:
        log.warning("SCOPE BLOCK [%s]: %s -> %s", self.program, target, decision.reason)
        if len(self.blocked) < _MAX_AUDIT:
            self.blocked.setdefault(target, decision.reason)
        return decision
