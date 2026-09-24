"""Shared fixtures. The suite makes NO real subprocess calls to security tools and NO network calls."""

from __future__ import annotations

import urllib.request
from collections.abc import Sequence

import pytest

from bounty_pilot.config import Config
from bounty_pilot.models import Endpoint, Finding, HttpService, OpenPort, Snapshot, Subdomain
from bounty_pilot.scope import Scope
from bounty_pilot.tools import base as tools_base
from bounty_pilot.tools import build_tools
from bounty_pilot.tools.base import RunResult

SCOPE_YAML = """
program: acme
platform: hackerone
in_scope:
  - "*.acme.com"
  - "acme.com"
  - "203.0.113.0/24"
out_of_scope:
  - "admin.acme.com"
  - "*.internal.acme.com"
  - "203.0.113.99"
"""


@pytest.fixture(autouse=True)
def _isolate(monkeypatch, tmp_path):
    monkeypatch.setenv("BOUNTYPILOT_HOME", str(tmp_path / "home"))
    for var in ("BOUNTYPILOT_DISCORD_WEBHOOK", "BOUNTYPILOT_TELEGRAM_TOKEN",
                "BOUNTYPILOT_TELEGRAM_CHAT_ID", "BOUNTYPILOT_LLM_API_KEY"):
        monkeypatch.delenv(var, raising=False)

    def no_subprocess(*a, **k):
        raise AssertionError("real subprocess call attempted in tests")

    def no_network(*a, **k):
        raise AssertionError("real network call attempted in tests")

    monkeypatch.setattr(tools_base.subprocess, "run", no_subprocess)
    monkeypatch.setattr(urllib.request, "urlopen", no_network)


@pytest.fixture
def scope() -> Scope:
    return Scope.from_yaml(SCOPE_YAML)


@pytest.fixture
def cfg() -> Config:
    return Config()


class FakeRunner:
    """Maps a tool binary name to canned output; records every invocation."""

    def __init__(self, outputs: dict[str, RunResult | str] | None = None):
        self.outputs = outputs or {}
        self.calls: list[tuple[list[str], str | None]] = []

    def __call__(self, args: Sequence[str], timeout: float, stdin: str | None = None) -> RunResult:
        self.calls.append((list(args), stdin))
        name = str(args[0]).replace("\\", "/").rsplit("/", 1)[-1]
        out = self.outputs.get(name, "")
        if isinstance(out, RunResult):
            return out
        return RunResult(0, out, "")


def fake_which(installed: set[str]):
    return lambda binary: f"/usr/bin/{binary}" if binary in installed else None


@pytest.fixture
def make_tools(cfg):
    def _make(outputs: dict | None = None, installed: set[str] | None = None):
        runner = FakeRunner(outputs)
        names = installed if installed is not None else {
            "subfinder", "dnsx", "httpx", "katana", "naabu", "ffuf", "nuclei"}
        tools = build_tools(cfg, runner=runner, which=fake_which(names))
        for t in tools.values():  # accept the fake httpx as the ProjectDiscovery one
            t.identity_markers = ()
        return tools, runner
    return _make


def snap(target="acme", run_id=None, subs=(), services=(), endpoints=(), ports=(), findings=()):
    s = Snapshot(target=target, run_id=run_id, started_at="2026-01-01T00:00:00+00:00",
                 finished_at="2026-01-01T00:01:00+00:00", phases=["subdomains", "http"])
    s.subdomains = [Subdomain(host=h, resolves=True) if isinstance(h, str) else h for h in subs]
    s.services = list(services)
    s.endpoints = list(endpoints)
    s.ports = list(ports)
    s.findings = list(findings)
    return s


def svc(url, status=200, title="", tech=(), server=""):
    from bounty_pilot.scope import extract_host

    return HttpService(url=url, host=extract_host(url), status_code=status, title=title,
                       technologies=list(tech), server=server)


def ep(url, method="GET"):
    from bounty_pilot.scope import extract_host

    return Endpoint(url=url, host=extract_host(url), method=method, source="katana")


def finding(tid="t1", sev="high", url="https://a.acme.com/x", name="Thing"):
    from bounty_pilot.scope import extract_host

    return Finding(template_id=tid, name=name, severity=sev, host=extract_host(url), matched_at=url)


def port(host, n):
    return OpenPort(host=host, port=n)
