"""Tool wrappers: output parsers, safe command construction, scope filtering, degradation."""

from __future__ import annotations

import json
import subprocess

import pytest

from bounty_pilot.config import Config, ToolSettings
from bounty_pilot.tools import TOOL_CLASSES, ToolNotInstalled, base
from bounty_pilot.tools.base import RunResult, ToolError, default_runner, iter_json_lines
from bounty_pilot.tools.dnsx import Dnsx
from bounty_pilot.tools.ffuf import Ffuf
from bounty_pilot.tools.httpx import Httpx
from bounty_pilot.tools.katana import Katana
from bounty_pilot.tools.naabu import Naabu
from bounty_pilot.tools.nuclei import Nuclei
from bounty_pilot.tools.subfinder import Subfinder

from .conftest import FakeRunner, fake_which


def jl(*objs) -> str:
    return "\n".join(json.dumps(o) for o in objs) + "\n"


# ---- parsers --------------------------------------------------------------------------
def test_iter_json_lines_skips_garbage():
    text = "[INF] banner\n{\"a\": 1}\nnot json\n{broken\n[1,2]\n{\"b\": 2}\n"
    assert list(iter_json_lines(text)) == [{"a": 1}, {"b": 2}]


def test_subfinder_parse():
    out = jl({"host": "WWW.acme.com", "source": ["crtsh", "alienvault"]},
             {"host": "www.acme.com", "source": ["dup"]},
             {"host": "api.acme.com", "source": "hackertarget"},
             {"host": "bad host"}, {"nohost": 1})
    subs = Subfinder.parse(out)
    assert [s.host for s in subs] == ["www.acme.com", "api.acme.com"]
    assert subs[0].source == "crtsh,alienvault"


def test_dnsx_parse():
    out = jl({"host": "a.acme.com", "a": ["1.1.1.1", "1.1.1.1"], "status_code": "NOERROR"},
             {"host": "b.acme.com", "status_code": "NXDOMAIN"},
             {"host": "c.acme.com", "aaaa": ["2001:db8::1"]})
    by = {s.host: s for s in Dnsx.parse(out)}
    assert by["a.acme.com"].resolves and by["a.acme.com"].ips == ["1.1.1.1"]
    assert by["b.acme.com"].resolves is False
    assert by["c.acme.com"].resolves is True


def test_httpx_parse():
    out = jl(
        {"url": "https://a.acme.com", "status_code": 200, "title": " Login ", "webserver": "nginx",
         "tech": ["Nginx", "PHP"], "content_length": 512, "host": "1.2.3.4", "host_ip": "1.2.3.4"},
        {"url": "http://b.acme.com:8080", "status_code": "403", "tech": None, "a": ["5.6.7.8"]},
        {"nourl": True},
    )
    a, b = Httpx.parse(out)
    assert (a.host, a.status_code, a.title, a.server, a.content_length, a.ip) == (
        "a.acme.com", 200, "Login", "nginx", 512, "1.2.3.4")
    assert a.technologies == ["Nginx", "PHP"]
    assert b.status_code == 403 and b.host == "b.acme.com" and b.ip == "5.6.7.8"


def test_katana_parse_jsonl_and_plain():
    out = jl({"request": {"method": "post", "endpoint": "https://a.acme.com/login"}},
             {"request": {"endpoint": "https://a.acme.com/x?id=1"}},
             {"request": {"endpoint": "https://a.acme.com/x?id=1"}})
    eps = Katana.parse(out)
    assert [(e.method, e.url) for e in eps] == [("POST", "https://a.acme.com/login"),
                                                ("GET", "https://a.acme.com/x?id=1")]
    plain = Katana.parse("https://a.acme.com/one\nnoise\nhttp://a.acme.com/two\n")
    assert [e.url for e in plain] == ["https://a.acme.com/one", "http://a.acme.com/two"]


def test_naabu_parse():
    out = jl({"host": "a.acme.com", "ip": "1.2.3.4", "port": 22},
             {"host": "a.acme.com", "ip": "1.2.3.4", "port": 22},
             {"ip": "203.0.113.5", "port": 8080},
             {"host": "a.acme.com", "port": 99999}, {"host": "a.acme.com", "port": "x"})
    ports = Naabu.parse(out)
    assert [(p.host, p.port) for p in ports] == [("a.acme.com", 22), ("203.0.113.5", 8080)]


def test_ffuf_parse():
    text = json.dumps({"results": [{"url": "https://a.acme.com/admin", "status": 301},
                                   {"url": "https://a.acme.com/admin", "status": 301},
                                   {"nourl": 1}]})
    assert [e.url for e in Ffuf.parse(text)] == ["https://a.acme.com/admin"]
    assert Ffuf.parse("not json") == []
    assert Ffuf.parse("[]") == []


def test_nuclei_parse():
    out = jl(
        {"template-id": "git-config", "info": {"name": "Git Config", "severity": "MEDIUM",
                                                "tags": "exposure,git", "description": "d"},
         "host": "https://a.acme.com", "matched-at": "https://a.acme.com/.git/config"},
        {"template-id": "x", "info": {"name": "X", "severity": "weird", "tags": ["a"]},
         "host": "a.acme.com:443", "matched-at": "a.acme.com:443"},
        {"info": {}}, {"template-id": "nohost", "info": {}},
    )
    f1, f2 = Nuclei.parse(out)
    assert f1.severity == "medium" and f1.tags == ["exposure", "git"]
    assert f1.host == "a.acme.com" and f1.matched_at.endswith("/.git/config")
    assert f2.severity == "info"


# ---- safe command construction --------------------------------------------------------
@pytest.mark.parametrize("name", list(TOOL_CLASSES))
def test_commands_are_argument_lists_with_rate_limits(name):
    tool = TOOL_CLASSES[name](ToolSettings(rate_limit=7, concurrency=3, timeout=9))
    if name == "subfinder":
        cmd = tool.build_command("/bin/x", "acme.com")
    elif name == "katana":
        cmd = tool.build_command("/bin/x", 2)
    elif name == "naabu":
        cmd = tool.build_command("/bin/x", 100)
    elif name == "ffuf":
        cmd = tool.build_command("/bin/x", "https://a.acme.com", "/wl.txt", "/o.json")
    elif name == "nuclei":
        cmd = tool.build_command("/bin/x", ["high"], ["dos"])
    else:
        cmd = tool.build_command("/bin/x")
    assert isinstance(cmd, list) and all(isinstance(a, str) for a in cmd)
    assert "7" in cmd  # the configured rate limit is applied to every tool


def test_nuclei_always_excludes_dangerous_tags_and_disables_interactsh(cfg):
    cfg.nuclei_extra_exclude_tags = ["custom"]
    tags = cfg.nuclei_exclude_tags()
    for forbidden in ("dos", "intrusive", "fuzz", "bruteforce", "default-login"):
        assert forbidden in tags
    cmd = Nuclei(cfg.tools["nuclei"]).build_command("n", ["high"], tags)
    assert "-ni" in cmd
    assert "-etags" in cmd and "default-login" in cmd[cmd.index("-etags") + 1]


def test_katana_stays_on_the_exact_host():
    cmd = Katana(ToolSettings(1, 1, 1)).build_command("k", 2)
    assert cmd[cmd.index("-fs") + 1] == "fqdn"


def test_httpx_does_not_follow_redirects():
    assert "-fr" not in Httpx(ToolSettings(1, 1, 1)).build_command("h")


def test_hostile_input_is_data_not_shell(scope, cfg):
    """Metacharacters in a host never reach a shell: they are dropped by scope or sent as stdin."""
    runner = FakeRunner({"httpx": ""})
    tool = Httpx(cfg.tools["httpx"], runner=runner, which=fake_which({"httpx"}))
    tool.identity_markers = ()
    tool.run(scope, ["a.acme.com; rm -rf /", "$(id).acme.com", "ok.acme.com"])
    args, stdin = runner.calls[0]
    assert stdin == "ok.acme.com\n"
    assert not any("rm" in a for a in args)


def test_default_runner_never_uses_shell(monkeypatch):
    seen = {}

    def fake_run(args, **kw):
        seen.update(kw, args=args)
        return subprocess.CompletedProcess(args, 0, "out", "")

    monkeypatch.setattr(base.subprocess, "run", fake_run)
    res = default_runner(["tool", "-x", "a b; c"], 5, "in")
    assert res.stdout == "out"
    assert seen["shell"] is False and seen["args"] == ["tool", "-x", "a b; c"]
    assert seen["timeout"] == 5 and seen["input"] == "in"


def test_default_runner_timeout_keeps_partial_output(monkeypatch):
    def fake_run(args, **kw):
        raise subprocess.TimeoutExpired(args, 1, output=b"partial", stderr=None)

    monkeypatch.setattr(base.subprocess, "run", fake_run)
    res = default_runner(["tool"], 1)
    assert res.timed_out and res.stdout == "partial"


def test_default_runner_missing_binary(monkeypatch):
    def fake_run(args, **kw):
        raise FileNotFoundError

    monkeypatch.setattr(base.subprocess, "run", fake_run)
    with pytest.raises(ToolNotInstalled):
        default_runner(["nope"], 1)


# ---- scope enforcement on inputs and outputs ------------------------------------------
def test_inputs_are_filtered_before_the_tool_runs(scope, cfg):
    runner = FakeRunner({"httpx": ""})
    tool = Httpx(cfg.tools["httpx"], runner=runner, which=fake_which({"httpx"}))
    tool.identity_markers = ()
    tool.run(scope, ["www.acme.com", "admin.acme.com", "x.internal.acme.com", "evil.org",
                     "203.0.113.99", "203.0.113.5"])
    assert runner.calls[0][1].split() == ["www.acme.com", "203.0.113.5"]


def test_no_allowed_inputs_means_no_subprocess(scope, cfg):
    runner = FakeRunner()
    tool = Nuclei(cfg.tools["nuclei"], runner=runner, which=fake_which({"nuclei"}))
    out = tool.run(scope, ["https://evil.org"], ["high"], ["dos"])
    assert out.items == [] and runner.calls == []


def test_outputs_are_filtered_too(scope, cfg):
    out = jl({"url": "https://www.acme.com", "status_code": 200},
             {"url": "https://admin.acme.com", "status_code": 200},   # out of scope
             {"url": "https://evil.org", "status_code": 200})         # never asked for
    runner = FakeRunner({"httpx": out})
    tool = Httpx(cfg.tools["httpx"], runner=runner, which=fake_which({"httpx"}))
    tool.identity_markers = ()
    res = tool.run(scope, ["www.acme.com"])
    assert [s.url for s in res.items] == ["https://www.acme.com"]
    assert "https://admin.acme.com" in scope.blocked and "https://evil.org" in scope.blocked


def test_subfinder_output_filtered_and_seeded_from_scope(scope, cfg):
    runner = FakeRunner({"subfinder": jl({"host": "a.acme.com"}, {"host": "admin.acme.com"},
                                         {"host": "b.internal.acme.com"}, {"host": "evil.org"})})
    tool = Subfinder(cfg.tools["subfinder"], runner=runner, which=fake_which({"subfinder"}))
    res = tool.run(scope, scope.seed_domains())
    assert [s.host for s in res.items] == ["a.acme.com"]
    assert runner.calls[0][0][1:3] == ["-d", "acme.com"]


def test_katana_output_outside_scope_is_dropped(scope, cfg):
    out = jl({"request": {"endpoint": "https://www.acme.com/a"}},
             {"request": {"endpoint": "https://admin.acme.com/b"}},
             {"request": {"endpoint": "https://cdn.evil.org/c.js"}})
    tool = Katana(cfg.tools["katana"], runner=FakeRunner({"katana": out}),
                  which=fake_which({"katana"}))
    assert [e.url for e in tool.run(scope, ["https://www.acme.com"]).items] == [
        "https://www.acme.com/a"]


# ---- degraded mode / failures ---------------------------------------------------------
@pytest.mark.parametrize("name", list(TOOL_CLASSES))
def test_missing_binary_raises_with_install_instructions(name, cfg):
    tool = TOOL_CLASSES[name](cfg.tools[name], which=fake_which(set()))
    assert not tool.available()
    with pytest.raises(ToolNotInstalled) as exc:
        tool.require()
    assert name in str(exc.value) and "go install" in str(exc.value)


def test_wrong_httpx_binary_is_detected(cfg):
    """The Python `httpx` CLI shares the name; it must not be mistaken for ProjectDiscovery's."""
    py = Httpx(cfg.tools["httpx"], which=fake_which({"httpx"}),
               runner=FakeRunner({"httpx": RunResult(0, "Usage: httpx [OPTIONS] URL", "")}))
    assert not py.available()
    pd = Httpx(cfg.tools["httpx"], which=fake_which({"httpx"}),
               runner=FakeRunner({"httpx": RunResult(0, "", "[INF] Current Version: v1.6.0")}))
    assert pd.available()


def test_timeout_yields_partial_results_and_warning(scope, cfg):
    partial = jl({"url": "https://www.acme.com", "status_code": 200})
    runner = FakeRunner({"httpx": RunResult(-1, partial, "", timed_out=True)})
    tool = Httpx(cfg.tools["httpx"], runner=runner, which=fake_which({"httpx"}))
    tool.identity_markers = ()
    res = tool.run(scope, ["www.acme.com"])
    assert res.timed_out and len(res.items) == 1
    assert "timeout" in res.warnings[0]


def test_nonzero_exit_without_output_warns(scope, cfg):
    runner = FakeRunner({"nuclei": RunResult(2, "", "boom: bad template")})
    tool = Nuclei(cfg.tools["nuclei"], runner=runner, which=fake_which({"nuclei"}))
    res = tool.run(scope, ["https://www.acme.com"], ["high"], ["dos"])
    assert res.items == [] and "exited with code 2" in res.warnings[0]


def test_ffuf_requires_wordlist(scope, cfg, tmp_path):
    tool = Ffuf(cfg.tools["ffuf"], runner=FakeRunner(), which=fake_which({"ffuf"}))
    with pytest.raises(ToolError):
        tool.run(scope, ["https://www.acme.com"], str(tmp_path / "missing.txt"))


def test_ffuf_reads_output_file(scope, cfg, tmp_path):
    wl = tmp_path / "wl.txt"
    wl.write_text("admin\n")

    def runner(args, timeout, stdin=None):
        out_file = args[args.index("-o") + 1]
        with open(out_file, "w", encoding="utf-8") as fh:
            json.dump({"results": [{"url": "https://www.acme.com/admin"},
                                   {"url": "https://admin.acme.com/x"}]}, fh)
        return RunResult(0)

    tool = Ffuf(cfg.tools["ffuf"], runner=runner, which=fake_which({"ffuf"}))
    res = tool.run(scope, ["https://www.acme.com", "https://admin.acme.com"], str(wl))
    assert [e.url for e in res.items] == ["https://www.acme.com/admin"]


def test_settings_validation():
    from bounty_pilot.config import ConfigError

    with pytest.raises(ConfigError):
        Config.from_dict({"tools": {"httpx": {"rate_limit": 0}}})
    with pytest.raises(ConfigError):
        Config.from_dict({"tools": {"nmap": {"rate_limit": 1}}})
    assert Config.from_dict({"tools": {"httpx": {"rate_limit": 3}}}).tools["httpx"].rate_limit == 3
