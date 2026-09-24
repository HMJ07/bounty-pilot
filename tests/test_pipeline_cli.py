"""Pipeline (degraded mode, carry-forward) and end-to-end CLI smoke tests with mocked tools."""

from __future__ import annotations

import json

import pytest

from bounty_pilot import cli
from bounty_pilot.diff import compute_diff
from bounty_pilot.pipeline import PhaseError, Pipeline, parse_phases
from bounty_pilot.storage import Storage
from bounty_pilot.tools import build_tools
from bounty_pilot.tools.base import RunResult

from .conftest import SCOPE_YAML, FakeRunner, fake_which


def jl(*objs) -> str:
    return "\n".join(json.dumps(o) for o in objs) + "\n"


RUN1 = {
    "subfinder": jl({"host": "www.acme.com"}, {"host": "old.acme.com"}, {"host": "admin.acme.com"}),
    "dnsx": jl({"host": "www.acme.com", "a": ["1.1.1.1"]}, {"host": "old.acme.com", "a": ["1.1.1.2"]},
               {"host": "acme.com", "a": ["1.1.1.3"]}),
    "httpx": jl({"url": "https://www.acme.com", "status_code": 200, "title": "Home", "tech": ["nginx"]},
                {"url": "https://old.acme.com", "status_code": 200, "title": "Old"}),
    "katana": jl({"request": {"endpoint": "https://www.acme.com/a"}}),
    "nuclei": jl({"template-id": "t-old", "info": {"name": "Old Thing", "severity": "low"},
                  "matched-at": "https://old.acme.com/x"}),
}
RUN2 = {
    "subfinder": jl({"host": "www.acme.com"}, {"host": "old.acme.com"},
                    {"host": "admin-staging.acme.com"}, {"host": "admin.acme.com"}),
    "dnsx": jl({"host": "www.acme.com", "a": ["1.1.1.1"]}, {"host": "old.acme.com", "a": ["1.1.1.2"]},
               {"host": "admin-staging.acme.com", "a": ["1.1.1.9"]}, {"host": "acme.com", "a": ["1.1.1.3"]}),
    "httpx": jl({"url": "https://www.acme.com", "status_code": 200, "title": "Home", "tech": ["nginx", "php"]},
                {"url": "https://old.acme.com", "status_code": 200, "title": "Old"},
                {"url": "https://admin-staging.acme.com", "status_code": 401, "title": "Login"}),
    "katana": jl({"request": {"endpoint": "https://www.acme.com/a"}},
                 {"request": {"endpoint": "https://www.acme.com/download?file=x"}}),
    "nuclei": jl({"template-id": "git-config", "info": {"name": "Git Config", "severity": "high"},
                  "matched-at": "https://www.acme.com/.git/config"}),
}
ALL = {"subfinder", "dnsx", "httpx", "katana", "naabu", "ffuf", "nuclei"}


def tools_for(cfg, outputs, installed=ALL):
    tools = build_tools(cfg, runner=FakeRunner(outputs), which=fake_which(set(installed)))
    tools["httpx"].identity_markers = ()
    return tools


def test_parse_phases():
    assert parse_phases("nuclei, subdomains", []) == ["subdomains", "nuclei"]
    assert parse_phases(None, ["http"]) == ["http"]
    with pytest.raises(PhaseError):
        parse_phases("subdomains,exploit", [])
    with pytest.raises(PhaseError):
        parse_phases(" , ", [])


def test_full_pipeline_respects_scope(scope, cfg):
    pipe = Pipeline(scope, cfg, tools_for(cfg, RUN1))
    snap = pipe.run(["subdomains", "http", "crawl", "nuclei"])
    assert pipe.completed == ["subdomains", "http", "crawl", "nuclei"]
    hosts = {s.host for s in snap.subdomains}
    assert "admin.acme.com" not in hosts and {"www.acme.com", "old.acme.com", "acme.com"} <= hosts
    assert {s.url for s in snap.services} == {"https://www.acme.com", "https://old.acme.com"}
    assert [f.template_id for f in snap.findings] == ["t-old"]
    assert any("blocked by the scope engine" in w for w in snap.warnings)


def test_no_tools_installed_degrades_without_crashing(scope, cfg):
    pipe = Pipeline(scope, cfg, tools_for(cfg, {}, installed=set()))
    snap = pipe.run(["subdomains", "http", "crawl", "ports", "fuzz", "nuclei"])
    assert pipe.completed == ["subdomains"]           # scope-listed hosts are still recorded
    assert [s.host for s in snap.subdomains] == ["acme.com"]
    joined = " ".join(snap.warnings)
    for tool in ("subfinder", "httpx", "katana", "naabu", "nuclei"):
        assert tool in joined
    assert "go install" in joined


def test_partial_toolchain_runs_what_it_can(scope, cfg):
    pipe = Pipeline(scope, cfg, tools_for(cfg, RUN1, installed={"subfinder", "httpx"}))
    snap = pipe.run(["subdomains", "http", "crawl", "nuclei"])
    assert pipe.completed == ["subdomains", "http"]
    assert snap.services and not snap.findings
    assert any("dnsx not installed" in w for w in snap.warnings)
    assert any("katana not installed" in w for w in snap.warnings)


def test_crashing_phase_is_contained(scope, cfg):
    def boom(args, timeout, stdin=None):
        if "nuclei" in args[0]:
            raise RuntimeError("kaboom")
        return RunResult(0, RUN1.get(args[0].rsplit("/", 1)[-1], ""))

    tools = build_tools(cfg, runner=boom, which=fake_which(set(ALL)))
    tools["httpx"].identity_markers = ()
    pipe = Pipeline(scope, cfg, tools)
    snap = pipe.run(["subdomains", "http", "nuclei"])
    assert pipe.completed == ["subdomains", "http"]
    assert any("nuclei failed unexpectedly" in w for w in snap.warnings)


def test_unrun_phases_are_carried_forward_so_partial_runs_do_not_create_noise(scope, cfg):
    first = Pipeline(scope, cfg, tools_for(cfg, RUN1)).run(["subdomains", "http", "nuclei"])
    first.run_id = 1
    second_pipe = Pipeline(scope, cfg, tools_for(cfg, RUN1), previous=first)
    second = second_pipe.run(["nuclei"])
    d = compute_diff(first, second)
    assert d.is_empty()
    assert {s.host for s in second.subdomains} == {s.host for s in first.subdomains}


def test_failed_tool_does_not_wipe_previous_data(scope, cfg):
    first = Pipeline(scope, cfg, tools_for(cfg, RUN1)).run(["subdomains", "http"])
    first.run_id = 1
    bad = dict(RUN1, httpx=RunResult(1, "", "crashed"))
    second = Pipeline(scope, cfg, tools_for(cfg, bad), previous=first).run(["http"])
    assert {s.url for s in second.services} == {s.url for s in first.services}


def test_timeout_merges_partial_output_with_history(scope, cfg):
    first = Pipeline(scope, cfg, tools_for(cfg, RUN1)).run(["subdomains", "http"])
    partial = dict(RUN1, httpx=RunResult(-1, jl({"url": "https://www.acme.com", "status_code": 200}),
                                         "", timed_out=True))
    second = Pipeline(scope, cfg, tools_for(cfg, partial), previous=first).run(["http"])
    assert {s.url for s in second.services} == {"https://www.acme.com", "https://old.acme.com"}
    assert any("timeout" in w for w in second.warnings)


def test_ffuf_skipped_without_wordlist(scope, cfg):
    pipe = Pipeline(scope, cfg, tools_for(cfg, RUN1))
    snap = pipe.run(["subdomains", "http", "fuzz"])
    assert "fuzz" not in pipe.completed and any("ffuf_wordlist" in w for w in snap.warnings)


# ---- CLI end to end -------------------------------------------------------------------
@pytest.fixture(autouse=True)
def _wide_console(monkeypatch):
    monkeypatch.setattr(cli.console, "width", 250)
    monkeypatch.setattr(cli.err, "width", 250)


@pytest.fixture
def scope_file(tmp_path):
    p = tmp_path / "acme.yaml"
    p.write_text(SCOPE_YAML, encoding="utf-8")
    return str(p)


def patch_tools(monkeypatch, outputs, installed=ALL):
    def fake_build(cfg, runner=None, which=None):
        return tools_for(cfg, outputs, installed)

    monkeypatch.setattr(cli, "build_tools", fake_build)


def test_two_runs_second_shows_only_what_changed(monkeypatch, scope_file, capsys):
    assert cli.main(["scope", "add", scope_file]) == 0
    patch_tools(monkeypatch, RUN1)
    assert cli.main(["scan", "acme"]) == 0
    out = capsys.readouterr().out
    assert "Baseline run" in out and "Run #1 stored" in out

    patch_tools(monkeypatch, RUN2)
    assert cli.main(["scan", "acme"]) == 0
    out = capsys.readouterr().out
    assert "Changes since run #1" in out
    assert "admin-staging.acme.com" in out           # new + live + admin-ish
    assert "Git Config" in out                       # new finding
    assert "download?file=x" in out                  # new endpoint with interesting param
    assert "technologies" in out                     # tech change on www
    assert "Resolved findings" in out and "Old Thing" in out
    assert "admin.acme.com/" not in out and "https://admin.acme.com" not in out

    # unchanged third run -> no changes
    assert cli.main(["scan", "acme"]) == 0
    assert "No changes since run #2" in capsys.readouterr().out


def test_show_diff_since_and_runs(monkeypatch, scope_file, capsys):
    cli.main(["scope", "add", scope_file])
    patch_tools(monkeypatch, RUN1)
    cli.main(["scan", "acme"])
    patch_tools(monkeypatch, RUN2)
    cli.main(["scan", "acme"])
    capsys.readouterr()

    assert cli.main(["show", "acme"]) == 0
    shown = capsys.readouterr().out
    assert "run #2" in shown and "admin-staging.acme.com" in shown

    assert cli.main(["show", "acme", "--run", "1"]) == 0
    assert "run #1" in capsys.readouterr().out

    assert cli.main(["diff", "acme"]) == 0
    assert "Changes since run #1" in capsys.readouterr().out
    assert cli.main(["diff", "acme", "--since", "1"]) == 0
    assert cli.main(["diff", "acme", "--since", "77"]) == 1
    assert cli.main(["runs", "acme"]) == 0
    assert "Runs for acme" in capsys.readouterr().out


def test_scan_with_no_tools_stores_nothing(monkeypatch, scope_file, capsys):
    cli.main(["scope", "add", scope_file])
    # Only the scope-listed apex host exists, so 'subdomains' still completes; use phases that need tools.
    patch_tools(monkeypatch, {}, installed=set())
    assert cli.main(["scan", "acme", "--phases", "http,nuclei"]) == 3
    captured = capsys.readouterr()
    assert "No phase could run" in captured.err
    st = Storage(cli.home_dir() / "history.db")
    assert st.latest_snapshot("acme") is None


def test_scan_unknown_target_and_bad_phase(monkeypatch, scope_file, capsys):
    assert cli.main(["scan", "ghost"]) == 2
    cli.main(["scope", "add", scope_file])
    assert cli.main(["scan", "acme", "--phases", "exploit"]) == 2
    assert "unknown phase" in capsys.readouterr().err


def test_scope_commands(scope_file, tmp_path, capsys):
    assert cli.main(["scope", "add", scope_file]) == 0
    assert cli.main(["scope", "list"]) == 0
    assert "acme" in capsys.readouterr().out
    assert cli.main(["scope", "check", "acme", "https://www.acme.com/x"]) == 0
    assert cli.main(["scope", "check", "acme", "admin.acme.com"]) == 1
    assert "BLOCKED" in capsys.readouterr().out
    bad = tmp_path / "bad.yaml"
    bad.write_text("program: x\nin_scope: ['*.com']\n")
    assert cli.main(["scope", "add", str(bad)]) == 2
    assert cli.main(["scope", "add", str(tmp_path / "missing.yaml")]) == 2
    assert cli.main(["scope", "remove", "acme"]) == 0
    assert cli.main(["scope", "remove", "acme"]) == 1


def test_doctor_reports_missing_tools(monkeypatch, capsys):
    monkeypatch.setattr("shutil.which", lambda b: None)
    assert cli.main(["doctor"]) == 0
    out = capsys.readouterr().out
    assert "0/7 tools available" in out
    assert "go install -v github.com/projectdiscovery/subfinder" in out


def test_doctor_with_all_installed(monkeypatch, capsys):
    monkeypatch.setattr(cli, "build_tools", lambda cfg: tools_for(cfg, {"httpx": ""}))
    assert cli.main(["doctor"]) == 0
    assert "7/7 tools available" in capsys.readouterr().out


def test_report_from_file_to_output(tmp_path, capsys):
    src = tmp_path / "f.yaml"
    src.write_text("title: T\nasset: https://x.example.com\nvuln_class: XSS\nsteps: [a, b]\nimpact: i\n")
    out = tmp_path / "out.md"
    assert cli.main(["report", "--from", str(src), "--format", "bugcrowd", "-o", str(out)]) == 0
    assert "## Steps to reproduce" in out.read_text(encoding="utf-8")
    assert cli.main(["report", "--from", str(src)]) == 0
    assert "## Steps to Reproduce" in capsys.readouterr().out
    assert cli.main(["report", "--from", str(tmp_path / "nope.yaml")]) == 2


def test_notify_flag_sends_counts_only(monkeypatch, scope_file, capsys):
    sent = []
    monkeypatch.setattr("bounty_pilot.notify.default_post",
                        lambda url, payload, timeout: sent.append(payload))
    monkeypatch.setattr(cli, "send", lambda s, text, post=None: sent.append(text) or ["discord: sent"])
    cli.main(["scope", "add", scope_file])
    patch_tools(monkeypatch, RUN1)
    cli.main(["scan", "acme", "--notify"])
    assert sent and "acme" in sent[0] and "www.acme.com" not in sent[0]
    sent.clear()
    cli.main(["scan", "acme"])           # off by default
    assert sent == []


def test_llm_flag_falls_back_when_endpoint_down(monkeypatch, scope_file, capsys):
    cli.main(["scope", "add", scope_file])
    patch_tools(monkeypatch, RUN1)
    import urllib.error
    import urllib.request

    def refuse(*a, **k):
        raise urllib.error.URLError("connection refused")

    monkeypatch.setattr(urllib.request, "urlopen", refuse)
    assert cli.main(["scan", "acme", "--llm"]) == 0
    captured = capsys.readouterr()
    assert "heuristic ranking" in captured.err and "Worth investigating first" in captured.out
