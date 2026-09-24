"""Report renderer and notification summaries."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from bounty_pilot.config import NotifySettings
from bounty_pilot.diff import compute_diff
from bounty_pilot.notify import NotifyError, build_summary, send
from bounty_pilot.report import (
    ReportData,
    ReportError,
    collect_interactive,
    load_report_file,
    render,
    severity_from_cvss,
)

from .conftest import finding, snap, svc

EXAMPLES = Path(__file__).resolve().parent.parent / "examples" / "reports"

BASE = {
    "title": "IDOR on /api/invoices/{id}",
    "asset": "https://app.example.com/api/invoices/1001",
    "vuln_class": "Insecure Direct Object Reference",
    "steps": ["Log in as user A", "Request invoice of user B", "Observe 200 with B's data"],
    "impact": "Any user can read any invoice.",
    "cvss_score": 6.5,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
    "remediation": "Enforce object-level authorization.",
}


def test_hackerone_skeleton():
    md = render(ReportData.from_mapping(BASE), "hackerone")
    for heading in ("## Summary", "## Steps to Reproduce", "## Impact", "## Remediation"):
        assert heading in md
    assert md.startswith("# IDOR on /api/invoices/{id}")
    assert "1. Log in as user A" in md and "3. Observe 200" in md
    assert "Medium - CVSS 6.5" in md and "`CVSS:3.1/AV:N" in md
    assert "manually verified" in md


def test_bugcrowd_style_differs():
    md = render(ReportData.from_mapping(BASE), "bugcrowd")
    assert "## Description" in md and "## Steps to reproduce" in md and "## Recommended fix" in md
    assert "**Vulnerability type:**" in md and "## Summary" not in md


def test_generic_format_and_unknown_format():
    assert "## Summary" in render(ReportData.from_mapping(BASE), "generic")
    with pytest.raises(ReportError):
        render(ReportData.from_mapping(BASE), "jira")


def test_references_and_missing_optional_fields():
    d = dict(BASE, references=["https://cwe.mitre.org/data/definitions/639.html"])
    d.pop("remediation")
    md = render(ReportData.from_mapping(d))
    assert "## References" in md and "cwe.mitre.org" in md
    assert "No remediation suggested" in md


@pytest.mark.parametrize("score,sev", [(0, "none"), (0.1, "low"), (3.9, "low"), (4.0, "medium"),
                                       (6.9, "medium"), (7.0, "high"), (8.9, "high"),
                                       (9.0, "critical"), (10, "critical")])
def test_cvss_to_severity(score, sev):
    assert severity_from_cvss(score) == sev


def test_explicit_severity_wins_over_derived():
    d = ReportData.from_mapping(dict(BASE, severity="High"))
    assert d.severity == "high"


@pytest.mark.parametrize("patch", [
    {"title": ""}, {"steps": []}, {"impact": None}, {"cvss_score": 11}, {"cvss_score": "abc"},
    {"cvss_vector": "AV:N/AC:L"}, {"severity": "urgent"},
])
def test_invalid_reports_rejected(patch):
    with pytest.raises(ReportError):
        ReportData.from_mapping(dict(BASE, **patch))


def test_non_mapping_rejected():
    with pytest.raises(ReportError):
        ReportData.from_mapping(["x"])


def test_steps_may_be_multiline_string():
    d = ReportData.from_mapping(dict(BASE, steps="one\n\ntwo\n"))
    assert d.steps == ["one", "two"]


def test_load_yaml_and_json(tmp_path):
    y = tmp_path / "r.yaml"
    y.write_text("title: T\nasset: a\nvuln_class: XSS\nsteps: [s1]\nimpact: i\n")
    assert load_report_file(y).title == "T"
    j = tmp_path / "r.json"
    j.write_text(json.dumps(BASE))
    assert load_report_file(j).cvss_score == 6.5
    bad = tmp_path / "bad.json"
    bad.write_text("{nope")
    with pytest.raises(ReportError):
        load_report_file(bad)


def test_interactive_collection():
    answers = iter(["My title", "https://x.example.com", "XSS", "sum", "step one", "step two", "",
                    "it is bad", "8.1", "", "", "sanitize"])
    said = []
    d = collect_interactive(lambda prompt: next(answers), said.append)
    assert d.title == "My title" and d.steps == ["step one", "step two"]
    assert d.severity == "high" and d.remediation == "sanitize"


def test_interactive_reprompts_for_required():
    answers = iter(["", "T", "a", "c", "", "", "s1", "", "impact", "", "", "", ""])
    said = []
    d = collect_interactive(lambda prompt: next(answers), said.append)
    assert d.title == "T" and any("required" in s for s in said)


@pytest.mark.parametrize("path", sorted(EXAMPLES.glob("*.yaml")))
def test_shipped_examples_are_valid_and_use_fictional_data(path):
    d = load_report_file(path)
    text = render(d)
    assert "example.com" in text or "example.org" in text
    assert "## Steps to Reproduce" in text


def test_examples_exist():
    assert len(list(EXAMPLES.glob("*.yaml"))) >= 2


# ---- notifications -----------------------------------------------------------------
def summary_diff():
    old = snap(run_id=1, subs=["a.acme.com"])
    new = snap(run_id=2, subs=["a.acme.com", "secret-admin.acme.com", "b.acme.com"],
               services=[svc("https://secret-admin.acme.com")],
               findings=[finding("t", "high", "https://secret-admin.acme.com/.env", "Env Leak")])
    return compute_diff(old, new)


def test_summary_is_counts_only():
    text = build_summary("acme", summary_diff(), 2)
    assert "2 new subdomain(s)" in text and "1 new finding(s) (1 high)" in text
    assert "bountypilot diff acme" in text
    for leak in ("secret-admin", ".env", "Env Leak", "https://"):
        assert leak not in text


def test_summary_variants():
    assert "no new changes" in build_summary("acme", compute_diff(snap(), snap()), 3)
    assert "baseline" in build_summary("acme", compute_diff(None, snap(subs=["a.acme.com"])), 1)


def test_send_discord_and_telegram():
    calls = []
    cfg = NotifySettings(enabled=True, discord_webhook="https://discord.com/api/webhooks/1/x",
                         telegram_token="123:ABC", telegram_chat_id="42")
    res = send(cfg, "hello", lambda url, payload, timeout: calls.append((url, payload)))
    assert res == ["discord: sent", "telegram: sent"]
    assert calls[0][1]["content"] == "hello" and calls[0][1]["allowed_mentions"] == {"parse": []}
    assert calls[1][0] == "https://api.telegram.org/bot123:ABC/sendMessage"
    assert calls[1][1] == {"chat_id": "42", "text": "hello"}


def test_send_nothing_configured_and_bad_webhooks():
    called = []
    assert send(NotifySettings(), "x", lambda *a: called.append(a)) == [
        "no notification channel configured"]
    for bad in ("http://discord.com/api/webhooks/1/x", "https://evil.example/hook",
                "https://discord.com.evil.net/x"):
        res = send(NotifySettings(discord_webhook=bad), "x", lambda *a: called.append(a))
        assert res[0].startswith("discord: failed")
    assert called == []


def test_send_failure_does_not_leak_secret():
    def post(url, payload, timeout):
        raise NotifyError("request failed (URLError)")

    res = send(NotifySettings(telegram_token="SECRETTOKEN", telegram_chat_id="1"), "x", post)
    assert "SECRETTOKEN" not in " ".join(res) and "failed" in res[0]


def test_env_configuration(monkeypatch):
    from bounty_pilot.config import Config

    monkeypatch.setenv("BOUNTYPILOT_DISCORD_WEBHOOK", "https://discord.com/api/webhooks/9/z")
    cfg = Config.from_dict({})
    assert cfg.notify.discord_webhook.endswith("/9/z") and cfg.notify.enabled is False
