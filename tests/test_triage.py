"""Heuristic ranking and (mocked) LLM re-ranking."""

from __future__ import annotations

import json

import pytest

from bounty_pilot.config import LLMSettings
from bounty_pilot.diff import compute_diff
from bounty_pilot.triage import triage
from bounty_pilot.triage.heuristic import rank
from bounty_pilot.triage.llm import LLMError, build_messages, parse_response, rerank

from .conftest import ep, finding, port, snap, svc


def big_diff():
    old = snap(subs=["www.acme.com"], services=[svc("https://www.acme.com", 200)])
    new = snap(
        subs=["www.acme.com", "admin-staging.acme.com", "shop.acme.com", "blog.acme.com"],
        services=[svc("https://www.acme.com", 200),
                  svc("https://admin-staging.acme.com", 401, "Login"),
                  svc("https://shop.acme.com", 200, "Shop")],
        endpoints=[ep("https://www.acme.com/page"), ep("https://www.acme.com/dl?file=a"),
                   ep("https://www.acme.com/admin/panel"), ep("https://www.acme.com/s?x=1")],
        ports=[port("www.acme.com", 6379), port("www.acme.com", 8081)],
        findings=[finding("crit", "critical", "https://www.acme.com/c"),
                  finding("low", "low", "https://www.acme.com/l"),
                  finding("info", "info", "https://www.acme.com/i")],
    )
    return compute_diff(old, new)


def test_priority_order():
    items = rank(big_diff())
    subjects = [i.subject for i in items]
    assert items[0].category == "finding" and "[critical]" in subjects[0]
    pos = {s: n for n, s in enumerate(subjects)}
    admin = next(s for s in subjects if "admin-staging" in s)
    shop = next(s for s in subjects if "shop.acme.com" in s)
    info = next(s for s in subjects if "[info]" in s)
    assert pos[subjects[0]] < pos[admin] < pos[shop] < pos[info]


def test_scores_follow_the_documented_order():
    scores = {i.subject: i.score for i in rank(big_diff())}
    crit = next(v for k, v in scores.items() if "[critical]" in k)
    admin = next(v for k, v in scores.items() if "admin-staging" in k)
    shop = next(v for k, v in scores.items() if "shop.acme.com" in k)
    param = next(v for k, v in scores.items() if "file=a" in k)
    plain = next(v for k, v in scores.items() if k.endswith("/page"))
    assert crit > admin > shop > param > plain


def test_new_live_host_is_not_listed_twice():
    items = rank(big_diff())
    assert sum("admin-staging" in i.subject for i in items) == 1
    # blog.acme.com is new but not live -> reported as a host
    assert any(i.category == "host" and i.subject == "blog.acme.com" for i in items)


def test_interesting_hostname_beats_boring_one():
    old = snap()
    new = snap(subs=["jenkins.acme.com", "zzz.acme.com"])
    items = rank(compute_diff(old, new))
    assert items[0].subject == "jenkins.acme.com" and items[0].score > items[1].score


def test_sensitive_port_ranks_above_plain_port():
    items = [i for i in rank(big_diff()) if i.category == "port"]
    assert items[0].subject.endswith(":6379") and "Redis" in items[0].rationale


def test_status_change_to_reachable_is_notable():
    d = compute_diff(snap(services=[svc("https://a.acme.com", 403)]),
                     snap(services=[svc("https://a.acme.com", 200)]))
    (item,) = rank(d)
    assert item.category == "change" and item.score >= 55


def test_ids_unique_and_empty_diff():
    items = rank(big_diff())
    assert len({i.id for i in items}) == len(items)
    assert rank(compute_diff(snap(), snap())) == []


# ---- LLM ----------------------------------------------------------------------------
def llm_settings(**kw):
    return LLMSettings(enabled=True, base_url="http://localhost:11434/v1", model="m", **kw)


def reply(content):
    return lambda url, headers, payload, timeout: {"choices": [{"message": {"content": content}}]}


def test_llm_reorders_and_never_drops():
    items = rank(big_diff())
    ids = [i.id for i in items]
    picked = ids[-1]
    content = "Sure!\n```json\n" + json.dumps([
        {"id": picked, "rationale": "look here first"},
        {"id": "bogus", "rationale": "ignored"},
        {"id": ids[0]},
    ]) + "\n```"
    out = rerank(items, llm_settings(), reply(content))
    assert [i.id for i in out][:2] == [picked, ids[0]]
    assert sorted(i.id for i in out) == sorted(ids)            # nothing dropped or invented
    assert out[0].rationale == "look here first" and out[0].source == "llm"
    assert out[1].source == "heuristic"                        # no rationale given -> unchanged


def test_llm_only_sees_top_n_and_tail_is_preserved():
    items = rank(big_diff())
    seen = {}

    def post(url, headers, payload, timeout):
        seen["user"] = payload["messages"][1]["content"]
        seen["url"] = url
        return {"choices": [{"message": {"content": json.dumps([{"id": items[1].id}])}}]}

    out = rerank(items, llm_settings(max_items=3), post)
    assert seen["user"].count("\n") == 4          # <data>, 3 lines, </data>
    assert seen["url"].endswith("/chat/completions")
    assert [i.id for i in out][-(len(items) - 3):] == [i.id for i in items[3:]]


def test_api_key_sent_as_bearer():
    got = {}

    def post(url, headers, payload, timeout):
        got.update(headers)
        return {"choices": [{"message": {"content": '[{"id": "i0001"}]'}}]}

    rerank(rank(big_diff()), llm_settings(api_key="sk-test"), post)
    assert got["Authorization"] == "Bearer sk-test"


@pytest.mark.parametrize("content", ["no json here", "[not json]", "[]", '[{"id": "zzz"}]', "{}"])
def test_bad_llm_output_raises(content):
    with pytest.raises(LLMError):
        rerank(rank(big_diff()), llm_settings(), reply(content))


def test_bad_response_shape_and_bad_url():
    with pytest.raises(LLMError):
        rerank(rank(big_diff()), llm_settings(), lambda *a: {"oops": 1})
    with pytest.raises(LLMError):
        rerank(rank(big_diff()), LLMSettings(enabled=True, base_url="file:///etc/passwd"),
               reply("[]"))


def test_triage_falls_back_to_heuristics_on_llm_failure():
    def boom(*a):
        raise LLMError("connection refused")

    items, warn = triage(big_diff(), llm_settings(), boom)
    assert items == rank(big_diff()) and "heuristic" in warn


def test_triage_without_llm_is_pure_heuristic():
    items, warn = triage(big_diff(), None)
    assert warn is None and items == rank(big_diff())
    items, warn = triage(big_diff(), LLMSettings(enabled=False))
    assert warn is None


def test_prompt_marks_target_data_untrusted():
    msgs = build_messages(rank(big_diff()))
    assert "untrusted" in msgs[0]["content"]
    assert msgs[1]["content"].startswith("<data>")


def test_parse_response_dedups_ids():
    out = parse_response('[{"id":"a","rationale":"x"},{"id":"a","rationale":"y"}]', {"a"})
    assert out == [("a", "x")]
