"""Diff engine against constructed snapshots + SQLite round-trips."""

from __future__ import annotations

from bounty_pilot.diff import compute_diff
from bounty_pilot.models import Subdomain
from bounty_pilot.storage import Storage

from .conftest import ep, finding, port, snap, svc


def old_new():
    old = snap(run_id=1,
               subs=["www.acme.com", "old.acme.com", Subdomain("dead.acme.com", resolves=False)],
               services=[svc("https://www.acme.com", 200, "Home", ["nginx"], "nginx"),
                         svc("https://old.acme.com", 200)],
               endpoints=[ep("https://www.acme.com/a")],
               ports=[port("www.acme.com", 443), port("www.acme.com", 8080)],
               findings=[finding("t-old", "low", "https://www.acme.com/old"),
                         finding("t-keep", "medium", "https://www.acme.com/keep")])
    new = snap(run_id=2,
               subs=["www.acme.com", "dead.acme.com", "admin-staging.acme.com"],
               services=[svc("https://www.acme.com", 200, "Home v2", ["nginx", "php"], "nginx"),
                         svc("https://www.acme.com:8443", 200),
                         svc("https://dead.acme.com", 200, "Revived"),
                         svc("https://admin-staging.acme.com", 401, "Login")],
               endpoints=[ep("https://www.acme.com/a"), ep("https://www.acme.com/b?id=1"),
                          ep("https://www.acme.com/a", "POST")],
               ports=[port("www.acme.com", 443), port("www.acme.com", 6379)],
               findings=[finding("t-keep", "medium", "https://www.acme.com/keep"),
                         finding("t-new", "high", "https://www.acme.com/new")])
    return old, new


def test_new_and_removed_subdomains():
    d = compute_diff(*old_new())
    assert [s.host for s in d.new_subdomains] == ["admin-staging.acme.com"]
    assert [s.host for s in d.removed_subdomains] == ["old.acme.com"]


def test_dead_to_alive_and_gone_dead():
    d = compute_diff(*old_new())
    assert sorted(s.host for s in d.newly_live) == ["admin-staging.acme.com", "dead.acme.com"]
    assert [s.url for s in d.gone_dead] == ["https://old.acme.com"]


def test_new_service_on_already_live_host_is_not_newly_live():
    d = compute_diff(*old_new())
    assert [s.url for s in d.new_services] == ["https://www.acme.com:8443"]


def test_technology_and_title_changes_on_existing_host():
    d = compute_diff(*old_new())
    got = {(c.field, c.old, c.new) for c in d.changed_services}
    assert ("technologies", "nginx", "nginx, php") in got
    assert ("title", "Home", "Home v2") in got
    assert not any(c.field == "server" for c in d.changed_services)


def test_endpoints_ports_findings():
    d = compute_diff(*old_new())
    assert sorted(e.key for e in d.new_endpoints) == [
        "GET https://www.acme.com/b?id=1", "POST https://www.acme.com/a"]
    assert [p.port for p in d.new_ports] == [6379]
    assert [p.port for p in d.closed_ports] == [8080]
    assert [f.template_id for f in d.new_findings] == ["t-new"]
    assert [f.template_id for f in d.resolved_findings] == ["t-old"]


def test_identical_snapshots_produce_empty_diff():
    old, _ = old_new()
    d = compute_diff(old, old)
    assert d.is_empty() and not d.is_baseline and all(v == 0 for v in d.counts().values())


def test_first_run_is_a_baseline():
    _, new = old_new()
    d = compute_diff(None, new)
    assert d.is_baseline and d.old_run_id is None
    assert len(d.new_subdomains) == 3 and len(d.new_findings) == 2


def test_status_change_detected():
    old = snap(services=[svc("https://a.acme.com", 403)])
    new = snap(services=[svc("https://a.acme.com", 200)])
    (c,) = compute_diff(old, new).changed_services
    assert (c.field, c.old, c.new) == ("status_code", "403", "200")


# ---- storage ------------------------------------------------------------------------
def test_snapshot_round_trip():
    st = Storage(":memory:")
    st.add_target("acme", "program: acme")
    _, new = old_new()
    run_id = st.save_snapshot(new)
    loaded = st.get_snapshot("acme", run_id)
    assert loaded.run_id == run_id and loaded.phases == new.phases
    assert sorted(s.host for s in loaded.subdomains) == sorted(s.host for s in new.subdomains)
    assert {s.url: s.technologies for s in loaded.services}["https://www.acme.com"] == [
        "nginx", "php"]
    assert loaded.findings[0].severity in ("high", "medium")
    assert {e.key for e in loaded.endpoints} == {e.key for e in new.endpoints}
    assert compute_diff(loaded, new).is_empty()


def test_latest_previous_and_list(tmp_path):
    st = Storage(tmp_path / "db" / "h.db")  # creates the directory
    st.add_target("acme", "y")
    old, new = old_new()
    r1, r2 = st.save_snapshot(old), st.save_snapshot(new)
    assert st.latest_snapshot("acme").run_id == r2
    assert st.previous_snapshot("acme", r2).run_id == r1
    assert st.previous_snapshot("acme", r1) is None
    assert [r["id"] for r in st.list_runs("acme")] == [r2, r1]
    assert st.latest_snapshot("nope") is None and st.get_snapshot("acme", 999) is None


def test_targets_and_cascade_delete():
    st = Storage(":memory:")
    st.add_target("acme", "v1")
    st.add_target("acme", "v2")  # upsert
    assert st.get_scope_yaml("acme") == "v2" and st.list_targets() == ["acme"]
    old, _ = old_new()
    st.save_snapshot(old)
    assert st.remove_target("acme") and not st.remove_target("acme")
    assert st.conn.execute("SELECT COUNT(*) FROM items").fetchone()[0] == 0
    assert st.get_scope_yaml("acme") is None


def test_persisted_across_connections(tmp_path):
    path = tmp_path / "h.db"
    st = Storage(path)
    st.add_target("acme", "y")
    st.save_snapshot(old_new()[0])
    st.close()
    assert Storage(path).latest_snapshot("acme").run_id == 1
