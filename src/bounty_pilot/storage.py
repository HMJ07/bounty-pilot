"""SQLite persistence: registered scopes and one immutable snapshot per scan run."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from .models import Endpoint, Finding, HttpService, OpenPort, Snapshot, Subdomain

SCHEMA = """
CREATE TABLE IF NOT EXISTS targets (
    name TEXT PRIMARY KEY,
    scope_yaml TEXT NOT NULL,
    added_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target TEXT NOT NULL REFERENCES targets(name) ON DELETE CASCADE,
    started_at TEXT NOT NULL,
    finished_at TEXT NOT NULL,
    phases TEXT NOT NULL,
    warnings TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS items (
    run_id INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    key TEXT NOT NULL,
    data TEXT NOT NULL,
    PRIMARY KEY (run_id, kind, key)
);
CREATE INDEX IF NOT EXISTS idx_runs_target ON runs(target, id);
"""

_KINDS = {
    "subdomains": Subdomain,
    "services": HttpService,
    "endpoints": Endpoint,
    "ports": OpenPort,
    "findings": Finding,
}


def utcnow() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


class Storage:
    def __init__(self, path: str | Path):
        self.path = str(path)
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.path)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")
        self.conn.executescript(SCHEMA)

    def close(self) -> None:
        self.conn.close()

    # ---- targets ------------------------------------------------------------------
    def add_target(self, name: str, scope_yaml: str) -> None:
        with self.conn:
            self.conn.execute(
                "INSERT INTO targets(name, scope_yaml, added_at) VALUES(?,?,?) "
                "ON CONFLICT(name) DO UPDATE SET scope_yaml=excluded.scope_yaml",
                (name, scope_yaml, utcnow()),
            )

    def get_scope_yaml(self, name: str) -> str | None:
        row = self.conn.execute("SELECT scope_yaml FROM targets WHERE name=?", (name,)).fetchone()
        return row["scope_yaml"] if row else None

    def list_targets(self) -> list[str]:
        return [r["name"] for r in self.conn.execute("SELECT name FROM targets ORDER BY name")]

    def remove_target(self, name: str) -> bool:
        with self.conn:
            cur = self.conn.execute("DELETE FROM targets WHERE name=?", (name,))
        return cur.rowcount > 0

    # ---- snapshots ----------------------------------------------------------------
    def save_snapshot(self, snap: Snapshot) -> int:
        """Persist a snapshot atomically and return its run id."""
        with self.conn:
            cur = self.conn.execute(
                "INSERT INTO runs(target, started_at, finished_at, phases, warnings) "
                "VALUES(?,?,?,?,?)",
                (snap.target, snap.started_at or utcnow(), snap.finished_at or utcnow(),
                 json.dumps(snap.phases), json.dumps(snap.warnings)),
            )
            run_id = int(cur.lastrowid or 0)
            rows = []
            for kind in _KINDS:
                for item in getattr(snap, kind):
                    rows.append((run_id, kind, item.key, json.dumps(item.to_dict(), sort_keys=True)))
            self.conn.executemany(
                "INSERT OR REPLACE INTO items(run_id, kind, key, data) VALUES(?,?,?,?)", rows
            )
        snap.run_id = run_id
        return run_id

    def _load(self, row: sqlite3.Row) -> Snapshot:
        snap = Snapshot(
            target=row["target"],
            run_id=row["id"],
            started_at=row["started_at"],
            finished_at=row["finished_at"],
            phases=json.loads(row["phases"]),
            warnings=json.loads(row["warnings"]),
        )
        for r in self.conn.execute(
            "SELECT kind, data FROM items WHERE run_id=? ORDER BY kind, key", (row["id"],)
        ):
            cls = _KINDS.get(r["kind"])
            if cls:
                getattr(snap, r["kind"]).append(cls.from_dict(json.loads(r["data"])))
        return snap

    def get_snapshot(self, target: str, run_id: int) -> Snapshot | None:
        row = self.conn.execute(
            "SELECT * FROM runs WHERE target=? AND id=?", (target, run_id)
        ).fetchone()
        return self._load(row) if row else None

    def latest_snapshot(self, target: str) -> Snapshot | None:
        row = self.conn.execute(
            "SELECT * FROM runs WHERE target=? ORDER BY id DESC LIMIT 1", (target,)
        ).fetchone()
        return self._load(row) if row else None

    def previous_snapshot(self, target: str, before_run_id: int) -> Snapshot | None:
        row = self.conn.execute(
            "SELECT * FROM runs WHERE target=? AND id<? ORDER BY id DESC LIMIT 1",
            (target, before_run_id),
        ).fetchone()
        return self._load(row) if row else None

    def list_runs(self, target: str) -> list[dict]:
        rows = self.conn.execute(
            "SELECT r.id, r.started_at, r.phases, "
            "(SELECT COUNT(*) FROM items i WHERE i.run_id=r.id) AS n_items "
            "FROM runs r WHERE r.target=? ORDER BY r.id DESC",
            (target,),
        )
        return [
            {"id": r["id"], "started_at": r["started_at"], "phases": json.loads(r["phases"]),
             "items": r["n_items"]}
            for r in rows
        ]
