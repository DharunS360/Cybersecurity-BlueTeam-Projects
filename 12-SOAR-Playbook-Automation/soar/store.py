"""SQLite storage: enrichment cache, case records and a tamper-evident audit log.

The audit log is a hash chain: every entry stores sha256(previous_hash + entry).
Editing or deleting any past row breaks every hash after it, which `verify()` detects.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

from .models import Finding

GENESIS = "0" * 64

SCHEMA = """
CREATE TABLE IF NOT EXISTS cache(
    provider TEXT, ioc_type TEXT, ioc_value TEXT, finding_json TEXT, fetched_at REAL,
    PRIMARY KEY(provider, ioc_type, ioc_value));
CREATE TABLE IF NOT EXISTS cases(
    id TEXT PRIMARY KEY, created_at TEXT, source TEXT, title TEXT, input_sha256 TEXT,
    label TEXT, score INTEGER, result_json TEXT);
CREATE TABLE IF NOT EXISTS audit_log(
    seq INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, actor TEXT, action TEXT, case_id TEXT,
    detail_json TEXT, prev_hash TEXT, entry_hash TEXT);
"""


def utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _entry_hash(prev: str, ts: str, actor: str, action: str, case_id: str, detail: str) -> str:
    return hashlib.sha256("|".join((prev, ts, actor, action, case_id, detail)).encode()).hexdigest()


class Store:
    def __init__(self, path: Path | str) -> None:
        if str(path) != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._db = sqlite3.connect(str(path), check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        self._lock = threading.RLock()
        with self._lock:
            if str(path) != ":memory:":
                self._db.execute("PRAGMA journal_mode=WAL")
            self._db.executescript(SCHEMA)

    def close(self) -> None:
        with self._lock:
            self._db.close()

    # cache ---------------------------------------------------------------
    def cache_get(self, provider: str, ioc_type: str, value: str, ttl_hours: float) -> Finding | None:
        with self._lock:
            row = self._db.execute(
                "SELECT finding_json, fetched_at FROM cache WHERE provider=? AND ioc_type=? AND ioc_value=?",
                (provider, ioc_type, value)).fetchone()
        if not row or (time.time() - row["fetched_at"]) > ttl_hours * 3600:
            return None
        f = Finding.from_dict(json.loads(row["finding_json"]))
        f.cached = True
        return f

    def cache_put(self, provider: str, ioc_type: str, value: str, finding: Finding) -> None:
        with self._lock:
            self._db.execute(
                "INSERT OR REPLACE INTO cache VALUES (?,?,?,?,?)",
                (provider, ioc_type, value, json.dumps(finding.to_dict()), time.time()))
            self._db.commit()

    # cases ---------------------------------------------------------------
    def save_case(self, case_id: str, created_at: str, source: str, title: str, sha: str,
                  label: str, score: int, result: dict) -> None:
        with self._lock:
            self._db.execute("INSERT OR REPLACE INTO cases VALUES (?,?,?,?,?,?,?,?)",
                             (case_id, created_at, source, title, sha, label, score, json.dumps(result)))
            self._db.commit()

    def list_cases(self, limit: int = 20) -> list[sqlite3.Row]:
        with self._lock:
            return self._db.execute(
                "SELECT id, created_at, source, title, label, score FROM cases ORDER BY created_at DESC LIMIT ?",
                (limit,)).fetchall()

    def get_case(self, case_id: str) -> dict | None:
        with self._lock:
            row = self._db.execute("SELECT result_json FROM cases WHERE id=?", (case_id,)).fetchone()
        return json.loads(row["result_json"]) if row else None

    # audit ---------------------------------------------------------------
    def audit(self, actor: str, action: str, case_id: str = "", detail: dict | None = None) -> str:
        detail_json = json.dumps(detail or {}, sort_keys=True, separators=(",", ":"), default=str)
        with self._lock:
            last = self._db.execute("SELECT entry_hash FROM audit_log ORDER BY seq DESC LIMIT 1").fetchone()
            prev = last["entry_hash"] if last else GENESIS
            ts = utcnow()
            h = _entry_hash(prev, ts, actor, action, case_id, detail_json)
            self._db.execute(
                "INSERT INTO audit_log(ts,actor,action,case_id,detail_json,prev_hash,entry_hash) VALUES (?,?,?,?,?,?,?)",
                (ts, actor, action, case_id, detail_json, prev, h))
            self._db.commit()
        return h

    def audit_entries(self, case_id: str | None = None) -> list[sqlite3.Row]:
        with self._lock:
            if case_id:
                return self._db.execute("SELECT * FROM audit_log WHERE case_id=? ORDER BY seq", (case_id,)).fetchall()
            return self._db.execute("SELECT * FROM audit_log ORDER BY seq").fetchall()

    def verify_audit(self) -> tuple[bool, int, int | None]:
        """Return (intact, entries_checked, first_broken_seq)."""
        prev, n = GENESIS, 0
        for row in self.audit_entries():
            n += 1
            expect = _entry_hash(prev, row["ts"], row["actor"], row["action"], row["case_id"], row["detail_json"])
            if row["prev_hash"] != prev or row["entry_hash"] != expect:
                return False, n, row["seq"]
            prev = row["entry_hash"]
        return True, n, None

    def raw_execute(self, sql: str, params: tuple = ()) -> None:   # used by tests to simulate tampering
        with self._lock:
            self._db.execute(sql, params)
            self._db.commit()