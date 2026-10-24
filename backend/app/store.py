"""SQLite store (plain sqlite3). Each row keeps the full model as JSON plus indexed columns.

Other backend modules (AI, validation, remediation) should use the module-level
`store` instance: get_finding/update_finding, save_validation, save_fix/get_fix, etc.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Callable, Iterator

from . import config
from .models import (
    OPEN_STATUSES,
    Asset,
    AuditEntry,
    Event,
    Finding,
    Fix,
    ModeSettings,
    Scan,
    Validation,
    now_iso,
)

SCHEMA = """
CREATE TABLE IF NOT EXISTS assets (id TEXT PRIMARY KEY, created_at TEXT, data TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS scans (id TEXT PRIMARY KEY, asset_id TEXT, created_at TEXT, data TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS scans_asset ON scans(asset_id);
CREATE TABLE IF NOT EXISTS findings (
  id TEXT PRIMARY KEY, scan_id TEXT, asset_id TEXT, fingerprint TEXT,
  severity TEXT, status TEXT, tool TEXT, seq INTEGER, data TEXT NOT NULL,
  UNIQUE(asset_id, fingerprint)
);
CREATE INDEX IF NOT EXISTS findings_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS findings_seq ON findings(seq);
CREATE INDEX IF NOT EXISTS findings_asset_tool ON findings(asset_id, tool);
CREATE TABLE IF NOT EXISTS validations (id TEXT PRIMARY KEY, finding_id TEXT, data TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS fixes (id TEXT PRIMARY KEY, finding_id TEXT, created_at TEXT, data TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS audit (
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, actor TEXT, action TEXT,
  target TEXT, allowed INTEGER, details TEXT
);
CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, type TEXT, data TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS kv (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS posture_history (
  id INTEGER PRIMARY KEY AUTOINCREMENT, asset_id TEXT, ts TEXT, score INTEGER
);
CREATE INDEX IF NOT EXISTS posture_asset ON posture_history(asset_id);
"""

PRIORITY_ORDER = "CASE WHEN status IN ('fixed','not_reproduced') THEN 1 ELSE 0 END, COALESCE(json_extract(data,'$.priority'),0) DESC"
SEV_ORDER = "CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END"


class Store:
    def __init__(self, db_path: Path | str | None = None):
        self.db_path = str(db_path or config.DB_PATH)
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._tx_depth = 0  # >0 while a transaction() is open (on the lock-holding thread)
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.executescript(SCHEMA)
            self._conn.commit()

    # -- helpers -------------------------------------------------------------
    def _exec(self, sql: str, params: tuple | list = ()) -> sqlite3.Cursor:
        with self._lock:
            cur = self._conn.execute(sql, params)
            if not self._tx_depth:
                self._conn.commit()
            return cur

    @contextmanager
    def transaction(self) -> Iterator["Store"]:
        """Batch writes: one commit at the end, rollback on error. Re-entrant on the same thread."""
        with self._lock:
            self._tx_depth += 1
            try:
                yield self
            except BaseException:
                self._tx_depth -= 1
                if not self._tx_depth:
                    self._conn.rollback()
                raise
            self._tx_depth -= 1
            if not self._tx_depth:
                self._conn.commit()

    def _all(self, sql: str, params: tuple | list = ()) -> list[sqlite3.Row]:
        with self._lock:
            return self._conn.execute(sql, params).fetchall()

    def _one(self, sql: str, params: tuple | list = ()) -> sqlite3.Row | None:
        with self._lock:
            return self._conn.execute(sql, params).fetchone()

    # -- assets --------------------------------------------------------------
    def save_asset(self, a: Asset) -> Asset:
        self._exec(
            "INSERT OR REPLACE INTO assets (id, created_at, data) VALUES (?,?,?)",
            (a.id, a.created_at, a.model_dump_json()),
        )
        return a

    def get_asset(self, asset_id: str) -> Asset | None:
        r = self._one("SELECT data FROM assets WHERE id=?", (asset_id,))
        return Asset.model_validate_json(r["data"]) if r else None

    def find_asset(self, kind: str, ref: str) -> Asset | None:
        for a in self.list_assets():
            if a.kind == kind and a.ref == ref:
                return a
        return None

    def list_assets(self) -> list[Asset]:
        return [Asset.model_validate_json(r["data"]) for r in self._all("SELECT data FROM assets ORDER BY created_at")]

    # -- scans ---------------------------------------------------------------
    def save_scan(self, s: Scan) -> Scan:
        with self._lock:
            existing = self._one("SELECT created_at FROM scans WHERE id=?", (s.id,))
            created = existing["created_at"] if existing else now_iso()
            self._exec(
                "INSERT OR REPLACE INTO scans (id, asset_id, created_at, data) VALUES (?,?,?,?)",
                (s.id, s.asset_id, created, s.model_dump_json()),
            )
        return s

    def get_scan(self, scan_id: str) -> Scan | None:
        r = self._one("SELECT data FROM scans WHERE id=?", (scan_id,))
        return Scan.model_validate_json(r["data"]) if r else None

    def list_scans(self, asset_id: str | None = None) -> list[Scan]:
        if asset_id:
            rows = self._all("SELECT data FROM scans WHERE asset_id=? ORDER BY created_at DESC, rowid DESC", (asset_id,))
        else:
            rows = self._all("SELECT data FROM scans ORDER BY created_at DESC, rowid DESC")
        return [Scan.model_validate_json(r["data"]) for r in rows]

    # -- findings ------------------------------------------------------------
    @staticmethod
    def _merge(old: Finding, f: Finding) -> Finding:
        return f.model_copy(
            update={
                "id": old.id,
                "status": "open" if old.status == "fixed" else old.status,
                "validation": old.validation,
                "fix_id": old.fix_id,
                "ai_summary": old.ai_summary,
            }
        )

    def upsert_finding(self, f: Finding) -> tuple[Finding, bool]:
        """Dedupe by (asset_id, fingerprint). Returns (stored finding, is_new).

        A re-detected finding keeps its id, status, validation, fix_id and ai_summary;
        scan_id moves to the latest scan. A previously `fixed` finding that shows up
        again is re-opened.
        """
        return self.upsert_findings([f])[0]

    def upsert_findings(self, findings: list[Finding], adopt_legacy: bool = False) -> list[tuple[Finding, bool]]:
        """Batch upsert in one transaction. Returns [(stored, is_new)] in input order.

        adopt_legacy: a finding whose fingerprint is unknown takes over a not-fixed stored finding of
        the same asset/tool/rule/file whose fingerprint this batch no longer reports (nearest line
        first), keeping its id/status/validation/fix_id/ai_summary. Used once per asset+tool when the
        fingerprint scheme changes, so stored state survives the migration.
        """
        out: list[tuple[Finding, bool] | None] = [None] * len(findings)
        with self.transaction():
            pending: list[int] = []
            for i, f in enumerate(findings):
                r = self._one("SELECT data FROM findings WHERE asset_id=? AND fingerprint=?", (f.asset_id, f.fingerprint))
                if r:
                    merged = self._merge(Finding.model_validate_json(r["data"]), f)
                    self._write_finding(merged)
                    out[i] = (merged, False)
                else:
                    pending.append(i)
            if pending and adopt_legacy:
                reported = {(f.asset_id, f.fingerprint) for f in findings}
                pools: dict[tuple, list[Finding]] = {}
                for i in pending:
                    f = findings[i]
                    key = (f.asset_id, f.tool, f.rule_id, f.file)
                    if key in pools or not f.file:
                        continue
                    rows = self._all("SELECT data FROM findings WHERE asset_id=? AND tool=?", (f.asset_id, f.tool))
                    pools[key] = [
                        o for o in (Finding.model_validate_json(r["data"]) for r in rows)
                        if o.rule_id == f.rule_id and o.file == f.file and o.status != "fixed"
                        and (o.asset_id, o.fingerprint) not in reported
                    ]
                still: list[int] = []
                for i in pending:
                    f = findings[i]
                    pool = pools.get((f.asset_id, f.tool, f.rule_id, f.file)) or []
                    if not pool:
                        still.append(i)
                        continue
                    old = min(pool, key=lambda o: abs((o.line or 0) - (f.line or 0)))
                    pool.remove(old)
                    merged = self._merge(old, f)
                    self._write_finding(merged)
                    out[i] = (merged, False)
                pending = still
            for i in pending:
                self._write_finding(findings[i])
                out[i] = (findings[i], True)
        return out  # type: ignore[return-value]

    def resolve_missing(
        self, asset_id: str, tool: str, seen: set[str], keep: Callable[[Finding], bool] | None = None,
    ) -> int:
        """After a *complete* run of `tool`: findings it no longer reports become `fixed`, in one
        transaction. `keep(f)` -> True leaves a finding untouched (excluded path, file the run could
        not analyze). Superseded pre-grouping per-advisory dependency records are dropped instead
        of counted as fixed. Returns how many were marked fixed."""
        resolved = 0
        with self.transaction():
            for f in self.list_findings(asset_id=asset_id, tool=tool):
                if f.fingerprint in seen or (keep and keep(f)):
                    continue
                if f.category == "dependency" and not f.advisories and not f.fix_id:
                    self.delete_finding(f.id)
                    continue
                if f.status != "fixed":
                    f.status = "fixed"
                    self._write_finding(f)
                    resolved += 1
        return resolved

    def _write_finding(self, f: Finding) -> None:
        from .focus import priority  # local import: focus -> models only, but keep store import-light

        f.priority = priority(f)
        seq_row = self._one("SELECT seq FROM findings WHERE id=?", (f.id,))
        seq = seq_row["seq"] if seq_row else (self._one("SELECT COALESCE(MAX(seq),0)+1 AS n FROM findings")["n"])
        self._exec(
            "INSERT OR REPLACE INTO findings (id, scan_id, asset_id, fingerprint, severity, status, tool, seq, data)"
            " VALUES (?,?,?,?,?,?,?,?,?)",
            (f.id, f.scan_id, f.asset_id, f.fingerprint, f.severity, f.status, f.tool, seq, f.model_dump_json()),
        )

    def get_finding(self, finding_id: str) -> Finding | None:
        r = self._one("SELECT data FROM findings WHERE id=?", (finding_id,))
        return Finding.model_validate_json(r["data"]) if r else None

    def update_finding(self, finding_id: str, **fields: Any) -> Finding | None:
        with self._lock:
            f = self.get_finding(finding_id)
            if not f:
                return None
            f = Finding.model_validate({**f.model_dump(), **fields})
            self._write_finding(f)
            return f

    def list_findings(
        self,
        scan_id: str | None = None,
        asset_id: str | None = None,
        severity: str | None = None,
        status: str | None = None,
        tool: str | None = None,
        component: str | None = None,
        sort: str = "priority",
    ) -> list[Finding]:
        """sort: "priority" (default; open first, then priority desc) or "severity" (legacy).
        component: comma list of "main", "periphery", "lab" (any lab sub-app) or "lab:<dir>"."""
        where, params = [], []
        for col, val in (("scan_id", scan_id), ("asset_id", asset_id), ("severity", severity), ("status", status), ("tool", tool)):
            if val:
                vals = val.split(",")
                where.append(f"{col} IN ({','.join('?' * len(vals))})")
                params.extend(vals)
        sql = "SELECT data FROM findings"
        if where:
            sql += " WHERE " + " AND ".join(where)
        order = SEV_ORDER if sort == "severity" else f"{PRIORITY_ORDER}, {SEV_ORDER}"
        sql += f" ORDER BY {order}, seq"
        out = [Finding.model_validate_json(r["data"]) for r in self._all(sql, params)]
        if component:
            want = [c.strip() for c in component.split(",") if c.strip()]
            out = [f for f in out if any(f.component == c or (c == "lab" and f.component.startswith("lab:")) for c in want)]
        return out

    def list_open_findings(self, asset_id: str | None = None, **filters: Any) -> list[Finding]:
        """Exactly what posture counts as open: list_findings(status="open,validated,fixing").

        Posture's counts are a severity tally of this list, so GET /findings with the same asset and
        status filter always shows the same numbers (lab sub-apps included)."""
        return self.list_findings(asset_id=asset_id, status=",".join(OPEN_STATUSES), **filters)

    def delete_finding(self, finding_id: str) -> None:
        self._exec("DELETE FROM findings WHERE id=?", (finding_id,))

    # -- validations / fixes (used by the AI/remediation module) -------------
    def save_validation(self, v: Validation) -> Validation:
        self._exec(
            "INSERT OR REPLACE INTO validations (id, finding_id, data) VALUES (?,?,?)",
            (v.id, v.finding_id, v.model_dump_json()),
        )
        return v

    def get_validation(self, validation_id: str) -> Validation | None:
        r = self._one("SELECT data FROM validations WHERE id=?", (validation_id,))
        return Validation.model_validate_json(r["data"]) if r else None

    def save_fix(self, fx: Fix) -> Fix:
        self._exec(
            "INSERT OR REPLACE INTO fixes (id, finding_id, created_at, data) VALUES (?,?,?,?)",
            (fx.id, fx.finding_id, fx.created_at, fx.model_dump_json()),
        )
        return fx

    def get_fix(self, fix_id: str) -> Fix | None:
        r = self._one("SELECT data FROM fixes WHERE id=?", (fix_id,))
        return Fix.model_validate_json(r["data"]) if r else None

    def list_fixes(self, finding_id: str | None = None) -> list[Fix]:
        if finding_id:
            rows = self._all("SELECT data FROM fixes WHERE finding_id=? ORDER BY created_at DESC", (finding_id,))
        else:
            rows = self._all("SELECT data FROM fixes ORDER BY created_at DESC")
        return [Fix.model_validate_json(r["data"]) for r in rows]

    # -- audit ---------------------------------------------------------------
    def add_audit(self, e: AuditEntry) -> AuditEntry:
        cur = self._exec(
            "INSERT INTO audit (ts, actor, action, target, allowed, details) VALUES (?,?,?,?,?,?)",
            (e.ts, e.actor, e.action, e.target, int(e.allowed), json.dumps(e.details) if e.details is not None else None),
        )
        e.id = cur.lastrowid
        return e

    def list_audit(self, limit: int = 100) -> list[AuditEntry]:
        rows = self._all("SELECT * FROM audit ORDER BY id DESC LIMIT ?", (limit,))
        return [
            AuditEntry(
                id=r["id"], ts=r["ts"], actor=r["actor"], action=r["action"], target=r["target"],
                allowed=bool(r["allowed"]), details=json.loads(r["details"]) if r["details"] else None,
            )
            for r in rows
        ]

    # -- events --------------------------------------------------------------
    def add_event(self, ev: Event) -> None:
        self._exec("INSERT INTO events (ts, type, data) VALUES (?,?,?)", (ev.ts, ev.type, ev.model_dump_json()))

    def recent_events(self, limit: int = 100) -> list[Event]:
        rows = self._all("SELECT data FROM events ORDER BY id DESC LIMIT ?", (limit,))
        return [Event.model_validate_json(r["data"]) for r in reversed(rows)]

    # -- kv / mode -----------------------------------------------------------
    def get_kv(self, key: str) -> str | None:
        r = self._one("SELECT value FROM kv WHERE key=?", (key,))
        return r["value"] if r else None

    def set_kv(self, key: str, value: str) -> None:
        self._exec("INSERT OR REPLACE INTO kv (key, value) VALUES (?,?)", (key, value))

    def get_mode(self) -> ModeSettings:
        raw = self.get_kv("mode")
        return ModeSettings.model_validate_json(raw) if raw else ModeSettings()

    def set_mode(self, m: ModeSettings) -> ModeSettings:
        self.set_kv("mode", m.model_dump_json())
        return m

    # -- posture history -----------------------------------------------------
    def add_posture_point(self, asset_id: str | None, score: int, ts: str | None = None) -> None:
        self._exec(
            "INSERT INTO posture_history (asset_id, ts, score) VALUES (?,?,?)",
            (asset_id or "*", ts or now_iso(), score),
        )

    def posture_history(self, asset_id: str | None, limit: int = 50) -> list[dict]:
        rows = self._all(
            "SELECT ts, score FROM posture_history WHERE asset_id=? ORDER BY id DESC LIMIT ?",
            (asset_id or "*", limit),
        )
        return [{"ts": r["ts"], "score": r["score"]} for r in reversed(rows)]


_store: Store | None = None


def get_store() -> Store:
    global _store
    if _store is None:
        config.ensure_dirs()
        _store = Store()
    return _store


def set_store(s: Store) -> None:
    """Tests: swap in a temp-file store."""
    global _store
    _store = s
