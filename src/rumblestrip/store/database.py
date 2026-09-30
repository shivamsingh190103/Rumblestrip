from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from rumblestrip.core.paths import state_home

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS sources(
 id INTEGER PRIMARY KEY, kind TEXT NOT NULL, path TEXT NOT NULL UNIQUE, session_id TEXT,
 repo_root TEXT, byte_offset INTEGER NOT NULL DEFAULT 0, size_seen INTEGER NOT NULL DEFAULT 0,
 mtime_ns INTEGER, first_line_hash TEXT, adapter_version TEXT, status TEXT NOT NULL DEFAULT 'active',
 last_error TEXT, updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS candidates(
 id INTEGER PRIMARY KEY, source_id INTEGER NOT NULL, repo_root TEXT NOT NULL, window_hash TEXT NOT NULL UNIQUE,
 cluster_id TEXT, signal TEXT NOT NULL, evidence_json TEXT NOT NULL, label_json TEXT,
 detector_version TEXT NOT NULL, state TEXT NOT NULL DEFAULT 'new', created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS proposals(
 id INTEGER PRIMARY KEY, candidate_id INTEGER NOT NULL UNIQUE, rule_json TEXT NOT NULL, check_kind TEXT NOT NULL,
 artifacts_json TEXT NOT NULL, validation_json TEXT NOT NULL, prompt_version TEXT NOT NULL DEFAULT 'heuristic-v1',
 model TEXT, state TEXT NOT NULL DEFAULT 'pending', decision_reason TEXT, decided_at TEXT, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS violations(
 id INTEGER PRIMARY KEY, repo_root TEXT NOT NULL, rule_id TEXT NOT NULL, file TEXT NOT NULL, line INTEGER,
 surface TEXT NOT NULL, severity TEXT NOT NULL, agent TEXT, session_ref TEXT, dedupe_key TEXT NOT NULL,
 suppressed INTEGER NOT NULL DEFAULT 0, verdict TEXT, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS jobs(
 id INTEGER PRIMARY KEY, kind TEXT NOT NULL, payload_json TEXT NOT NULL, state TEXT NOT NULL DEFAULT 'queued',
 attempts INTEGER NOT NULL DEFAULT 0, last_error TEXT, created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_candidates_state ON candidates(state);
CREATE INDEX IF NOT EXISTS idx_candidates_cluster ON candidates(repo_root, cluster_id);
CREATE INDEX IF NOT EXISTS idx_violations_rule ON violations(rule_id, created_at);
"""


def utc_now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


class StateDB:
    def __init__(self, home: Path | None = None) -> None:
        directory = home or state_home()
        try:
            directory.mkdir(parents=True, exist_ok=True)
        except PermissionError:
            # Sandboxed/portable environments sometimes expose a read-only user
            # profile. Keep the product usable without silently dropping state.
            directory = Path.cwd() / ".rumblestrip" / ".cache" / "local-state"
            directory.mkdir(parents=True, exist_ok=True)
        self.path = directory / "state.db"
        self.conn = self._connect(self.path)
        self._bootstrap()

    def _connect(self, path: Path) -> sqlite3.Connection:
        conn = sqlite3.connect(path, timeout=5)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=5000")
        return conn

    def _bootstrap(self) -> None:
        try:
            self.conn.executescript(SCHEMA)
            self.conn.execute("INSERT OR REPLACE INTO meta(key, value) VALUES ('schema_version', '1')")
            check = self.conn.execute("PRAGMA integrity_check").fetchone()
            if check and check[0] != "ok":
                raise sqlite3.DatabaseError(str(check[0]))
            self.conn.commit()
        except sqlite3.DatabaseError:
            backup = self.path.with_suffix(".db.corrupt")
            try:
                if backup.exists():
                    backup.unlink()
                self.path.replace(backup)
            except OSError:
                pass
            self.conn.close()
            self.conn = self._connect(self.path)
            self.conn.executescript(SCHEMA)
            self.conn.execute("INSERT OR REPLACE INTO meta(key, value) VALUES ('schema_version', '1')")
            self.conn.commit()

    def close(self) -> None:
        self.conn.close()

    def source(self, kind: str, path: Path, repo_root: Path) -> sqlite3.Row:
        row = self.conn.execute("SELECT * FROM sources WHERE path = ?", (str(path),)).fetchone()
        if row:
            return row
        now = utc_now()
        self.conn.execute(
            "INSERT INTO sources(kind,path,repo_root,updated_at) VALUES (?,?,?,?)",
            (kind, str(path), str(repo_root), now),
        )
        self.conn.commit()
        return self.conn.execute("SELECT * FROM sources WHERE path = ?", (str(path),)).fetchone()

    def update_source(self, source_id: int, offset: int, size: int, error: str | None = None) -> None:
        self.conn.execute(
            "UPDATE sources SET byte_offset=?,size_seen=?,last_error=?,status=?,updated_at=? WHERE id=?",
            (offset, size, error, "error" if error else "active", utc_now(), source_id),
        )
        self.conn.commit()

    def add_candidate(
        self,
        source_id: int,
        repo_root: Path,
        window_hash: str,
        evidence: dict[str, Any],
        signal: str,
        *,
        cluster_id: str | None = None,
        labels: dict[str, Any] | None = None,
    ) -> bool:
        if cluster_id:
            existing = self.conn.execute(
                "SELECT 1 FROM candidates WHERE repo_root=? AND cluster_id=? LIMIT 1",
                (str(repo_root), cluster_id),
            ).fetchone()
            if existing:
                return False
        try:
            self.conn.execute(
                "INSERT INTO candidates(source_id,repo_root,window_hash,cluster_id,signal,evidence_json,label_json,detector_version,created_at) VALUES (?,?,?,?,?,?,?,?,?)",
                (
                    source_id,
                    str(repo_root),
                    window_hash,
                    cluster_id,
                    signal,
                    json.dumps(evidence),
                    json.dumps(labels) if labels else None,
                    "heuristic-v2",
                    utc_now(),
                ),
            )
            self.conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False

    def candidates(self, repo_root: Path, state: str = "new") -> list[sqlite3.Row]:
        return list(self.conn.execute("SELECT * FROM candidates WHERE repo_root=? AND state=? ORDER BY id", (str(repo_root), state)))

    def candidate(self, candidate_id: int) -> sqlite3.Row | None:
        return self.conn.execute("SELECT * FROM candidates WHERE id=?", (candidate_id,)).fetchone()

    def update_candidate_state(self, candidate_id: int, state: str) -> None:
        self.conn.execute("UPDATE candidates SET state=? WHERE id=?", (state, candidate_id))
        self.conn.commit()

    def add_proposal(self, candidate_id: int, rule: dict[str, Any], kind: str, artifacts: dict[str, Any], validation: dict[str, Any]) -> bool:
        try:
            self.conn.execute(
                "INSERT INTO proposals(candidate_id,rule_json,check_kind,artifacts_json,validation_json,created_at) VALUES (?,?,?,?,?,?)",
                (candidate_id, json.dumps(rule), kind, json.dumps(artifacts), json.dumps(validation), utc_now()),
            )
            self.conn.execute("UPDATE candidates SET state='proposed' WHERE id=?", (candidate_id,))
            self.conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False

    def proposals(self, repo_root: Path, state: str = "pending") -> list[sqlite3.Row]:
        return list(self.conn.execute(
            "SELECT p.*,c.evidence_json FROM proposals p JOIN candidates c ON c.id=p.candidate_id WHERE c.repo_root=? AND p.state=? ORDER BY p.id",
            (str(repo_root), state),
        ))

    def proposal(self, proposal_id: int) -> sqlite3.Row | None:
        return self.conn.execute("SELECT * FROM proposals WHERE id=?", (proposal_id,)).fetchone()

    def decide_proposal(self, proposal_id: int, state: str, reason: str | None = None) -> None:
        self.conn.execute("UPDATE proposals SET state=?,decision_reason=?,decided_at=? WHERE id=?", (state, reason, utc_now(), proposal_id))
        self.conn.commit()

    def record_violations(self, root: Path, violations: list[Any], surface: str) -> None:
        now = utc_now()
        self.conn.executemany(
            "INSERT INTO violations(repo_root,rule_id,file,line,surface,severity,dedupe_key,suppressed,created_at) VALUES (?,?,?,?,?,?,?,?,?)",
            [(str(root), v.rule_id, v.file, v.line, surface, v.severity, v.fingerprint, int(v.suppressed), now) for v in violations],
        )
        self.conn.commit()

    def stats(self, root: Path) -> list[sqlite3.Row]:
        return list(self.conn.execute(
            "SELECT rule_id,COUNT(*) AS fires,SUM(CASE WHEN severity='error' THEN 1 ELSE 0 END) AS errors,SUM(CASE WHEN severity='warning' THEN 1 ELSE 0 END) AS warnings,SUM(CASE WHEN verdict='false_positive' THEN 1 ELSE 0 END) AS false_positives,MAX(created_at) AS last_seen FROM violations WHERE repo_root=? GROUP BY rule_id ORDER BY fires DESC",
            (str(root),),
        ))

    def purge(self) -> None:
        self.conn.executescript("DELETE FROM candidates; DELETE FROM proposals; DELETE FROM violations; DELETE FROM sources; DELETE FROM jobs;")
        self.conn.commit()
