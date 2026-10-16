"""On-disk state: jobs, queue and benchmark results, backed by SQLite.

Uses only the standard library so the whole tool stays dependency-free.
"""

from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

SCHEMA = """
CREATE TABLE IF NOT EXISTS jobs (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    name          TEXT NOT NULL,
    session       TEXT NOT NULL,
    status        TEXT NOT NULL DEFAULT 'created',
    mode          INTEGER,
    attack_mode   INTEGER,
    cmd           TEXT NOT NULL,
    hashfile      TEXT,
    outfile       TEXT,
    restore_file  TEXT,
    log_file      TEXT,
    created_at    REAL NOT NULL,
    started_at    REAL,
    ended_at      REAL,
    exit_code     INTEGER,
    recovered     INTEGER DEFAULT 0,
    total         INTEGER DEFAULT 0,
    speed         REAL DEFAULT 0,
    progress_pct  REAL DEFAULT 0,
    queued        INTEGER DEFAULT 0,
    note          TEXT
);

CREATE TABLE IF NOT EXISTS benchmarks (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    mode       INTEGER NOT NULL,
    name       TEXT,
    speed      REAL NOT NULL,
    device     TEXT,
    created_at REAL NOT NULL
);
"""


class Store:
    def __init__(self, db_path: Path):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(self.db_path))
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()

    # --- jobs ------------------------------------------------------------
    def create_job(self, **fields: Any) -> int:
        fields.setdefault("created_at", time.time())
        fields.setdefault("status", "created")
        if isinstance(fields.get("cmd"), (list, tuple)):
            fields["cmd"] = json.dumps(list(fields["cmd"]))
        cols = ", ".join(fields.keys())
        ph = ", ".join("?" for _ in fields)
        cur = self.conn.execute(
            f"INSERT INTO jobs ({cols}) VALUES ({ph})", tuple(fields.values())
        )
        self.conn.commit()
        return int(cur.lastrowid)

    def update_job(self, job_id: int, **fields: Any) -> None:
        if not fields:
            return
        if isinstance(fields.get("cmd"), (list, tuple)):
            fields["cmd"] = json.dumps(list(fields["cmd"]))
        sets = ", ".join(f"{k} = ?" for k in fields)
        self.conn.execute(
            f"UPDATE jobs SET {sets} WHERE id = ?",
            (*fields.values(), job_id),
        )
        self.conn.commit()

    def get_job(self, job_id: int) -> Optional[Dict[str, Any]]:
        row = self.conn.execute("SELECT * FROM jobs WHERE id = ?", (job_id,)).fetchone()
        return self._row(row)

    def list_jobs(self, limit: int = 50, queued: Optional[bool] = None) -> List[Dict[str, Any]]:
        q = "SELECT * FROM jobs"
        args: list = []
        if queued is not None:
            q += " WHERE queued = ?"
            args.append(1 if queued else 0)
        q += " ORDER BY id DESC LIMIT ?"
        args.append(limit)
        return [self._row(r) for r in self.conn.execute(q, args).fetchall()]

    def next_queued(self) -> Optional[Dict[str, Any]]:
        row = self.conn.execute(
            "SELECT * FROM jobs WHERE queued = 1 AND status IN ('created','queued') "
            "ORDER BY id ASC LIMIT 1"
        ).fetchone()
        return self._row(row)

    def delete_job(self, job_id: int) -> None:
        self.conn.execute("DELETE FROM jobs WHERE id = ?", (job_id,))
        self.conn.commit()

    # --- benchmarks ------------------------------------------------------
    def add_benchmark(self, mode: int, name: str, speed: float, device: str) -> None:
        self.conn.execute(
            "INSERT INTO benchmarks (mode, name, speed, device, created_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (mode, name, speed, device, time.time()),
        )
        self.conn.commit()

    def latest_benchmark(self, mode: int) -> Optional[Dict[str, Any]]:
        row = self.conn.execute(
            "SELECT * FROM benchmarks WHERE mode = ? ORDER BY id DESC LIMIT 1", (mode,)
        ).fetchone()
        return self._row(row)

    def list_benchmarks(self, limit: int = 50) -> List[Dict[str, Any]]:
        return [
            self._row(r)
            for r in self.conn.execute(
                "SELECT * FROM benchmarks ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        ]

    # --- helpers ---------------------------------------------------------
    @staticmethod
    def _row(row: Optional[sqlite3.Row]) -> Optional[Dict[str, Any]]:
        if row is None:
            return None
        d = dict(row)
        if d.get("cmd"):
            try:
                d["cmd"] = json.loads(d["cmd"])
            except (ValueError, TypeError):
                pass
        return d
