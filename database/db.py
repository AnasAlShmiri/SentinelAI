"""
SentinelAI SQLite data layer.

Key rules:
- detections belong to a model run;
- analytics default to the latest run instead of silently aggregating all runs;
- model_runs can carry a stable run_key to make demo population idempotent.
"""

from __future__ import annotations

import os
import sqlite3
import sys
from datetime import datetime, timezone

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

DB_PATH = os.path.join(os.path.dirname(__file__), "sentinelai.db")


def get_connection(db_path=DB_PATH):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def _table_columns(conn, table_name):
    return {row["name"] for row in conn.execute(f"PRAGMA table_info({table_name})")}


def _ensure_column(conn, table_name, column_name, ddl):
    if column_name not in _table_columns(conn, table_name):
        conn.execute(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {ddl}")


def create_tables(conn):
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS model_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_timestamp TEXT NOT NULL,
            model_name TEXT NOT NULL,
            model_path TEXT NOT NULL,
            num_records INTEGER NOT NULL DEFAULT 0,
            notes TEXT
        );

        CREATE TABLE IF NOT EXISTS detections (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id INTEGER NOT NULL,
            timestamp TEXT NOT NULL,
            dst_port INTEGER,
            protocol INTEGER,
            flow_duration INTEGER,
            predicted_label_code INTEGER NOT NULL,
            predicted_attack_type TEXT NOT NULL,
            is_attack INTEGER NOT NULL,
            confidence REAL NOT NULL,
            risk_score REAL NOT NULL,
            true_label_code INTEGER,
            true_attack_type TEXT,
            FOREIGN KEY (run_id) REFERENCES model_runs(id)
        );
        """
    )

    # Lightweight migrations for databases created by earlier project versions.
    _ensure_column(conn, "model_runs", "run_key", "TEXT")
    _ensure_column(conn, "model_runs", "source_kind", "TEXT NOT NULL DEFAULT 'unknown'")
    _ensure_column(
        conn, "model_runs", "timestamps_simulated", "INTEGER NOT NULL DEFAULT 0"
    )

    conn.executescript(
        """
        CREATE UNIQUE INDEX IF NOT EXISTS idx_model_runs_run_key
            ON model_runs(run_key)
            WHERE run_key IS NOT NULL;

        CREATE INDEX IF NOT EXISTS idx_detections_run_id
            ON detections(run_id);

        CREATE INDEX IF NOT EXISTS idx_detections_attack_type
            ON detections(predicted_attack_type);

        CREATE INDEX IF NOT EXISTS idx_detections_timestamp
            ON detections(timestamp);

        CREATE INDEX IF NOT EXISTS idx_detections_is_attack
            ON detections(is_attack);
        """
    )
    conn.commit()


def insert_model_run(
    conn,
    model_name,
    model_path,
    num_records=0,
    notes=None,
    run_timestamp=None,
    run_key=None,
    source_kind="unknown",
    timestamps_simulated=False,
):
    run_timestamp = run_timestamp or datetime.now(timezone.utc).isoformat()
    cur = conn.execute(
        """
        INSERT INTO model_runs (
            run_timestamp, model_name, model_path, num_records, notes,
            run_key, source_kind, timestamps_simulated
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            run_timestamp,
            model_name,
            model_path,
            num_records,
            notes,
            run_key,
            source_kind,
            int(bool(timestamps_simulated)),
        ),
    )
    conn.commit()
    return cur.lastrowid


def get_model_run_by_key(conn, run_key):
    if not run_key:
        return None
    row = conn.execute(
        "SELECT * FROM model_runs WHERE run_key = ? LIMIT 1", (run_key,)
    ).fetchone()
    return dict(row) if row else None


def get_latest_run_id(conn):
    row = conn.execute(
        "SELECT id FROM model_runs ORDER BY run_timestamp DESC, id DESC LIMIT 1"
    ).fetchone()
    return int(row["id"]) if row else None


def delete_model_run(conn, run_id):
    conn.execute("DELETE FROM detections WHERE run_id = ?", (run_id,))
    conn.execute("DELETE FROM model_runs WHERE id = ?", (run_id,))
    conn.commit()


def insert_detection(
    conn,
    run_id,
    timestamp,
    predicted_label_code,
    predicted_attack_type,
    is_attack,
    confidence,
    risk_score,
    dst_port=None,
    protocol=None,
    flow_duration=None,
    true_label_code=None,
    true_attack_type=None,
):
    conn.execute(
        """
        INSERT INTO detections (
            run_id, timestamp, dst_port, protocol, flow_duration,
            predicted_label_code, predicted_attack_type, is_attack,
            confidence, risk_score, true_label_code, true_attack_type
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            run_id,
            timestamp,
            dst_port,
            protocol,
            flow_duration,
            predicted_label_code,
            predicted_attack_type,
            is_attack,
            confidence,
            risk_score,
            true_label_code,
            true_attack_type,
        ),
    )
    conn.commit()


def insert_detections_batch(conn, run_id, records):
    rows = [
        (
            run_id,
            r["timestamp"],
            r.get("dst_port"),
            r.get("protocol"),
            r.get("flow_duration"),
            r["predicted_label_code"],
            r["predicted_attack_type"],
            r["is_attack"],
            r["confidence"],
            r["risk_score"],
            r.get("true_label_code"),
            r.get("true_attack_type"),
        )
        for r in records
    ]

    conn.executemany(
        """
        INSERT INTO detections (
            run_id, timestamp, dst_port, protocol, flow_duration,
            predicted_label_code, predicted_attack_type, is_attack,
            confidence, risk_score, true_label_code, true_attack_type
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        rows,
    )
    conn.commit()


def _effective_run_id(conn, run_id=None):
    return int(run_id) if run_id is not None else get_latest_run_id(conn)


def query_by_attack_type(conn, attack_type, limit=100, run_id=None):
    run_id = _effective_run_id(conn, run_id)
    if run_id is None:
        return []
    cur = conn.execute(
        """
        SELECT * FROM detections
        WHERE run_id = ? AND predicted_attack_type = ?
        ORDER BY timestamp DESC
        LIMIT ?
        """,
        (run_id, attack_type, int(limit)),
    )
    return [dict(row) for row in cur.fetchall()]


def query_by_date_range(conn, start_date, end_date, limit=1000, run_id=None):
    run_id = _effective_run_id(conn, run_id)
    if run_id is None:
        return []
    cur = conn.execute(
        """
        SELECT * FROM detections
        WHERE run_id = ? AND timestamp BETWEEN ? AND ?
        ORDER BY timestamp
        LIMIT ?
        """,
        (run_id, start_date, end_date, int(limit)),
    )
    return [dict(row) for row in cur.fetchall()]


def query_top_attacks(conn, limit=10, run_id=None):
    run_id = _effective_run_id(conn, run_id)
    if run_id is None:
        return []
    cur = conn.execute(
        """
        SELECT predicted_attack_type, COUNT(*) AS count
        FROM detections
        WHERE run_id = ? AND is_attack = 1
        GROUP BY predicted_attack_type
        ORDER BY count DESC
        LIMIT ?
        """,
        (run_id, int(limit)),
    )
    return [dict(row) for row in cur.fetchall()]


def query_counts(conn, run_id=None):
    run_id = _effective_run_id(conn, run_id)
    if run_id is None:
        return []
    cur = conn.execute(
        """
        SELECT predicted_attack_type,
               COUNT(*) AS count,
               ROUND(AVG(confidence), 4) AS avg_confidence,
               ROUND(AVG(risk_score), 2) AS avg_risk_score
        FROM detections
        WHERE run_id = ?
        GROUP BY predicted_attack_type
        ORDER BY count DESC
        """,
        (run_id,),
    )
    return [dict(row) for row in cur.fetchall()]


def query_recent(conn, limit=20, run_id=None):
    run_id = _effective_run_id(conn, run_id)
    if run_id is None:
        return []
    cur = conn.execute(
        """
        SELECT * FROM detections
        WHERE run_id = ?
        ORDER BY id DESC
        LIMIT ?
        """,
        (run_id, int(limit)),
    )
    return [dict(row) for row in cur.fetchall()]


def query_high_risk(conn, min_risk_score=80, limit=100, run_id=None):
    run_id = _effective_run_id(conn, run_id)
    if run_id is None:
        return []
    cur = conn.execute(
        """
        SELECT * FROM detections
        WHERE run_id = ? AND risk_score >= ?
        ORDER BY risk_score DESC
        LIMIT ?
        """,
        (run_id, float(min_risk_score), int(limit)),
    )
    return [dict(row) for row in cur.fetchall()]


if __name__ == "__main__":
    conn = get_connection()
    create_tables(conn)
    print(f"Database ready: {DB_PATH}")
    conn.close()
