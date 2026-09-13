"""
SentinelAI - وحدة قاعدة البيانات (SQLite)

تخزّن هذه القاعدة نتائج الكشف (Detections) التي ينتجها أفضل نموذج مدرَّب
(models/best_model.joblib)، ليستخدمها لاحقاً الوكيل الذكي للاستعلام باللغة الطبيعية.

الجداول:
- model_runs: كل عملية تشغيل للنموذج (متى، أي نموذج، كم سجلاً أنتجت).
- detections: كل سجل اكتشاف على حدة (تصنيف متوقَّع، ثقة النموذج، درجة الخطورة...).
"""

import os
import sys
import sqlite3
from datetime import datetime, timezone

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

DB_PATH = os.path.join(os.path.dirname(__file__), "sentinelai.db")


def get_connection(db_path=DB_PATH):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def create_tables(conn):
    conn.executescript("""
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

    CREATE INDEX IF NOT EXISTS idx_detections_attack_type ON detections(predicted_attack_type);
    CREATE INDEX IF NOT EXISTS idx_detections_timestamp ON detections(timestamp);
    CREATE INDEX IF NOT EXISTS idx_detections_is_attack ON detections(is_attack);
    """)
    conn.commit()


def insert_model_run(conn, model_name, model_path, num_records=0, notes=None, run_timestamp=None):
    run_timestamp = run_timestamp or datetime.now(timezone.utc).isoformat()
    cur = conn.execute(
        "INSERT INTO model_runs (run_timestamp, model_name, model_path, num_records, notes) "
        "VALUES (?, ?, ?, ?, ?)",
        (run_timestamp, model_name, model_path, num_records, notes),
    )
    conn.commit()
    return cur.lastrowid


def insert_detection(conn, run_id, timestamp, predicted_label_code, predicted_attack_type,
                      is_attack, confidence, risk_score, dst_port=None, protocol=None,
                      flow_duration=None, true_label_code=None, true_attack_type=None):
    conn.execute("""
        INSERT INTO detections (
            run_id, timestamp, dst_port, protocol, flow_duration,
            predicted_label_code, predicted_attack_type, is_attack,
            confidence, risk_score, true_label_code, true_attack_type
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (run_id, timestamp, dst_port, protocol, flow_duration,
          predicted_label_code, predicted_attack_type, is_attack,
          confidence, risk_score, true_label_code, true_attack_type))
    conn.commit()


def insert_detections_batch(conn, run_id, records):
    """إدخال دفعة سجلات دفعة واحدة (أسرع بكثير من استدعاء insert_detection في حلقة).

    records: قائمة قواميس، كل قاموس بنفس مفاتيح insert_detection (بدون run_id)."""
    rows = [
        (
            run_id, r["timestamp"], r.get("dst_port"), r.get("protocol"), r.get("flow_duration"),
            r["predicted_label_code"], r["predicted_attack_type"], r["is_attack"],
            r["confidence"], r["risk_score"], r.get("true_label_code"), r.get("true_attack_type"),
        )
        for r in records
    ]
    conn.executemany("""
        INSERT INTO detections (
            run_id, timestamp, dst_port, protocol, flow_duration,
            predicted_label_code, predicted_attack_type, is_attack,
            confidence, risk_score, true_label_code, true_attack_type
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, rows)
    conn.commit()


def query_by_attack_type(conn, attack_type, limit=100):
    cur = conn.execute(
        "SELECT * FROM detections WHERE predicted_attack_type = ? ORDER BY timestamp DESC LIMIT ?",
        (attack_type, limit),
    )
    return [dict(row) for row in cur.fetchall()]


def query_by_date_range(conn, start_date, end_date, limit=1000):
    """start_date/end_date: نصوص ISO (مثال: '2026-09-01T00:00:00+00:00')."""
    cur = conn.execute(
        "SELECT * FROM detections WHERE timestamp BETWEEN ? AND ? ORDER BY timestamp LIMIT ?",
        (start_date, end_date, limit),
    )
    return [dict(row) for row in cur.fetchall()]


def query_top_attacks(conn, limit=10):
    """أكثر أنواع الهجمات تكراراً (يستبعد Benign)."""
    cur = conn.execute("""
        SELECT predicted_attack_type, COUNT(*) AS count
        FROM detections
        WHERE is_attack = 1
        GROUP BY predicted_attack_type
        ORDER BY count DESC
        LIMIT ?
    """, (limit,))
    return [dict(row) for row in cur.fetchall()]


def query_counts(conn):
    """عدد السجلات ومتوسط الثقة/الخطورة لكل نوع تصنيف (يشمل Benign)."""
    cur = conn.execute("""
        SELECT predicted_attack_type,
               COUNT(*) AS count,
               ROUND(AVG(confidence), 4) AS avg_confidence,
               ROUND(AVG(risk_score), 2) AS avg_risk_score
        FROM detections
        GROUP BY predicted_attack_type
        ORDER BY count DESC
    """)
    return [dict(row) for row in cur.fetchall()]


def query_recent(conn, limit=20):
    cur = conn.execute("SELECT * FROM detections ORDER BY id DESC LIMIT ?", (limit,))
    return [dict(row) for row in cur.fetchall()]


def query_high_risk(conn, min_risk_score=80, limit=100):
    cur = conn.execute(
        "SELECT * FROM detections WHERE risk_score >= ? ORDER BY risk_score DESC LIMIT ?",
        (min_risk_score, limit),
    )
    return [dict(row) for row in cur.fetchall()]


if __name__ == "__main__":
    conn = get_connection()
    create_tables(conn)
    print(f"قاعدة البيانات جاهزة في: {DB_PATH}")
    conn.close()
