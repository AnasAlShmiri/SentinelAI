"""
Populate SentinelAI's SQLite database from the saved test set.

The script is idempotent by default: the same demo test-set batch is not inserted
again silently. Use --replace to intentionally replace that batch.

The processed arrays do not contain original capture timestamps. This script
therefore generates simulated timestamps and records that fact in model_runs.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import joblib
import numpy as np

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

sys.path.insert(0, os.path.dirname(__file__))
import db  # noqa: E402

BASE_DIR = Path(__file__).resolve().parent.parent
PROCESSED_DIR = BASE_DIR / "data" / "processed"
MODELS_DIR = BASE_DIR / "models"

TIME_WINDOW_DAYS = 7
DEFAULT_RUN_KEY = "demo:test-set:v2"


def compute_risk_score(is_attack, confidence):
    """Legacy confidence-based indicator retained for dashboard compatibility."""
    confidence = min(max(float(confidence), 0.0), 1.0)
    if is_attack:
        return round(confidence * 100, 2)
    return round((1.0 - confidence) * 20, 2)


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--replace",
        action="store_true",
        help="Delete the previous demo run with the same run key before inserting.",
    )
    parser.add_argument(
        "--run-key",
        default=DEFAULT_RUN_KEY,
        help="Stable key used to prevent accidental duplicate demo population.",
    )
    return parser.parse_args()


def required(path: Path):
    if not path.exists():
        raise FileNotFoundError(f"Required local artifact not found: {path}")
    return path


def main():
    args = parse_args()

    x_path = required(PROCESSED_DIR / "X_test.npy")
    y_path = required(PROCESSED_DIR / "y_test.npy")
    feature_path = required(PROCESSED_DIR / "feature_names.json")
    mapping_path = required(PROCESSED_DIR / "label_mapping.json")
    scaler_path = required(PROCESSED_DIR / "scaler.joblib")
    model_path = required(MODELS_DIR / "best_model.joblib")
    encoder_path = required(MODELS_DIR / "best_model_label_encoder.joblib")

    print("Loading test data and model...")
    X_test = np.load(x_path)
    y_test = np.load(y_path)

    with feature_path.open(encoding="utf-8") as f:
        feature_names = json.load(f)
    with mapping_path.open(encoding="utf-8") as f:
        label_mapping = {int(k): v for k, v in json.load(f).items()}

    scaler = joblib.load(scaler_path)
    model = joblib.load(model_path)
    label_encoder = joblib.load(encoder_path)

    conn = db.get_connection()
    db.create_tables(conn)

    existing = db.get_model_run_by_key(conn, args.run_key)
    if existing and not args.replace:
        print(
            f"Demo batch already exists as run_id={existing['id']} "
            f"(run_key={args.run_key}). Nothing was inserted."
        )
        print("Use --replace only if you intentionally want to rebuild that batch.")
        conn.close()
        return

    if existing and args.replace:
        print(f"Replacing previous run_id={existing['id']}...")
        db.delete_model_run(conn, existing["id"])

    print(f"Test rows: {X_test.shape[0]:,}")

    # Recover a few human-readable raw values for the dashboard.
    X_test_original = scaler.inverse_transform(X_test)
    dst_port_idx = feature_names.index("Dst Port")
    protocol_idx = feature_names.index("Protocol")
    flow_duration_idx = feature_names.index("Flow Duration")

    dst_ports = np.rint(X_test_original[:, dst_port_idx]).astype(int)
    protocols = np.rint(X_test_original[:, protocol_idx]).astype(int)
    flow_durations = np.rint(X_test_original[:, flow_duration_idx]).astype(int)

    print("Running predict_proba...")
    pred_proba = model.predict_proba(X_test)
    pred_encoded = np.argmax(pred_proba, axis=1)
    confidences = pred_proba[np.arange(len(pred_encoded)), pred_encoded]
    pred_codes = label_encoder.inverse_transform(pred_encoded)

    # Simulated presentation timestamps only.
    now = datetime.now(timezone.utc)
    window_seconds = TIME_WINDOW_DAYS * 24 * 3600
    start_time = now - timedelta(seconds=window_seconds)
    offsets = np.linspace(0, window_seconds, num=len(pred_codes))
    timestamps = [
        (start_time + timedelta(seconds=float(off))).isoformat() for off in offsets
    ]

    run_id = db.insert_model_run(
        conn,
        model_name="XGBoost (Tuned) - best_model.joblib",
        model_path="models/best_model.joblib",
        num_records=len(pred_codes),
        notes=(
            "Demo/test-set inference batch. Classification outputs come from the trained "
            "model; timestamps are simulated because original per-row capture timestamps "
            "are not present in the processed arrays. risk_score is confidence-based only."
        ),
        run_key=args.run_key,
        source_kind="saved_test_set",
        timestamps_simulated=True,
    )

    records = []
    for i in range(len(pred_codes)):
        pred_code = int(pred_codes[i])
        true_code = int(y_test[i])
        is_attack = pred_code != 1
        confidence = float(confidences[i])

        records.append(
            {
                "timestamp": timestamps[i],
                "dst_port": int(dst_ports[i]),
                "protocol": int(protocols[i]),
                "flow_duration": int(flow_durations[i]),
                "predicted_label_code": pred_code,
                "predicted_attack_type": label_mapping.get(
                    pred_code, f"Class_{pred_code}"
                ),
                "is_attack": int(is_attack),
                "confidence": round(confidence, 4),
                "risk_score": compute_risk_score(is_attack, confidence),
                "true_label_code": true_code,
                "true_attack_type": label_mapping.get(
                    true_code, f"Class_{true_code}"
                ),
            }
        )

    print(f"Inserting {len(records):,} detections as run_id={run_id}...")
    db.insert_detections_batch(conn, run_id, records)
    conn.close()

    print("Done.")
    print(f"Database: {db.DB_PATH}")
    print(f"run_key: {args.run_key}")
    print("timestamps_simulated: true")


if __name__ == "__main__":
    main()
