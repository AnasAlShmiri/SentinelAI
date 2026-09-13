"""
SentinelAI agent tools.

The agent can:
1) classify one network-flow feature vector with the trained classifier;
2) query predefined SQLite analytics.

This module intentionally exposes no raw-SQL tool and no offensive action tool.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd

BASE_DIR = Path(__file__).resolve().parent.parent
DATABASE_DIR = BASE_DIR / "database"
MODELS_DIR = BASE_DIR / "models"
PROCESSED_DIR = BASE_DIR / "data" / "processed"

if str(DATABASE_DIR) not in sys.path:
    sys.path.insert(0, str(DATABASE_DIR))
import db  # noqa: E402

_model = None
_label_encoder = None
_scaler = None
_feature_names = None
_label_mapping = None
_X_test = None
_y_test = None


def _required_path(path: Path, purpose: str) -> Path:
    if not path.exists():
        raise FileNotFoundError(
            f"Missing {purpose}: {path}. "
            "Restore the local trained/processed artifact before using classification."
        )
    return path


def _lazy_load() -> None:
    """Load core runtime artifacts once. Test arrays remain optional."""
    global _model, _label_encoder, _scaler, _feature_names, _label_mapping, _X_test, _y_test
    if _model is not None:
        return

    model_path = _required_path(MODELS_DIR / "best_model.joblib", "trained model")
    encoder_path = _required_path(
        MODELS_DIR / "best_model_label_encoder.joblib", "model label encoder"
    )
    scaler_path = _required_path(PROCESSED_DIR / "scaler.joblib", "training scaler")
    features_path = _required_path(PROCESSED_DIR / "feature_names.json", "feature metadata")
    mapping_path = _required_path(PROCESSED_DIR / "label_mapping.json", "label mapping")

    _model = joblib.load(model_path)
    _label_encoder = joblib.load(encoder_path)
    _scaler = joblib.load(scaler_path)

    with features_path.open(encoding="utf-8") as f:
        _feature_names = json.load(f)

    with mapping_path.open(encoding="utf-8") as f:
        _label_mapping = {int(k): v for k, v in json.load(f).items()}

    x_test_path = PROCESSED_DIR / "X_test.npy"
    y_test_path = PROCESSED_DIR / "y_test.npy"
    if x_test_path.exists() and y_test_path.exists():
        _X_test = np.load(x_test_path, mmap_mode="r")
        _y_test = np.load(y_test_path, mmap_mode="r")


def compute_risk_score(is_attack: bool, confidence: float) -> float:
    """Legacy confidence-based indicator retained for dashboard compatibility.

    This is not a validated severity score. It only combines the selected class
    (attack/benign) with model confidence.
    """
    confidence = min(max(float(confidence), 0.0), 1.0)
    if is_attack:
        return round(confidence * 100, 2)
    return round((1.0 - confidence) * 20, 2)


def _raw_baseline() -> np.ndarray:
    """Return a reasonable raw-value baseline for omitted custom features.

    StandardScaler.mean_ is in the original feature space. Starting from that
    vector means an omitted feature becomes approximately zero after scaling,
    instead of pretending the real raw value was literally zero.
    """
    n_features = len(_feature_names)
    means = getattr(_scaler, "mean_", None)
    if means is not None and len(means) == n_features:
        return np.asarray(means, dtype=float).reshape(1, -1).copy()
    return np.zeros((1, n_features), dtype=float)


def _label_name(code: int) -> str:
    return _label_mapping.get(code, f"Class_{code}")


def classify_network_flow(sample_index=None, features=None) -> dict[str, Any]:
    """Classify one network flow.

    Exactly one input mode should be used:
    - sample_index: local saved test row (requires X_test.npy and y_test.npy)
    - features: raw custom features keyed by feature name

    Custom partial dictionaries use the scaler training mean for omitted values.
    """
    _lazy_load()

    using_sample = sample_index is not None
    using_features = bool(features)

    if using_sample == using_features:
        return {"error": "حدد sample_index أو features فقط، وليس الاثنين معاً."}

    true_label = None
    warnings = []

    if using_sample:
        if _X_test is None or _y_test is None:
            return {
                "error": (
                    "sample_index غير متاح لأن X_test.npy/y_test.npy غير موجودين محلياً. "
                    "استخدم features أو أعد ملفات الاختبار."
                )
            }

        try:
            idx = int(sample_index)
        except (TypeError, ValueError):
            return {"error": "sample_index يجب أن يكون رقماً صحيحاً."}

        if idx < 0 or idx >= _X_test.shape[0]:
            return {"error": f"sample_index يجب أن يكون بين 0 و {_X_test.shape[0] - 1}"}

        x_scaled = np.asarray(_X_test[idx : idx + 1])
        true_code = int(_y_test[idx])
        true_label = _label_name(true_code)

    else:
        raw_row = _raw_baseline()
        feature_index = {name: i for i, name in enumerate(_feature_names)}
        unknown_features = []
        invalid_features = []

        for name, value in features.items():
            if name not in feature_index:
                unknown_features.append(name)
                continue
            try:
                numeric_value = float(value)
            except (TypeError, ValueError):
                invalid_features.append(name)
                continue
            if not np.isfinite(numeric_value):
                invalid_features.append(name)
                continue
            raw_row[0, feature_index[name]] = numeric_value

        if invalid_features:
            return {
                "error": f"قيم غير رقمية/غير محدودة للخصائص: {sorted(invalid_features)}"
            }

        raw_df = pd.DataFrame(raw_row, columns=_feature_names)
        x_scaled = _scaler.transform(raw_df)

        supplied_known = len(features) - len(unknown_features)
        missing_count = max(len(_feature_names) - supplied_known, 0)
        if missing_count:
            warnings.append(
                f"{missing_count} خاصية غير مرسلة تم تعويضها بمتوسط التدريب قبل StandardScaler."
            )
        if unknown_features:
            warnings.append(f"خصائص غير معروفة تم تجاهلها: {sorted(unknown_features)}")

    proba = np.asarray(_model.predict_proba(x_scaled))[0]
    pred_encoded = int(np.argmax(proba))
    confidence = float(proba[pred_encoded])
    pred_code = int(_label_encoder.inverse_transform([pred_encoded])[0])
    pred_label = _label_name(pred_code)
    is_attack = pred_code != 1

    result = {
        "predicted_attack_type": pred_label,
        "predicted_label_code": pred_code,
        "confidence": round(confidence, 4),
        "confidence_percent": round(confidence * 100, 2),
        "is_attack": is_attack,
        "risk_score": compute_risk_score(is_attack, confidence),
        "risk_basis": "confidence_only",
        "label_mapping_resolved": not pred_label.startswith("Attack_"),
    }

    if true_label is not None:
        result["true_attack_type"] = true_label
        result["prediction_correct"] = true_label == pred_label

    if warnings:
        result["warnings"] = warnings

    return result


def query_database(query_type, **kwargs):
    """Run one predefined analytics query; the agent never receives raw SQL."""
    conn = db.get_connection()
    try:
        run_id = kwargs.get("run_id")
        if query_type == "by_attack_type":
            rows = db.query_by_attack_type(
                conn,
                kwargs.get("attack_type", ""),
                limit=kwargs.get("limit", 20),
                run_id=run_id,
            )
        elif query_type == "top_attacks":
            rows = db.query_top_attacks(
                conn, limit=kwargs.get("limit", 10), run_id=run_id
            )
        elif query_type == "counts":
            rows = db.query_counts(conn, run_id=run_id)
        elif query_type == "recent":
            rows = db.query_recent(
                conn, limit=kwargs.get("limit", 20), run_id=run_id
            )
        elif query_type == "high_risk":
            rows = db.query_high_risk(
                conn,
                min_risk_score=kwargs.get("min_risk_score", 80),
                limit=kwargs.get("limit", 20),
                run_id=run_id,
            )
        elif query_type == "by_date_range":
            rows = db.query_by_date_range(
                conn,
                kwargs["start_date"],
                kwargs["end_date"],
                limit=kwargs.get("limit", 100),
                run_id=run_id,
            )
        else:
            return {"error": f"query_type غير معروف: {query_type}"}

        effective_run_id = run_id if run_id is not None else db.get_latest_run_id(conn)
        return {
            "rows": rows,
            "count": len(rows),
            "run_id": effective_run_id,
            "scope": "requested_run" if run_id is not None else "latest_run",
        }
    finally:
        conn.close()


TOOLS_SCHEMA = [
    {
        "type": "function",
        "function": {
            "name": "query_database",
            "description": (
                "استعلام دفاعي عن سجلات وإحصائيات الاكتشاف المخزنة في SQLite. "
                "إذا لم يحدد run_id تستخدم الاستعلامات أحدث تشغيل فقط لتجنب جمع دفعات مستقلة."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "query_type": {
                        "type": "string",
                        "enum": [
                            "by_attack_type",
                            "top_attacks",
                            "counts",
                            "recent",
                            "high_risk",
                            "by_date_range",
                        ],
                    },
                    "attack_type": {"type": "string"},
                    "limit": {"type": "integer"},
                    "min_risk_score": {
                        "type": "number",
                        "description": "مؤشر confidence-based قديم، وليس severity حقيقية.",
                    },
                    "start_date": {"type": "string"},
                    "end_date": {"type": "string"},
                    "run_id": {
                        "type": "integer",
                        "description": "اختياري. عند حذفه يتم استخدام أحدث تشغيل.",
                    },
                },
                "required": ["query_type"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "classify_network_flow",
            "description": (
                "يصنف تدفق شبكة واحد بالمودل المدرب. استخدم sample_index لصف اختبار محلي "
                "أو features لقيم تدفق مخصصة."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "sample_index": {"type": "integer"},
                    "features": {
                        "type": "object",
                        "additionalProperties": {"type": "number"},
                    },
                },
                "required": [],
            },
        },
    },
]
