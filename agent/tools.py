"""
SentinelAI - أدوات الوكيل الذكي

هذا الملف يعرّف الأداتين الوحيدتين المسموح بهما للوكيل (حسب CLAUDE.md):
1. classify_network_flow: يستخدم أفضل نموذج مدرَّب (models/best_model.joblib)
   لتصنيف تدفّق شبكة واحد.
2. query_database: يستعلم عن سجلات الاكتشاف المخزَّنة في database/sentinelai.db
   عبر الدوال الجاهزة في database/db.py (لا SQL خام من الوكيل مباشرة).

ممنوع تماماً أي أداة هجومية أو خدمة خارجية (RapidAPI أو غيرها) — هاتان الأداتان فقط.
"""

import os
import sys
import json

import numpy as np
import pandas as pd
import joblib

BASE_DIR = os.path.join(os.path.dirname(__file__), "..")
DATABASE_DIR = os.path.join(BASE_DIR, "database")
MODELS_DIR = os.path.join(BASE_DIR, "models")
PROCESSED_DIR = os.path.join(BASE_DIR, "data", "processed")

sys.path.insert(0, DATABASE_DIR)
import db  # noqa: E402

_model = None
_label_encoder = None
_scaler = None
_feature_names = None
_label_mapping = None
_X_test = None
_y_test = None


def _lazy_load():
    """نحمّل النموذج والبيانات مرة واحدة فقط عند أول استخدام، وليس عند استيراد الملف."""
    global _model, _label_encoder, _scaler, _feature_names, _label_mapping, _X_test, _y_test
    if _model is not None:
        return
    _model = joblib.load(os.path.join(MODELS_DIR, "best_model.joblib"))
    _label_encoder = joblib.load(os.path.join(MODELS_DIR, "best_model_label_encoder.joblib"))
    _scaler = joblib.load(os.path.join(PROCESSED_DIR, "scaler.joblib"))
    with open(os.path.join(PROCESSED_DIR, "feature_names.json"), encoding="utf-8") as f:
        _feature_names = json.load(f)
    with open(os.path.join(PROCESSED_DIR, "label_mapping.json"), encoding="utf-8") as f:
        _label_mapping = {int(k): v for k, v in json.load(f).items()}
    _X_test = np.load(os.path.join(PROCESSED_DIR, "X_test.npy"))
    _y_test = np.load(os.path.join(PROCESSED_DIR, "y_test.npy"))


def compute_risk_score(is_attack, confidence):
    """درجة خطورة مبسّطة من 0 إلى 100 (نفس المنطق المستخدم عند تعبئة قاعدة البيانات
    في database/populate_from_test_set.py):
    - تصنيف هجوم بثقة عالية -> قريب من 100 (خطر عالٍ).
    - تصنيف طبيعي بثقة عالية -> قريب من 0 (خطر منخفض)."""
    if is_attack:
        return round(confidence * 100, 2)
    return round((1 - confidence) * 20, 2)


def classify_network_flow(sample_index=None, features=None):
    """يصنّف تدفّق شبكة واحد باستخدام أفضل نموذج مدرَّب (XGBoost محسَّن).

    استخدم أحد الخيارين فقط:
    - sample_index: رقم صف حقيقي من بيانات الاختبار (0 إلى 227081) لتجربة سريعة
      على بيانات حقيقية فعلاً (وليست مختلَقة).
    - features: قاموس {اسم الخاصية: قيمة أصلية} لتدفّق مخصّص، مثل
      {"Flow Duration": 5000, "Dst Port": 80}. أي خاصية غير مذكورة تُعتبر 0
      (تبسيط، وليس قياساً حقيقياً — النتيجة في هذه الحالة تقريبية).
    """
    _lazy_load()

    if sample_index is not None:
        idx = int(sample_index)
        if idx < 0 or idx >= _X_test.shape[0]:
            return {"error": f"sample_index يجب أن يكون بين 0 و {_X_test.shape[0] - 1}"}
        x_scaled = _X_test[idx:idx + 1]
        true_code = int(_y_test[idx])
        true_label = _label_mapping[true_code]
    elif features:
        raw_row = np.zeros((1, len(_feature_names)))
        unknown_features = []
        for name, value in features.items():
            if name in _feature_names:
                raw_row[0, _feature_names.index(name)] = float(value)
            else:
                unknown_features.append(name)
        raw_df = pd.DataFrame(raw_row, columns=_feature_names)
        x_scaled = _scaler.transform(raw_df)
        true_label = None
    else:
        return {"error": "يجب تحديد sample_index أو features"}

    proba = _model.predict_proba(x_scaled)[0]
    pred_encoded = int(np.argmax(proba))
    confidence = float(proba[pred_encoded])
    pred_code = int(_label_encoder.inverse_transform([pred_encoded])[0])
    pred_label = _label_mapping[pred_code]

    is_attack = pred_code != 1
    result = {
        "predicted_attack_type": pred_label,
        "predicted_label_code": pred_code,
        "confidence": round(confidence, 4),
        "is_attack": is_attack,
        "risk_score": compute_risk_score(is_attack, confidence),
    }
    if true_label is not None:
        result["true_attack_type"] = true_label
        result["prediction_correct"] = (true_label == pred_label)
    if features is not None and unknown_features:
        result["warning"] = f"خصائص غير معروفة تم تجاهلها: {unknown_features}"
    return result


def query_database(query_type, **kwargs):
    """ينفّذ استعلاماً محدَّداً مسبقاً على قاعدة بيانات الاكتشافات (لا SQL خام).

    query_type أحد: by_attack_type, top_attacks, counts, recent, high_risk, by_date_range
    """
    conn = db.get_connection()
    try:
        if query_type == "by_attack_type":
            rows = db.query_by_attack_type(
                conn, kwargs.get("attack_type", ""), limit=kwargs.get("limit", 20)
            )
        elif query_type == "top_attacks":
            rows = db.query_top_attacks(conn, limit=kwargs.get("limit", 10))
        elif query_type == "counts":
            rows = db.query_counts(conn)
        elif query_type == "recent":
            rows = db.query_recent(conn, limit=kwargs.get("limit", 20))
        elif query_type == "high_risk":
            rows = db.query_high_risk(
                conn, min_risk_score=kwargs.get("min_risk_score", 80), limit=kwargs.get("limit", 20)
            )
        elif query_type == "by_date_range":
            rows = db.query_by_date_range(
                conn, kwargs["start_date"], kwargs["end_date"], limit=kwargs.get("limit", 100)
            )
        else:
            return {"error": f"query_type غير معروف: {query_type}"}
        return {"rows": rows, "count": len(rows)}
    finally:
        conn.close()


TOOLS_SCHEMA = [
    {
        "type": "function",
        "function": {
            "name": "query_database",
            "description": (
                "استعلام عن سجلات الاكتشاف المخزَّنة في قاعدة بيانات SQLite. "
                "استخدمه لأي سؤال عن إحصائيات، أعداد الهجمات، أخطر الهجمات، "
                "أحدث السجلات، أو سجلات في فترة زمنية معيّنة."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "query_type": {
                        "type": "string",
                        "enum": [
                            "by_attack_type", "top_attacks", "counts",
                            "recent", "high_risk", "by_date_range",
                        ],
                        "description": (
                            "by_attack_type: كل سجلات نوع هجوم معيّن. "
                            "top_attacks: أكثر أنواع الهجمات تكراراً. "
                            "counts: عدد ومتوسط الثقة/الخطورة لكل نوع (يشمل Benign). "
                            "recent: آخر السجلات المُدخلة. "
                            "high_risk: السجلات الأعلى في درجة الخطورة (risk_score). "
                            "by_date_range: سجلات بين تاريخين."
                        ),
                    },
                    "attack_type": {"type": "string", "description": "مثال: Attack_4 أو Benign (فقط مع by_attack_type)"},
                    "limit": {"type": "integer", "description": "أقصى عدد نتائج (اختياري)"},
                    "min_risk_score": {"type": "number", "description": "أقل درجة خطورة 0-100 (فقط مع high_risk)"},
                    "start_date": {"type": "string", "description": "تاريخ البداية ISO (فقط مع by_date_range)"},
                    "end_date": {"type": "string", "description": "تاريخ النهاية ISO (فقط مع by_date_range)"},
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
                "يصنّف تدفّق شبكة واحد باستخدام أفضل نموذج مدرَّب، لمعرفة هل هو "
                "طبيعي (Benign) أم نوع هجوم معيّن، مع نسبة ثقة النموذج."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "sample_index": {
                        "type": "integer",
                        "description": "رقم صف حقيقي من بيانات الاختبار (0 إلى 227081) لتجربة سريعة",
                    },
                    "features": {
                        "type": "object",
                        "description": "قاموس اختياري لقيم خصائص تدفّق مخصّص (اسم الخاصية -> رقم)",
                    },
                },
                "required": [],
            },
        },
    },
]
