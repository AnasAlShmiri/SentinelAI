"""
SentinelAI - تعبئة قاعدة البيانات ببيانات اكتشاف حقيقية

يشغّل هذا السكربت أفضل نموذج مدرَّب (models/best_model.joblib) على بيانات الاختبار
الكاملة (data/processed/X_test.npy)، ويخزّن كل التوقعات في قاعدة بيانات SQLite
(database/sentinelai.db)، حتى يكون لدينا بيانات حقيقية (وليست وهمية) للاستعلام عنها
في مرحلة الوكيل الذكي القادمة.

ملاحظتان مهمتان عن البيانات المُدخلة (للشفافية):
1. "dst_port" و"protocol" و"flow_duration" مُستخرجة فعلياً من بيانات الاختبار عبر عكس
   عملية StandardScaler (scaler.inverse_transform) — هذا الملف لا يحتوي أصلاً على عناوين
   IP (لا للمصدر ولا للوجهة)، لذلك هذه هي "معلومات المصدر" الوحيدة المتوفرة في العيّنة.
2. عمود "timestamp": بيانات CSE-CIC-IDS2018 المعالَجة هنا لا تحمل توقيت التقاط حقيقياً
   لكل صف، لذلك وزّعنا زمن كل سجل بشكل متتابع (Simulated) على نافذة زمنية آخر 7 أيام،
   فقط حتى تكون استعلامات "حسب التاريخ" ذات معنى للتجربة. التصنيف والثقة ودرجة الخطورة
   كلها نتائج حقيقية من النموذج، ولا شيء منها مُختلَق.
"""

import os
import sys
import json
from datetime import datetime, timedelta, timezone

import numpy as np
import joblib

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

sys.path.insert(0, os.path.dirname(__file__))
import db  # noqa: E402

BASE_DIR = os.path.join(os.path.dirname(__file__), "..")
PROCESSED_DIR = os.path.join(BASE_DIR, "data", "processed")
MODELS_DIR = os.path.join(BASE_DIR, "models")

TIME_WINDOW_DAYS = 7


def compute_risk_score(is_attack, confidence):
    """درجة خطورة مبسّطة من 0 إلى 100:
    - تصنيف هجوم بثقة عالية -> قريب من 100 (خطر عالٍ).
    - تصنيف طبيعي بثقة عالية -> قريب من 0 (خطر منخفض).
    - أي عدم يقين من النموذج -> يقلّل ثقتنا في القرار (يرفع خطر الحالة الطبيعية قليلاً،
      ويخفّض قليلاً خطر حالة الهجوم شديدة الثقة المنخفضة)."""
    if is_attack:
        return round(confidence * 100, 2)
    return round((1 - confidence) * 20, 2)


def main():
    print("تحميل البيانات والنموذج...")
    X_test = np.load(os.path.join(PROCESSED_DIR, "X_test.npy"))
    y_test = np.load(os.path.join(PROCESSED_DIR, "y_test.npy"))

    with open(os.path.join(PROCESSED_DIR, "feature_names.json"), encoding="utf-8") as f:
        feature_names = json.load(f)
    with open(os.path.join(PROCESSED_DIR, "label_mapping.json"), encoding="utf-8") as f:
        label_mapping = {int(k): v for k, v in json.load(f).items()}

    scaler = joblib.load(os.path.join(PROCESSED_DIR, "scaler.joblib"))
    model = joblib.load(os.path.join(MODELS_DIR, "best_model.joblib"))
    label_encoder = joblib.load(os.path.join(MODELS_DIR, "best_model_label_encoder.joblib"))

    print(f"عدد صفوف الاختبار: {X_test.shape[0]:,}")

    # استرجاع القيم الأصلية (غير المُقاسة) لبعض الأعمدة لعرضها كـ \"معلومات مصدر\"
    X_test_original = scaler.inverse_transform(X_test)
    dst_port_idx = feature_names.index("Dst Port")
    protocol_idx = feature_names.index("Protocol")
    flow_duration_idx = feature_names.index("Flow Duration")

    dst_ports = np.round(X_test_original[:, dst_port_idx]).astype(int)
    protocols = np.round(X_test_original[:, protocol_idx]).astype(int)
    flow_durations = np.round(X_test_original[:, flow_duration_idx]).astype(int)

    print("تشغيل النموذج على بيانات الاختبار (predict_proba)...")
    pred_proba = model.predict_proba(X_test)
    pred_encoded = np.argmax(pred_proba, axis=1)
    confidences = pred_proba[np.arange(len(pred_encoded)), pred_encoded]
    pred_codes = label_encoder.inverse_transform(pred_encoded)

    # توزيع زمني اصطناعي (موثّق أعلاه) لجعل الاستعلام بحسب التاريخ ذا معنى
    now = datetime.now(timezone.utc)
    window_seconds = TIME_WINDOW_DAYS * 24 * 3600
    start_time = now - timedelta(seconds=window_seconds)
    offsets = np.linspace(0, window_seconds, num=len(pred_codes))
    timestamps = [(start_time + timedelta(seconds=float(off))).isoformat() for off in offsets]

    conn = db.get_connection()
    db.create_tables(conn)

    run_id = db.insert_model_run(
        conn,
        model_name="XGBoost (Tuned) - best_model.joblib",
        model_path="models/best_model.joblib",
        num_records=len(pred_codes),
        notes=(
            "دفعة أولية من كامل بيانات الاختبار (X_test/y_test) لتغذية قاعدة البيانات "
            "ببيانات اكتشاف حقيقية قبل بدء مرحلة الوكيل الذكي."
        ),
    )

    print("تجهيز السجلات...")
    records = []
    for i in range(len(pred_codes)):
        pred_code = int(pred_codes[i])
        true_code = int(y_test[i])
        is_attack = 0 if pred_code == 1 else 1
        confidence = float(confidences[i])
        records.append({
            "timestamp": timestamps[i],
            "dst_port": int(dst_ports[i]),
            "protocol": int(protocols[i]),
            "flow_duration": int(flow_durations[i]),
            "predicted_label_code": pred_code,
            "predicted_attack_type": label_mapping[pred_code],
            "is_attack": is_attack,
            "confidence": round(confidence, 4),
            "risk_score": compute_risk_score(is_attack, confidence),
            "true_label_code": true_code,
            "true_attack_type": label_mapping[true_code],
        })

    print(f"إدخال {len(records):,} سجل اكتشاف في قاعدة البيانات...")
    db.insert_detections_batch(conn, run_id, records)
    print(f"تم! قاعدة البيانات: {db.DB_PATH}")

    conn.close()


if __name__ == "__main__":
    main()
