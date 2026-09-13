"""
SentinelAI - FastAPI Backend

يربط هذا الملف كل ما بنيناه سابقاً بواجهة برمجية (API) واحدة:
- تصنيف تدفّق شبكة عبر أفضل نموذج مدرَّب (models/best_model.joblib).
- استعلامات جاهزة عن سجلات الاكتشاف في قاعدة بيانات SQLite (database/sentinelai.db).
- سؤال الوكيل الذكي بلغة طبيعية (agent/agent.py، يستخدم مفتاح LLM_API_KEY من .env).

قواعد صارمة (راجع CLAUDE.md):
- دفاعي فقط: لا يوجد أي Endpoint ينفّذ هجوماً أو يستدعي أداة اختراق.
- بدون RapidAPI أو أي خدمة خارجية أخرى.
- الوكيل يستخدم فقط الأداتين المسموح بهما (query_database و classify_network_flow).

تشغيل الخادم:
    uvicorn api.main:app --reload
(يجب تشغيل الأمر من داخل مجلد المشروع D:\\SentinelAI حتى تعمل المسارات النسبية).

بعد التشغيل:
- توثيق تفاعلي (Swagger UI): http://127.0.0.1:8000/docs
"""

import os
import sys

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

API_DIR = os.path.dirname(os.path.abspath(__file__))
BASE_DIR = os.path.dirname(API_DIR)
AGENT_DIR = os.path.join(BASE_DIR, "agent")
DATABASE_DIR = os.path.join(BASE_DIR, "database")

sys.path.insert(0, API_DIR)
sys.path.insert(0, AGENT_DIR)
sys.path.insert(0, DATABASE_DIR)

from agent import ask_agent  # noqa: E402
from tools import classify_network_flow  # noqa: E402
import db  # noqa: E402

from schemas import AskRequest, ClassifyRequest  # noqa: E402

app = FastAPI(
    title="SentinelAI API",
    description=(
        "منصّة دفاعية لكشف وتصنيف تهديدات الشبكات (CSE-CIC-IDS2018) — "
        "تصنيف، استعلامات قاعدة بيانات، ووكيل ذكي بلغة طبيعية."
    ),
    version="1.0.0",
)

# تفعيل CORS للسماح لواجهة الـ Dashboard (HTML/CSS/JS) بمناداة الـ API من متصفح
# (سواء عبر ملف مباشر أو خادم محلي بمنفذ مختلف). المشروع تجريبي/تعليمي، بلا بيانات
# مستخدمين حسّاسة، لذلك السماح بأي أصل (*) هنا مقبول.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
def root():
    return {
        "service": "SentinelAI API",
        "status": "running",
        "docs": "/docs",
        "endpoints": [
            "POST /api/classify",
            "GET  /api/detections/counts",
            "GET  /api/detections/top-attacks",
            "GET  /api/detections/recent",
            "GET  /api/detections/by-type/{attack_type}",
            "GET  /api/detections/high-risk",
            "GET  /api/detections/by-date-range",
            "POST /api/agent/ask",
        ],
    }


@app.get("/health")
def health():
    return {"status": "ok"}


# ---------------------------------------------------------------------------
# 1) تصنيف تدفّق شبكة (النموذج المدرَّب best_model.joblib)
# ---------------------------------------------------------------------------

@app.post("/api/classify")
def classify(request: ClassifyRequest):
    if request.sample_index is None and not request.features:
        raise HTTPException(
            status_code=400, detail="يجب إرسال sample_index أو features"
        )
    result = classify_network_flow(
        sample_index=request.sample_index, features=request.features
    )
    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])
    return result


# ---------------------------------------------------------------------------
# 2) استعلامات قاعدة بيانات الاكتشافات (SQLite)
# ---------------------------------------------------------------------------

@app.get("/api/detections/counts")
def detections_counts():
    conn = db.get_connection()
    try:
        rows = db.query_counts(conn)
        return {"rows": rows, "count": len(rows)}
    finally:
        conn.close()


@app.get("/api/detections/top-attacks")
def detections_top_attacks(limit: int = 10):
    conn = db.get_connection()
    try:
        rows = db.query_top_attacks(conn, limit=limit)
        return {"rows": rows, "count": len(rows)}
    finally:
        conn.close()


@app.get("/api/detections/recent")
def detections_recent(limit: int = 20):
    conn = db.get_connection()
    try:
        rows = db.query_recent(conn, limit=limit)
        return {"rows": rows, "count": len(rows)}
    finally:
        conn.close()


@app.get("/api/detections/by-type/{attack_type}")
def detections_by_type(attack_type: str, limit: int = 20):
    conn = db.get_connection()
    try:
        rows = db.query_by_attack_type(conn, attack_type, limit=limit)
        return {"rows": rows, "count": len(rows)}
    finally:
        conn.close()


@app.get("/api/detections/high-risk")
def detections_high_risk(min_risk_score: float = 80, limit: int = 20):
    conn = db.get_connection()
    try:
        rows = db.query_high_risk(conn, min_risk_score=min_risk_score, limit=limit)
        return {"rows": rows, "count": len(rows)}
    finally:
        conn.close()


@app.get("/api/detections/by-date-range")
def detections_by_date_range(start_date: str, end_date: str, limit: int = 100):
    conn = db.get_connection()
    try:
        rows = db.query_by_date_range(conn, start_date, end_date, limit=limit)
        return {"rows": rows, "count": len(rows)}
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# 3) سؤال الوكيل الذكي بلغة طبيعية
# ---------------------------------------------------------------------------

@app.post("/api/agent/ask")
def agent_ask(request: AskRequest):
    try:
        answer = ask_agent(request.question)
    except RuntimeError as e:
        # يحدث هذا إن كان LLM_API_KEY غير مضبوط في .env
        raise HTTPException(status_code=503, detail=str(e))
    return {"question": request.question, "answer": answer}
