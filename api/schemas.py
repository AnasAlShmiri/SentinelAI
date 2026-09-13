"""
SentinelAI - نماذج البيانات (Pydantic) لطلبات واستجابات الـ API

هذا الملف فقط يعرّف "شكل" البيانات المتوقَّعة في الطلبات (Request Body)،
لا يحتوي على أي منطق. المنطق الفعلي في agent/tools.py و agent/agent.py و database/db.py.
"""

from typing import Optional, Dict

from pydantic import BaseModel, Field


class ClassifyRequest(BaseModel):
    """طلب تصنيف تدفّق شبكة واحد. استخدم أحد الحقلين فقط:
    - sample_index: رقم صف حقيقي من بيانات الاختبار (0 إلى 227081) لتجربة سريعة.
    - features: قاموس {اسم الخاصية: قيمة} لتدفّق مخصّص."""

    sample_index: Optional[int] = Field(
        None, description="رقم صف من بيانات الاختبار الحقيقية (0-227081)"
    )
    features: Optional[Dict[str, float]] = Field(
        None, description="قيم خصائص تدفّق مخصّص، مثال: {\"Dst Port\": 80, \"Flow Duration\": 5000}"
    )


class AskRequest(BaseModel):
    """سؤال بلغة طبيعية (عربي أو إنجليزي) يُوجَّه للوكيل الذكي."""

    question: str = Field(..., min_length=1, description="السؤال بلغة طبيعية")
