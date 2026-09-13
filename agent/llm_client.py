"""
SentinelAI - عميل LLM قابل للتهيئة عبر متغيرات البيئة

لماذا Groq افتراضياً؟ يوفّر مفتاح API مجانياً (بحد استخدام سخي)، وواجهته متوافقة مع
OpenAI (Chat Completions + function/tool calling)، لذلك نستخدم مكتبة `openai` نفسها
موجَّهة إلى خادم Groq بدل خادم OpenAI. هذا يجعل تبديل مزوّد LLM لاحقاً (OpenAI نفسه،
أو أي مزوّد آخر متوافق مع OpenAI) مجرد تغيير في متغيرات البيئة، دون تعديل الكود.

## طريقة إعداد المفتاح (خطوات المستخدم):
1. اذهب إلى https://console.groq.com/keys وأنشئ حساباً مجانياً، ثم أنشئ مفتاح API.
2. اضبط متغيرات البيئة قبل تشغيل الوكيل:

   في PowerShell (Windows):
       $env:LLM_API_KEY = "gsk_...المفتاح_هنا..."

   في Bash (Linux/Mac/Git Bash):
       export LLM_API_KEY="gsk_...المفتاح_هنا..."

3. (اختياري) لاستخدام مزوّد آخر متوافق مع OpenAI بدل Groq، اضبط أيضاً:
       $env:LLM_BASE_URL = "https://api.openai.com/v1"
       $env:LLM_MODEL   = "gpt-4o-mini"
   ولا تنسَ ضبط LLM_API_KEY بمفتاح ذلك المزوّد.
"""

import os
from dotenv import load_dotenv
from openai import OpenAI

load_dotenv(os.path.join(os.path.dirname(__file__), "..", ".env"))

DEFAULT_BASE_URL = "https://api.groq.com/openai/v1"
DEFAULT_MODEL = "openai/gpt-oss-120b"


def get_client():
    api_key = os.environ.get("LLM_API_KEY") or os.environ.get("GROQ_API_KEY")
    if not api_key:
        raise RuntimeError(
            "لم يتم ضبط مفتاح API لأي نموذج لغوي (LLM).\n"
            "الرجاء ضبط متغير البيئة LLM_API_KEY (أو GROQ_API_KEY) قبل تشغيل الوكيل.\n"
            "راجع التعليمات في أعلى ملف agent/llm_client.py للحصول على مفتاح Groq مجاني."
        )
    base_url = os.environ.get("LLM_BASE_URL", DEFAULT_BASE_URL)
    return OpenAI(api_key=api_key, base_url=base_url)


def get_model_name():
    return os.environ.get("LLM_MODEL", DEFAULT_MODEL)
