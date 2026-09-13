"""
SentinelAI - تجربة الوكيل من الطرفية (Terminal)

الاستخدام:
    python agent/test_agent.py                  -> يشغّل أسئلة تجريبية جاهزة
    python agent/test_agent.py "سؤالك هنا"        -> يشغّل سؤالك أنت مباشرة

يتطلب ضبط متغير البيئة LLM_API_KEY أولاً (راجع agent/llm_client.py للتفاصيل).
"""

import sys
import os

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

sys.path.insert(0, os.path.dirname(__file__))
from agent import ask_agent  # noqa: E402

EXAMPLE_QUESTIONS = [
    "كم عدد هجمات Attack_4؟",
    "ما أخطر الهجمات المكتشفة؟",
    "How many benign flows were detected in total?",
    "صنّف لي التدفّق رقم 100 من بيانات الاختبار، وهل التصنيف صحيح؟",
]


def run_question(question):
    print("=" * 70)
    print(f"السؤال: {question}")
    try:
        answer = ask_agent(question, verbose=True)
        print(f"\nإجابة الوكيل:\n{answer}\n")
    except RuntimeError as e:
        print(f"\nخطأ في الإعداد: {e}\n")


def main():
    if len(sys.argv) > 1:
        run_question(" ".join(sys.argv[1:]))
        return

    print("تشغيل أسئلة تجريبية على الوكيل الذكي...\n")
    for q in EXAMPLE_QUESTIONS:
        run_question(q)


if __name__ == "__main__":
    main()
