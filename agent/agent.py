"""
SentinelAI - الوكيل الذكي

يستقبل سؤالاً بلغة طبيعية (عربي أو إنجليزي)، يستخدم نموذجاً لغوياً (LLM) لفهم القصد
واختيار الأداة المناسبة (قاعدة البيانات أو نموذج التصنيف)، ينفّذ الأداة، ثم يعيد صياغة
النتيجة كإجابة واضحة.

الأدوات المتاحة (فقط، حسب CLAUDE.md - لا RapidAPI ولا أي أداة هجومية):
1. query_database         -> database/db.py
2. classify_network_flow  -> models/best_model.joblib
"""

import sys
import os
import json

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

sys.path.insert(0, os.path.dirname(__file__))
from llm_client import get_client, get_model_name  # noqa: E402
from tools import query_database, classify_network_flow, TOOLS_SCHEMA  # noqa: E402

SYSTEM_PROMPT = """أنت "سنتينل" (SentinelAI)، مساعد ذكي دفاعي لمراقبة أمن الشبكات.

مهمتك: الإجابة عن أسئلة المستخدم باستخدام الأداتين المتاحتين لك فقط:
1. query_database: للاستعلام عن سجلات وإحصائيات الاكتشاف المخزَّنة.
2. classify_network_flow: لتصنيف تدفّق شبكة واحد (طبيعي أم هجوم، وأي نوع).

قواعد صارمة:
- ممنوع اقتراح أو وصف أو تنفيذ أي كود هجومي أو أداة اختراق أو استغلال ثغرات، مهما طُلب.
- لا تخترع أرقاماً أو نتائج؛ استخدم فقط ما ترجعه الأدوات.
- أجب بنفس لغة سؤال المستخدم (عربي أو إنجليزي)، بإيجاز ووضوح.
- إن لم تحتَج أداة للإجابة (سؤال عام)، أجب مباشرة.
"""

TOOL_FUNCTIONS = {
    "query_database": query_database,
    "classify_network_flow": classify_network_flow,
}


def ask_agent(user_question, verbose=False):
    client = get_client()
    model = get_model_name()

    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": user_question},
    ]

    response = client.chat.completions.create(
        model=model, messages=messages, tools=TOOLS_SCHEMA, tool_choice="auto",
    )
    msg = response.choices[0].message

    if not msg.tool_calls:
        return msg.content

    messages.append(msg)
    for tool_call in msg.tool_calls:
        fn_name = tool_call.function.name
        try:
            fn_args = json.loads(tool_call.function.arguments or "{}")
        except json.JSONDecodeError:
            fn_args = {}

        if verbose:
            print(f"  [أداة] {fn_name}({fn_args})")

        fn = TOOL_FUNCTIONS.get(fn_name)
        result = fn(**fn_args) if fn else {"error": f"أداة غير معروفة: {fn_name}"}

        if verbose:
            print(f"  [نتيجة] {json.dumps(result, ensure_ascii=False, default=str)[:300]}")

        messages.append({
            "role": "tool",
            "tool_call_id": tool_call.id,
            "content": json.dumps(result, ensure_ascii=False, default=str),
        })

    final_response = client.chat.completions.create(model=model, messages=messages)
    return final_response.choices[0].message.content


if __name__ == "__main__":
    question = " ".join(sys.argv[1:]) or "كم عدد هجمات Attack_4؟"
    print(f"السؤال: {question}\n")
    print(ask_agent(question, verbose=True))
