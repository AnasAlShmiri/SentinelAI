// SentinelAI - منطق لوحة التحكم (Dashboard)
//
// كل الدوال هنا تنادي الـ FastAPI Backend (عنوانه في config.js) عبر fetch،
// ولا تحتوي على أي منطق هجومي - فقط عرض بيانات وإرسال طلبات تصنيف/أسئلة.

const API = CONFIG.API_BASE_URL;

const PROTOCOL_NAMES = { 6: "TCP", 17: "UDP", 1: "ICMP", 0: "HOPOPT" };

function fmtNum(n) {
  if (n === null || n === undefined) return "-";
  return Number(n).toLocaleString("en-US");
}

function fmtPct(n) {
  if (n === null || n === undefined) return "-";
  return (Number(n) * 100).toFixed(1) + "%";
}

function fmtTime(iso) {
  if (!iso) return "-";
  try {
    return new Date(iso).toLocaleString("ar-EG", { hour12: false });
  } catch (e) {
    return iso;
  }
}

async function apiGet(path) {
  const res = await fetch(`${API}${path}`);
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.detail || `خطأ HTTP ${res.status}`);
  return data;
}

async function apiPost(path, body) {
  const res = await fetch(`${API}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.detail || `خطأ HTTP ${res.status}`);
  return data;
}

// =====================================================================
// 1) ملخّص الأعداد + 2) الرسم البياني (كلاهما من نفس /api/detections/counts)
// =====================================================================

let attackChart = null;

async function loadSummaryAndChart() {
  const statusEl = document.getElementById("summary-status");
  try {
    statusEl.textContent = "جارٍ التحميل...";
    const { rows } = await apiGet("/api/detections/counts");

    const total = rows.reduce((sum, r) => sum + r.count, 0);
    const benignRow = rows.find((r) => r.predicted_attack_type === "Benign");
    const benignCount = benignRow ? benignRow.count : 0;
    const attackCount = total - benignCount;
    const attackTypesCount = rows.filter((r) => r.predicted_attack_type !== "Benign").length;

    document.getElementById("summary-grid").innerHTML = `
      <div class="stat-box">
        <div class="value">${fmtNum(total)}</div>
        <div class="label">إجمالي السجلات</div>
      </div>
      <div class="stat-box safe">
        <div class="value">${fmtNum(benignCount)}</div>
        <div class="label">طبيعي (Benign)</div>
      </div>
      <div class="stat-box danger">
        <div class="value">${fmtNum(attackCount)}</div>
        <div class="label">هجمات مكتشفة</div>
      </div>
      <div class="stat-box">
        <div class="value">${fmtNum(attackTypesCount)}</div>
        <div class="label">أنواع هجمات مختلفة</div>
      </div>
    `;
    statusEl.textContent = "";

    renderChart(rows);
  } catch (err) {
    statusEl.textContent = `تعذّر تحميل الملخّص: ${err.message}`;
    statusEl.classList.add("error");
  }
}

function renderChart(rows) {
  const chartWrap = document.querySelector(".chart-wrap");

  if (typeof Chart === "undefined") {
    chartWrap.innerHTML = `<div class="status-msg error">
      تعذّر تحميل مكتبة الرسم البياني (Chart.js). تحقّق من اتصال الإنترنت ثم أعد تحميل الصفحة.
    </div>`;
    return;
  }

  const sorted = [...rows].sort((a, b) => b.count - a.count);
  const labels = sorted.map((r) => r.predicted_attack_type);
  const counts = sorted.map((r) => r.count);
  const colors = sorted.map((r) =>
    r.predicted_attack_type === "Benign" ? "#1f9d55" : "#d64545"
  );

  const ctx = document.getElementById("attack-chart").getContext("2d");
  if (attackChart) attackChart.destroy();
  attackChart = new Chart(ctx, {
    type: "bar",
    data: {
      labels,
      datasets: [{ label: "عدد السجلات", data: counts, backgroundColor: colors, borderRadius: 4 }],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: {
        y: { beginAtZero: true, ticks: { precision: 0 } },
      },
    },
  });
}

// =====================================================================
// 3) جدول السجلات (الأحدث / الأعلى خطورة)
// =====================================================================

async function loadTable() {
  const kind = document.getElementById("table-kind").value;
  const limit = Math.max(1, Math.min(200, Number(document.getElementById("table-limit").value) || 20));
  const statusEl = document.getElementById("table-status");
  const tbody = document.querySelector("#detections-table tbody");

  statusEl.textContent = "جارٍ التحميل...";
  statusEl.classList.remove("error");
  try {
    const path = kind === "high_risk"
      ? `/api/detections/high-risk?min_risk_score=70&limit=${limit}`
      : `/api/detections/recent?limit=${limit}`;
    const { rows } = await apiGet(path);

    tbody.innerHTML = rows.map((r) => `
      <tr>
        <td>${fmtTime(r.timestamp)}</td>
        <td>${r.dst_port ?? "-"}</td>
        <td>${PROTOCOL_NAMES[r.protocol] ?? r.protocol ?? "-"}</td>
        <td><span class="badge ${r.is_attack ? "danger" : "safe"}">${r.predicted_attack_type}</span></td>
        <td>${fmtPct(r.confidence)}</td>
        <td>
          <span class="risk-bar"><span style="width:${Math.min(100, r.risk_score)}%"></span></span>
          ${Number(r.risk_score).toFixed(1)}
        </td>
        <td>${r.true_attack_type ?? "-"}</td>
      </tr>
    `).join("") || `<tr><td colspan="7">لا توجد سجلات</td></tr>`;

    statusEl.textContent = `${rows.length} سجل`;
  } catch (err) {
    statusEl.textContent = `تعذّر تحميل الجدول: ${err.message}`;
    statusEl.classList.add("error");
    tbody.innerHTML = "";
  }
}

// =====================================================================
// 4) نموذج تصنيف تدفّق
// =====================================================================

function setupClassifyForm() {
  const modeRadios = document.querySelectorAll('input[name="classify-mode"]');
  const quickBox = document.getElementById("mode-quick");
  const customBox = document.getElementById("mode-custom");

  modeRadios.forEach((r) => r.addEventListener("change", () => {
    const isQuick = document.querySelector('input[name="classify-mode"]:checked').value === "quick";
    quickBox.classList.toggle("hidden", !isQuick);
    customBox.classList.toggle("hidden", isQuick);
  }));

  document.getElementById("classify-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const btn = document.getElementById("classify-btn");
    const resultBox = document.getElementById("classify-result");
    const mode = document.querySelector('input[name="classify-mode"]:checked').value;

    let body;
    if (mode === "quick") {
      const idx = Number(document.getElementById("sample-index").value);
      body = { sample_index: idx };
    } else {
      const features = {};
      document.querySelectorAll("#mode-custom [data-feature]").forEach((input) => {
        if (input.value !== "") features[input.dataset.feature] = Number(input.value);
      });
      if (Object.keys(features).length === 0) {
        alert("عبّئ خاصية واحدة على الأقل، أو استخدم وضع الاختبار السريع.");
        return;
      }
      body = { features };
    }

    btn.disabled = true;
    btn.textContent = "جارٍ التصنيف...";
    resultBox.classList.add("hidden");
    try {
      const result = await apiPost("/api/classify", body);
      renderClassifyResult(result);
    } catch (err) {
      resultBox.classList.remove("hidden");
      resultBox.innerHTML = `<div class="status-msg error">تعذّر التصنيف: ${err.message}</div>`;
    } finally {
      btn.disabled = false;
      btn.textContent = "تصنيف";
    }
  });
}

function renderClassifyResult(r) {
  const resultBox = document.getElementById("classify-result");
  resultBox.classList.remove("hidden");

  const isAttack = r.is_attack;
  const confidencePct = (r.confidence * 100).toFixed(1);
  const riskPct = Math.min(100, r.risk_score);

  let correctnessLine = "";
  if (r.true_attack_type !== undefined) {
    correctnessLine = `
      <div class="result-row">
        <span class="k">التصنيف الحقيقي</span>
        <span>${r.true_attack_type} ${r.prediction_correct ? "✅ (توقّع صحيح)" : "❌ (توقّع خاطئ)"}</span>
      </div>`;
  }

  let warningLine = "";
  if (r.warning) {
    warningLine = `<div class="note">⚠️ ${r.warning}</div>`;
  }

  resultBox.innerHTML = `
    <div class="result-title">
      النتيجة: <span class="badge ${isAttack ? "danger" : "safe"}">${r.predicted_attack_type}</span>
    </div>
    <div class="result-row">
      <span class="k">ثقة النموذج</span>
      <span class="gauge confidence"><span style="width:${confidencePct}%"></span></span>
      <span>${confidencePct}%</span>
    </div>
    <div class="result-row">
      <span class="k">درجة الخطورة</span>
      <span class="gauge risk"><span style="width:${riskPct}%"></span></span>
      <span>${r.risk_score}</span>
    </div>
    ${correctnessLine}
    ${warningLine}
  `;
}

// =====================================================================
// 5) الدردشة مع الوكيل الذكي
// =====================================================================

function addMessage(text, cls) {
  const win = document.getElementById("chat-window");
  const div = document.createElement("div");
  div.className = `msg ${cls}`;
  div.textContent = text;
  win.appendChild(div);
  win.scrollTop = win.scrollHeight;
  return div;
}

function setupChat() {
  const form = document.getElementById("chat-form");
  const input = document.getElementById("chat-input");

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const question = input.value.trim();
    if (!question) return;

    addMessage(question, "user");
    input.value = "";
    input.disabled = true;
    const pending = addMessage("الوكيل يفكّر...", "pending");

    try {
      const { answer } = await apiPost("/api/agent/ask", { question });
      pending.remove();
      addMessage(answer, "agent");
    } catch (err) {
      pending.remove();
      addMessage(`تعذّر الحصول على إجابة: ${err.message}`, "error");
    } finally {
      input.disabled = false;
      input.focus();
    }
  });
}

// =====================================================================
// تشغيل كل شيء عند تحميل الصفحة
// =====================================================================

document.addEventListener("DOMContentLoaded", () => {
  loadSummaryAndChart();
  loadTable();

  document.getElementById("refresh-summary").addEventListener("click", loadSummaryAndChart);
  document.getElementById("refresh-table").addEventListener("click", loadTable);
  document.getElementById("table-kind").addEventListener("change", loadTable);

  setupClassifyForm();
  setupChat();
});
