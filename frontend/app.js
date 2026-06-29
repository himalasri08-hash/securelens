let selectedLanguage = "python";

// ---------- Navigation ----------
function goToScreen(name) {
  document.querySelectorAll(".screen").forEach(s => s.classList.remove("active"));
  document.getElementById("screen-" + name).classList.add("active");

  document.querySelectorAll(".nav-item").forEach(n => n.classList.remove("active"));
  const navBtn = document.querySelector(`.nav-item[data-screen="${name}"]`);
  if (navBtn) navBtn.classList.add("active");

  if (name === "dashboard") loadDashboard();
  if (name === "history") loadHistory();
}

// ---------- Language buttons ----------
document.getElementById("lang-row").addEventListener("click", (e) => {
  if (!e.target.classList.contains("lang-btn")) return;
  document.querySelectorAll(".lang-btn").forEach(b => b.classList.remove("active"));
  e.target.classList.add("active");
  selectedLanguage = e.target.dataset.lang;
});

// ---------- Sample code ----------
function loadSample() {
  document.getElementById("code-input").value =
`import os

password = "admin123"  # hardcoded credential

def run_query(user_input):
    query = "SELECT * FROM users WHERE name = '" + user_input + "'"
    os.system(query)
    return query
`;
}

// ---------- File upload ----------
document.getElementById("file-input").addEventListener("change", function (e) {
  const file = e.target.files[0];
  if (!file) return;
  const reader = new FileReader();
  reader.onload = function (evt) {
    document.getElementById("code-input").value = evt.target.result;
  };
  reader.readAsText(file);
});

// ---------- Analyze ----------
async function analyzeCode() {
  const code = document.getElementById("code-input").value;
  const title = document.getElementById("title-input").value;
  const btn = document.getElementById("analyze-btn");
  const resultsDiv = document.getElementById("scan-results");

  if (!code.trim()) {
    resultsDiv.innerHTML = `<div class="finding-card">Please paste or upload some code first.</div>`;
    return;
  }

  btn.disabled = true;
  btn.innerText = "Analyzing...";
  resultsDiv.innerHTML = `<div class="loading">Running SAST scan and LLM analysis...</div>`;

  try {
    const res = await fetch("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ language: selectedLanguage, title, code }),
    });
    const data = await res.json();

    if (data.error) {
      resultsDiv.innerHTML = `<div class="finding-card">${data.error}</div>`;
    } else if (data.findings.length === 0) {
      resultsDiv.innerHTML = `<div class="finding-card">No issues found. ✅</div>`;
    } else {
      resultsDiv.innerHTML = data.findings.map(renderFinding).join("");
    }
  } catch (err) {
    resultsDiv.innerHTML = `<div class="finding-card">Something went wrong: ${err.message}</div>`;
  }

  btn.disabled = false;
  btn.innerText = "🛡 Analyze Code";
}

function renderFinding(f) {
  return `
    <div class="finding-card">
      <div class="finding-top">
        <span class="severity-badge badge-${f.severity}">${f.severity}</span>
        <span class="finding-line">Line ${f.line}</span>
      </div>
      <div class="finding-rule">${f.rule}</div>
      <div class="finding-snippet">${escapeHtml(f.snippet)}</div>
      <div class="finding-explain">${f.explanation}</div>
      <div class="finding-fix">Fix: ${f.fix_suggestion}</div>
    </div>
  `;
}

function escapeHtml(str) {
  const div = document.createElement("div");
  div.innerText = str;
  return div.innerHTML;
}

// ---------- Dashboard ----------
async function loadDashboard() {
  try {
    const res = await fetch("/api/dashboard");
    const d = await res.json();

    document.getElementById("stat-total").innerText = d.total_vulnerabilities;
    document.getElementById("stat-scans-sub").innerText = `across ${d.total_scans} scans`;
    document.getElementById("stat-critical").innerText = d.critical;
    document.getElementById("stat-high").innerText = d.high;
    document.getElementById("stat-medium").innerText = d.medium;
    document.getElementById("stat-low").innerText = d.low;

    document.getElementById("empty-state").style.display = d.total_scans === 0 ? "block" : "none";
  } catch (err) {
    console.error(err);
  }
}

// ---------- History ----------
async function loadHistory() {
  const list = document.getElementById("history-list");
  list.innerHTML = `<div class="loading">Loading...</div>`;
  try {
    const res = await fetch("/api/history");
    const scans = await res.json();

    if (scans.length === 0) {
      list.innerHTML = `<div class="card empty-card">No scans yet.</div>`;
      return;
    }

    list.innerHTML = scans.map(s => `
      <div class="history-card" onclick="openDetail('${s.id}')">
        <div class="history-top">
          <span class="history-title">${s.title}</span>
          <span class="severity-badge badge-${s.highest_severity}">${s.highest_severity}</span>
        </div>
        <div class="history-date">${s.language} · ${s.total_findings} findings · ${new Date(s.created_at).toLocaleString()}</div>
      </div>
    `).join("");
  } catch (err) {
    list.innerHTML = `<div class="card">Failed to load history.</div>`;
  }
}

// ---------- Scan detail ----------
async function openDetail(scanId) {
  goToScreen("detail");
  const titleEl = document.getElementById("detail-title");
  const container = document.getElementById("detail-findings");
  container.innerHTML = `<div class="loading">Loading...</div>`;

  const res = await fetch(`/api/scan/${scanId}`);
  const data = await res.json();

  if (data.error) {
    container.innerHTML = `<div class="card">${data.error}</div>`;
    return;
  }

  titleEl.innerText = data.scan.title;
  container.innerHTML = data.findings.map(renderFinding).join("") ||
    `<div class="finding-card">No issues found. ✅</div>`;
}

// ---------- Init ----------
loadDashboard();
