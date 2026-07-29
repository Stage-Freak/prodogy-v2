"use strict";

// Prodogy dashboard front-end. Pure vanilla JS, no build step, no CDN.
// It calls the local API and renders the Report JSON — the single source of truth.

const SEV_ORDER = { critical: 4, error: 3, warning: 2, info: 1 };
const SEV_EMOJI = { critical: "🛑", error: "❌", warning: "⚠️", info: "ℹ️" };

const el = (id) => document.getElementById(id);
const escapeHtml = (s) =>
  String(s ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");

let currentReport = null;

// Auth token is passed via the URL (?token=...) when the server requires it.
// The CLI prints a ready-to-open URL with the token embedded.
const AUTH_TOKEN = new URLSearchParams(window.location.search).get("token");

function authHeaders(extra) {
  const h = Object.assign({}, extra || {});
  if (AUTH_TOKEN) h["Authorization"] = `Bearer ${AUTH_TOKEN}`;
  return h;
}

async function runScan(path, maintainability, enrich) {
  const res = await fetch("/api/scan", {
    method: "POST",
    headers: authHeaders({ "Content-Type": "application/json" }),
    body: JSON.stringify({ path, maintainability }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(err.detail || `HTTP ${res.status}`);
  }
  return res.json();
}

async function runEnrichScan(path, maintainability, enrich) {
  if (!enrich) {
    return runScan(path, maintainability, false);
  }
  const res = await fetch("/api/enrich", {
    method: "POST",
    headers: authHeaders({ "Content-Type": "application/json" }),
    body: JSON.stringify({ path, maintainability, force: false }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(err.detail || `HTTP ${res.status}`);
  }
  return res.json();
}

function activeFindings(report) {
  return (report.findings || []).filter((f) => !f.suppressed);
}

function renderGate(report) {
  const findings = activeFindings(report);
  const blocking = findings.filter((f) => SEV_ORDER[f.severity] >= SEV_ORDER.error).length;
  const banner = el("gate-banner");
  if (blocking > 0) {
    banner.className = "gate fail";
    banner.textContent = `✗ Gate would fail: ${blocking} finding(s) at or above 'error'.`;
  } else {
    banner.className = "gate pass";
    banner.textContent = "✓ Gate passes — no blocking findings.";
  }
}

function renderCards(report) {
  const by = report.summary.by_severity || {};
  const cards = [
    ["critical", "Critical"],
    ["error", "Error"],
    ["warning", "Warning"],
    ["info", "Info"],
  ];
  el("summary-cards").innerHTML = cards
    .map(
      ([sev, label]) => `
      <div class="card ${sev}">
        <div class="num">${by[sev] || 0}</div>
        <div class="lbl">${label}</div>
      </div>`
    )
    .join("");
}

function renderFindings() {
  if (!currentReport) return;
  const enabled = new Set(
    Array.from(document.querySelectorAll(".sev-filter:checked")).map((c) => c.value)
  );
  const text = el("text-filter").value.trim().toLowerCase();

  let findings = activeFindings(currentReport)
    .filter((f) => enabled.has(f.severity))
    .filter((f) => {
      if (!text) return true;
      const hay = `${f.rule_id} ${f.title} ${f.message} ${f.location.path}`.toLowerCase();
      return hay.includes(text);
    })
    .sort(
      (a, b) =>
        SEV_ORDER[b.severity] - SEV_ORDER[a.severity] ||
        a.location.path.localeCompare(b.location.path) ||
        (a.location.line || 0) - (b.location.line || 0)
    );

  const list = el("findings-list");
  if (findings.length === 0) {
    list.innerHTML = `<p class="hint">No findings match the current filters. 🎉</p>`;
    return;
  }

  list.innerHTML = findings
    .map((f) => {
      const loc = f.location.line
        ? `${escapeHtml(f.location.path)}:${f.location.line}`
        : escapeHtml(f.location.path);
      return `
      <div class="finding ${f.severity}">
        <div class="finding-head">
          <span class="badge ${f.severity}">${SEV_EMOJI[f.severity]} ${f.severity}</span>
          <span class="rule-id">${escapeHtml(f.rule_id)}</span>
          <span>${escapeHtml(f.title)}</span>
          <span class="loc">${loc}</span>
        </div>
        <p class="finding-msg">${escapeHtml(f.message)}</p>
        ${f.rationale ? `<p class="finding-detail"><span class="k">Why:</span> ${escapeHtml(f.rationale)}</p>` : ""}
        ${f.remediation ? `<p class="finding-detail fix"><span class="k">Fix:</span> ${escapeHtml(f.remediation)}</p>` : ""}
        ${f.llm_explanation ? `<p class="finding-detail llm"><span class="k">LLM:</span> ${escapeHtml(f.llm_explanation)}</p>` : ""}
        ${f.audit_note ? `<p class="finding-detail audit"><span class="k">Audit:</span> ${escapeHtml(f.audit_note)}</p>` : ""}
      </div>`;
    })
    .join("");
}

function renderHeatmap(report) {
  const list = el("heatmap-list");
  const signals = (report.maintainability || []).filter((s) => s.heat > 0);
  if (signals.length === 0) {
    list.innerHTML = `<p class="hint">No maintainability signals (is this a git repo? enable the heatmap checkbox).</p>`;
    return;
  }
  list.innerHTML = signals
    .map((s) => {
      const pct = Math.round(s.heat * 100);
      const coupled = (s.coupled_with || []).slice(0, 3).join(", ");
      const stale = s.last_changed_days != null ? `${s.last_changed_days}d old` : "—";
      return `
      <div class="heat-row">
        <div class="heat-path">${escapeHtml(s.path)}</div>
        <div class="heat-bar-wrap"><div class="heat-bar" style="width:${pct}%"></div></div>
        <div class="heat-meta">
          heat ${s.heat.toFixed(2)} · churn ${s.change_frequency} · ${s.todo_count} TODO · ${stale}
          ${coupled ? `<br/>↔ ${escapeHtml(coupled)}` : ""}
        </div>
      </div>`;
    })
    .join("");
}

function renderFiles(report) {
  const body = el("files-body");
  body.innerHTML = (report.files || [])
    .map(
      (f) => `
      <tr>
        <td class="mono">${escapeHtml(f.path)}</td>
        <td>${escapeHtml(f.kind)}</td>
        <td>${f.scanned ? "scanned" : escapeHtml(f.skip_reason || "skipped")}</td>
      </tr>`
    )
    .join("");
}

function renderReport(report) {
  currentReport = report;
  el("empty-state").classList.add("hidden");
  el("error-state").classList.add("hidden");
  el("results").classList.remove("hidden");
  renderGate(report);
  renderCards(report);
  renderFindings();
  renderHeatmap(report);
  renderFiles(report);
}

function showError(msg) {
  el("results").classList.add("hidden");
  el("empty-state").classList.add("hidden");
  const e = el("error-state");
  e.classList.remove("hidden");
  e.textContent = `Scan failed: ${msg}`;
}

function switchTab(name) {
  document.querySelectorAll(".tab").forEach((t) => t.classList.toggle("active", t.dataset.tab === name));
  document.querySelectorAll(".tab-panel").forEach((p) => p.classList.add("hidden"));
  el(`tab-${name}`).classList.remove("hidden");
}

function init() {
  fetch("/api/health")
    .then((r) => r.json())
    .then((h) => (el("footer-version").textContent = `Prodogy v${h.version}`))
    .catch(() => {});

  el("scan-form").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const btn = el("scan-btn");
    const original = btn.innerHTML;
    btn.disabled = true;
    btn.innerHTML = `<span class="spinner"></span>`;
    try {
      const path = el("path-input").value || ".";
      const maintain = el("maint-input").checked;
      const enrich = el("enrich-input").checked;
      const report = await runEnrichScan(path, maintain, enrich);
      renderReport(report);
    } catch (e) {
      showError(e.message);
    } finally {
      btn.disabled = false;
      btn.innerHTML = original;
    }
  });

  document.querySelectorAll(".tab").forEach((t) =>
    t.addEventListener("click", () => switchTab(t.dataset.tab))
  );
  document.querySelectorAll(".sev-filter").forEach((c) => c.addEventListener("change", renderFindings));
  el("text-filter").addEventListener("input", renderFindings);
}

document.addEventListener("DOMContentLoaded", init);
