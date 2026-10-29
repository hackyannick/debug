// Magic Box – Web-Oberfläche (ohne Frameworks, läuft komplett offline)
"use strict";

const $ = (sel) => document.querySelector(sel);
const state = { jobs: new Map(), current: null, status: null, ai: "", aiLen: 0, log: [], logTotal: 0, loading: false };
const cpLen = (t) => [...t].length;  // Länge in Unicode-Zeichen – so zählt auch der Server

const STATUS = {
  queued: ["⏳", "wartet"], running: ["⚙️", "läuft"], done: ["✅", "fertig"],
  error: ["❌", "Fehler"], cancelled: ["⛔", "abgebrochen"],
};
const RISK_ICON = { hoch: "🔴", mittel: "🟠", gering: "🟢" };

// ------------------------------------------------------------------ API
async function api(path, opts = {}) {
  const headers = { "X-MagicBox": "1", ...(opts.headers || {}) };
  if (opts.json !== undefined) {
    headers["Content-Type"] = "application/json";
    opts.body = JSON.stringify(opts.json);
  }
  const res = await fetch(path, { ...opts, headers, credentials: "same-origin" });
  const data = res.headers.get("Content-Type")?.includes("json") ? await res.json() : await res.text();
  if (res.status === 401) {
    needLogin(data);
    throw new Error("Anmeldung erforderlich");
  }
  if (!res.ok) throw new Error(data?.error || `HTTP ${res.status}`);
  return data;
}

function toast(msg, err = false) {
  const el = document.createElement("div");
  el.className = "toast" + (err ? " err" : "");
  el.textContent = msg;
  $("#toasts").append(el);
  setTimeout(() => el.remove(), err ? 9000 : 4500);
}

function el(tag, cls, text) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text !== undefined) e.textContent = text;
  return e;
}

function fmtSize(n) {
  const u = ["B", "KB", "MB", "GB"];
  let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return `${i ? n.toFixed(1) : n} ${u[i]}`;
}

function fmtTime(ts) {
  if (!ts) return "";
  return new Date(ts * 1000).toLocaleString("de-DE", { dateStyle: "short", timeStyle: "short" });
}

// ------------------------------------------------------------------ Status / Werkzeuge
async function loadStatus() {
  const s = await api("/api/status");
  state.status = s;
  $("#opt-profile").value = s.profile;
  const llm = $("#pill-llm");
  llm.querySelector(".label").textContent = s.llm.enabled ? `${s.llm.model} @ ${s.llm.url}` : "KI aus";
  llm.querySelector(".dot").className = "dot " + (s.llm.enabled ? "" : "off");
  const ok = s.tools.filter((t) => t.path).length;
  $("#pill-tools").querySelector(".label").textContent = `🧰 Werkzeuge ${ok}/${s.tools.length}`;
  const user = $("#user");
  user.classList.toggle("hidden", s.user.method === "none");
  $("#user-name").textContent = s.user.method === "token" ? "🔑 Zugangsschlüssel" : `👤 ${s.user.name}`;
  $("#user-name").title = s.auth_mode === "token" ? "" : `Angemeldet über Ory (${s.auth_mode})`;
  renderTools(s.tools);
  renderFoot();
  if (s.llm.enabled) checkLLM(true);
}

// Fußzeile wie beim OWA-Gate: Version · Modell · Uhrzeit (UTC)
function renderFoot() {
  const s = state.status;
  if (!s) return;
  const now = new Date().toISOString().slice(0, 16).replace("T", " ");
  $("#foot").textContent = `Magic Box v${s.version} · ${s.llm.enabled ? s.llm.model : "KI aus"} · ${now} UTC`;
}
setInterval(renderFoot, 30000);

async function checkLLM(silent) {
  const dot = $("#pill-llm .dot");
  dot.className = "dot";
  try {
    const r = await api("/api/llm/check", { method: "POST" });
    dot.className = "dot " + (r.ok ? "ok" : "bad");
    $("#pill-llm").title = r.message;
    if (!silent) toast(r.message, !r.ok);
    return r;
  } catch (e) {
    dot.className = "dot bad";
    if (!silent) toast(e.message, true);
  }
}

function renderTools(list) {
  const body = $("#tools-body");
  body.replaceChildren();
  for (const t of list) {
    const tr = el("tr");
    tr.append(el("td", "", t.path ? "✅" : "➖"), el("td", "", t.name), el("td", "muted", t.purpose));
    const td = el("td");
    if (t.path) td.append(el("span", "muted", t.path));
    else td.append(el("code", "", t.hint));
    tr.append(td);
    body.append(tr);
  }
}

// ------------------------------------------------------------------ Aufträge
function upsertJob(job) {
  const old = state.jobs.get(job.id);
  if (old && (job.rev ?? 0) < (old.rev ?? 0)) return;  // veralteter Stand (z. B. späte Antwort) – verwerfen
  state.jobs.set(job.id, { ...(old || {}), ...job });
  renderJobs();
  if (state.current === job.id) renderJob();
}

function renderJobs() {
  const list = $("#jobs");
  const jobs = [...state.jobs.values()].sort((a, b) => b.created - a.created);
  $("#job-count").textContent = jobs.length || "";
  list.replaceChildren();
  for (const j of jobs) {
    const li = el("li", "job-item" + (j.id === state.current ? " active" : ""));
    li.dataset.id = j.id;
    const icon = j.status === "done" ? RISK_ICON[j.risk] || "✅" : STATUS[j.status]?.[0] || "•";
    li.append(el("span", "ico", icon), el("span", "nm", j.name));
    let sub = j.status === "done" ? j.description
      : j.status === "queued" ? "in Warteschlange" : `${STATUS[j.status]?.[1] || j.status} · ${j.stage || ""}`;
    if (j.status === "error") sub = j.error || "Fehler";
    li.append(el("span", "sub", `${sub} · ${fmtTime(j.created)}`));
    if (j.status === "running") {
      const mini = el("div", "mini");
      const bar = el("div");
      bar.style.width = `${j.progress || 0}%`;
      mini.append(bar);
      li.append(mini);
    }
    li.addEventListener("click", () => selectJob(j.id));
    list.append(li);
  }
}

async function selectJob(id, switchTabs = true) {
  state.current = id;
  location.hash = id;
  state.loading = true;  // Live-Ereignisse bis zur Antwort ignorieren – Lücken werden danach erkannt
  renderJobs();
  try {
    const detail = await api(`/api/jobs/${id}`);
    if (state.current !== id) return;  // inzwischen anderer Auftrag gewählt
    state.ai = detail.ai || "";
    state.aiLen = cpLen(state.ai);
    state.log = detail.log || [];
    state.logTotal = detail.log_total ?? state.log.length;
    upsertJob(detail);
  } catch (e) {
    toast(e.message, true);
  } finally {
    if (state.current === id) state.loading = false;
  }
  renderJob(true, switchTabs);
}

function renderJob(fresh = false, switchTabs = fresh) {
  const j = state.jobs.get(state.current);
  $("#empty").classList.toggle("hidden", !!j);
  $("#job").classList.toggle("hidden", !j);
  if (!j) return;
  const followUp = !!j.ask && ["queued", "running"].includes(j.status);  // Nachfrage zu fertigem Bericht

  $("#job-name").textContent = j.name;
  const meta = $("#job-meta");
  meta.replaceChildren();
  meta.append(`${j.description || "…"} · ${fmtSize(j.size)}${j.created_by ? ` · von ${j.created_by}` : ""} · `);
  const sha = el("code", "", j.sha256);
  sha.title = "Klicken zum Kopieren";
  sha.addEventListener("click", () => navigator.clipboard?.writeText(j.sha256).then(() => toast("SHA-256 kopiert")));
  meta.append(sha);

  const chips = $("#job-chips");
  chips.replaceChildren();
  const chip = (cls, text) => chips.append(el("span", "chip " + cls, text));
  chip("neutral", j.profile === "malware" ? "🛡️ Malware-Profil" : "📘 Software-Doku (ohne Malware-Prüfung)");
  if (j.status === "done") {
    if (j.risk) chip(j.risk, `${RISK_ICON[j.risk] || ""} Risiko ${j.risk}`);
    if (j.llm_verdict) {
      const v = j.llm_verdict;
      chip(/bösartig|gefährlich/.test(v) ? "bad" : /verdächtig|auffällig/.test(v) ? "warn" : "good", `🤖 KI: ${v}`);
    }
    for (const d of j.detections || []) chip("bad", `YARA: ${d}`);
    const c = j.counts || {};
    if (c.high || c.medium) chip("neutral", `${c.high || 0} hoch · ${c.medium || 0} mittel · ${c.low || 0} niedrig`);
    if (j.ioc_count) chip("info", `${j.ioc_count} IOCs`);
    if (j.llm_error) chip("warn", "ohne KI-Text");
    if (j.qa_count) chip("info", `❓ ${j.qa_count} ${j.qa_count === 1 ? "Frage" : "Fragen"} beantwortet`);
    if (j.notice) chip("warn", `⚠ ${j.notice}`);
  } else if (followUp) {
    chip("info", j.status === "queued" ? "❓ Frage wartet" : "❓ KI beantwortet deine Frage");
  } else {
    chip("neutral", `${STATUS[j.status]?.[0] || ""} ${STATUS[j.status]?.[1] || j.status}`);
    if (j.question) chip("info", "❓ mit Frage an die KI");
  }
  renderSteps(j);
  renderAsk(j);

  const done = j.status === "done";
  const hasReport = done || (followUp && !!j.finished);
  const base = `/api/jobs/${j.id}`;
  $("#act-open").href = `${base}/report`;
  $("#act-open").classList.toggle("disabled", !hasReport);
  $("#act-download").disabled = !hasReport;
  $("#dl-md").href = `${base}/report.md`;
  $("#dl-json").href = `${base}/analysis.json`;
  $("#dl-iocs").href = `${base}/iocs.csv`;
  $("#act-cancel").classList.toggle("hidden", !["queued", "running"].includes(j.status));
  $("#act-cancel").textContent = followUp ? "⛔ Frage abbrechen" : "⛔ Abbrechen";
  $("#act-rerun").classList.toggle("hidden", ["queued", "running"].includes(j.status));
  $("#act-delete").disabled = j.status === "running";

  const running = j.status === "running" || j.status === "queued";
  $("#job-progress").classList.toggle("hidden", !running);
  $("#job-bar").style.width = `${Math.max(3, j.progress || 0)}%`;
  $("#job-track").classList.toggle("busy", j.status === "running");
  $("#job-pct").textContent = `${j.progress || 0} %`;
  $("#job-stage").textContent = j.status === "queued" ? "wartet auf einen freien Platz" : j.stage || "";
  updateAiWait();

  const frame = $("#report-frame");
  const ph = $("#report-placeholder");
  if (hasReport) {
    const src = `${base}/report?t=${j.finished}`;
    if (frame.dataset.src !== src) {
      frame.src = src;
      frame.dataset.src = src;
    }
    frame.classList.remove("hidden");
    ph.classList.add("hidden");
  } else {
    frame.classList.add("hidden");
    frame.dataset.src = "";
    ph.classList.remove("hidden");
    ph.textContent = j.status === "error" ? `❌ ${j.error}` : j.status === "cancelled" ? "⛔ Abgebrochen"
      : running ? "⏳ Analyse läuft … im Tab „KI live“ kannst du zusehen." : "";
  }
  if (fresh) {
    $("#ai-text").textContent = state.ai || (running ? "" : "(keine KI-Ausgabe)");
    if (followUp) $("#ai-text").scrollTop = $("#ai-text").scrollHeight;  // neue Antwort folgt unten
    $("#log-text").textContent = state.log.join("\n");
    if (switchTabs && running && j.status === "running") switchTab("ai");
    else if (switchTabs && done) switchTab("report");
  }
}

// Schritt-Anzeige (wie Captcha → Login → 2FA beim OWA-Gate): Analyse → KI → Bericht
const STEP_LABELS = ["Analyse", "KI", "Bericht"];
function renderSteps(j) {
  const p = j.progress || 0;
  const ki = /^KI/.test(j.stage || "");
  let current;
  if (j.status === "done") current = 3;
  else if (j.ask) current = p >= 95 ? 2 : 1;
  else if (j.status === "queued") current = 0;
  else if (["error", "cancelled"].includes(j.status)) current = p >= 95 ? 2 : p >= 45 ? 1 : 0;
  else current = ki ? 1 : p >= 95 ? 2 : 0;
  const failed = ["error", "cancelled"].includes(j.status);
  const noKi = j.status === "done" && !j.model;
  document.querySelectorAll("#job-steps li").forEach((li, i) => {
    li.className = i < current ? "done" : i === current ? (failed ? "failed" : "active") : "";
    if (i === current && j.status === "running") li.classList.add("busy");
    if (i === 1 && noKi) li.className = "skipped";
    li.querySelector(".lbl").textContent = i === 1 && j.ask ? "KI · Frage" : STEP_LABELS[i];
  });
  $("#job-level").textContent = j.status === "done" ? "abgeschlossen"
    : failed ? (j.status === "error" ? "Fehler" : "abgebrochen")
    : `${j.ask ? "Nachfrage · " : ""}Schritt ${Math.min(current + 1, 3)} von 3`;
}

function renderAsk(j) {
  const input = $("#ask-input");
  const btn = $("#ask-btn");
  const llm = state.status?.llm.enabled;
  const ready = j.status === "done" && llm;
  input.disabled = btn.disabled = !ready;
  btn.textContent = j.ask && ["queued", "running"].includes(j.status) ? "⏳ …" : "Fragen";
  input.placeholder = !llm ? "Die KI ist in den Einstellungen deaktiviert."
    : ready ? "Frage zur Datei, z. B. „Suche die Funktion, die die Daten verschlüsselt, und erkläre sie verständlich.“ (Strg+Enter)"
    : j.status === "done" || j.ask ? "Die KI beantwortet gerade eine Frage …"
    : ["queued", "running"].includes(j.status) ? "Fragen kannst du stellen, sobald die Analyse fertig ist."
    : "Fragen gehen nur zu fertigen Analysen – ggf. „↻ Neu“ starten.";
}

async function askQuestion() {
  const question = $("#ask-input").value.trim();
  if (!question || !state.current) return;
  try {
    upsertJob(await api(`/api/jobs/${state.current}/ask`, { method: "POST", json: { question } }));
    $("#ask-input").value = "";
    switchTab("ai");
  } catch (e) { toast(e.message, true); }
}

function switchTab(name) {
  document.querySelectorAll(".tab").forEach((t) => t.classList.toggle("active", t.dataset.tab === name));
  document.querySelectorAll(".panel").forEach((p) => p.classList.toggle("active", p.dataset.panel === name));
}

// Hinweis im KI-Tab, solange das Modell (noch) nichts schreibt – z. B. beim ersten Laden in den Speicher
function updateAiWait() {
  const j = state.jobs.get(state.current);
  const box = $("#ai-wait");
  const llmPhase = j && j.status === "running" && /^KI/.test(j.stage || "");
  const idle = (Date.now() - (state.lastTokenAt || 0)) / 1000;
  if (!llmPhase || idle < 4) { box.classList.add("hidden"); return; }
  const since = Math.round(Math.min(idle, (Date.now() - (state.llmSince || Date.now())) / 1000));
  $("#ai-wait-text").textContent = since < 20
    ? "Das Sprachmodell liest die Analyse-Fakten ein …"
    : `Warte auf das Sprachmodell (seit ${since} s) – beim ersten Aufruf lädt Ollama das Modell in den Speicher, ` +
      "bei großen Modellen und langen Eingaben dauert das auf CPU 1–3 Minuten.";
  box.classList.remove("hidden");
}
setInterval(updateAiWait, 1000);

function appendTo(pre, text) {
  const atBottom = pre.scrollTop + pre.clientHeight >= pre.scrollHeight - 30;
  if (pre.textContent.startsWith("(keine KI-Ausgabe)")) pre.textContent = "";
  pre.append(text);
  if (atBottom) pre.scrollTop = pre.scrollHeight;
}

// ------------------------------------------------------------------ Upload
function uploadAll(files) {
  files = [...files];
  if (!files.length) return;
  const question = $("#opt-question").value.trim();
  files.forEach((f) => upload(f, question));
  $("#opt-question").value = "";  // die Frage gilt für genau diese Datei(en)
}

function upload(file, question = "") {
  const params = new URLSearchParams({ name: file.name, profile: $("#opt-profile").value });
  const pw = $("#opt-password").value.trim();
  if (pw) params.set("password", pw);
  if (question) params.set("question", question);
  const row = el("div", "upload", `⬆ ${file.name} (${fmtSize(file.size)})`);
  const wrap = el("div", "bar-wrap");
  const bar = el("div");
  wrap.append(bar);
  row.append(wrap);
  $("#uploads").append(row);

  const xhr = new XMLHttpRequest();
  xhr.open("POST", `/api/jobs?${params}`);
  xhr.setRequestHeader("X-MagicBox", "1");
  xhr.setRequestHeader("Content-Type", "application/octet-stream");
  xhr.upload.onprogress = (e) => { if (e.lengthComputable) bar.style.width = `${(100 * e.loaded) / e.total}%`; };
  xhr.onload = () => {
    row.remove();
    let data = {};
    try { data = JSON.parse(xhr.responseText); } catch { /* leer */ }
    if (xhr.status === 201) {
      upsertJob(data);
      selectJob(data.id);
    } else if (xhr.status === 401) {
      needLogin(data);
    } else {
      toast(`${file.name}: ${data.error || "Upload fehlgeschlagen"}`, true);
    }
  };
  xhr.onerror = () => { row.remove(); toast(`${file.name}: Verbindung fehlgeschlagen`, true); };
  xhr.send(file);
}

function setupDrop() {
  const drop = $("#drop");
  const input = $("#file-input");
  input.addEventListener("change", () => { uploadAll(input.files); input.value = ""; });
  drop.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); input.click(); } });
  // Dateien dürfen überall ins Fenster fallen
  window.addEventListener("dragover", (e) => { e.preventDefault(); drop.classList.add("over"); });
  window.addEventListener("dragleave", (e) => { if (!e.relatedTarget) drop.classList.remove("over"); });
  window.addEventListener("drop", (e) => {
    e.preventDefault();
    drop.classList.remove("over");
    const items = [...(e.dataTransfer?.items || [])];
    if (items.some((i) => i.webkitGetAsEntry?.()?.isDirectory)) {
      toast("Ordner bitte als ZIP hochladen (oder auf dem Server den Drop-Ordner nutzen).", true);
    }
    uploadAll([...(e.dataTransfer?.files || [])].filter((f) => f.size > 0 || f.type));
  });
}

// ------------------------------------------------------------------ Live-Ereignisse
function connectEvents() {
  const es = new EventSource("/api/events");
  es.onmessage = (msg) => {
    const ev = JSON.parse(msg.data);
    if (ev.type === "job") {
      const before = state.jobs.get(ev.job.id);
      if (ev.job.id === state.current && /^KI/.test(ev.job.stage || "") && !/^KI/.test(before?.stage || "")) {
        state.llmSince = Date.now();
      }
      upsertJob(ev.job);
      if (before && before.status !== ev.job.status && ev.job.id === state.current) {
        if (ev.job.status === "running") {
          selectJob(ev.job.id, false);  // Stand neu laden – eine Nachfrage setzt KI-Text und Protokoll fort
          switchTab("ai");
        }
        if (ev.job.status === "done") switchTab("report");
      }
      if (before?.status === "running" && ev.job.status === "done") {
        toast(before.ask ? `✅ Antwort zu ${ev.job.name} steht im Bericht` : `✅ ${ev.job.name} ist fertig`);
      }
    } else if (ev.type === "token" && ev.id === state.current && !state.loading) {
      const chars = [...ev.text];
      const pos = ev.pos ?? state.aiLen;
      if (pos > state.aiLen) { selectJob(ev.id, false); return; }  // Lücke → Stand neu laden
      const fresh = chars.slice(state.aiLen - pos).join("");
      state.aiLen = Math.max(state.aiLen, pos + chars.length);
      if (fresh) { state.ai += fresh; appendTo($("#ai-text"), fresh); }
      // Abschnitts-Überschriften ("──── …") zählen nicht als Lebenszeichen des Modells
      if (ev.text.trim() && !ev.text.includes("────")) state.lastTokenAt = Date.now();
      else state.llmSince = Date.now();
      updateAiWait();
    } else if (ev.type === "log" && ev.id === state.current && !state.loading) {
      const n = ev.n ?? state.logTotal;
      if (n > state.logTotal) { selectJob(ev.id, false); return; }  // Lücke → Stand neu laden
      if (n < state.logTotal) return;  // schon enthalten
      state.logTotal = n + 1;
      appendTo($("#log-text"), ($("#log-text").textContent ? "\n" : "") + ev.line);
    } else if (ev.type === "deleted") {
      state.jobs.delete(ev.id);
      if (state.current === ev.id) { state.current = null; location.hash = ""; }
      renderJobs();
      renderJob();
    }
  };
  es.onerror = () => { $("#pill-llm .dot").className = "dot"; };
}

// ------------------------------------------------------------------ Aktionen
function setupActions() {
  document.querySelectorAll(".tab").forEach((t) => t.addEventListener("click", () => switchTab(t.dataset.tab)));
  $("#act-download").addEventListener("click", (e) => { e.stopPropagation(); $("#download-list").classList.toggle("hidden"); });
  document.addEventListener("click", () => $("#download-list").classList.add("hidden"));
  $("#act-cancel").addEventListener("click", () => api(`/api/jobs/${state.current}/cancel`, { method: "POST" }).catch((e) => toast(e.message, true)));
  $("#act-rerun").addEventListener("click", async () => {
    try {
      state.ai = ""; state.log = [];
      upsertJob(await api(`/api/jobs/${state.current}/rerun`, { method: "POST" }));
      renderJob(true);
    } catch (e) { toast(e.message, true); }
  });
  $("#act-delete").addEventListener("click", async () => {
    const j = state.jobs.get(state.current);
    if (!j || !confirm(`„${j.name}“ inkl. Probe und Bericht löschen?`)) return;
    try { await api(`/api/jobs/${j.id}`, { method: "DELETE" }); } catch (e) { toast(e.message, true); }
  });
  $("#ask-form").addEventListener("submit", (e) => { e.preventDefault(); askQuestion(); });
  $("#ask-input").addEventListener("keydown", (e) => {
    if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) { e.preventDefault(); askQuestion(); }
  });
  $("#pill-llm").addEventListener("click", () => checkLLM(false));
  $("#pill-tools").addEventListener("click", () => $("#dlg-tools").showModal());
  $("#tools-close").addEventListener("click", () => $("#dlg-tools").close());
}

// ------------------------------------------------------------------ Einstellungen
async function openSettings() {
  const s = await api("/api/settings");
  const form = $("#settings-form");
  for (const [k, v] of Object.entries(s)) {
    const field = form.elements.namedItem(k);
    if (!field) continue;
    if (field.type === "checkbox") field.checked = !!v;
    else if (Array.isArray(v)) field.value = v.join("\n");
    else {
      if (field.tagName === "SELECT" && ![...field.options].some((o) => o.value === String(v))) {
        field.append(new Option(String(v), String(v)));
      }
      field.value = v;
    }
  }
  $("#check-result").textContent = "";
  $("#dlg-settings").showModal();
}

function formData() {
  const form = $("#settings-form");
  const out = {};
  for (const field of form.elements) {
    if (!field.name) continue;
    if (field.type === "checkbox") out[field.name] = field.checked;
    else if (field.type === "number") out[field.name] = Number(field.value);
    else out[field.name] = field.value;
  }
  return out;
}

function setupSettings() {
  $("#btn-settings").addEventListener("click", () => openSettings().catch((e) => toast(e.message, true)));
  $("#settings-cancel").addEventListener("click", () => $("#dlg-settings").close());
  $("#settings-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    try {
      await api("/api/settings", { method: "PUT", json: formData() });
      $("#dlg-settings").close();
      toast("Einstellungen gespeichert – gelten ab dem nächsten Auftrag.");
      loadStatus();
    } catch (err) { toast(err.message, true); }
  });
  $("#btn-check").addEventListener("click", async () => {
    $("#check-result").textContent = "⏳ prüfe …";
    try {
      await api("/api/settings", { method: "PUT", json: formData() });
      const r = await api("/api/llm/check", { method: "POST" });
      $("#check-result").textContent = (r.ok ? "✅ " : "❌ ") + r.message;
    } catch (err) { $("#check-result").textContent = "❌ " + err.message; }
  });
  $("#btn-models").addEventListener("click", async () => {
    try {
      await api("/api/settings", { method: "PUT", json: formData() });
      const r = await api("/api/llm/models");
      const dl = $("#model-list");
      dl.replaceChildren(...r.models.map((m) => new Option(m, m)));
      $("#check-result").textContent = r.error ? "❌ " + r.error : `✅ ${r.models.length} Modell(e): ${r.models.join(", ")}`;
    } catch (err) { $("#check-result").textContent = "❌ " + err.message; }
  });
}

// ------------------------------------------------------------------ Login
function needLogin(data) {
  // Ory (Kratos/Oathkeeper): zum Login-Flow weiterleiten; sonst Zugangsschlüssel abfragen
  if (data && data.login_url) location.href = data.login_url;
  else if (data && data.mode === "token") showLogin();
  else if (data && data.mode) toast(data.error || "Anmeldung erforderlich", true);
  // 401 kam nicht von der Magic Box (z. B. Oathkeeper, Sitzung abgelaufen): Seite neu laden,
  // dann leitet der Proxy zum Login weiter
  else location.reload();
}

function showLogin() {
  const dlg = $("#dlg-login");
  if (!dlg.open) dlg.showModal();
}

function setupLogin() {
  $("#login-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const token = e.target.elements.token.value;
    const res = await fetch("/api/login", {
      method: "POST", headers: { "Content-Type": "application/json", "X-MagicBox": "1" }, body: JSON.stringify({ token }),
    });
    if (res.ok) { $("#dlg-login").close(); start(); } else toast("Falscher Zugangsschlüssel", true);
  });
}

// ------------------------------------------------------------------ Start
let started = false;
async function start() {
  try {
    await loadStatus();
  } catch (e) {
    if (!/Anmeldung/.test(e.message)) toast(e.message, true);
    return;
  }
  const jobs = await api("/api/jobs");
  jobs.forEach((j) => state.jobs.set(j.id, j));
  renderJobs();
  if (!started) { connectEvents(); started = true; }
  const fromHash = location.hash.slice(1);
  if (fromHash && state.jobs.has(fromHash)) selectJob(fromHash);
  else renderJob();
}

setupDrop();
setupActions();
setupSettings();
setupLogin();
start();
