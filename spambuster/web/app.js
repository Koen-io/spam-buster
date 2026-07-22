// Spam Buster dashboard — Nightwatch
let STATE = null;
let CURRENT_TAB = "overview";
let connectPoll = null;

const $ = (id) => document.getElementById(id);
async function api(p, o) { return (await fetch(p, o)).json(); }
async function post(p, b) {
  return api(p, {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify(b || {})});
}
function toast(m) { const t = $("toast"); t.textContent = m; t.classList.add("show"); setTimeout(() => t.classList.remove("show"), 2600); }
function ago(ts) { if (!ts) return t("st.never"); const s = Math.max(0, Math.floor(Date.now()/1000 - ts));
  if (s < 60) return t("ago.s", s); if (s < 3600) return t("ago.m", Math.floor(s/60)); return t("ago.h", Math.floor(s/3600)); }
function esc(s) { return (s||"").replace(/[&<>"]/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c])); }

// ---------------- tabs
function showTab(name) {
  CURRENT_TAB = name;
  document.querySelectorAll(".tab-panel").forEach(p => p.classList.add("hidden"));
  $("tab-" + name).classList.remove("hidden");
  document.querySelectorAll(".tab").forEach(t => t.classList.toggle("active", t.dataset.tab === name));
  if (name === "reports") loadReports();
  if (name === "protection") loadProtection();
  if (name === "quarantine") loadQuarantine();
  if (name === "settings") { fillSettings(); loadLists(); loadThreat(); }
}

// ---------------- state
async function refresh() { STATE = await api("/api/state"); applyLang(); render(); }
function applyLang() {
  if (STATE && STATE.language) setLang(STATE.language);
  applyI18n();
  document.querySelectorAll("[data-lang]").forEach(c =>
    c.classList.toggle("active", c.dataset.lang === (STATE ? STATE.language : "en")));
}
function modeName(m) { return t(m === "auto" ? "mode.auto" : m === "suggest" ? "mode.suggest" : "mode.observing"); }
function render() {
  const s = STATE;
  $("version").textContent = s.version;
  const mode = s.detection.mode;
  const paused = s.engine.paused;
  $("mode-badge").textContent = paused ? t("mode.paused") : modeName(mode);

  $("status-mode").textContent = paused ? t("mode.paused") : modeName(mode);
  $("status-dot").className = "dot" + (paused ? " paused" : "");
  const acctInfo = s.engine.accounts || {};
  const connected = s.accounts.filter(a => a.connected).length;
  let detail = t("status.detail", connected, s.accounts.length, ago(s.engine.last_scan));
  if (s.engine.last_error) detail += ` · ⚠ ${esc(s.engine.last_error)}`;
  $("status-detail").innerHTML = detail;
  document.querySelectorAll(".chip[data-mode]").forEach(c => {
    if (c.closest(".acct")) return;  // per-account chips handled separately
    c.classList.toggle("active", c.dataset.mode === mode);
  });
  $("pause-btn").textContent = paused ? t("nav.resume") : t("nav.pause");

  // onboarding banner: only when nothing is set up yet
  $("onboard").classList.toggle("hidden", s.accounts.length !== 0);

  // connection-lost / scan-error warning
  const problems = [];
  s.accounts.forEach(a => {
    const info = acctInfo[a.id] || {};
    if (!a.connected) problems.push(t("warn.expired", a.email));
    else if (info.error) problems.push(`${a.email} — ${info.error}`);
  });
  const wb = $("warn-banner");
  if (s.accounts.length && problems.length) {
    wb.innerHTML = `<div><div class="wtitle">${t("warn.title", problems.length, problems.length>1?"es":"")}</div>
        <div class="wsub">${t("warn.sub", problems.map(esc).join(" · "))}</div></div>
      <button class="btn" onclick="showTab('settings')">${t("warn.fix")}</button>`;
    wb.classList.remove("hidden");
  } else { wb.classList.add("hidden"); }

  const st = s.stats;
  $("stat-row").innerHTML = [
    [t("stat.learned"), st.spam_examples], [t("stat.autodeleted"), st.auto_deleted],
    [t("stat.inquarantine"), st.auto_deleted_active], [t("stat.knownsenders"), st.known_senders + st.known_domains],
  ].map(([l,n]) => `<div class="stat"><div class="n">${n}</div><div class="l">${l}</div></div>`).join("");

  const sug = s.suggestions || [];
  $("ov-suggestions").innerHTML = sug.length ? sug.map(x => `
    <div class="row"><div class="main"><div>${esc(x.subject || "(no subject)")}</div>
      <div class="sub">${esc(x.sender || "")}</div></div>
      <div style="display:flex;gap:6px;align-items:center;flex-shrink:0">
        <span class="pill spam">${x.confidence}%</span>
        <button class="btn tiny ghost" data-sender="${esc(x.sender||'')}" data-subject="${esc(x.subject||'')}" onclick="notSpam(this)">${t("com.notspam")}</button>
      </div></div>`).join("")
    : `<div class="muted">${st.spam_examples ? t("sug.nothing") : t("sug.learning")}</div>`;

  $("ov-accounts").innerHTML = s.accounts.length ? s.accounts.map(a => `
    <div class="row"><div class="main"><div>${esc(a.email)}</div>
      <div class="sub">${acctInfo[a.id]?.junk_count ?? "–"} ${t("st.injunk")}</div></div>
      <span class="pill ${a.connected ? "ham":"warn"}">${a.connected ? t("st.connected"):t("st.notconnected")}</span></div>`).join("")
    : `<div class="muted">—</div>`;

  // This-week + 14-day trend now live on the Overview (first thing you see).
  loadDigest(); loadTrends();

  const lc = s.updates.last_checked ? new Date(s.updates.last_checked).toLocaleString() : t("st.never");
  if ($("update-line")) $("update-line").textContent = t("set.lastcheck", lc);
}

// ---------------- actions
async function togglePause() { await post("/api/pause", {paused: !STATE.engine.paused}); refresh(); }
async function scanNow() { await post("/api/scan"); toast(t("toast.scanning")); }
async function setLanguage(l) {
  await post("/api/settings", {language: l});
  await refresh();
  const map = {reports: loadReports, protection: loadProtection, quarantine: loadQuarantine};
  if (CURRENT_TAB === "settings") { fillSettings(); loadLists(); }
  else if (map[CURRENT_TAB]) map[CURRENT_TAB]();
}
async function setMode(mode) { await post("/api/settings", {detection: {...STATE.detection, mode}}); toast("Mode: " + mode); refresh(); }

// ---------------- UPDATE FLOW (animated popups)
function openUpdateFlow() {
  openModal(`<div class="upd-center">
      <div class="spinner"></div>
      <div class="upd-title">Checking for updates…</div>
      <div class="muted">Contacting the update server</div>
    </div>`);
  post("/api/updates/check").then(r => {
    if (r.available) showWhatsNew(r); else showUpToDate(r);
  }).catch(() => showUpToDate({current: STATE?.version}));
}

function showUpToDate(r) {
  openModal(`<div class="upd-center">
      <div class="checkmark"><svg viewBox="0 0 60 60"><path d="M14 32 L26 44 L47 18"/></svg></div>
      <div class="upd-title">You’re up to date</div>
      <div class="upd-version">Spam Buster v${esc(r.current || STATE.version)}</div>
      <div class="modal-actions"><button class="btn primary" onclick="closeModal()">Great</button></div>
    </div>`);
}

function showWhatsNew(r) {
  const notes = (r.notes && r.notes.length) ? r.notes : ["Improvements and fixes."];
  openModal(`<div>
      <div class="upd-center" style="padding-bottom:2px">
        <div class="upd-title">Update available 🎉</div>
        <div class="upd-version">v${esc(r.current)} → v${esc(r.new_version || "")}</div>
      </div>
      <div class="whatsnew">
        <div class="card-label">What’s new</div>
        <ul>${notes.map(n => `<li>${esc(n)}</li>`).join("")}</ul>
      </div>
      <div class="modal-actions">
        <button class="btn ghost" onclick="closeModal()">Not now</button>
        <button class="btn primary" onclick="applyUpdate()">Update now</button>
      </div>
    </div>`);
}

async function applyUpdate() {
  openModal(`<div class="upd-center">
      <div class="spinner"></div>
      <div class="upd-title">Updating…</div>
      <div class="muted">Downloading and installing the new version</div>
    </div>`);
  const r = await post("/api/updates/apply");
  if (r.status === "ok") {
    openModal(`<div class="upd-center">
        <div class="checkmark"><svg viewBox="0 0 60 60"><path d="M14 32 L26 44 L47 18"/></svg></div>
        <div class="upd-title">Updated!</div>
        <div class="upd-version">Now on v${esc(r.version)} · restarting…</div></div>`);
    setTimeout(() => location.reload(), 4500);
  } else {
    toast(r.message || "Update failed"); closeModal();
  }
}

async function notSpam(btn) {
  const sender = btn.dataset.sender || "", subject = btn.dataset.subject || "";
  const domain = btn.dataset.domain || "", account = btn.dataset.account || "";
  await post("/api/notspam", {sender, subject, sender_domain: domain, account_id: account});
  toast(t("toast.notspam"));
  const row = btn.closest(".row"); if (row) row.style.display = "none";
  refresh();
}

// ---------------- reports
async function loadReports() {
  const r = await api("/api/reports"); const rules = r.rules;
  const m = r.model || {};
  const mline = $("model-line");
  if (mline) mline.textContent = m.ready
    ? t("model.active", m.examples) : t("model.warming", m.examples||0, m.min||15);
  $("rep-rules").innerHTML = rules.auto_rules.length ? rules.auto_rules.map(x => `
    <div class="row"><div class="main"><div>${esc(x.text)}</div><div class="sub">${esc(x.evidence)}</div></div>
      <div style="display:flex;gap:6px;align-items:center;flex-shrink:0">
        <span class="pill spam">auto-delete</span>
        <button class="btn tiny ghost" onclick="openRuleEmail('${esc(x.type||'')}','${esc(x.key||'')}')">${t("com.openmail")}</button>
        <button class="btn tiny" data-type="${esc(x.type||'')}" data-key="${esc(x.key||'')}" onclick="trustRule(this)" title="${t('rule.trusttip')}">${t("com.friend")}</button>
        <button class="btn tiny ghost" data-type="${esc(x.type||'')}" data-key="${esc(x.key||'')}" onclick="undoRule(this)">${t("rule.undo")}</button>
      </div></div>`).join("")
    : `<div class="muted">No firm rules yet. Keep deleting spam unread and rules will appear here.</div>`;
  $("rep-words").innerHTML = rules.spammy_words.length ? rules.spammy_words.slice(0,20).map(w =>
    `<span class="pill spam" style="margin:3px;display:inline-block">${esc(w.word)} ${Math.round(w.ratio*100)}%</span>`).join("")
    : `<div class="muted">Nothing yet.</div>`;
  $("rep-events").innerHTML = r.events.length ? r.events.slice(0,40).map(e => `
    <div class="row"><div class="main"><div>${esc(e.subject || "(no subject)")}</div>
      <div class="sub">${esc(e.sender || "")} · ${ago(e.ts)}</div></div>
      <div style="display:flex;gap:6px;align-items:center;flex-shrink:0">
        ${e.corrected ? `<span class="pill" title="${t('act.correctedtip')}">${t('act.corrected')}</span>` : ""}
        <span class="pill ${e.label === "spam" ? "spam" : (e.label === "ham" ? "ham" : "warn")}">${labelFor(e.kind)}</span>
      </div></div>`).join("")
    : `<div class="muted">No activity yet.</div>`;
  const h = r.hint, hb = $("reports-hint");
  if (hb) {
    if (h) {
      const msg = h.type === "enable_auto" ? t("hint.enable", (STATE.stats||{}).spam_examples||0) : t("hint.lower", h.to);
      const btn = h.type === "enable_auto"
        ? `<button class="btn primary" onclick="setMode('auto')">${t("mode.auto")}</button>`
        : `<button class="btn primary" onclick="applyThreshold(${h.to})">${t("hint.apply")}</button>`;
      hb.innerHTML = `<div>💡 ${esc(msg)}</div>${btn}`; hb.classList.remove("hidden");
    } else hb.classList.add("hidden");
  }
  loadFlagged();
}

// ---- undo / trust an auto-delete rule
async function undoRule(btn) {
  await post("/api/rule/undo", {type: btn.dataset.type, key: btn.dataset.key});
  toast(t("toast.ruleundone"));
  const row = btn.closest(".row"); if (row) row.style.display = "none";
  refresh();
}
async function trustRule(btn) {
  const key = btn.dataset.key || "";
  if (key) await post("/api/lists/add", {kind: "allow_sender", value: key});
  await post("/api/rule/undo", {type: btn.dataset.type, key});
  toast(t("toast.friend"));
  const row = btn.closest(".row"); if (row) row.style.display = "none";
  refresh();
}

// ---- review the real email in a neat popup (always opens; has a Back button)
function mailBackBar() {
  return `<div class="mail-topbar"><button class="btn ghost mail-back" onclick="closeModal()">← ${t("com.back")}</button></div>`;
}
function actionBtns(ctx, opts) {
  const del = (opts && opts.canDelete)
    ? `<button class="btn danger" data-account-id="${esc(ctx.accountId||'')}" data-graph-id="${esc(ctx.graphId||'')}" onclick="modalDelete(this)">${t("com.delete")}</button>` : "";
  return `<button class="btn ghost" data-sender="${esc(ctx.sender||'')}" data-domain="${esc(ctx.domain||'')}" data-subject="${esc(ctx.subject||'')}" data-account="${esc(ctx.accountId||'')}" onclick="modalNotSpam(this)">${t("com.notspam")}</button>
    <button class="btn" data-sender="${esc(ctx.sender||'')}" data-domain="${esc(ctx.domain||'')}" data-subject="${esc(ctx.subject||'')}" data-account="${esc(ctx.accountId||'')}" onclick="modalFriend(this)">${t("com.friend")}</button>${del}`;
}
function renderMailBody(r, ctx) {
  const reasons = (r.reasons || []).map(esc).join(" · ");
  const att = (r.attachments || []).length
    ? `<div class="muted small" style="margin-top:4px">📎 ${(r.attachments||[]).map(a => esc(a.name||a)).join(", ")}</div>` : "";
  const when = r.received ? new Date(r.received).toLocaleString() : "";
  openModal(`${mailBackBar()}
    <div class="mail-head">
      <div class="mail-subj">${esc(r.subject || ctx.subject || "(no subject)")}</div>
      <div class="muted small">${esc(r.sender_name || "")} &lt;${esc(r.sender || ctx.sender || "")}&gt;${when ? ` · ${esc(when)}` : ""}</div>
      ${reasons ? `<div class="mail-warn">⚠ ${reasons}</div>` : ""}
      ${att}
    </div>
    <iframe id="mail-frame" class="mail-frame" sandbox referrerpolicy="no-referrer"></iframe>
    <div class="modal-actions mail-actions">${actionBtns(ctx, {canDelete: true})}</div>`);
  const f = $("mail-frame");
  if (f) f.srcdoc = r.html || `<p style="font-family:-apple-system,sans-serif;color:#888;padding:12px">${t("mail.empty")}</p>`;
}
function renderMailGone(info, ctx, ruleCtx) {
  const reasons = (info.reasons || []).map(esc).join(" · ");
  const acts = ruleCtx
    ? `<button class="btn ghost" onclick="modalTrustRule('${esc(ruleCtx.type)}','${esc(ruleCtx.key)}')">${t("com.friend")}</button>
       <button class="btn" onclick="modalUndoRule('${esc(ruleCtx.type)}','${esc(ruleCtx.key)}')">${t("rule.undo")}</button>`
    : (ctx.sender ? actionBtns(ctx, {canDelete: false}) : "");
  openModal(`${mailBackBar()}
    <div class="mail-head">
      <div class="mail-subj">${esc(info.subject || ctx.subject || "(no subject)")}</div>
      <div class="muted small">${esc(ctx.sender || (ruleCtx ? ruleCtx.key : "") || "")}</div>
    </div>
    <div class="mail-gone">
      <div class="mail-gone-ic">📭</div>
      <div><strong>${t("mail.goneTitle")}</strong><div class="muted small">${t("mail.goneBody")}</div></div>
    </div>
    ${reasons ? `<div class="mail-warn">⚠ ${reasons}</div>` : ""}
    <div class="modal-actions mail-actions">${acts}</div>`);
}
async function viewEmail(accountId, graphId, sender, domain, subject) {
  openModal(`<div class="upd-center"><div class="spinner"></div><div class="muted">${t("mail.loading")}</div></div>`);
  const ctx = {accountId, graphId, sender, domain, subject};
  const r = await post("/api/message/full", {account_id: accountId, graph_id: graphId});
  if (r.ok) renderMailBody(r, ctx);
  else renderMailGone({subject, reasons: []}, ctx, null);
}
async function openRuleEmail(type, key) {
  openModal(`<div class="upd-center"><div class="spinner"></div><div class="muted">${t("mail.loading")}</div></div>`);
  const r = await post("/api/rule/open", {type, key});
  if (r.found) {
    renderMailBody(r, {accountId: r.account_id, graphId: r.graph_id, sender: r.sender,
      domain: (type === "domain" ? key : ""), subject: r.subject});
  } else {
    renderMailGone({subject: r.subject, reasons: r.reasons || []},
      {sender: key, domain: (type === "domain" ? key : ""), subject: r.subject}, {type, key});
  }
}
async function modalUndoRule(type, key) {
  await post("/api/rule/undo", {type, key});
  toast(t("toast.ruleundone")); closeModal(); reloadCurrentList(); refresh();
}
async function modalTrustRule(type, key) {
  if (key) await post("/api/lists/add", {kind: "allow_sender", value: key});
  await post("/api/rule/undo", {type, key});
  toast(t("toast.friend")); closeModal(); reloadCurrentList(); refresh();
}
function reloadCurrentList() {
  if (CURRENT_TAB === "reports") loadReports();
  else if (CURRENT_TAB === "protection") loadProtection();
}
async function modalNotSpam(b) {
  await post("/api/notspam", {sender: b.dataset.sender, subject: b.dataset.subject,
    sender_domain: b.dataset.domain, account_id: b.dataset.account});
  toast(t("toast.notspam")); closeModal(); reloadCurrentList(); refresh();
}
async function modalFriend(b) {
  await post("/api/friend/add", {sender: b.dataset.sender, sender_domain: b.dataset.domain,
    subject: b.dataset.subject, account_id: b.dataset.account});
  toast(t("toast.friend")); closeModal(); reloadCurrentList(); refresh();
}
async function modalDelete(b) {
  await post("/api/message/delete", {account_id: b.dataset.accountId, graph_id: b.dataset.graphId});
  toast(t("com.delete")); closeModal(); reloadCurrentList(); refresh();
}
async function loadFlagged() {
  const el = $("flagged-list"); if (!el) return;
  const r = await api("/api/flagged");
  const thr = (STATE.detection || {}).confidence_threshold || 95;
  el.innerHTML = (r.items && r.items.length) ? r.items.map(x => `
    <div class="row"><div class="main">
      <div>${esc(x.subject || "(no subject)")} <span class="pill ${x.confidence>=thr?'spam':'warn'}">${x.confidence}%</span></div>
      <div class="sub" style="white-space:normal;max-width:none">${esc(x.sender || "")}${x.account?` · ${esc(x.account)}`:""}${(x.reasons||[]).length?` · ${esc((x.reasons||[])[0])}`:""}</div></div>
    <div style="display:flex;gap:6px;flex-shrink:0">
      <button class="btn tiny ghost" onclick="viewEmail('${esc(x.account_id||'')}','${esc(x.graph_id||'')}','${esc(x.sender||'')}','${esc(x.sender_domain||'')}','${esc((x.subject||'').replace(/'/g,'’'))}')">${t("com.view")}</button>
      <button class="btn tiny ghost" data-sender="${esc(x.sender||'')}" data-domain="${esc(x.sender_domain||'')}" data-subject="${esc(x.subject||'')}" data-account="${esc(x.account_id||'')}" onclick="notSpam(this)">${t("com.notspam")}</button>
      <button class="btn tiny" data-sender="${esc(x.sender||'')}" data-domain="${esc(x.sender_domain||'')}" data-subject="${esc(x.subject||'')}" data-account="${esc(x.account_id||'')}" onclick="addFriend(this)">${t("com.friend")}</button>
      <button class="btn tiny danger" data-account-id="${esc(x.account_id||'')}" data-graph-id="${esc(x.graph_id||'')}" onclick="flagDelete(this)">${t("com.delete")}</button>
    </div></div>`).join("")
    : `<div class="muted">${t("rep.flaggednone")}</div>`;
}
async function addFriend(btn) {
  await post("/api/friend/add", {sender: btn.dataset.sender || "", sender_domain: btn.dataset.domain || "",
    subject: btn.dataset.subject || "", account_id: btn.dataset.account || ""});
  toast(t("toast.friend"));
  const row = btn.closest(".row"); if (row) row.style.display = "none";
  refresh();
}
async function flagDelete(btn) {
  await post("/api/message/delete", {account_id: btn.dataset.accountId, graph_id: btn.dataset.graphId});
  toast(t("com.delete"));
  const row = btn.closest(".row"); if (row) row.style.display = "none";
  refresh();
}
async function applyThreshold(v) {
  await post("/api/settings", {detection: {...STATE.detection, confidence_threshold: v}});
  toast(t("toast.saved")); await refresh(); loadReports();
}
async function loadDigest() {
  const d = await api("/api/digest");
  const item = (n,l) => `<div class="digest-item"><div class="dn">${n}</div><div class="dl">${l}</div></div>`;
  $("digest").innerHTML = `<div class="digest-grid">
    ${item(d.spam_removed,t("dig.removed"))}${item(d.phishing,t("dig.phishing"))}${item(d.spoofing,t("dig.spoofed"))}
    ${item(d.trackers,t("dig.trackers"))}${item(d.learned,t("dig.learned"))}${item(d.restored,t("dig.restored"))}
  </div>`;
}
async function loadTrends() {
  const t = await api("/api/trends"); const days = t.daily || [];
  const max = Math.max(1, ...days.map(x => x.n));
  const w = 300, h = 60, gap = 3, bw = (w - (days.length-1)*gap) / Math.max(1,days.length);
  const bars = days.map((x,i) => { const bh = x.n ? Math.max(3, x.n/max*h) : 2;
    return `<rect x="${(i*(bw+gap)).toFixed(1)}" y="${(h-bh).toFixed(1)}" width="${bw.toFixed(1)}" height="${bh.toFixed(1)}" rx="2" fill="var(--accent)" opacity="${x.n?0.9:0.2}"></rect>`; }).join("");
  const total = days.reduce((s,x)=>s+x.n,0);
  $("trends").innerHTML = `<svg viewBox="0 0 ${w} ${h}" width="100%" height="72" preserveAspectRatio="none">${bars}</svg>
    <div class="muted small" style="margin-top:6px">${total} spam caught in the last 14 days</div>`;
}
async function emptyQuarantine() {
  const r = await post("/api/quarantine/empty");
  toast(`Cleared ${r.emptied||0} from the list`); loadQuarantine(); refresh();
}

// ---------------- welcome wizard (first run)
let WIZARD_SHOWN = false;
function maybeWizard() {
  if (!WIZARD_SHOWN && STATE && STATE.accounts.length === 0) {
    WIZARD_SHOWN = true;
    openModal(`<div class="upd-center" style="padding-top:0">
        <div style="font-size:44px;margin-bottom:6px">🛡️</div>
        <div class="upd-title">${t("wiz.title")}</div>
        <div class="muted">${t("wiz.sub")}</div>
      </div>
      <ol class="muted" style="line-height:1.9;margin:18px 4px">
        <li>${t("wiz.step1")}</li>
        <li>${t("wiz.step2")}</li>
      </ol>
      <p class="muted small">${t("wiz.note")}</p>
      <div class="modal-actions">
        <button class="btn ghost" onclick="closeModal()">${t("wiz.later")}</button>
        <button class="btn primary" onclick="closeModal();showTab('settings')">${t("wiz.cta")}</button>
      </div>`);
  }
}
function labelFor(k) { return ({deleted_unread:t("act.deleted"), auto_deleted:t("act.autodeleted"), rescued:t("act.rescued"), marked_not_spam:t("act.notspam"), rule_undone:t("act.ruleundone")})[k] || k; }

// ---------------- protection
async function loadProtection() {
  const p = await api("/api/protection"); const s = p.summary;
  $("prot-stats").innerHTML = [
    [t("prot.authenticated"), s.authenticated], [t("prot.spoofingblocked"), s.spoofing],
    [t("prot.phishingcaught"), s.phishing], [t("prot.trackersseen"), s.trackers], [t("prot.newsletters"), s.newsletters_current],
  ].map(([l,n]) => `<div class="stat"><div class="n">${n}</div><div class="l">${l}</div></div>`).join("");

  const nsBtn = (x) => `<button class="btn tiny ghost" data-sender="${esc(x.sender||'')}" data-domain="${esc(x.sender_domain||'')}" data-subject="${esc(x.subject||'')}" data-account="${esc(x.account_id||'')}" onclick="notSpam(this)">${t("com.notspam")}</button>`;
  const actBtns = (x) => `<div style="display:flex;gap:6px;flex-shrink:0">
      <button class="btn tiny ghost" onclick="viewEmail('${esc(x.account_id||'')}','${esc(x.graph_id||'')}','${esc(x.sender||'')}','${esc(x.sender_domain||'')}','${esc((x.subject||'').replace(/'/g,'’'))}')">${t("com.view")}</button>
      ${nsBtn(x)}
      <button class="btn tiny" data-sender="${esc(x.sender||'')}" data-domain="${esc(x.sender_domain||'')}" data-subject="${esc(x.subject||'')}" data-account="${esc(x.account_id||'')}" onclick="addFriend(this)">${t("com.friend")}</button>
      <button class="btn tiny danger" data-account-id="${esc(x.account_id||'')}" data-graph-id="${esc(x.graph_id||'')}" onclick="flagDelete(this)">${t("com.delete")}</button>
    </div>`;
  $("prot-phishing").innerHTML = p.phishing.length ? p.phishing.map(x => `
    <div class="row"><div class="main"><div>${esc(x.subject || "(no subject)")}
      <span class="pill spam">${x.phishing_score}%</span></div>
      <div class="sub" style="white-space:normal;max-width:none">${esc(x.sender || "")} · ${esc((x.phishing_reasons||[])[0] || "")}</div></div>
      ${actBtns(x)}</div>`).join("")
    : `<div class="muted">${t("prot.none.phish")}</div>`;

  const safe = p.safe_senders || [];
  if ($("rep-safe")) $("rep-safe").innerHTML = safe.length ? safe.slice(0,20).map(sa =>
    `<div class="row"><div class="main">${esc(sa.key)}</div><span class="pill ham">${t("prot.kept", sa.kept)}</span></div>`).join("")
    : `<div class="muted">${t("prot.none.safe")}</div>`;

  const viewBtn = (x) => `<button class="btn tiny ghost" onclick="viewEmail('${esc(x.account_id||'')}','${esc(x.graph_id||'')}','${esc(x.sender||'')}','${esc(x.sender_domain||'')}','${esc((x.subject||'').replace(/'/g,'’'))}')">${t("com.view")}</button>`;
  $("prot-spoofing").innerHTML = p.spoofing.length ? p.spoofing.map(x => `
    <div class="row"><div class="main"><div>${esc(x.subject || "(no subject)")}</div>
      <div class="sub">${esc(x.sender || "")} · spf:${esc(x.spf)} dkim:${esc(x.dkim)} dmarc:${esc(x.dmarc)}</div></div>
      <div style="display:flex;gap:6px;align-items:center;flex-shrink:0"><span class="pill warn">${t("com.spoofed")}</span>${viewBtn(x)}${nsBtn(x)}</div></div>`).join("")
    : `<div class="muted">${t("prot.none.spoof")}</div>`;

  $("prot-newsletters").innerHTML = p.newsletters.length ? p.newsletters.map(x => `
    <div class="row"><div class="main"><div>${esc(x.subject || "(no subject)")}</div>
      <div class="sub">${esc(x.sender || "")}${x.trackers ? ` · ${x.trackers} tracker(s)` : ""}</div></div>
      <div style="display:flex;gap:6px;align-items:center;flex-shrink:0">${viewBtn(x)}${x.unsub_oneclick
          ? `<button class="btn tiny" onclick="unsub('${x.account_id}','${x.graph_id}')">${t("com.unsubscribe")}</button>`
          : (x.unsub_http && x.unsub_http.length
             ? `<button class="btn tiny" onclick="unsub('${x.account_id}','${x.graph_id}')">${t("com.unsubscribe")} ↗</button>` : "")}
        <button class="btn tiny danger" onclick="delNews('${x.account_id}','${x.graph_id}')">${t("com.delete")}</button></div></div>`).join("")
    : `<div class="muted">${t("prot.none.news")}</div>`;
}
async function unsub(account_id, graph_id) {
  const r = await post("/api/unsubscribe", {account_id, graph_id});
  if (r.ok && r.result && r.result.open_url) { window.open(r.result.open_url, "_blank"); toast("Opening unsubscribe page…"); }
  else toast(r.ok ? "Unsubscribed ✓" : ("Couldn’t unsubscribe: " + (r.result||"")));
  loadProtection();
}
async function delNews(account_id, graph_id) {
  const r = await post("/api/newsletters/delete", {account_id, graph_id});
  toast(r.ok ? "Deleted" : "Failed"); loadProtection();
}
async function deleteAllNewsletters() {
  const r = await post("/api/newsletters/delete_all");
  toast(`Deleted ${r.deleted || 0} newsletter(s)`); loadProtection();
}

// ---------------- quarantine
async function loadQuarantine() {
  const q = await api("/api/quarantine");
  $("q-active").innerHTML = q.active.length ? q.active.map(it => `
    <div class="row"><div class="main">
      <div>${esc(it.subject || "(no subject)")} <span class="conf">${it.confidence ?? ""}%</span></div>
      <div class="sub" style="white-space:normal;max-width:none">${esc(it.sender || "")}${(it.reasons||[]).length ? " · " + (it.reasons||[]).map(esc).join(" · ") : ""}</div></div>
    <div style="display:flex;gap:6px;flex-shrink:0">
      <button class="btn tiny ghost" onclick="viewEmail('${esc(it.account_id||'')}','${esc(it.graph_id||'')}','${esc(it.sender||'')}','${esc(it.sender_domain||'')}','${esc((it.subject||'').replace(/'/g,'’'))}')">${t("com.view")}</button>
      <button class="btn tiny" onclick="restore(${it.id})">${t("q.undo")}</button>
      <button class="btn tiny ghost" onclick="keepSender(${it.id})">${t("q.keep")}</button></div></div>`).join("")
    : `<div class="muted">${t("q.nothing")}</div>`;
  $("q-restored").innerHTML = q.restored.length ? q.restored.map(it =>
    `<div class="row"><div class="main"><div>${esc(it.subject||"")}</div><div class="sub">${esc(it.sender||"")}</div></div>
      <span class="pill ham">${t("dig.restored")}</span></div>`).join("") : `<div class="muted">${t("q.none")}</div>`;
}
async function restore(id) {
  const r = await post("/api/quarantine/restore", {id});
  toast(r.ok ? t("toast.restored") : ("Failed: " + r.message));
  loadQuarantine(); refresh();
}
async function keepSender(id) {
  const r = await post("/api/quarantine/keep_sender", {id});
  toast(r.ok ? "✓ Added to Friends & restored" : ("Failed: " + r.message));
  loadQuarantine(); refresh();
}

// ---------------- settings
function fillSettings() {
  const s = STATE;
  $("set-threshold").value = s.detection.confidence_threshold; $("thr-val").textContent = s.detection.confidence_threshold;
  $("set-obs").value = s.detection.min_observations; $("obs-val").textContent = s.detection.min_observations;
  $("set-poll").value = s.detection.poll_interval_seconds; $("poll-val").textContent = s.detection.poll_interval_seconds;
  renderSettingsAccounts();
}
function renderSettingsAccounts() {
  if (!STATE.accounts.length) { $("set-accounts").innerHTML = `<div class="muted">No accounts yet.</div>`; return; }
  const modes = {default:"mode.default", observe:"mode.observe", suggest:"mode.suggest", auto:"mode.auto"};
  $("set-accounts").innerHTML = STATE.accounts.map(a => {
    const cur = a.mode || "default";
    const chips = Object.entries(modes).map(([m,k]) => `<button class="chip ${cur===m?'active':''}" onclick="setAcctMode('${a.id}','${m}')">${t(k)}</button>`).join("");
    const fc = (a.folders||[]).length;
    const ftxt = `${t("set.mon.pre")} ${fc} ${fc!==1?t("set.mon.folders"):t("set.mon.folder")} — ${t("set.mon.edit")}`;
    return `<div class="acct">
      <div class="row" style="border-bottom:none;padding-bottom:4px">
        <div class="main"><div>${esc(a.email)}</div><div class="sub">${a.connected?t("st.connected"):t("st.notconnected")}</div></div>
        <div>${a.connected?`<button class="btn tiny ghost" onclick="signout('${a.id}')">${t("set.signout")}</button>`:`<button class="btn tiny primary" onclick="connect('${a.id}')">${t("set.connect")}</button>`}
          <button class="btn tiny danger" onclick="removeAccount('${a.id}')">${t("set.remove")}</button></div>
      </div>
      ${a.connected?`<div class="acct-ctl">
        <span class="ctl-label">${t("set.mode")}</span><div class="mode-quick">${chips}</div></div>
      <div class="acct-ctl">
        <span class="ctl-label">${t("set.folders")}</span>
        <button class="btn tiny" onclick="openFolders('${a.id}')">${ftxt}</button></div>`:''}
    </div>`;
  }).join("");
}
async function setAcctMode(id, mode) {
  await post("/api/account/set_mode", {id, mode: mode==="default" ? "" : mode});
  toast("Account mode updated"); await refresh(); renderSettingsAccounts();
}
async function openFolders(id) {
  const r = await api("/api/account/folders?id=" + encodeURIComponent(id));
  if (!r.ok) { toast(r.error || "Couldn’t load folders"); return; }
  const mon = new Set(r.monitored);
  const rows = r.folders.map(f => {
    const name = f.name || f.well_known || "folder";
    const checked = mon.has(f.id) || (f.well_known === "junkemail" && mon.has("junkemail"));
    return `<label class="folder-item">
      <input type="checkbox" value="${f.id}" data-name="${esc(name)}" ${checked?'checked':''}>
      <span>${f.depth?'&nbsp;&nbsp;↳ ':''}${esc(name)}</span>
      <span class="muted small">${f.total||0}</span></label>`;
  }).join("");
  openModal(`<h2 style="margin-top:0">${t("folders.title")}</h2>
    <p class="muted small">${t("folders.desc")}</p>
    <div class="folder-list">${rows}</div>
    <div class="modal-actions"><button class="btn ghost" onclick="closeModal()">${t("com.cancel")}</button>
      <button class="btn primary" onclick="saveFolders('${id}')">${t("com.save")}</button></div>`);
}
async function saveFolders(id) {
  const boxes = [...document.querySelectorAll('.folder-list input:checked')];
  const folders = boxes.map(b => ({id: b.value, name: b.getAttribute('data-name')}));
  const r = await post("/api/account/set_folders", {id, folders});
  toast(r.ok ? "Folders updated" : "Failed"); closeModal(); await refresh(); renderSettingsAccounts();
}

// backup / restore
function exportBrain() { window.location.href = "/api/export"; toast("Exporting your brain…"); }
function importBrain(input) {
  const f = input.files[0]; if (!f) return;
  const rd = new FileReader();
  rd.onload = async () => {
    try { const data = JSON.parse(rd.result); const r = await post("/api/import", data);
      toast(`Imported ${r.added.reputation} rules · ${r.added.lists} list items`); refresh(); }
    catch (e) { toast("That file isn’t a valid Spam Buster backup"); }
  };
  rd.readAsText(f); input.value = "";
}
async function addAccount() {
  const email = $("new-account").value.trim();
  const r = await post("/api/account/add", {email});
  if (r.ok) { $("new-account").value=""; toast("Added " + email); await refresh(); renderSettingsAccounts(); }
  else toast(r.error || "Could not add");
}
async function removeAccount(id) { await post("/api/account/remove", {id}); await refresh(); renderSettingsAccounts(); }
async function signout(id) { await post("/api/account/signout", {id}); await refresh(); renderSettingsAccounts(); }
async function saveDetection() {
  await post("/api/settings", {detection: {
    mode: STATE.detection.mode, confidence_threshold: parseInt($("set-threshold").value),
    min_observations: parseInt($("set-obs").value), poll_interval_seconds: parseInt($("set-poll").value)}});
  toast("Detection settings saved"); refresh();
}
async function loadLogs() { const r = await api("/api/logs"); const el = $("logs");
  el.textContent = r.log || "(empty)"; el.classList.remove("hidden"); el.scrollTop = el.scrollHeight; }

// ---------------- lists (block / allow)
async function loadLists() {
  const l = await api("/api/lists");
  $("block-domains").innerHTML = tags(l.block_domain, "block", "block_domain");
  $("block-senders").innerHTML = tags(l.block_sender, "block", "block_sender");
  $("allow-senders").innerHTML = tags(l.allow_sender, "allow", "allow_sender");
  if ($("watch-words")) $("watch-words").innerHTML = tags(l.watch_word, "watch", "watch_word");
}
async function loadThreat() {
  const th = await api("/api/threat"); const c = th.counts || {};
  const mal = (c.urlhaus||0) + (c.threatfox||0), disp = c.disposable||0;
  const parts = [];
  if (mal || disp) parts.push(`${mal} ${t("threat.mal")}`, `${disp} ${t("threat.disp")}`);
  const last = th.last_update ? t("threat.last", new Date(th.last_update).toLocaleString()) : t("threat.none");
  if ($("threat-status")) $("threat-status").textContent = (parts.length ? parts.join(" · ") + " · " : "") + last;
}
async function updateThreat() {
  if ($("threat-status")) $("threat-status").textContent = t("threat.updating");
  await post("/api/threat/update");
  setTimeout(loadThreat, 4000); setTimeout(loadThreat, 12000);
}
async function saveThreatKey() {
  await post("/api/settings", {threat: {abuse_ch_key: $("threat-key").value.trim()}});
  $("threat-key").value = ""; toast(t("toast.saved")); updateThreat();
}
function tags(items, cls, kind) {
  if (!items || !items.length) return `<span class="muted small">${t("com.noneyet")}</span>`;
  return items.map(it => `<span class="tag ${cls}">${esc(it.value)}
    <button onclick="removeList('${kind}','${esc(it.value)}')" title="Remove">×</button></span>`).join("");
}
async function addList(kind, inputId) {
  const v = $(inputId).value.trim();
  if (!v) { toast("Enter a value"); return; }
  const r = await post("/api/lists/add", {kind, value: v});
  if (r.ok) { $(inputId).value = ""; toast("Saved"); loadLists(); } else toast(r.error || "Failed");
}
async function removeList(kind, value) { await post("/api/lists/remove", {kind, value}); loadLists(); }

// ---------------- connect modal (device code)
async function connect(id) {
  const r = await post("/api/account/connect", {id});
  if (!r.ok) { toast(r.error || "Could not start sign-in"); return; }
  openModal(`<h2 style="margin-top:0">Connect account</h2>
    <p class="muted">1. Go to <a href="https://www.microsoft.com/link" target="_blank">microsoft.com/link</a><br>
       2. Enter this code and sign in with your Hotmail account:</p>
    <div class="code-box">${esc(r.user_code)}</div>
    <p class="muted" id="connect-status">Waiting for you to sign in…</p>`);
  clearInterval(connectPoll);
  connectPoll = setInterval(async () => {
    const st = await api("/api/account/connect/status?id=" + encodeURIComponent(id));
    if (st.status === "connected") { clearInterval(connectPoll); $("connect-status").innerHTML = "✅ Connected!";
      toast("Account connected"); setTimeout(closeModal, 900); await refresh(); renderSettingsAccounts(); }
    else if (st.status === "error") { clearInterval(connectPoll); $("connect-status").innerHTML = "⚠ " + esc(st.error || "failed"); }
  }, 2500);
}
function openModal(html) { $("modal-body").innerHTML = html; $("modal").classList.remove("hidden"); }
function closeModal() { $("modal").classList.add("hidden"); clearInterval(connectPoll); }

// ---------------- boot
async function boot() {
  await refresh();
  maybeWizard();
  if (location.hash === "#settings") showTab("settings");
  if (location.hash === "#update") setTimeout(openUpdateFlow, 400);
  setInterval(() => { if (CURRENT_TAB === "overview") refresh(); }, 8000);
}
boot();
