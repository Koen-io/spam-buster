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
function ago(ts) { if (!ts) return "never"; const s = Math.max(0, Math.floor(Date.now()/1000 - ts));
  if (s < 60) return s + "s ago"; if (s < 3600) return Math.floor(s/60) + "m ago"; return Math.floor(s/3600) + "h ago"; }
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
  if (name === "settings") { fillSettings(); loadLists(); }
}

// ---------------- state
async function refresh() { STATE = await api("/api/state"); render(); }
function render() {
  const s = STATE;
  $("version").textContent = s.version;
  const mode = s.detection.mode;
  const paused = s.engine.paused;
  $("mode-badge").textContent = paused ? "paused" : mode;

  $("status-mode").textContent = paused ? "Paused" :
    (mode === "auto" ? "Auto-delete" : mode === "suggest" ? "Suggest" : "Observing");
  $("status-dot").className = "dot" + (paused ? " paused" : "");
  const acctInfo = s.engine.accounts || {};
  const connected = s.accounts.filter(a => a.connected).length;
  let detail = `${connected}/${s.accounts.length} account(s) connected · last scan ${ago(s.engine.last_scan)}`;
  if (s.engine.last_error) detail += ` · ⚠ ${esc(s.engine.last_error)}`;
  $("status-detail").innerHTML = detail;
  document.querySelectorAll(".chip").forEach(c => c.classList.toggle("active", c.dataset.mode === mode));
  $("pause-btn").textContent = paused ? "Resume" : "Pause";

  // onboarding banner: only when nothing is set up yet
  $("onboard").classList.toggle("hidden", s.accounts.length !== 0);

  // connection-lost / scan-error warning
  const problems = [];
  s.accounts.forEach(a => {
    const info = acctInfo[a.id] || {};
    if (!a.connected) problems.push(`${a.email} — sign-in expired or disconnected`);
    else if (info.error) problems.push(`${a.email} — ${info.error}`);
  });
  const wb = $("warn-banner");
  if (s.accounts.length && problems.length) {
    wb.innerHTML = `<div><div class="wtitle">⚠️ Can’t scan ${problems.length} mailbox${problems.length>1?"es":""}</div>
        <div class="wsub">${problems.map(esc).join(" · ")}. Reconnect the account to resume protection.</div></div>
      <button class="btn" onclick="showTab('settings')">Fix in Settings →</button>`;
    wb.classList.remove("hidden");
  } else { wb.classList.add("hidden"); }

  const st = s.stats;
  $("stat-row").innerHTML = [
    ["Spam learned", st.spam_examples], ["Auto-deleted", st.auto_deleted],
    ["In quarantine", st.auto_deleted_active], ["Known senders", st.known_senders + st.known_domains],
  ].map(([l,n]) => `<div class="stat"><div class="n">${n}</div><div class="l">${l}</div></div>`).join("");

  const sug = s.suggestions || [];
  $("ov-suggestions").innerHTML = sug.length ? sug.map(x => `
    <div class="row"><div class="main"><div>${esc(x.subject || "(no subject)")}</div>
      <div class="sub">${esc(x.sender || "")}</div></div>
      <span class="pill spam">${x.confidence}%</span></div>`).join("")
    : (st.spam_examples ? `<div class="muted">Nothing above the threshold right now.</div>`
                        : `<div class="muted">Learning… delete some spam unread to train it.</div>`);

  $("ov-accounts").innerHTML = s.accounts.length ? s.accounts.map(a => `
    <div class="row"><div class="main"><div>${esc(a.email)}</div>
      <div class="sub">${acctInfo[a.id]?.junk_count ?? "–"} in Junk</div></div>
      <span class="pill ${a.connected ? "ham":"warn"}">${a.connected ? "connected":"not connected"}</span></div>`).join("")
    : `<div class="muted">No accounts yet — add them in Settings.</div>`;

  const lc = s.updates.last_checked ? new Date(s.updates.last_checked).toLocaleString() : "never";
  if ($("update-line")) $("update-line").textContent = "Last update check: " + lc;
}

// ---------------- actions
async function togglePause() { await post("/api/pause", {paused: !STATE.engine.paused}); refresh(); }
async function scanNow() { await post("/api/scan"); toast("Scanning your Junk folders…"); }
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

// ---------------- reports
async function loadReports() {
  const r = await api("/api/reports"); const rules = r.rules;
  $("rep-rules").innerHTML = rules.auto_rules.length ? rules.auto_rules.map(x => `
    <div class="row"><div class="main"><div>${esc(x.text)}</div><div class="sub">${esc(x.evidence)}</div></div>
      <span class="pill spam">auto-delete</span></div>`).join("")
    : `<div class="muted">No firm rules yet. Keep deleting spam unread and rules will appear here.</div>`;
  $("rep-words").innerHTML = rules.spammy_words.length ? rules.spammy_words.slice(0,20).map(w =>
    `<span class="pill spam" style="margin:3px;display:inline-block">${esc(w.word)} ${Math.round(w.ratio*100)}%</span>`).join("")
    : `<div class="muted">Nothing yet.</div>`;
  $("rep-safe").innerHTML = rules.safe_senders.length ? rules.safe_senders.slice(0,15).map(sa =>
    `<div class="row"><div class="main">${esc(sa.key)}</div><span class="pill ham">kept ${sa.kept}×</span></div>`).join("")
    : `<div class="muted">Rescue a message or add a Friend and it appears here.</div>`;
  $("rep-events").innerHTML = r.events.length ? r.events.slice(0,40).map(e => `
    <div class="row"><div class="main"><div>${esc(e.subject || "(no subject)")}</div>
      <div class="sub">${esc(e.sender || "")} · ${ago(e.ts)}</div></div>
      <span class="pill ${e.label === "spam" ? "spam":"ham"}">${labelFor(e.kind)}</span></div>`).join("")
    : `<div class="muted">No activity yet.</div>`;
}
function labelFor(k) { return ({deleted_unread:"you deleted", auto_deleted:"auto-deleted", rescued:"rescued", marked_not_spam:"not spam"})[k] || k; }

// ---------------- protection
async function loadProtection() {
  const p = await api("/api/protection"); const s = p.summary;
  $("prot-stats").innerHTML = [
    ["Authenticated", s.authenticated], ["Spoofing blocked", s.spoofing],
    ["Phishing caught", s.phishing], ["Trackers seen", s.trackers], ["Newsletters", s.newsletters_current],
  ].map(([l,n]) => `<div class="stat"><div class="n">${n}</div><div class="l">${l}</div></div>`).join("");

  $("prot-phishing").innerHTML = p.phishing.length ? p.phishing.map(x => `
    <div class="row"><div class="main"><div>${esc(x.subject || "(no subject)")}
      <span class="pill spam">${x.phishing_score}%</span></div>
      <div class="sub">${esc(x.sender || "")} · ${esc((x.phishing_reasons||[])[0] || "")}</div></div></div>`).join("")
    : `<div class="muted">No phishing detected. 🛡️</div>`;

  $("prot-spoofing").innerHTML = p.spoofing.length ? p.spoofing.map(x => `
    <div class="row"><div class="main"><div>${esc(x.subject || "(no subject)")}</div>
      <div class="sub">${esc(x.sender || "")} · spf:${esc(x.spf)} dkim:${esc(x.dkim)} dmarc:${esc(x.dmarc)}</div></div>
      <span class="pill warn">spoofed</span></div>`).join("")
    : `<div class="muted">No spoofing detected.</div>`;

  $("prot-newsletters").innerHTML = p.newsletters.length ? p.newsletters.map(x => `
    <div class="row"><div class="main"><div>${esc(x.subject || "(no subject)")}</div>
      <div class="sub">${esc(x.sender || "")}${x.trackers ? ` · ${x.trackers} tracker(s)` : ""}</div></div>
      <div>${x.unsub_oneclick
          ? `<button class="btn tiny" onclick="unsub('${x.account_id}','${x.graph_id}')">Unsubscribe</button>`
          : (x.unsub_http && x.unsub_http.length
             ? `<button class="btn tiny" onclick="unsub('${x.account_id}','${x.graph_id}')">Unsubscribe ↗</button>` : "")}
        <button class="btn tiny danger" onclick="delNews('${x.account_id}','${x.graph_id}')">Delete</button></div></div>`).join("")
    : `<div class="muted">No newsletters in your Junk right now.</div>`;
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
      <div class="sub">${esc(it.sender || "")} · ${(it.reasons||[]).slice(0,1).map(esc).join("")}</div></div>
    <button class="btn tiny" onclick="restore(${it.id})">Undo · not spam</button></div>`).join("")
    : `<div class="muted">Nothing quarantined. 🎉</div>`;
  $("q-restored").innerHTML = q.restored.length ? q.restored.map(it =>
    `<div class="row"><div class="main"><div>${esc(it.subject||"")}</div><div class="sub">${esc(it.sender||"")}</div></div>
      <span class="pill ham">restored</span></div>`).join("") : `<div class="muted">None.</div>`;
}
async function restore(id) {
  const r = await post("/api/quarantine/restore", {id});
  toast(r.ok ? "Restored to Inbox & marked not spam" : ("Failed: " + r.message));
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
  $("set-accounts").innerHTML = STATE.accounts.length ? STATE.accounts.map(a => `
    <div class="row"><div class="main"><div>${esc(a.email)}</div>
      <div class="sub">${a.connected ? "connected" : "not connected"}</div></div>
      <div>${a.connected
          ? `<button class="btn tiny ghost" onclick="signout('${a.id}')">Sign out</button>`
          : `<button class="btn tiny primary" onclick="connect('${a.id}')">Connect</button>`}
        <button class="btn tiny danger" onclick="removeAccount('${a.id}')">Remove</button></div></div>`).join("")
    : `<div class="muted">No accounts yet.</div>`;
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
}
function tags(items, cls, kind) {
  if (!items || !items.length) return `<span class="muted small">None yet.</span>`;
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
  if (location.hash === "#settings") showTab("settings");
  if (location.hash === "#update") setTimeout(openUpdateFlow, 400);
  setInterval(() => { if (CURRENT_TAB === "overview") refresh(); }, 8000);
}
boot();
