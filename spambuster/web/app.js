// Spam Buster dashboard logic
let STATE = null;
let UPDATE_AVAILABLE = false;
let CURRENT_TAB = "overview";
let connectPoll = null;

const $ = (id) => document.getElementById(id);
async function api(path, opts) {
  const r = await fetch(path, opts);
  return r.json();
}
async function post(path, body) {
  return api(path, {method: "POST", headers: {"Content-Type": "application/json"},
                    body: JSON.stringify(body || {})});
}
function toast(msg) {
  const t = $("toast"); t.textContent = msg; t.classList.add("show");
  setTimeout(() => t.classList.remove("show"), 2600);
}
function fmtTime(ts) {
  if (!ts) return "never";
  const d = new Date(ts * 1000);
  return d.toLocaleString();
}
function ago(ts) {
  if (!ts) return "never";
  const s = Math.max(0, Math.floor(Date.now()/1000 - ts));
  if (s < 60) return s + "s ago";
  if (s < 3600) return Math.floor(s/60) + "m ago";
  return Math.floor(s/3600) + "h ago";
}
function esc(s){ return (s||"").replace(/[&<>"]/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c])); }

// ---------------------------------------------------------------- tabs
function showTab(name) {
  CURRENT_TAB = name;
  document.querySelectorAll(".tab-panel").forEach(p => p.classList.add("hidden"));
  $("tab-" + name).classList.remove("hidden");
  document.querySelectorAll(".tab").forEach(t =>
    t.classList.toggle("active", t.dataset.tab === name));
  if (name === "reports") loadReports();
  if (name === "quarantine") loadQuarantine();
  if (name === "settings") fillSettings();
}

// ---------------------------------------------------------------- state
async function refresh() {
  STATE = await api("/api/state");
  render();
}
function render() {
  const s = STATE;
  $("version").textContent = s.version;
  const mode = s.detection.mode;
  $("mode-badge").textContent = s.engine.paused ? "paused" : mode;

  // status card
  const paused = s.engine.paused;
  $("status-mode").textContent = paused ? "Paused" :
    (mode === "auto" ? "Auto-delete" : mode === "suggest" ? "Suggest" : "Observing");
  $("status-dot").className = "dot" + (paused ? " paused" : "");
  const acctInfo = s.engine.accounts || {};
  const connected = s.accounts.filter(a => a.connected).length;
  let detail = `${connected}/${s.accounts.length} account(s) connected · last scan ${ago(s.engine.last_scan)}`;
  if (s.engine.last_error) detail += ` · ⚠ ${esc(s.engine.last_error)}`;
  $("status-detail").innerHTML = detail;
  document.querySelectorAll(".chip").forEach(c =>
    c.classList.toggle("active", c.dataset.mode === mode));
  $("pause-btn").textContent = paused ? "Resume" : "Pause";

  // onboarding
  $("onboard").classList.toggle("hidden", !(s.first_run || !s.configured_client || connected === 0));

  // updates
  const lc = s.updates.last_checked ? new Date(s.updates.last_checked).toLocaleString() : "never";
  $("last-checked").textContent = lc;
  if ($("last-checked-2")) $("last-checked-2").textContent = lc;
  if (s.updates.last_result) $("update-result").textContent = s.updates.last_result;

  // stats
  const st = s.stats;
  $("stat-row").innerHTML = [
    ["Spam learned", st.spam_examples],
    ["Auto-deleted", st.auto_deleted],
    ["In quarantine", st.auto_deleted_active],
    ["Known senders", st.known_senders + st.known_domains],
  ].map(([l,n]) => `<div class="stat"><div class="n">${n}</div><div class="l">${l}</div></div>`).join("");

  // accounts on overview
  // suggestions preview
  const sug = s.suggestions || [];
  $("ov-suggestions").innerHTML = sug.length ? sug.map(x => `
    <div class="row"><div class="main"><div>${esc(x.subject || "(no subject)")}</div>
      <div class="sub">${esc(x.sender || "")}</div></div>
      <span class="pill spam">${x.confidence}%</span></div>`).join("")
    : (STATE.stats.spam_examples ? `<div class="muted">Nothing above the threshold right now.</div>`
                                 : `<div class="muted">Learning… delete some spam unread to train it.</div>`);

  $("ov-accounts").innerHTML = s.accounts.length ? s.accounts.map(a => `
    <div class="row"><div class="main"><div>${esc(a.email)}</div>
      <div class="sub">${acctInfo[a.id]?.junk_count ?? "–"} in Junk</div></div>
      <span class="pill ${a.connected ? "ham":"warn"}">${a.connected ? "connected":"not connected"}</span>
    </div>`).join("") : `<div class="muted">No accounts yet — add them in Settings.</div>`;
}

// ---------------------------------------------------------------- actions
async function togglePause() { await post("/api/pause", {paused: !STATE.engine.paused}); refresh(); }
async function scanNow() { await post("/api/scan"); toast("Scanning your Junk folders…"); }
async function setMode(mode) {
  await post("/api/settings", {detection: {...STATE.detection, mode}});
  toast("Mode: " + mode); refresh();
}

// ---------------------------------------------------------------- updates
async function checkOrApplyUpdate() {
  const btns = [$("big-update"), $("big-update-2")].filter(Boolean);
  if (UPDATE_AVAILABLE) {
    btns.forEach(b => { b.classList.add("spin"); });
    setText("Updating…");
    const r = await post("/api/updates/apply");
    if (r.status === "ok") { toast(r.message); setTimeout(()=>location.reload(), 4000); }
    else { toast(r.message || "Update failed"); btns.forEach(b=>b.classList.remove("spin")); }
    return;
  }
  btns.forEach(b => b.classList.add("spin"));
  setText("Checking…");
  const r = await post("/api/updates/check");
  btns.forEach(b => b.classList.remove("spin"));
  UPDATE_AVAILABLE = !!r.available;
  setText(UPDATE_AVAILABLE ? "Update now" : "Check for updates");
  btns.forEach(b => b.classList.toggle("ready", UPDATE_AVAILABLE));
  $("update-result").textContent = r.message || "";
  refresh();
}
function setText(t) {
  if ($("update-text")) $("update-text").textContent = t;
  if ($("update-text-2")) $("update-text-2").textContent = t;
}

// ---------------------------------------------------------------- reports
async function loadReports() {
  const r = await api("/api/reports");
  const rules = r.rules;
  $("rep-rules").innerHTML = rules.auto_rules.length ? rules.auto_rules.map(x => `
    <div class="row"><div class="main"><div>${esc(x.text)}</div>
      <div class="sub">${esc(x.evidence)}</div></div>
      <span class="pill spam">auto-delete</span></div>`).join("")
    : `<div class="muted">No firm rules yet. Keep deleting spam unread and rules will appear here.</div>`;

  $("rep-words").innerHTML = rules.spammy_words.length ? rules.spammy_words.slice(0,20).map(w =>
    `<span class="pill spam" style="margin:3px;display:inline-block">${esc(w.word)} ${Math.round(w.ratio*100)}%</span>`).join("")
    : `<div class="muted">Nothing yet.</div>`;

  $("rep-safe").innerHTML = rules.safe_senders.length ? rules.safe_senders.slice(0,15).map(sa =>
    `<div class="row"><div class="main">${esc(sa.key)}</div><span class="pill ham">kept ${sa.kept}×</span></div>`).join("")
    : `<div class="muted">Rescue a message and its sender becomes trusted.</div>`;

  $("rep-events").innerHTML = r.events.length ? r.events.slice(0,40).map(e => `
    <div class="row"><div class="main"><div>${esc(e.subject || "(no subject)")}</div>
      <div class="sub">${esc(e.sender || "")} · ${ago(e.ts)}</div></div>
      <span class="pill ${e.label === "spam" ? "spam":"ham"}">${labelFor(e.kind)}</span></div>`).join("")
    : `<div class="muted">No activity yet.</div>`;
}
function labelFor(kind){
  return ({deleted_unread:"you deleted", auto_deleted:"auto-deleted",
           rescued:"rescued", marked_not_spam:"not spam"})[kind] || kind;
}

// ---------------------------------------------------------------- quarantine
async function loadQuarantine() {
  const q = await api("/api/quarantine");
  $("q-active").innerHTML = q.active.length ? q.active.map(it => `
    <div class="row"><div class="main">
      <div>${esc(it.subject || "(no subject)")} <span class="conf">${it.confidence ?? ""}%</span></div>
      <div class="sub">${esc(it.sender || "")} · ${(it.reasons||[]).slice(0,1).map(esc).join("")}</div>
    </div>
    <button class="btn tiny" onclick="restore(${it.id})">Undo · not spam</button></div>`).join("")
    : `<div class="muted">Nothing quarantined. 🎉</div>`;
  $("q-restored").innerHTML = q.restored.length ? q.restored.map(it =>
    `<div class="row"><div class="main"><div>${esc(it.subject||"")}</div>
      <div class="sub">${esc(it.sender||"")}</div></div><span class="pill ham">restored</span></div>`).join("")
    : `<div class="muted">None.</div>`;
}
async function restore(id) {
  const r = await post("/api/quarantine/restore", {id});
  toast(r.ok ? "Restored to Inbox & marked not spam" : ("Failed: " + r.message));
  loadQuarantine(); refresh();
}

// ---------------------------------------------------------------- settings
function fillSettings() {
  const s = STATE;
  $("client-id").value = s.configured_client ? "•••• saved ••••" : "";
  $("set-mode").value = s.detection.mode;
  $("set-threshold").value = s.detection.confidence_threshold;
  $("thr-val").textContent = s.detection.confidence_threshold;
  $("set-obs").value = s.detection.min_observations;
  $("obs-val").textContent = s.detection.min_observations;
  $("set-poll").value = s.detection.poll_interval_seconds;
  $("poll-val").textContent = s.detection.poll_interval_seconds;
  $("set-repo").value = s.updates.repo || "";
  $("set-channel").value = s.updates.channel || "main";
  renderSettingsAccounts();
}
function renderSettingsAccounts() {
  $("set-accounts").innerHTML = STATE.accounts.length ? STATE.accounts.map(a => `
    <div class="row"><div class="main"><div>${esc(a.email)}</div>
      <div class="sub">${a.connected ? "connected" : "not connected"}</div></div>
      <div>
        ${a.connected
          ? `<button class="btn tiny ghost" onclick="signout('${a.id}')">Sign out</button>`
          : `<button class="btn tiny primary" onclick="connect('${a.id}')">Connect</button>`}
        <button class="btn tiny danger" onclick="removeAccount('${a.id}')">Remove</button>
      </div></div>`).join("")
    : `<div class="muted">No accounts yet.</div>`;
}
async function saveClientId() {
  const v = $("client-id").value.trim();
  if (!v || v.startsWith("••")) { toast("Paste your app ID"); return; }
  await post("/api/settings", {azure_client_id: v});
  toast("Microsoft app ID saved"); await refresh(); fillSettings();
}
async function addAccount() {
  const email = $("new-account").value.trim();
  const r = await post("/api/account/add", {email});
  if (r.ok) { $("new-account").value=""; toast("Added " + email); await refresh(); renderSettingsAccounts(); }
  else toast(r.error || "Could not add");
}
async function removeAccount(id) {
  await post("/api/account/remove", {id}); await refresh(); renderSettingsAccounts();
}
async function signout(id) {
  await post("/api/account/signout", {id}); await refresh(); renderSettingsAccounts();
}
async function saveDetection() {
  await post("/api/settings", {detection: {
    mode: $("set-mode").value,
    confidence_threshold: parseInt($("set-threshold").value),
    min_observations: parseInt($("set-obs").value),
    poll_interval_seconds: parseInt($("set-poll").value),
  }});
  toast("Detection settings saved"); refresh();
}
async function saveUpdates() {
  await post("/api/settings", {updates: {
    repo: $("set-repo").value.trim(), channel: $("set-channel").value.trim() || "main"}});
  toast("Update settings saved"); refresh();
}
async function loadLogs() {
  const r = await api("/api/logs");
  const el = $("logs"); el.textContent = r.log || "(empty)"; el.classList.remove("hidden");
  el.scrollTop = el.scrollHeight;
}

// ---------------------------------------------------------------- connect modal (device code)
async function connect(id) {
  const r = await post("/api/account/connect", {id});
  if (!r.ok) { toast(r.error || "Could not start sign-in"); return; }
  openModal(`
    <h2 style="margin-top:0">Connect account</h2>
    <p class="muted">1. Go to <a href="https://microsoft.com/devicelogin" target="_blank">microsoft.com/devicelogin</a><br>
       2. Enter this code and sign in with your Hotmail account:</p>
    <div class="code-box">${esc(r.user_code)}</div>
    <p class="muted" id="connect-status">Waiting for you to sign in…</p>
  `);
  clearInterval(connectPoll);
  connectPoll = setInterval(async () => {
    const st = await api("/api/account/connect/status?id=" + encodeURIComponent(id));
    if (st.status === "connected") {
      clearInterval(connectPoll); $("connect-status").innerHTML = "✅ Connected!";
      toast("Account connected"); setTimeout(closeModal, 900); await refresh(); renderSettingsAccounts();
    } else if (st.status === "error") {
      clearInterval(connectPoll); $("connect-status").innerHTML = "⚠ " + esc(st.error || "failed");
    }
  }, 2500);
}
function openModal(html) { $("modal-body").innerHTML = html; $("modal").classList.remove("hidden"); }
function closeModal() { $("modal").classList.add("hidden"); clearInterval(connectPoll); }
function showAzureHelp() {
  openModal(`
    <h2 style="margin-top:0">Get your Microsoft app ID</h2>
    <ol class="muted" style="line-height:1.7">
      <li>Go to <a href="https://entra.microsoft.com" target="_blank">entra.microsoft.com</a> → App registrations → New registration.</li>
      <li>Name it “Spam Buster”. Under supported account types choose <b>Personal Microsoft accounts</b>.</li>
      <li>Create it, then enable <b>Allow public client flows</b> under Authentication.</li>
      <li>Copy the <b>Application (client) ID</b> and paste it here.</li>
    </ol>
    <p class="muted small">It’s free and takes ~2 minutes. Spam Buster only requests permission to read and move your mail.</p>
  `);
}

// ---------------------------------------------------------------- boot
refresh();
setInterval(() => { if (CURRENT_TAB === "overview") refresh(); }, 8000);
