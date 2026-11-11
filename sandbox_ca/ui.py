"""HTML for the local sandbox CA admin console.

The page is deliberately dependency-free: it is served from the same TLS
listener as the CA and talks to the JSON admin API with the admin token.  It
exists so a person running the Java GUI can approve, sign, reject and revoke
requests without reaching for curl.
"""

import json

_DASHBOARD = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>pyCertWiz sandbox CA</title>
<style>
  :root { color-scheme: light dark; --line: #8884; --accent: #2b6cb0; --ok: #276749; --bad: #9b2c2c; }
  body { font: 14px/1.45 system-ui, sans-serif; margin: 0; padding: 24px; background: #f6f7f9; color: #17202a; }
  header { display: flex; flex-wrap: wrap; gap: 12px; align-items: baseline; justify-content: space-between; }
  h1 { font-size: 22px; margin: 0; }
  h2 { font-size: 16px; margin: 24px 0 8px; }
  .muted { color: #5d6d7e; }
  .card { background: #fff; border: 1px solid var(--line); border-radius: 8px; padding: 14px; margin-top: 12px; }
  .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 10px; }
  .kv { font-family: ui-monospace, monospace; font-size: 12px; overflow-wrap: anywhere; }
  table { border-collapse: collapse; width: 100%; background: #fff; }
  th, td { text-align: left; border-bottom: 1px solid var(--line); padding: 7px 8px; vertical-align: top; }
  th { background: #eef2f6; font-weight: 600; }
  button { border: 1px solid var(--line); border-radius: 5px; background: #fff; padding: 4px 9px; cursor: pointer; margin: 1px; }
  button.primary { background: var(--accent); color: #fff; border-color: var(--accent); }
  button.danger { color: var(--bad); border-color: var(--bad); }
  button:disabled { opacity: .4; cursor: not-allowed; }
  input[type=text], input[type=number] { padding: 4px 6px; border: 1px solid var(--line); border-radius: 4px; }
  .status-NEW { color: #975a16; font-weight: 600; }
  .status-APPROVED { color: #2b6cb0; font-weight: 600; }
  .status-VALID { color: var(--ok); font-weight: 600; }
  .status-REVOKED, .status-REJECTED, .status-DELETED { color: var(--bad); font-weight: 600; }
  .error { color: var(--bad); white-space: pre-wrap; }
  .row { display: flex; flex-wrap: wrap; gap: 10px; align-items: center; }
  .log { max-height: 280px; overflow: auto; font-family: ui-monospace, monospace; font-size: 12px; }
  .log pre { margin: 4px 0 10px; white-space: pre-wrap; }
  @media (prefers-color-scheme: dark) {
    body { background: #12171d; color: #e6edf3; }
    .card, table, button { background: #1b232c; }
    th { background: #26313c; }
    .muted { color: #9aa8b6; }
  }
</style>
</head>
<body>
<header>
  <div><h1>pyCertWiz sandbox CA</h1><div class="muted" id="server-url"></div></div>
  <div class="row"><span class="muted" id="clock"></span><button id="refresh">Refresh</button></div>
</header>
<div id="error" class="error"></div>

<div class="card grid" id="summary"></div>

<h2>Certificate requests</h2>
<div class="card">
  <div class="row" style="margin-bottom:8px">
    <button data-action="approve-all">Approve all</button>
    <button data-action="sign-all" class="primary">Sign all pending</button>
    <span class="muted">Sign issues a certificate immediately; use Approve first to mirror the RA flow.</span>
  </div>
  <table><thead><tr><th>ID</th><th>Kind</th><th>Status</th><th>Subject</th><th>Email</th><th>PIN hash</th><th>Polls</th><th>Cert</th><th>Actions</th></tr></thead><tbody id="csrs"></tbody></table>
</div>

<h2>Issued certificates</h2>
<div class="card">
  <table><thead><tr><th>ID</th><th>Status</th><th>Serial</th><th>Subject</th><th>Reason</th><th>Actions</th></tr></thead><tbody id="certs"></tbody></table>
</div>

<h2>Sandbox settings</h2>
<div class="card">
  <form id="settings" class="row">
    <label><input type="checkbox" id="auto_approve"> Auto-sign</label>
    <label>Issue after <input type="number" id="sign_after_polls" min="0" max="10000" style="width:6em"> status lookup(s)</label>
    <label>User validity <input type="number" id="valid_days" min="1" max="3650" style="width:7em"> days</label>
    <label>Host validity <input type="number" id="host_valid_days" min="1" max="3650" style="width:7em"> days</label>
    <label>PPPK <select id="pppk_mode"><option>normal</option><option>opaque</option><option>no_challenge</option><option>bad_keyid</option><option>bad_response</option></select></label>
    <button class="primary" type="submit">Save settings</button>
    <button type="button" id="reset" class="danger">Clear all requests/certs</button>
  </form>
  <div class="muted" id="settings-message"></div>
</div>

<h2>Recent protocol requests</h2>
<div class="card log" id="requests"></div>

<script>
const TOKEN = __TOKEN__;
const API = "/__sandbox__";
const $ = (id) => document.getElementById(id);
function esc(value) {
  return String(value === undefined || value === null ? "" : value).replace(/[&<>"']/g, (c) => (
    {"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]
  ));
}
function showError(message) { $("error").textContent = message || ""; }
async function api(path, options) {
  const opts = Object.assign({headers: {"X-Sandbox-Token": TOKEN}}, options || {});
  if (opts.body && !opts.headers["Content-Type"]) opts.headers["Content-Type"] = "application/json";
  const response = await fetch(path, opts);
  const text = await response.text();
  let body = null;
  try { body = text ? JSON.parse(text) : null; } catch (e) { body = text; }
  if (!response.ok) throw new Error((body && body.error) || text || ("HTTP " + response.status));
  return body;
}
function settingsPayload() {
  return {
    auto_approve: $("auto_approve").checked,
    sign_after_polls: Number($("sign_after_polls").value || 0),
    valid_days: Number($("valid_days").value || 365),
    host_valid_days: Number($("host_valid_days").value || 365),
    pppk_mode: $("pppk_mode").value
  };
}
async function act(action, id) {
  showError("");
  try {
    if (action === "approve" || action === "sign" || action === "reject") {
      const payload = {id: id};
      if (action === "reject") payload.reason = "rejected in the sandbox admin UI";
      await api(API + "/" + action, {method: "POST", body: JSON.stringify(payload)});
    } else if (action === "approve-all" || action === "sign-all") {
      const name = action === "approve-all" ? "approve" : "sign";
      await api(API + "/" + name, {method: "POST", body: JSON.stringify({all: true})});
    } else if (action === "revoke") {
      const reason = prompt("Revocation reason", "Key compromise");
      if (reason === null) return;
      await api(API + "/revoke", {method: "POST", body: JSON.stringify({id: id, reason: reason || "unspecified"})});
    }
    await refresh();
  } catch (error) { showError(error.message || String(error)); }
}
function actionButtons(row, status) {
  const id = Number(row.id);
  const buttons = [];
  if (status === "NEW" || status === "RENEW") buttons.push('<button data-act="approve" data-id="' + id + '">Approve</button>');
  if (!row.cert_id && status !== "REJECTED" && status !== "DELETED") buttons.push('<button class="primary" data-act="sign" data-id="' + id + '">Sign</button>');
  if (status === "NEW" || status === "RENEW" || status === "APPROVED") buttons.push('<button class="danger" data-act="reject" data-id="' + id + '">Reject</button>');
  return buttons.join(" ");
}
function render(status) {
  $("server-url").textContent = status.url + "  (mode: " + (status.auto_approve ? "auto-sign" : "manual") + ")";
  const summary = [
    ["CA URL", status.url],
    ["Issuer DN", status.issuer_dn],
    ["Root SHA-256", status.root_sha256],
    ["Issuing SHA-256", status.issuing_sha256],
    ["State file", status.data_dir + "/state.json"]
  ];
  $("summary").innerHTML = summary.map(([k, v]) => '<div><div class="muted">' + esc(k) + '</div><div class="kv">' + esc(v) + '</div></div>').join("");
  $("auto_approve").checked = !!status.auto_approve;
  $("sign_after_polls").value = status.sign_after_polls;
  $("valid_days").value = status.valid_days || 365;
  $("host_valid_days").value = status.host_valid_days || 365;
  $("pppk_mode").value = status.pppk_mode || "normal";
  $("csrs").innerHTML = (status.csrs || []).map((row) => (
    "<tr><td>" + esc(row.id) + "</td><td>" + esc(row.kind) + "</td><td class='status-" + esc(row.status) + "'>" + esc(row.status) + "</td><td>" + esc(row.subject) + "</td><td>" + esc(row.email) + "</td><td class='kv'>" + esc(row.pin_hash) + "</td><td>" + esc(row.polls) + "</td><td>" + esc(row.cert_id) + "</td><td>" + actionButtons(row, row.status) + (row.reject_reason ? '<div class="muted">' + esc(row.reject_reason) + '</div>' : '') + "</td></tr>"
  )).join("");
  $("certs").innerHTML = (status.certificates || []).map((row) => (
    "<tr><td>" + esc(row.id) + "</td><td class='status-" + esc(row.status) + "'>" + esc(row.status) + "</td><td>" + esc(row.serial) + "</td><td>" + esc(row.subject) + "</td><td>" + esc(row.revoke_reason) + "</td><td>" + (row.status === "VALID" ? '<button class="danger" data-act="revoke" data-id="' + esc(row.id) + '">Revoke</button>' : "") + "</td></tr>"
  )).join("");
}
async function refresh() {
  try {
    const status = await api(API + "/status");
    render(status);
    const log = await api(API + "/requests?limit=30");
    $("requests").innerHTML = (log || []).map((item) => (
      '<div><strong>' + esc(item.method) + " " + esc(item.path) + "</strong><pre>" + esc(item.body) + "</pre></div>"
    )).join("") || '<span class="muted">No requests captured yet.</span>';
    $("clock").textContent = new Date().toLocaleTimeString();
    showError("");
  } catch (error) { showError(error.message || String(error)); }
}
$("refresh").onclick = refresh;
document.addEventListener("click", (event) => {
  const button = event.target.closest("button[data-act]");
  if (button) act(button.dataset.act, Number(button.dataset.id));
  if (event.target.matches("button[data-action]")) act(event.target.dataset.action);
});
$("settings").onsubmit = async (event) => {
  event.preventDefault();
  try {
    await api(API + "/settings", {method: "POST", body: JSON.stringify(settingsPayload())});
    $("settings-message").textContent = "Saved.";
    await refresh();
  } catch (error) { showError(error.message || String(error)); }
};
$("reset").onclick = async () => {
  if (!confirm("Forget all CSRs, certificates and captured requests?")) return;
  try { await api(API + "/reset", {method: "POST", body: "{}"}); await refresh(); }
  catch (error) { showError(error.message || String(error)); }
};
refresh();
setInterval(refresh, 3000);
</script>
</body>
</html>
"""

_LOGIN = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>pyCertWiz sandbox CA login</title>
<style>body{font:14px system-ui,sans-serif;max-width:34rem;margin:10vh auto;padding:1rem}input,button{padding:.5rem;margin:.3rem 0;width:100%;box-sizing:border-box}label{display:block;margin-top:1rem}</style>
</head><body>
<h1>pyCertWiz sandbox CA</h1>
<p>Enter the admin token printed when the sandbox started (also in <code>sandbox.json</code>).</p>
__ERROR__
<form method="get" action="/__sandbox__/ui">
<label for="token">Admin token</label>
<input id="token" name="token" type="password" autofocus autocomplete="off">
<button type="submit">Open admin console</button>
</form>
</body></html>
"""


def render_dashboard(token: str) -> str:
    return _DASHBOARD.replace("__TOKEN__", json.dumps(str(token)).replace("<", "\\u003c"))


def render_login(error: bool = False) -> str:
    message = '<p style="color:#9b2c2c">That token was not accepted.</p>' if error else ""
    return _LOGIN.replace("__ERROR__", message)
