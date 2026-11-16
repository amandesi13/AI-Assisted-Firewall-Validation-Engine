"use strict";

// Loads the Python engine into Pyodide and renders what web/bridge.py returns.

const PRESETS = {
  clean: {
    name: "least-privilege-edge",
    default_action: "deny",
    rules: [
      { id: "allow-https-web", action: "allow", source: "0.0.0.0/0", destination: "10.0.1.0/24",
        protocol: "tcp", ports: [443], description: "Public HTTPS to the web tier" },
      { id: "allow-ssh-mgmt", action: "allow", source: "10.0.100.0/24", destination: "10.0.1.0/24",
        protocol: "tcp", ports: [22], description: "SSH only from the management subnet" },
      { id: "allow-dns", action: "allow", source: "10.0.0.0/16", destination: "10.0.0.53/32",
        protocol: "udp", ports: [53], description: "Internal DNS" },
    ],
  },
  open: {
    name: "quick-fix-weekend",
    default_action: "allow",
    rules: [
      { id: "allow-everything", action: "allow", source: "any", destination: "any",
        protocol: "any", ports: "any", description: "Temporary: unblock the release" },
      { id: "deny-db-public", action: "deny", source: "0.0.0.0/0", destination: "10.0.3.25/32",
        protocol: "tcp", ports: [5432], description: "Keep the database private" },
      { id: "allow-rdp", action: "allow", source: "0.0.0.0/0", destination: "10.0.4.10/32",
        protocol: "tcp", ports: [3389], description: "Remote desktop for the vendor" },
    ],
  },
};

const $ = (id) => document.getElementById(id);
const statusEl = $("status");
const policyEl = $("policy");
const findingsEl = $("findings");
const rulesEl = $("rules");
const verdictEl = $("verdict");

let bridge = null;
let lastRules = [];
let lastFlags = {};
let lastHit = null;

function esc(value) {
  return String(value ?? "").replace(/[&<>"']/g, (c) => (
    { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]
  ));
}

function setStatus(text, cls) {
  statusEl.textContent = text;
  statusEl.className = "status" + (cls ? " " + cls : "");
}

async function boot() {
  await loadPreset("sample");
  try {
    const pyodide = await loadPyodide();
    const manifest = await (await fetch("py/manifest.json")).json();
    for (const path of manifest) {
      const source = await (await fetch("py/" + path)).text();
      const full = "/home/pyodide/" + path;
      const dir = full.split("/").slice(0, -1).join("/");
      if (dir) pyodide.FS.mkdirTree(dir);
      pyodide.FS.writeFile(full, source);
    }
    bridge = pyodide.pyimport("bridge");
    setStatus("Python ready", "ready");
    $("validate").disabled = false;
    $("simulate").disabled = false;
    validate();
  } catch (err) {
    setStatus("Python failed to load", "failed");
    findingsEl.innerHTML = `<div class="error">${esc(err && err.message ? err.message : (err && err.type) || err)}</div>`;
    console.error(err);
  }
}

async function loadPreset(name) {
  if (name === "sample") {
    policyEl.value = await (await fetch("samples/policy.json")).text();
  } else {
    policyEl.value = JSON.stringify(PRESETS[name], null, 2);
  }
}

function validate() {
  if (!bridge) return;
  const result = JSON.parse(bridge.validate(policyEl.value));
  lastHit = null;
  verdictEl.innerHTML = "";
  if (!result.ok) {
    findingsEl.innerHTML = `<div class="error">${esc(result.error)}</div>`;
    lastRules = [];
    renderRules();
    return;
  }
  lastRules = result.rules;
  lastFlags = {};
  for (const f of result.findings) {
    if (f.rule_id) (lastFlags[f.rule_id] ||= []).push(f);
  }
  renderFindings(result);
  renderRules();
}

function renderFindings(result) {
  const order = ["critical", "high", "medium", "low"];
  const chips = order
    .filter((s) => result.summary[s])
    .map((s) => `<span class="sev ${s}">${result.summary[s]} ${s}</span>`)
    .join("");
  const cards = result.findings.map((f) => `
    <article class="finding ${f.severity}">
      <h3><span class="sev ${f.severity}">${f.severity}</span>${esc(f.title)}
        ${f.rule_id ? `<code>${esc(f.rule_id)}</code>` : ""}</h3>
      <p>${esc(f.message)}</p>
      <p class="rec">${esc(f.recommendation)}</p>
    </article>`).join("");
  findingsEl.innerHTML = `
    <div class="chips">${chips || '<span class="sev ok">no findings</span>'}
      <span class="empty">${result.rules.length} rules, default ${esc(result.default_action)}</span></div>
    ${cards}
    <div class="callout">${esc(result.review)}</div>`;
}

function renderRules() {
  if (!lastRules.length) {
    rulesEl.innerHTML = '<p class="empty">Fix the policy to see its rules.</p>';
    return;
  }
  const rows = lastRules.map((r, i) => {
    const flags = (lastFlags[r.id] || [])
      .map((f) => `<span class="sev ${f.severity}">${esc(f.title)}</span>`).join(" ");
    const hit = lastHit && lastHit.matched_rule === r.id ? ` class="hit ${lastHit.action}"` : "";
    const ports = r.ports === "any" ? "any" : r.ports.join(", ");
    return `<tr${hit}>
      <td>${i + 1}</td><td><code>${esc(r.id)}</code></td>
      <td class="action-${r.action}">${r.action}</td>
      <td class="mono">${esc(r.source)}</td><td class="mono">${esc(r.destination)}</td>
      <td>${esc(r.protocol)}</td><td class="mono">${esc(ports)}</td>
      <td class="wrap">${flags || '<span class="empty">–</span>'}</td>
      <td class="wrap empty">${esc(r.description)}</td></tr>`;
  }).join("");
  rulesEl.innerHTML = `<table>
    <thead><tr><th>#</th><th>Rule</th><th>Action</th><th>Source</th><th>Destination</th>
      <th>Proto</th><th>Ports</th><th>Findings</th><th>Description</th></tr></thead>
    <tbody>${rows}</tbody></table>`;
}

function simulate(ev) {
  if (ev) ev.preventDefault();
  if (!bridge) return;
  validate();
  if (!lastRules.length) return;
  const f = $("sim").elements;
  const result = JSON.parse(bridge.simulate(
    policyEl.value, f.src.value, f.dst.value, f.protocol.value, f.port.value));
  if (!result.ok) {
    lastHit = null;
    verdictEl.innerHTML = `<div class="error">${esc(result.error)}</div>`;
    renderRules();
    return;
  }
  lastHit = result;
  const via = result.matched_rule ? `rule <code>${esc(result.matched_rule)}</code>` : "the default action";
  const warn = result.matched_rule && lastFlags[result.matched_rule]
    ? `<br><span class="empty">That rule has findings: ${lastFlags[result.matched_rule].map((x) => esc(x.title)).join(", ")}.</span>`
    : "";
  verdictEl.innerHTML = `<div class="verdict ${result.action}">
    <strong class="action-${result.action}">${result.action.toUpperCase()}</strong> via ${via}. ${esc(result.reason)}.${warn}</div>`;
  renderRules();
}

$("validate").addEventListener("click", validate);
$("sim").addEventListener("submit", simulate);
$("preset").addEventListener("change", async (ev) => {
  await loadPreset(ev.target.value);
  validate();
});
policyEl.addEventListener("keydown", (ev) => {
  if ((ev.ctrlKey || ev.metaKey) && ev.key === "Enter") validate();
});
document.querySelectorAll("[data-ex]").forEach((btn) => {
  btn.addEventListener("click", () => {
    const [src, dst, protocol, port] = btn.dataset.ex.split(",");
    const f = $("sim").elements;
    f.src.value = src; f.dst.value = dst; f.protocol.value = protocol; f.port.value = port;
    simulate();
  });
});

boot();
