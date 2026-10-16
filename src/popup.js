/* global browser */
"use strict";
const LABEL = { clean: "No threats found", caution: "Review before opening", suspicious: "Dangerous" };

function ago(t) {
  const s = Math.round((Date.now() - t) / 1000);
  if (s < 60) return "just now";
  if (s < 3600) return Math.round(s / 60) + " min ago";
  if (s < 86400) return Math.round(s / 3600) + " h ago";
  return new Date(t).toLocaleDateString();
}
function size(n) { return n < 1024 ? n + " B" : n < 1048576 ? (n / 1024).toFixed(0) + " KB" : (n / 1048576).toFixed(1) + " MB"; }

async function render() {
  const { history = [] } = await browser.storage.local.get({ history: [] });
  const list = document.getElementById("list");
  list.replaceChildren();
  if (!history.length) {
    const li = document.createElement("li");
    li.className = "empty";
    li.textContent = "No attachments scanned yet. Open a LinkedIn chat with a file in it.";
    list.append(li);
    return;
  }
  for (const h of history) {
    const li = document.createElement("li");
    li.className = h.verdict;
    li.title = "SHA-256 " + h.sha256;
    const dot = document.createElement("span"); dot.className = "dot";
    const body = document.createElement("div");
    const name = document.createElement("div"); name.className = "name"; name.textContent = h.filename;
    const meta = document.createElement("div"); meta.className = "meta";
    const v = document.createElement("span"); v.className = "v"; v.textContent = LABEL[h.verdict] || h.verdict;
    meta.append(v, document.createTextNode(` \u00b7 ${h.reason ? h.reason + " \u00b7 " : ""}${size(h.size)} \u00b7 ${ago(h.at)}`));
    body.append(name, meta);
    li.append(dot, body);
    list.append(li);
  }
}

(async () => {
  const s = await browser.storage.local.get({ autoScan: true, vtApiKey: "" });
  const t = document.getElementById("autoScan");
  t.checked = s.autoScan;
  t.addEventListener("change", () => browser.storage.local.set({ autoScan: t.checked }));
  // A saved key only counts once the user has allowed the data sharing it needs (see getSettings in background.js).
  const perms = await browser.permissions.getAll();
  const vtOn = s.vtApiKey && (!perms.data_collection || perms.data_collection.includes("websiteContent"));
  document.getElementById("vt").textContent = vtOn ? "VirusTotal lookup on" : "VirusTotal lookup off";
  document.getElementById("settings").addEventListener("click", () => { browser.runtime.openOptionsPage(); window.close(); });
  document.getElementById("clear").addEventListener("click", async () => { await browser.storage.local.set({ history: [] }); render(); });
  render();
})();
