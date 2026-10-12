/* global browser */
"use strict";
const $ = (id) => document.getElementById(id);
const DEFAULTS = { vtApiKey: "", watchAllDownloads: true, blockOnCaution: false, driveClientId: "" };

(async () => {
  const s = await browser.storage.local.get(DEFAULTS);
  $("vtApiKey").value = s.vtApiKey;
  $("driveClientId").value = s.driveClientId;
  // Must match driveRedirectUrl() in background.js.
  $("driveRedirect").value = `http://127.0.0.1/mozoauth2/${new URL(browser.identity.getRedirectURL()).hostname.split(".")[0]}`;
  $("watchAllDownloads").checked = s.watchAllDownloads;
  $("blockOnCaution").checked = s.blockOnCaution;
})();

$("save").addEventListener("click", async () => {
  await browser.storage.local.set({
    vtApiKey: $("vtApiKey").value.trim(),
    driveClientId: $("driveClientId").value.trim(),
    watchAllDownloads: $("watchAllDownloads").checked,
    blockOnCaution: $("blockOnCaution").checked
  });
  $("status").textContent = "Saved.";
  setTimeout(() => ($("status").textContent = ""), 2000);
});

$("test").addEventListener("click", async () => {
  const key = $("vtApiKey").value.trim();
  if (!key) { $("testResult").textContent = "Enter a key first."; return; }
  $("testResult").textContent = "Testing\u2026";
  const r = await browser.runtime.sendMessage({ type: "testVirusTotal", apiKey: key });
  $("testResult").textContent = !r ? "No response."
    : r.error ? r.error
    : r.known ? `Key works (test file flagged by ${r.malicious}/${r.total} engines).`
    : "Key works.";
});
