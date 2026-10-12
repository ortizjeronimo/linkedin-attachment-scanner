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
  const vtApiKey = $("vtApiKey").value.trim();
  const driveClientId = $("driveClientId").value.trim();
  // Both optional features send data off this device, so Firefox asks the user to allow it.
  // This has to be the first await: the prompt only appears from a user action.
  // Keep the data types in sync with background.js and data_collection_permissions in manifest.json.
  const wanted = [...(vtApiKey || driveClientId ? ["websiteContent"] : []), ...(driveClientId ? ["personalCommunications"] : [])];
  let allowed = true;
  if (wanted.length) {
    try { allowed = await browser.permissions.request({ data_collection: wanted }); } catch (_) { allowed = false; }
  }
  await browser.storage.local.set({
    vtApiKey,
    driveClientId,
    watchAllDownloads: $("watchAllDownloads").checked,
    blockOnCaution: $("blockOnCaution").checked
  });
  if (allowed) {
    $("status").textContent = "Saved.";
    setTimeout(() => ($("status").textContent = ""), 2000);
  } else {
    $("status").textContent = "Saved, but VirusTotal and Google Drive stay off until you allow the data sharing Firefox asked about. Click Save to be asked again.";
  }
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
