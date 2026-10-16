/* global browser, AttachmentAnalyzer */
"use strict";

const LINKEDIN_HOST = /(^|\.)(linkedin\.com|licdn\.com)$/i;
const MAX_BYTES = 100 * 1024 * 1024;

// Scanned files waiting for the user's decision: scanId -> { bytes, result, url }
const pending = new Map();
// Downloads this extension started itself (skip re-scanning them).
const ownDownloads = new Set();
const ownBlobUrls = new Set();
// Original URLs already scanned and approved in the chat UI, so the safety net doesn't fire twice.
const approvedUrls = new Map();

const newId = () => Math.random().toString(36).slice(2) + Date.now().toString(36);

function isLinkedInUrl(u) {
  try { return LINKEDIN_HOST.test(new URL(u).hostname); } catch (_) { return false; }
}

// The two optional features send data off this device, so each only counts as switched on once the
// user has allowed its data types in Firefox (asked when the key is saved in the settings page).
// Keep these in sync with options.js and data_collection_permissions in manifest.json.
const DATA_VIRUSTOTAL = ["websiteContent"];
const DATA_DRIVE = ["websiteContent", "personalCommunications"];
async function dataAllowed(types) {
  const p = await browser.permissions.getAll();
  return !p.data_collection || types.every((t) => p.data_collection.includes(t));
}

async function getSettings() {
  const s = await browser.storage.local.get({ vtApiKey: "", watchAllDownloads: true, blockOnCaution: false, autoScan: true, driveClientId: "" });
  if (s.vtApiKey && !(await dataAllowed(DATA_VIRUSTOTAL))) s.vtApiKey = "";
  if (s.driveClientId && !(await dataAllowed(DATA_DRIVE))) s.driveClientId = "";
  return s;
}

// ---------- fetching ----------
async function fetchBytes(url) {
  const resp = await fetch(url, { credentials: "include", redirect: "follow" });
  if (!resp.ok) throw new Error(`LinkedIn returned HTTP ${resp.status}`);
  const len = Number(resp.headers.get("content-length") || 0);
  if (len > MAX_BYTES) throw new Error("File is larger than 100 MB; not scanned.");
  const buf = new Uint8Array(await resp.arrayBuffer());
  if (buf.length > MAX_BYTES) throw new Error("File is larger than 100 MB; not scanned.");
  return { bytes: buf, filenameHint: filenameFromHeaders(resp.headers), finalUrl: resp.url };
}

function filenameFromHeaders(h) {
  const cd = h.get("content-disposition") || "";
  const star = /filename\*\s*=\s*(?:UTF-8'')?([^;]+)/i.exec(cd);
  if (star) { try { return decodeURIComponent(star[1].trim().replace(/^"|"$/g, "")); } catch (_) { /* fallthrough */ } }
  const plain = /filename\s*=\s*"?([^";]+)"?/i.exec(cd);
  return plain ? plain[1].trim() : "";
}

function filenameFromUrl(u) {
  try {
    const p = new URL(u).pathname.split("/").filter(Boolean).pop() || "";
    return decodeURIComponent(p);
  } catch (_) { return ""; }
}

// ---------- VirusTotal (hash only \u2014 the file is never uploaded) ----------
async function virusTotalLookup(sha256, apiKey) {
  if (!apiKey) return null;
  try {
    const r = await fetch(`https://www.virustotal.com/api/v3/files/${sha256}`, { headers: { "x-apikey": apiKey } });
    if (r.status === 404) return { known: false };
    if (r.status === 401 || r.status === 403) return { error: "VirusTotal rejected the API key." };
    if (r.status === 429) return { error: "VirusTotal rate limit reached (free keys allow 4 lookups/minute)." };
    if (!r.ok) return { error: `VirusTotal error ${r.status}` };
    const j = await r.json();
    const a = (j.data && j.data.attributes) || {};
    const st = a.last_analysis_stats || {};
    return {
      known: true,
      malicious: st.malicious || 0,
      suspicious: st.suspicious || 0,
      total: Object.values(st).reduce((x, y) => x + y, 0),
      label: (a.popular_threat_classification && a.popular_threat_classification.suggested_threat_label) || "",
      link: `https://www.virustotal.com/gui/file/${sha256}`
    };
  } catch (e) {
    return { error: "Could not reach VirusTotal: " + e.message };
  }
}

function mergeVirusTotal(result, vt) {
  result.virustotal = vt;
  if (!vt) return result;
  if (vt.error) {
    result.findings.push({ level: "info", title: "VirusTotal lookup failed", detail: vt.error });
  } else if (!vt.known) {
    result.findings.push({ level: "info", title: "Not known to VirusTotal",
      detail: "Nobody has submitted this exact file before. That's normal for personal documents, but targeted attacks also use fresh files, so rely on the local checks above." });
  } else if (vt.malicious > 0) {
    result.findings.unshift({ level: "danger", title: `VirusTotal: ${vt.malicious}/${vt.total} engines flag this file`,
      detail: (vt.label ? `Identified as "${vt.label}". ` : "") + "This is a known malicious file." });
    result.verdict = "suspicious";
  } else if (vt.suspicious > 0) {
    result.findings.unshift({ level: "warning", title: `VirusTotal: ${vt.suspicious}/${vt.total} engines consider it suspicious`, detail: "" });
    if (result.verdict === "clean") result.verdict = "caution";
  } else {
    result.findings.push({ level: "info", title: `VirusTotal: 0/${vt.total} detections`, detail: "This exact file is known and no engine flags it." });
  }
  return result;
}

// ---------- scan cache, queue and history ----------
// The same attachment is often rendered several times (chat page + overlay), and signed
// URLs change their query string, so results are cached by origin + path.
const scanCache = new Map(); // key -> Promise<{scanId, result}>
const vtCache = new Map();   // sha256 -> VirusTotal result
const urlKey = (u) => { try { const x = new URL(u); return x.origin + x.pathname; } catch (_) { return u; } };

let active = 0;
const waiting = [];
async function limited(fn) {
  if (active >= 2) await new Promise((r) => waiting.push(r));
  active++;
  try { return await fn(); } finally { active--; const n = waiting.shift(); if (n) n(); }
}

function scanCached(url, nameHint) {
  const key = urlKey(url);
  if (scanCache.has(key)) return scanCache.get(key);
  const p = limited(() => scanUrl(url, nameHint));
  scanCache.set(key, p);
  p.catch(() => scanCache.delete(key));
  setTimeout(() => scanCache.delete(key), 30 * 60 * 1000);
  return p;
}

async function addHistory(result) {
  const { history } = await browser.storage.local.get({ history: [] });
  const top = result.findings.find((f) => f.level !== "info");
  const entry = { filename: result.filename, verdict: result.verdict, size: result.size, sha256: result.sha256,
    at: Date.now(), reason: top ? top.title : "" };
  const next = [entry, ...history.filter((h) => h.sha256 !== result.sha256)].slice(0, 50);
  await browser.storage.local.set({ history: next });
}

async function scanUrl(url, nameHint) {
  const { bytes, filenameHint, finalUrl } = await fetchBytes(url);
  const hasExt = (n) => /\.[a-z0-9]{2,5}$/i.test(n || "");
  const filename = [nameHint, filenameHint, filenameFromUrl(finalUrl)].find(hasExt) || nameHint || filenameHint || "attachment";
  const result = await AttachmentAnalyzer.analyze(bytes, filename);
  const { vtApiKey } = await getSettings();
  let vt = vtCache.get(result.sha256);
  if (!vt && vtApiKey) { vt = await virusTotalLookup(result.sha256, vtApiKey); if (vt && !vt.error) vtCache.set(result.sha256, vt); }
  mergeVirusTotal(result, vt || null);
  addHistory(result).catch(() => {});
  const scanId = newId();
  pending.set(scanId, { bytes, result, url });
  setTimeout(() => pending.delete(scanId), 30 * 60 * 1000);
  return { scanId, result };
}

async function saveScanned(scanId) {
  const p = pending.get(scanId);
  if (!p || !p.bytes) throw new Error("This scan has expired. Please scan the file again.");
  const blobUrl = URL.createObjectURL(new Blob([p.bytes]));
  ownBlobUrls.add(blobUrl);
  approvedUrls.set(p.url, Date.now());
  const safeName = p.result.filename.replace(/[\u202a-\u202e\u2066-\u2069]/g, "").replace(/[\\/:*?"<>|]/g, "_");
  const id = await browser.downloads.download({ url: blobUrl, filename: safeName, saveAs: false, conflictAction: "uniquify" });
  ownDownloads.add(id);
  setTimeout(() => { URL.revokeObjectURL(blobUrl); ownBlobUrls.delete(blobUrl); }, 120000);
  return id;
}

// ---------- Google Drive (opt-in: uploads the file so it can be viewed without saving it locally) ----------
// The drive.file scope only gives access to files this extension uploaded, not the rest of the user's Drive.
const DRIVE_SCOPE = "https://www.googleapis.com/auth/drive.file";
const DRIVE_MIME = {
  pdf: "application/pdf", rtf: "application/rtf", txt: "text/plain", csv: "text/csv", zip: "application/zip",
  doc: "application/msword", xls: "application/vnd.ms-excel", ppt: "application/vnd.ms-powerpoint",
  docx: "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
  xlsx: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
  pptx: "application/vnd.openxmlformats-officedocument.presentationml.presentation",
  png: "image/png", jpg: "image/jpeg", jpeg: "image/jpeg", gif: "image/gif"
};
let driveToken = null; // { clientId, token, expires }

// Google only accepts redirect URLs on domains the developer owns, so use Firefox's loopback form.
function driveRedirectUrl() {
  const sub = new URL(browser.identity.getRedirectURL()).hostname.split(".")[0];
  return `http://127.0.0.1/mozoauth2/${sub}`;
}

async function driveAuth(clientId) {
  if (driveToken && driveToken.clientId === clientId && Date.now() < driveToken.expires) return driveToken.token;
  const state = newId();
  const url = "https://accounts.google.com/o/oauth2/v2/auth?" + new URLSearchParams({
    client_id: clientId, response_type: "token", redirect_uri: driveRedirectUrl(), scope: DRIVE_SCOPE, state
  });
  const parse = (back) => new URLSearchParams(new URL(back).hash.slice(1));
  let params;
  try {
    // Silent first (already signed in and consented). Google answers that with an error such as
    // "interaction_required" when it needs the user, so then show the sign-in window.
    params = await browser.identity.launchWebAuthFlow({ url: url + "&prompt=none", interactive: false }).then(parse).catch(() => null);
    if (!params || params.get("error")) params = parse(await browser.identity.launchWebAuthFlow({ url, interactive: true }));
  } catch (e) {
    throw new Error("Google sign-in was cancelled or failed: " + e.message);
  }
  if (params.get("error")) throw new Error("Google sign-in failed: " + params.get("error"));
  const token = params.get("access_token");
  if (!token || params.get("state") !== state) throw new Error("Google sign-in returned an unexpected response.");
  driveToken = { clientId, token, expires: Date.now() + (Number(params.get("expires_in") || 3600) - 60) * 1000 };
  return token;
}

async function driveError(resp) {
  if (resp.status === 401) driveToken = null;
  let detail = "";
  try { detail = (await resp.json()).error.message; } catch (_) { /* no JSON body */ }
  return new Error(`Google Drive error ${resp.status}${detail ? ": " + detail : ""}`);
}

async function openInDrive(scanId) {
  const p = pending.get(scanId);
  if (!p || !p.bytes) throw new Error("This scan has expired. Please scan the file again.");
  const { driveClientId } = await getSettings();
  if (!driveClientId) throw new Error("Google Drive isn't set up, or sharing files with it isn't allowed yet. Open the extension's settings and click Save.");
  const token = await driveAuth(driveClientId);
  const name = p.result.filename.replace(/[‪-‮⁦-⁩]/g, "");
  const mime = DRIVE_MIME[(/\.([a-z0-9]+)$/i.exec(name) || [])[1]?.toLowerCase()] || "application/octet-stream";

  // Resumable upload: the simpler multipart endpoint is limited to 5 MB.
  const start = await fetch("https://www.googleapis.com/upload/drive/v3/files?uploadType=resumable&fields=id,webViewLink", {
    method: "POST",
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json; charset=UTF-8", "X-Upload-Content-Type": mime },
    body: JSON.stringify({ name, description: "Uploaded by LinkedIn Attachment Scanner to view without opening it on this computer." })
  });
  if (!start.ok) throw await driveError(start);
  const session = start.headers.get("location");
  if (!session) throw new Error("Google Drive didn't return an upload address.");
  const put = await fetch(session, { method: "PUT", headers: { "Content-Type": mime }, body: p.bytes });
  if (!put.ok) throw await driveError(put);
  const file = await put.json();
  const link = file.webViewLink || `https://drive.google.com/file/d/${file.id}/view`;
  await browser.tabs.create({ url: link });
  return link;
}

// ---------- capture: attachments LinkedIn only exposes as a button ----------
// Such a card has no link to fetch, so the content script clicks LinkedIn's own button and the
// download it starts is intercepted below: the original is discarded and its URL scanned instead.
const captures = new Map(); // token -> { name, key, claimed, promise, resolve }

function expectDownload(filename) {
  const token = newId();
  const name = (filename || "").trim();
  const c = { name, key: name.toLowerCase(), claimed: false };
  c.promise = new Promise((r) => { c.resolve = r; });
  captures.set(token, c);
  setTimeout(() => { if (!c.claimed) { c.claimed = true; c.resolve({ error: "LinkedIn didn't start a download for this file." }); } }, 15000);
  setTimeout(() => captures.delete(token), 10 * 60 * 1000);
  return token;
}

function claimCapture(item) {
  const name = (item.filename || "").split(/[\\/]/).pop().toLowerCase();
  const open = [...captures.values()].filter((c) => !c.claimed);
  const c = open.find((x) => x.key && x.key === name) || open[0];
  if (c) c.claimed = true;
  return c || null;
}

async function discardDownload(id) {
  await browser.downloads.cancel(id).catch(() => {});
  const [d] = await browser.downloads.search({ id }).catch(() => []);
  if (d && d.state === "complete") await browser.downloads.removeFile(id).catch(() => {});
  await browser.downloads.erase({ id }).catch(() => {});
}

// ---------- messages from content script / warning page / options ----------
browser.runtime.onMessage.addListener((msg, sender) => {
  switch (msg && msg.type) {
    case "scan":
      return scanCached(msg.url, msg.filename).catch((e) => ({ error: e.message }));
    case "expectDownload":
      return Promise.resolve({ token: expectDownload(msg.filename) });
    case "awaitDownload": {
      const c = captures.get(msg.token);
      return c ? c.promise : Promise.resolve({ error: "This scan request has expired." });
    }
    case "settings":
      return getSettings().then(({ autoScan, driveClientId }) => ({ autoScan, drive: !!driveClientId }));
    case "openInDrive":
      return openInDrive(msg.scanId).then((link) => ({ ok: true, link })).catch((e) => ({ error: e.message, expired: !pending.has(msg.scanId) }));
    case "getHistory":
      return browser.storage.local.get({ history: [] });
    case "clearHistory":
      return browser.storage.local.set({ history: [] }).then(() => ({ ok: true }));
    case "save":
      return saveScanned(msg.scanId).then((id) => ({ ok: true, id })).catch((e) => ({ error: e.message, expired: !pending.has(msg.scanId) }));
    case "discard":
      // Scans stay cached (and expire after 30 minutes) so the inline status stays accurate.
      return Promise.resolve({ ok: true });
    case "getScan": {
      const p = pending.get(msg.scanId);
      if (!p) return Promise.resolve({ error: "Scan expired." });
      if (p.error) return Promise.resolve({ scanError: p.error, filename: p.filename, safetyNet: p.safetyNet });
      return getSettings().then(({ driveClientId }) => ({ result: p.result, safetyNet: p.safetyNet || null, drive: !!driveClientId }));
    }
    case "deleteDownloaded": {
      const p = pending.get(msg.scanId);
      if (!p || !p.safetyNet || p.safetyNet.downloadId == null) return Promise.resolve({ error: "Nothing to delete." });
      return browser.downloads.removeFile(p.safetyNet.downloadId)
        .then(() => browser.downloads.erase({ id: p.safetyNet.downloadId }))
        .then(() => ({ ok: true })).catch((e) => ({ error: e.message }));
    }
    case "downloadUnscanned": {
      // Only for a download the safety net stopped because its scan failed; the user asked for it anyway.
      const p = pending.get(msg.scanId);
      if (!p || !p.error) return Promise.resolve({ error: "Nothing to download." });
      approvedUrls.set(p.url, Date.now());
      return browser.downloads.download({ url: p.url }).then(() => ({ ok: true })).catch((e) => ({ error: e.message }));
    }
    case "testVirusTotal":
      return virusTotalLookup("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", msg.apiKey); // EICAR test file hash
    default:
      return undefined;
  }
});

// ---------- safety net: any download coming from LinkedIn ----------
// Catches files that the chat button didn't intercept (UI changes, "Download" menus, previews\u2026).
browser.downloads.onCreated.addListener(async (item) => {
  if (ownDownloads.has(item.id) || ownBlobUrls.has(item.url)) return;
  const fromLinkedIn = isLinkedInUrl(item.url) || (item.referrer && isLinkedInUrl(item.referrer));
  if (!fromLinkedIn || !/^https?:/i.test(item.url)) return;

  // A download the content script triggered just to learn the file's URL (see "capture" above).
  const capture = claimCapture(item);
  if (capture) {
    await discardDownload(item.id);
    capture.resolve(await scanCached(item.url, capture.name || (item.filename || "").split(/[\\/]/).pop()).catch((e) => ({ error: e.message })));
    return;
  }

  const { watchAllDownloads } = await getSettings();
  if (!watchAllDownloads) return;
  const ap = approvedUrls.get(item.url);
  if (ap && Date.now() - ap < 5 * 60 * 1000) return;

  let paused = false;
  try { await browser.downloads.pause(item.id); paused = true; } catch (_) { /* small files may already be finished */ }

  let scan;
  const nameHint = (item.filename || "").split(/[\\/]/).pop();
  try {
    scan = await scanCached(item.url, nameHint);
  } catch (e) {
    console.error("[LAS] scan of LinkedIn download failed", item.url, e);
    // Fail closed: a file that couldn't be scanned (possibly because it was built to break the
    // scanner) is stopped and explained, and only continues if the user asks for it.
    if (paused) {
      await browser.downloads.cancel(item.id).catch(() => {});
      await browser.downloads.erase({ id: item.id }).catch(() => {});
    }
    const scanId = newId();
    pending.set(scanId, { url: item.url, error: e.message, filename: nameHint,
      safetyNet: paused ? { stopped: true } : { stopped: false, downloadId: item.id } });
    setTimeout(() => pending.delete(scanId), 30 * 60 * 1000);
    notify("LinkedIn download couldn't be scanned", e.message);
    browser.tabs.create({ url: browser.runtime.getURL(`warning.html?id=${encodeURIComponent(scanId)}`) });
    return;
  }

  const { result } = scan;
  const { blockOnCaution } = await getSettings();
  const block = result.verdict === "suspicious" || (blockOnCaution && result.verdict === "caution");

  // LinkedIn's signed download links don't survive pause/resume, so when we paused the
  // original we drop it and save the copy we already downloaded and scanned instead.
  const dropOriginal = async () => {
    await browser.downloads.cancel(item.id).catch(() => {});
    await browser.downloads.erase({ id: item.id }).catch(() => {});
  };

  if (!block) {
    if (paused) {
      await dropOriginal();
      await saveScanned(scan.scanId).catch((e) => notify("Download failed", e.message));
    }
    if (result.verdict === "caution") notify(`Be careful with ${result.filename}`, result.findings[0].title);
    else notify(`Scanned ${result.filename}`, "No red flags found.");
    return;
  }

  const entry = pending.get(scan.scanId);
  if (paused) {
    await dropOriginal();
    entry.safetyNet = { stopped: true };
  } else {
    entry.safetyNet = { stopped: false, downloadId: item.id };
  }
  browser.tabs.create({ url: browser.runtime.getURL(`warning.html?id=${encodeURIComponent(scan.scanId)}`) });
});

function notify(title, message) {
  browser.notifications.create({ type: "basic", iconUrl: browser.runtime.getURL("icons/shield.svg"), title, message: message || "" }).catch(() => {});
}

