/* global browser, LASRender */
"use strict";

(() => {
  // Paths where LinkedIn serves files sent in messages. Anyone can paste a linkedin.com link into a
  // message, so a link only counts as an attachment by its path (or by sitting in an attachment card),
  // never by its query string: otherwise a sender could make the extension fetch any LinkedIn URL
  // with the user's cookies.
  const ATTACHMENT_PATH = /^(?:\/(?:dms|dms-uploads|ambry)\/|.*messaging-attachments)/i;
  const IMAGE_HREF = /\.(png|jpe?g|gif|webp)(\?|$)|\/image\//i;
  const LI_HOST = /(^|\.)(linkedin\.com|licdn\.com)$/i;
  // LinkedIn's newer attachment card: a button with no URL; its script starts the download on click.
  const BUTTON_SEL = 'button[class*="download-attachment-button"]';
  const CARD_SEL ='[class*="download-attachment"], [class*="listitem__attachment"], [class*="attachment-item"], [class*="attachment-card"]';
  const FONT = '-apple-system, system-ui, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", sans-serif';

  let autoScan = true;
  let driveEnabled = false;
  let bypass = null;
  const cards = new Map(); // link element -> { host, row, state, result, scanId, promise, filename }

  // ---------- DOM helpers ----------
  const shadowOf = (el) => el.openOrClosedShadowRoot || el.shadowRoot || null;
  function deepQueryAll(sel, root = document, out = []) {
    out.push(...root.querySelectorAll(sel));
    for (const el of root.querySelectorAll("*")) {
      if (el.hasAttribute("data-las-chip")) continue;
      const sr = shadowOf(el);
      if (sr) deepQueryAll(sel, sr, out);
    }
    return out;
  }
  // Page-type checks look at the path only, so text elsewhere in a URL (e.g. its query) can't match.
  function pathOf(url) {
    try { return new URL(url, location.href).pathname; } catch (_) { return ""; }
  }
  function hostOk(url) {
    try { return LI_HOST.test(new URL(url, location.href).hostname); } catch (_) { return false; }
  }
  function inMessaging(a) {
    return location.pathname.startsWith("/messaging") ||
      !!a.closest('[class*="msg-"], [class*="messaging"], [data-test-id*="msg"], aside[class*="overlay"]');
  }
  function isAttachmentLink(a) {
    if (!a || !a.href || !hostOk(a.href)) return false;
    if (!inMessaging(a)) return false;
    const cls = (a.className && a.className.baseVal !== undefined ? a.className.baseVal : a.className) || "";
    const containerHint = /attachment|file/i.test(cls) || !!a.closest('[class*="attachment"], [class*="file-"]') ||
      !!a.querySelector('[class*="attachment"]');
    const looksLikeFile = a.hasAttribute("download") || ATTACHMENT_PATH.test(pathOf(a.href));
    if (!looksLikeFile && !containerHint) return false;
    const onlyImage = a.querySelector("img") && !a.textContent.trim();
    if (onlyImage && IMAGE_HREF.test(a.href)) return false;
    if (/^\/(in|company|jobs|feed|posts|school|events|groups)\//i.test(pathOf(a.href))) return false;
    return true;
  }
  function findAttachmentLink(target) {
    if (!target || !target.closest) return null;
    const button = target.closest(BUTTON_SEL);
    if (button) return button;
    const a = target.closest("a[href]");
    if (a && isAttachmentLink(a)) return a;
    const card = target.closest(CARD_SEL);
    if (!card) return null;
    if (a && hostOk(a.href)) return a;
    let c = card;
    for (let i = 0; c && i < 5; i++, c = c.parentElement) {
      const x = c.matches("a[href]") ? c : c.querySelector("a[href]");
      if (x && hostOk(x.href) && !/^\/(in|company)\//i.test(pathOf(x.href))) return x;
    }
    return null;
  }
  // The visual card: the nearest ancestor that also holds LinkedIn's Download button.
  function cardRoot(a) {
    let c = a.parentElement;
    for (let i = 0; c && i < 5; i++, c = c.parentElement) {
      if (c.querySelector('[class*="download-attachment"]')) return c;
    }
    return (a.parentElement && a.parentElement.closest(CARD_SEL)) || a;
  }
  function guessFilename(a) {
    const dl = a.getAttribute("download");
    if (dl) return dl;
    const scope = a.matches(BUTTON_SEL) ? a : cardRoot(a);
    const named = scope.querySelector('[class*="file-name"], [class*="filename"], [class*="attachment-name"], [class*="attachment__name"], [class*="title"]');
    if (named && named.textContent.trim()) return named.textContent.trim();
    const aria = a.getAttribute("aria-label") || a.title || "";
    const m = /(?:download|open|view)\s+(?:attachment\s+)?(.+)/i.exec(aria);
    if (m) return m[1].trim();
    const line = (a.innerText || "").split("\n").map((s) => s.trim()).find((s) => /\.[a-z0-9]{2,5}$/i.test(s));
    return line || "";
  }

  // ---------- inline status line under each attachment ----------
  const ICONS = {
    shield: '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16" width="14" height="14" aria-hidden="true"><path fill="currentColor" d="M8 1 2.5 3v4.2c0 3.4 2.3 6.3 5.5 7.3 3.2-1 5.5-3.9 5.5-7.3V3L8 1zm0 1.6 4 1.5v3.1c0 2.6-1.7 4.9-4 5.8-2.3-.9-4-3.2-4-5.8V4.1l4-1.5z"/></svg>',
    check: '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16" width="14" height="14" aria-hidden="true"><path fill="currentColor" d="M8 1 2.5 3v4.2c0 3.4 2.3 6.3 5.5 7.3 3.2-1 5.5-3.9 5.5-7.3V3L8 1zm-1 10L4.3 8.3l1.1-1.1L7 8.8l3.6-3.6 1.1 1.1L7 11z"/></svg>',
    warn: '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16" width="14" height="14" aria-hidden="true"><path fill="currentColor" d="M8 1.5 1 14h14L8 1.5zM7.25 6h1.5v4h-1.5V6zm0 5h1.5v1.5h-1.5V11z"/></svg>',
    stop: '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16" width="14" height="14" aria-hidden="true"><path fill="currentColor" d="M5.1 1 1 5.1v5.8L5.1 15h5.8l4.1-4.1V5.1L10.9 1H5.1zm-.2 4 1.1-1.1L8 5.9l2-2L11.1 5l-2 2 2 2L10 10.1l-2-2-2 2L4.9 9l2-2-2-2z"/></svg>'
  };
  function svgIcon(markup) {
    const doc = new DOMParser().parseFromString(markup, "image/svg+xml");
    return document.importNode(doc.documentElement, true);
  }
  const CHIP_CSS = `
    :host { all: initial; display: block; }
    .row { font: 600 12px/16px ${FONT}; display: flex; align-items: center; gap: 6px; margin: 6px 0 2px;
      padding: 5px 10px; border-radius: 8px; width: fit-content; max-width: 100%; box-sizing: border-box;
      color: var(--fg); background: var(--bg); border: 1px solid var(--bd); }
    .icon { display: inline-flex; flex: none; }
    .text { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; min-width: 0; }
    .sub { font-weight: 400; opacity: .85; }
    button { all: unset; cursor: pointer; font: 600 12px/16px ${FONT}; color: #0a66c2; margin-left: 4px; white-space: nowrap; }
    button:hover { text-decoration: underline; }
    button:focus-visible { outline: 2px solid #0a66c2; outline-offset: 2px; border-radius: 3px; }
    .spin { width: 10px; height: 10px; border: 2px solid currentColor; border-right-color: transparent; border-radius: 50%; animation: r .8s linear infinite; }
    @keyframes r { to { transform: rotate(360deg); } }
    .scanning, .idle, .error { --fg: #56687a; --bg: #f3f6f8; --bd: #e0e5e9; }
    .clean      { --fg: #057642; --bg: #eef7f1; --bd: #cfe8d8; }
    .caution    { --fg: #915907; --bg: #fdf6e7; --bd: #f1ddb0; }
    .suspicious { --fg: #b24020; --bg: #fdeee9; --bd: #f3c8bb; }
    .dark.scanning, .dark.idle, .dark.error { --fg: #c0c7cd; --bg: #2a3036; --bd: #3d454c; }
    .dark.clean { --fg: #7fd1a1; --bg: #16302a; --bd: #24493b; }
    .dark.caution { --fg: #f2c46b; --bg: #362c17; --bd: #54441f; }
    .dark.suspicious { --fg: #f6a28c; --bg: #3b211c; --bd: #5c3027; }
    .dark button { color: #71b7fb; }`;
  // Follow LinkedIn's own theme, not the system's: the page can be light while the OS is dark.
  const isDark = () => !!document.querySelector(".theme--dark");

  // The chip sits below the message bubble; indent it so it lines up with the attachment card.
  function alignChip(a, host) {
    host.style.marginLeft = "";
    const dx = a.getBoundingClientRect().left - host.getBoundingClientRect().left;
    if (dx > 0 && dx < 300) host.style.marginLeft = dx + "px";
  }

  function ensureChip(a) {
    let entry = cards.get(a);
    if (entry && entry.host.isConnected) return entry;
    const host = document.createElement("div");
    host.setAttribute("data-las-chip", "");
    const shadow = host.attachShadow({ mode: "closed" });
    const style = document.createElement("style");
    style.textContent = CHIP_CSS;
    const row = document.createElement("div");
    shadow.append(style, row);
    cardRoot(a).after(host);
    entry = Object.assign(entry || { state: "idle", filename: guessFilename(a) }, { host, row });
    cards.set(a, entry);
    renderChip(a);
    return entry;
  }

  function renderChip(a) {
    const e = cards.get(a);
    if (!e) return;
    const row = e.row;
    row.className = "row " + e.state + (isDark() ? " dark" : "");
    if (a.matches(BUTTON_SEL)) alignChip(a, e.host);
    row.replaceChildren();
    const icon = document.createElement("span");
    icon.className = "icon";
    const text = document.createElement("span");
    text.className = "text";
    const sub = document.createElement("span");
    sub.className = "sub";
    let action = null;

    if (e.state === "scanning") {
      const s = document.createElement("span"); s.className = "spin"; icon.append(s);
      text.textContent = "Scanning for threats\u2026";
    } else if (e.state === "idle") {
      icon.append(svgIcon(ICONS.shield));
      text.textContent = a.matches(BUTTON_SEL) ? "Will be scanned when you download" : "Not scanned yet";
      action = ["Scan now", () => startScan(a)];
    } else if (e.state === "error") {
      icon.append(svgIcon(ICONS.shield));
      text.textContent = "Couldn't scan";
      sub.textContent = " \u00b7 " + (e.error || "unknown error");
      action = ["Retry", () => startScan(a, true)];
    } else {
      const r = e.result;
      const top = r.findings.find((f) => f.level !== "info");
      if (e.state === "clean") {
        icon.append(svgIcon(ICONS.check));
        text.textContent = "No threats found";
        sub.textContent = r.virustotal && r.virustotal.known ? " \u00b7 checked locally and on VirusTotal" : " \u00b7 checked locally";
      } else if (e.state === "caution") {
        icon.append(svgIcon(ICONS.warn));
        text.textContent = "Review before opening";
        sub.textContent = top ? " \u00b7 " + top.title : "";
      } else {
        icon.append(svgIcon(ICONS.stop));
        text.textContent = "Dangerous file \u2014 don't open";
        sub.textContent = top ? " \u00b7 " + top.title : "";
      }
      action = ["Details", () => showResultDialog(a)];
    }
    text.append(sub);
    row.append(icon, text);
    if (action) {
      const b = document.createElement("button");
      b.type = "button";
      b.textContent = action[0];
      b.addEventListener("click", (ev) => { ev.preventDefault(); ev.stopPropagation(); action[1](); });
      row.append(b);
    }
    row.title = e.result ? `${e.result.filename} \u00b7 SHA-256 ${e.result.sha256.slice(0, 16)}\u2026` : "";
  }

  // Button cards have no URL: click LinkedIn's button for real and let the background intercept
  // the download it starts. One at a time, so each download is matched to the right card.
  let captureQueue = Promise.resolve();
  function captureScan(a, e) {
    const p = captureQueue.then(async () => {
      const { token } = await browser.runtime.sendMessage({ type: "expectDownload", filename: e.filename });
      bypass = a;
      a.click();
      bypass = null;
      return browser.runtime.sendMessage({ type: "awaitDownload", token });
    });
    captureQueue = p.catch(() => {});
    return p;
  }

  function startScan(a, force) {
    const e = ensureChip(a);
    if (e.promise && !force) return e.promise;
    e.state = "scanning";
    renderChip(a);
    const request = a.matches(BUTTON_SEL) ? captureScan(a, e)
      : browser.runtime.sendMessage({ type: "scan", url: a.href, filename: e.filename });
    e.promise = request
      .catch((err) => ({ error: err.message }))
      .then((resp) => {
        if (resp.error) { e.state = "error"; e.error = resp.error; e.promise = null; }
        else { e.state = resp.result.verdict; e.result = resp.result; e.scanId = resp.scanId; }
        renderChip(a);
        return resp;
      });
    return e.promise;
  }

  // ---------- dialog ----------
  let overlay = null;
  let dialogFor = null;
  function openDialog(a) {
    dialogFor = a;
    closeDialog();
    overlay = document.createElement("div");
    overlay.style.cssText = "position:fixed;inset:0;z-index:2147483647;display:grid;place-items:center;background:rgba(0,0,0,.6);";
    const shadow = overlay.attachShadow({ mode: "closed" });
    const style = document.createElement("style");
    style.textContent = LASRender.CSS;
    LASRender.setDark(isDark());
    const slot = document.createElement("div");
    shadow.append(style, slot);
    overlay.addEventListener("click", (ev) => { if (ev.target === overlay) closeDialog(); });
    document.documentElement.append(overlay);
    document.addEventListener("keydown", onKey, true);
    return slot;
  }
  function onKey(ev) { if (ev.key === "Escape") { ev.stopPropagation(); closeDialog(); } }
  function closeDialog() {
    if (overlay) overlay.remove();
    overlay = null;
    dialogFor = null;
    document.removeEventListener("keydown", onKey, true);
  }

  // The background keeps a scanned file for 30 minutes. After that the status line still shows the
  // old verdict, so scan again; returns false if the new verdict needs the user to look first.
  async function rescanExpired(a) {
    const e = cards.get(a);
    const before = e.state;
    await startScan(a, true);
    if (e.state === before) return true;
    if (dialogFor === a) closeDialog();
    showResultDialog(a);
    return false;
  }

  async function save(a, retried) {
    const e = cards.get(a);
    const s = await browser.runtime.sendMessage({ type: "save", scanId: e.scanId });
    if (s.expired && !retried) {
      if (await rescanExpired(a)) return save(a, true);
      return;
    }
    if (dialogFor === a) closeDialog();
    if (s.error) toast("Download failed", s.error, "suspicious");
    else toast(e.result.filename, e.state === "clean" ? "Scanned and saved \u00b7 no threats found" : "Saved to your Downloads", e.state);
  }

  async function openInDrive(a, retried) {
    const e = cards.get(a);
    if (dialogFor === a) closeDialog();
    toast(e.result.filename, "Uploading to Google Drive…");
    const r = await browser.runtime.sendMessage({ type: "openInDrive", scanId: e.scanId }).catch((err) => ({ error: err.message }));
    if (r.expired && !retried) {
      if (await rescanExpired(a)) return openInDrive(a, true);
      return;
    }
    if (r.error) toast("Couldn't open in Google Drive", r.error, "suspicious");
    else toast(e.result.filename, "Opened in Google Drive · not saved to this computer", e.state);
  }

  async function showResultDialog(a) {
    const e = ensureChip(a);
    const slot = openDialog(a);
    if (e.state !== "clean" && e.state !== "caution" && e.state !== "suspicious") {
      slot.replaceChildren(LASRender.loadingCard(e.filename));
      await startScan(a, e.state === "error");
      if (!overlay || dialogFor !== a) return;
    }
    if (e.state === "error") {
      slot.replaceChildren(LASRender.errorCard(e.error, [
        { label: "Download without scanning", kind: "danger", onClick: () => { closeDialog(); bypass = a; a.click(); } },
        { label: "Cancel", kind: "primary", onClick: closeDialog }
      ]));
      return;
    }
    const r = e.result;
    const buttons = r.verdict === "clean"
      ? [{ label: "Close", onClick: closeDialog }, { label: "Download", kind: "primary", onClick: () => save(a) }]
      : r.verdict === "caution"
        ? [{ label: "Download", onClick: () => save(a) }, { label: "Close", kind: "primary", onClick: closeDialog }]
        : [{ label: "Download anyway", kind: "danger", onClick: () => { if (confirm("This file shows strong signs of being malicious. Download it anyway?")) save(a); } },
           { label: "Don't download", kind: "primary", onClick: closeDialog }];
    if (driveEnabled) buttons.splice(1, 0, { label: "Open in Google Drive", onClick: () => openInDrive(a) });
    slot.replaceChildren(LASRender.resultCard(r, buttons));
  }

  // ---------- toast ----------
  let toastEl = null;
  function toast(title, message, state) {
    if (toastEl) toastEl.remove();
    toastEl = document.createElement("div");
    toastEl.style.cssText = "position:fixed;left:24px;bottom:24px;z-index:2147483647;";
    const sh = toastEl.attachShadow({ mode: "closed" });
    const color = { clean: "#057642", caution: "#915907", suspicious: "#b24020" }[state] || "#0a66c2";
    const st = document.createElement("style");
    st.textContent = `
      .t { font: 14px/20px ${FONT}; background: #1d2226; color: #fff; padding: 12px 16px; border-radius: 8px;
        box-shadow: 0 4px 16px rgba(0,0,0,.3); max-width: 360px; border-left: 4px solid ${color}; animation: in .2s ease-out; }
      .h { font-weight: 600; word-break: break-all; } .m { color: #c9d1d9; font-size: 13px; }
      @keyframes in { from { transform: translateY(8px); opacity: 0; } }
    `;
    const box = document.createElement("div"); box.className = "t";
    const h = document.createElement("div"); h.className = "h";
    const m = document.createElement("div"); m.className = "m";
    box.append(h, m);
    sh.append(st, box);
    h.textContent = title;
    m.textContent = message;
    document.documentElement.append(toastEl);
    const mine = toastEl;
    setTimeout(() => { if (toastEl === mine) { mine.remove(); toastEl = null; } }, 4500);
  }

  // ---------- click handling ----------
  async function onClick(ev) {
    if (ev.button === 2) return;
    const path = ev.composedPath ? ev.composedPath() : [ev.target];
    if (path.some((n) => n && n.nodeType === 1 && n.hasAttribute("data-las-chip"))) return;
    const origin = path.find((n) => n && n.nodeType === 1) || ev.target;
    const a = findAttachmentLink(origin);
    if (!a) return;
    if (bypass === a) { bypass = null; return; }
    ev.preventDefault();
    ev.stopImmediatePropagation();

    const e = ensureChip(a);
    if (e.state === "idle" && a.matches(BUTTON_SEL)) startScan(a);
    if (e.state === "scanning") await e.promise; // wait quietly; clean files then save straight away
    if (e.state === "clean") return save(a);
    showResultDialog(a);
  }
  window.addEventListener("click", onClick, true);
  window.addEventListener("auxclick", onClick, true);

  // ---------- discover attachments ----------
  function refresh() {
    for (const a of deepQueryAll(`a[href], ${BUTTON_SEL}`)) {
      const button = a.matches(BUTTON_SEL);
      if (!button && !isAttachmentLink(a)) continue;
      const e = ensureChip(a);
      // Button cards can only be scanned by starting LinkedIn's download, so they wait for a click.
      if (autoScan && !button && e.state === "idle" && !e.promise) startScan(a);
    }
    for (const [a, e] of cards) if (!a.isConnected) { e.host.remove(); cards.delete(a); }
  }

  browser.runtime.sendMessage({ type: "settings" })
    .then((s) => { autoScan = !s || s.autoScan !== false; driveEnabled = !!(s && s.drive); refresh(); }).catch(() => {});
  browser.storage.onChanged.addListener((ch) => {
    if (ch.autoScan) { autoScan = ch.autoScan.newValue !== false; refresh(); }
    if (ch.driveClientId) driveEnabled = !!ch.driveClientId.newValue;
  });

  let t = null;
  new MutationObserver((muts) => {
    const onlyOurs = muts.every((m) => m.target.nodeType === 1 && (m.target.hasAttribute("data-las-chip") ||
      [...m.addedNodes, ...m.removedNodes].every((n) => n.nodeType === 1 && n.hasAttribute("data-las-chip"))));
    if (onlyOurs) return;
    clearTimeout(t); t = setTimeout(refresh, 300);
  }).observe(document.documentElement, { childList: true, subtree: true });
  setInterval(refresh, 2000); // shadow roots aren't seen by the observer
  refresh();
  console.debug("[LAS] content script active in", location.href);
})();
