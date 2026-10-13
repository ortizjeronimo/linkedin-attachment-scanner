/* Shared UI for showing a scan result (used by the in-page dialog and the warning tab). */
"use strict";
(function (root) {
  const VERDICT = {
    suspicious: { label: "Dangerous \u2014 do not open", color: "#b42318", bg: "#fef3f2", darkColor: "#f97066", darkBg: "#3a1a17", icon: "\u2716" },
    caution: { label: "Be careful", color: "#b54708", bg: "#fffaeb", darkColor: "#fdb022", darkBg: "#3a2a10", icon: "!" },
    clean: { label: "No red flags found", color: "#067647", bg: "#ecfdf3", darkColor: "#47cd89", darkBg: "#12301f", icon: "\u2713" }
  };
  // The card is light or dark as a whole. The caller decides (the page's theme in LinkedIn, the
  // system's on the extension's own pages), so header and body can never end up mismatched.
  let dark = false;
  const setDark = (v) => { dark = !!v; };
  const newCard = () => el("div", "las-card" + (dark ? " las-dark" : ""));
  function tint(head, v, withTitle) {
    head.style.setProperty("--las-bg", v.bg);
    head.style.setProperty("--las-bg-dark", v.darkBg);
    if (withTitle) { head.style.setProperty("--las-fg", v.color); head.style.setProperty("--las-fg-dark", v.darkColor); }
  }
  const LEVEL = { danger: "#b42318", warning: "#b54708", info: "#475467" };
  // Office and OpenDocument files are zip containers; say what the file is, not how it is packed.
  const TYPE_LABEL = { office: "Office document", odf: "OpenDocument file" };

  const CSS = `
    :host, .las-root { all: initial; }
    .las-card { font: 14px/1.45 -apple-system, "Segoe UI", Roboto, sans-serif; color: #101828; background: #fff;
      border-radius: 12px; box-shadow: 0 20px 50px rgba(0,0,0,.25); width: min(520px, calc(100vw - 32px));
      max-height: calc(100vh - 48px); overflow: auto; box-sizing: border-box; }
    .las-head { display: flex; gap: 12px; align-items: center; padding: 18px 20px; border-radius: 12px 12px 0 0; background: var(--las-bg, transparent); }
    .las-head .las-title { color: var(--las-fg, inherit); }
    .las-badge { width: 32px; height: 32px; border-radius: 50%; color: #fff; display: grid; place-items: center; font-weight: 700; flex: none; }
    .las-eyebrow { font-size: 11px; font-weight: 600; letter-spacing: .04em; text-transform: uppercase; color: #667085; margin-bottom: 2px; }
    .las-title { font-size: 16px; font-weight: 650; }
    .las-file { font-size: 12.5px; color: #475467; word-break: break-all; }
    .las-body { padding: 8px 20px 4px; }
    .las-f { padding: 10px 0; border-bottom: 1px solid #eaecf0; }
    .las-f:last-child { border-bottom: 0; }
    .las-ft { font-weight: 600; display: flex; gap: 8px; align-items: baseline; }
    .las-dot { width: 8px; height: 8px; border-radius: 50%; flex: none; transform: translateY(-1px); }
    .las-fd { color: #475467; font-size: 13px; margin-top: 2px; word-break: break-word; }
    .las-meta { color: #667085; font-size: 12px; padding: 10px 20px; border-top: 1px solid #eaecf0; word-break: break-all; }
    .las-meta a { color: #0a66c2; }
    .las-actions { display: flex; gap: 8px; justify-content: flex-end; padding: 14px 20px 18px; flex-wrap: wrap; }
    .las-btn { font: inherit; font-weight: 600; border-radius: 999px; padding: 8px 16px; cursor: pointer; border: 1px solid #d0d5dd; background: #fff; color: #344054; }
    .las-btn.primary { background: #0a66c2; border-color: #0a66c2; color: #fff; }
    .las-btn.danger { background: #fff; border-color: #b42318; color: #b42318; }
    .las-spin { width: 28px; height: 28px; border: 3px solid #d0d5dd; border-top-color: #0a66c2; border-radius: 50%; animation: las-r .8s linear infinite; }
    @keyframes las-r { to { transform: rotate(360deg); } }
    .las-card.las-dark { background: #1d2939; color: #f2f4f7; }
    .las-dark .las-head { background: var(--las-bg-dark, transparent); }
    .las-dark .las-head .las-title { color: var(--las-fg-dark, inherit); }
    .las-dark .las-file, .las-dark .las-fd, .las-dark .las-eyebrow { color: #d0d5dd; }
    .las-dark .las-meta { color: #98a2b3; border-color: #344054; }
    .las-dark .las-meta a { color: #71b7fb; }
    .las-dark .las-f { border-color: #344054; }
    .las-dark .las-btn:not(.primary) { background: #1d2939; color: #f2f4f7; border-color: #475467; }
    .las-dark .las-btn.danger { color: #f97066; border-color: #f97066; }`;

  function el(tag, cls, text) {
    const e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text != null) e.textContent = text;
    return e;
  }
  function fmtSize(n) {
    return n < 1024 ? n + " B" : n < 1048576 ? (n / 1024).toFixed(1) + " KB" : (n / 1048576).toFixed(1) + " MB";
  }

  function loadingCard(filename) {
    const card = newCard();
    const head = el("div", "las-head");
    head.append(el("div", "las-spin"));
    const t = el("div");
    t.append(el("div", "las-title", "Scanning attachment\u2026"), el("div", "las-file", filename || ""));
    head.append(t);
    card.append(head);
    return card;
  }

  function errorCard(message, buttons) {
    const card = newCard();
    const head = el("div", "las-head");
    tint(head, VERDICT.caution, false);
    const b = el("div", "las-badge", "?"); b.style.background = VERDICT.caution.color;
    const t = el("div");
    t.append(el("div", "las-title", "Couldn't scan this file"), el("div", "las-file", message));
    head.append(b, t);
    card.append(head, actions(buttons));
    return card;
  }

  function resultCard(result, buttons) {
    const v = VERDICT[result.verdict] || VERDICT.caution;
    const card = newCard();
    const head = el("div", "las-head");
    tint(head, v, true);
    const badge = el("div", "las-badge", v.icon); badge.style.background = v.color;
    const t = el("div");
    const title = el("div", "las-title", v.label);
    t.append(el("div", "las-eyebrow", "Attachment scan"), title, el("div", "las-file", `${result.filename} \u00b7 ${fmtSize(result.size)} \u00b7 detected as ${TYPE_LABEL[result.kind] || result.detectedType.toUpperCase()}`));
    head.append(badge, t);
    card.append(head);

    const body = el("div", "las-body");
    if (!result.findings.length) {
      body.append(el("div", "las-fd", "None of the local checks found anything unusual. This doesn't guarantee the file is safe, so only open it if you expected it from this person."));
    }
    for (const f of result.findings) {
      const row = el("div", "las-f");
      const ft = el("div", "las-ft");
      const dot = el("span", "las-dot"); dot.style.background = LEVEL[f.level];
      ft.append(dot, el("span", null, f.title));
      row.append(ft);
      if (f.detail) row.append(el("div", "las-fd", f.detail));
      body.append(row);
    }
    card.append(body);

    const meta = el("div", "las-meta");
    meta.append(document.createTextNode("Scanned on this device" + (result.virustotal && result.virustotal.known ? " and checked against VirusTotal" : "") + ". SHA-256: " + result.sha256 + " "));
    const vt = el("a", null, "View on VirusTotal");
    vt.href = (result.virustotal && result.virustotal.link) || `https://www.virustotal.com/gui/file/${result.sha256}`;
    vt.target = "_blank"; vt.rel = "noopener noreferrer";
    meta.append(vt);
    card.append(meta);
    card.append(actions(buttons));
    return card;
  }

  function actions(buttons) {
    const a = el("div", "las-actions");
    for (const b of buttons || []) {
      const btn = el("button", "las-btn " + (b.kind || ""), b.label);
      btn.addEventListener("click", b.onClick);
      a.append(btn);
    }
    return a;
  }

  root.LASRender = { CSS, setDark, loadingCard, errorCard, resultCard };
})(typeof globalThis !== "undefined" ? globalThis : this);
