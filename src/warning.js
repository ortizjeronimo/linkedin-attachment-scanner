/* global browser, LASRender */
"use strict";
(async () => {
  const style = document.createElement("style");
  style.textContent = LASRender.CSS;
  document.head.append(style);

  const slot = document.getElementById("slot");
  const note = document.getElementById("note");
  const scanId = new URLSearchParams(location.search).get("id");
  const resp = await browser.runtime.sendMessage({ type: "getScan", scanId });
  const close = () => window.close();

  if (resp.error) {
    slot.replaceChildren(LASRender.errorCard(resp.error, [{ label: "Close", kind: "primary", onClick: close }]));
    return;
  }

  const stopped = resp.safetyNet && resp.safetyNet.stopped;

  // The scan itself failed, so there is no verdict: the file is treated as unsafe until the user decides.
  if (resp.scanError) {
    note.textContent = stopped
      ? "The download was stopped because it couldn't be checked. A file can be built to break scanners on purpose."
      : "The file finished downloading before it could be checked. It is already on your computer, but you can delete it here.";
    const failedButtons = stopped
      ? [
          { label: "Download without scanning", kind: "danger", onClick: async () => {
              if (!confirm("This file could not be scanned. Download it anyway?")) return;
              const r = await browser.runtime.sendMessage({ type: "downloadUnscanned", scanId });
              if (r.error) note.textContent = "Couldn't download: " + r.error + ". Try again from LinkedIn."; else close();
            } },
          { label: "Close", kind: "primary", onClick: close }
        ]
      : [
          { label: "Keep file", onClick: close },
          { label: "Delete downloaded file", kind: "primary", onClick: async () => {
              const r = await browser.runtime.sendMessage({ type: "deleteDownloaded", scanId });
              note.textContent = r.error ? "Couldn't delete: " + r.error : "The file was deleted.";
            } }
        ];
    slot.replaceChildren(LASRender.errorCard(`${resp.filename || "LinkedIn download"}: ${resp.scanError}`, failedButtons));
    return;
  }

  note.textContent = stopped
    ? "The download was stopped before it was saved."
    : "The file finished downloading before the scan completed. It is already on your computer, but you can delete it here.";

  const buttons = stopped
    ? [
        { label: "Download anyway", kind: "danger", onClick: async () => {
            if (!confirm("This file shows strong signs of being malicious. Download it anyway?")) return;
            const r = await browser.runtime.sendMessage({ type: "save", scanId });
            if (r.error) alert(r.error); else close();
          } },
        { label: "Close", kind: "primary", onClick: () => { browser.runtime.sendMessage({ type: "discard", scanId }); close(); } }
      ]
    : [
        { label: "Keep file", onClick: close },
        { label: "Delete downloaded file", kind: "primary", onClick: async () => {
            const r = await browser.runtime.sendMessage({ type: "deleteDownloaded", scanId });
            note.textContent = r.error ? "Couldn't delete: " + r.error : "The file was deleted.";
          } }
      ];
  if (stopped && resp.drive) {
    buttons.splice(1, 0, { label: "Open in Google Drive", onClick: async () => {
      note.textContent = "Uploading to Google Drive…";
      const r = await browser.runtime.sendMessage({ type: "openInDrive", scanId });
      note.textContent = r.error ? "Couldn't open in Google Drive: " + r.error : "Opened in Google Drive. The file was not saved to this computer.";
    } });
  }
  slot.replaceChildren(LASRender.resultCard(resp.result, buttons));
})();
