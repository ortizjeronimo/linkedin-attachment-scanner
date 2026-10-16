// Checks background.js logic that needs no browser: cache keys, download matching and how
// VirusTotal results become findings. Run: node test/background.test.js
const fs = require("fs");
const path = require("path");
const vm = require("vm");

// background.js registers browser listeners at load time; stub just enough for that.
const noop = { addListener() {} };
const ctx = vm.createContext({
  console, URL, URLSearchParams, setTimeout, clearTimeout, Blob, TextEncoder, TextDecoder,
  AttachmentAnalyzer: {},
  browser: { runtime: { onMessage: noop }, downloads: { onCreated: noop } }
});
vm.runInContext(fs.readFileSync(path.join(__dirname, "../src/background.js"), "utf8"), ctx, { filename: "background.js" });
const run = (code) => vm.runInContext(code, ctx);

let failed = 0;
function check(label, actual, expected) {
  const ok = JSON.stringify(actual) === JSON.stringify(expected);
  if (!ok) failed++;
  console.log(`${ok ? "ok   " : "FAIL "} ${label}${ok ? "" : `\n        expected ${JSON.stringify(expected)}\n        got      ${JSON.stringify(actual)}`}`);
}

// --- cache keys: attachment paths ignore the signed query string, anything else keeps it
const att = "https://www.linkedin.com/dms/prv/vid/v2/D4D06AQE/messaging-uploadedDocument/B4Da/0/1791";
check("attachment URL keyed by path", run(`urlKey(${JSON.stringify(att + "?m=1&t=abc")})`), att);
check("same attachment, new signature, same key", run(`urlKey(${JSON.stringify(att + "?m=2&t=xyz")}) === urlKey(${JSON.stringify(att + "?m=1&t=abc")})`), true);
check("other URLs keep their query", run(`urlKey("https://www.linkedin.com/download?id=1") === urlKey("https://www.linkedin.com/download?id=2")`), false);

// --- download names compare loosely
check("duplicate suffix and case ignored", run(`nameKey("C:\\\\Users\\\\x\\\\Downloads\\\\Job Description (1).docx") === nameKey("job description.docx")`), true);
check("different files differ", run(`nameKey("offer.docx") === nameKey("invoice.docx")`), false);

// --- a download goes to the card waiting for that name, not just the first card waiting
run(`captures.clear();
  globalThis.tA = expectDownload("Offer_Letter.docx");
  globalThis.tB = expectDownload("Job Description.pdf");`);
check("matched by name", run(`claimCapture({ filename: "/home/u/Downloads/Job Description(1).pdf" }) === captures.get(tB)`), true);
check("unrelated download is not claimed", run(`claimCapture({ filename: "/home/u/Downloads/report.xlsx" })`), null);
check("nameless download claimed when only one card waits", run(`claimCapture({ filename: "" }) === captures.get(tA)`), true);
run(`captures.clear(); expectDownload("a.pdf"); expectDownload("b.pdf");`);
check("nameless download not claimed when two cards wait", run(`claimCapture({ filename: "" })`), null);
run(`captures.clear();`);

// --- VirusTotal behaviour results become findings
const clean = () => ({ verdict: "clean", findings: [] });
function vtResult(attributes, stats = { malicious: 0, suspicious: 0, undetected: 60, "type-unsupported": 15 }) {
  return run(`({ known: true, malicious: ${stats.malicious}, suspicious: ${stats.suspicious}, total: 75, label: "", link: "",
    ...behaviourOf(${JSON.stringify(attributes)}) })`);
}
function merge(vt) {
  ctx.r = clean(); ctx.vt = vt;
  return run(`mergeVirusTotal(r, vt)`);
}

// The file from the user's screenshot: 0/75, one medium and one low Sigma match.
let r = merge(vtResult({
  sigma_analysis_stats: { critical: 0, high: 0, medium: 1, low: 1 },
  sigma_analysis_results: [{ rule_title: "Office Application Initiated Network Connection To Non-Local IP", rule_level: "medium" },
    { rule_title: "Office Macro File Creation", rule_level: "low" }]
}));
check("low/medium Sigma: stays clean", r.verdict, "clean");
check("low/medium Sigma: shown as information", r.findings.map((f) => f.level + ":" + f.title),
  ["info:VirusTotal: 0/75 detections", "info:VirusTotal behaviour rules: 1 medium, 1 low"]);

r = merge(vtResult({ sigma_analysis_stats: { high: 2 }, sigma_analysis_results: [{ rule_title: "Suspicious PowerShell" }] }));
check("high Sigma: review", [r.verdict, r.findings[0].title], ["caution", "VirusTotal behaviour rules: 2 high"]);

r = merge(vtResult({ sandbox_verdicts: {
  "Zenbox": { category: "malicious", sandbox_name: "Zenbox", malware_names: ["Emotet"] },
  "C2AE": { category: "harmless", sandbox_name: "C2AE" } } }));
check("malicious sandbox: review, harmless ones ignored", [r.verdict, r.findings[0].title], ["caution", "VirusTotal sandbox: 1 sandbox calls this file malicious"]);
check("malicious sandbox: names the family", /Zenbox \(Emotet\)/.test(r.findings[0].detail), true);

r = merge(vtResult({ crowdsourced_yara_results: [{ rule_name: "SUSP_Office_Macro", ruleset_name: "signature-base" }] }));
check("YARA match: review", [r.verdict, r.findings[0].title], ["caution", "VirusTotal: 1 community YARA rule matches this file"]);

r = merge(vtResult({ crowdsourced_ids_stats: { high: 1 } }));
check("high IDS alert: review", r.verdict, "caution");

r = merge(vtResult({}));
check("no behaviour data: unchanged", [r.verdict, r.findings.length], ["clean", 1]);

ctx.r = clean(); ctx.vt = { known: true, malicious: 0, suspicious: 0, total: 70, label: "", link: "" };
check("older cached result without behaviour fields still works", run(`mergeVirusTotal(r, vt).findings.length`), 1);

console.log(failed ? `\n${failed} check(s) FAILED` : "\nall checks passed");
process.exit(failed ? 1 : 0);
