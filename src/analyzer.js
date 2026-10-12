/*
 * Local static analyzer for document attachments.
 * Runs entirely in the browser: no file content ever leaves the machine.
 * Works in the extension background page and in Node (for tests).
 */
(function (root) {
  "use strict";

  const DANGEROUS_EXT = new Set([
    "exe", "scr", "com", "pif", "bat", "cmd", "msi", "msp", "msc", "dll", "cpl",
    "js", "jse", "vbs", "vbe", "wsf", "wsh", "ps1", "psm1", "hta", "jar",
    "lnk", "url", "scf", "reg", "inf", "iso", "img", "vhd", "vhdx",
    "appx", "msix", "application", "gadget", "chm", "xll", "library-ms",
    "settingcontent-ms", "app", "command", "sh", "dmg", "pkg", "apk",
    "one", "onepkg", "iqy", "slk", "wsc", "sct", "jnlp", "diagcab", "search-ms"
  ]);
  const MACRO_EXT = new Set(["docm", "dotm", "xlsm", "xltm", "xlam", "pptm", "potm", "ppsm", "sldm"]);
  const ARCHIVE_EXT = new Set(["zip", "rar", "7z", "gz", "tgz", "tar", "cab", "arj", "ace", "xz", "bz2"]);
  const DOC_LOOKALIKE_EXT = new Set(["pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "rtf", "jpg", "jpeg", "png", "csv"]);
  const HTML_EXT = new Set(["html", "htm", "xhtml", "shtml", "svg", "mht", "mhtml"]);

  const MAX_INFLATE_BYTES = 8 * 1024 * 1024;
  const MAX_PDF_STREAMS = 5000;
  const MAX_PDF_INFLATE_TOTAL = 256 * 1024 * 1024;
  const MAX_ZIP_PARTS = 300; // .rels parts and nested documents read per archive

  // ---------- helpers ----------
  const startsWith = (b, sig, off = 0) => sig.every((v, i) => b[off + i] === v);
  const ascii = (s) => Array.from(s, (c) => c.charCodeAt(0));
  const utf16 = (s) => Array.from(s).flatMap((c) => [c.charCodeAt(0), 0]);

  function indexOfBytes(hay, needle, from = 0) {
    const n = needle.length, first = needle[0];
    outer: for (let i = hay.indexOf(first, from); i !== -1 && i <= hay.length - n; i = hay.indexOf(first, i + 1)) {
      for (let j = 1; j < n; j++) if (hay[i + j] !== needle[j]) continue outer;
      return i;
    }
    return -1;
  }
  const hasBytes = (b, needle) => indexOfBytes(b, needle) !== -1;
  const latin1 = (b) => {
    let s = "";
    for (let i = 0; i < b.length; i += 0x8000) s += String.fromCharCode.apply(null, b.subarray(i, i + 0x8000));
    return s;
  };

  function extOf(name) {
    const m = /\.([a-z0-9\-]{1,20})$/i.exec(name || "");
    return m ? m[1].toLowerCase() : "";
  }

  async function inflate(bytes, format) {
    if (typeof DecompressionStream === "undefined") return null;
    try {
      const ds = new DecompressionStream(format);
      const stream = new Blob([bytes]).stream().pipeThrough(ds);
      const reader = stream.getReader();
      const chunks = [];
      let total = 0;
      try {
        for (;;) {
          const { done, value } = await reader.read();
          if (done) break;
          chunks.push(value);
          total += value.length;
          if (total > MAX_INFLATE_BYTES) { reader.cancel().catch(() => {}); break; }
        }
      } catch (_) {
        // Trailing junk or truncated data: keep whatever was decoded.
        if (!total) return null;
      }
      const out = new Uint8Array(total);
      let o = 0;
      for (const c of chunks) { out.set(c.subarray(0, Math.min(c.length, total - o)), o); o += c.length; if (o >= total) break; }
      return out;
    } catch (_) {
      return null;
    }
  }

  async function sha256Hex(bytes) {
    const c = (root.crypto && root.crypto.subtle) ? root.crypto : require("crypto").webcrypto;
    const h = await c.subtle.digest("SHA-256", bytes);
    return Array.from(new Uint8Array(h), (x) => x.toString(16).padStart(2, "0")).join("");
  }

  // ---------- type detection ----------
  function detectType(b) {
    if (startsWith(b, [0x4d, 0x5a])) return "pe";
    if (startsWith(b, [0x7f, 0x45, 0x4c, 0x46])) return "elf";
    if (startsWith(b, [0xcf, 0xfa, 0xed, 0xfe]) || startsWith(b, [0xca, 0xfe, 0xba, 0xbe])) return "macho";
    if (startsWith(b, [0x4c, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00])) return "lnk";
    if (startsWith(b, [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1])) return "ole";
    if (startsWith(b, [0x50, 0x4b, 0x03, 0x04]) || startsWith(b, [0x50, 0x4b, 0x05, 0x06])) return "zip";
    if (startsWith(b, ascii("Rar!\x1a\x07"))) return "rar";
    if (startsWith(b, [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c])) return "7z";
    if (startsWith(b, [0x1f, 0x8b])) return "gzip";
    if (startsWith(b, ascii("MSCF"))) return "cab";
    if (startsWith(b, ascii("{\\rt"))) return "rtf";
    for (const off of [0x8001, 0x8801, 0x9001]) if (b.length > off + 5 && startsWith(b, ascii("CD001"), off)) return "iso";
    if (startsWith(b, ascii("koly"), Math.max(0, b.length - 512))) return "dmg";
    if (indexOfBytes(b.subarray(0, 1024), ascii("%PDF-")) !== -1) return "pdf";
    if (startsWith(b, [0xff, 0xd8, 0xff])) return "jpeg";
    if (startsWith(b, [0x89, 0x50, 0x4e, 0x47])) return "png";
    if (startsWith(b, ascii("GIF8"))) return "gif";
    const head = latin1(b.subarray(0, 2048)).toLowerCase().trimStart();
    if (/^(\ufeff)?(<!doctype html|<html|<head|<body|<script|<meta)/.test(head)) return "html";
    if (/<svg[\s>]/.test(head)) return "svg";
    if (head.startsWith("mime-version:") && head.includes("multipart/related")) return "mht";
    return "unknown";
  }

  const TYPE_FAMILY = {
    pdf: ["pdf"], ole: ["doc", "dot", "xls", "xlt", "ppt", "pps", "pot", "msg", "msi"],
    zip: ["zip", "docx", "docm", "dotx", "dotm", "xlsx", "xlsm", "xltx", "xlam", "pptx", "pptm", "ppsx", "potx", "odt", "ods", "odp", "jar", "apk", "epub", "vsdx", "xps", "appx", "msix"],
    rtf: ["rtf", "doc"], jpeg: ["jpg", "jpeg"], png: ["png"], gif: ["gif"],
    rar: ["rar"], "7z": ["7z"], gzip: ["gz", "tgz"], cab: ["cab"],
    html: ["html", "htm", "xhtml", "shtml"], svg: ["svg"], mht: ["mht", "mhtml"]
  };

  // ---------- filename checks ----------
  function checkName(name, findings) {
    if (/[\u202a-\u202e\u2066-\u2069]/.test(name)) {
      findings.push({ level: "danger", title: "Filename uses hidden text-direction characters",
        detail: "A Unicode override character makes the displayed extension differ from the real one (e.g. \"invoice\u202Efdp.exe\" shows as \"invoiceexe.pdf\")." });
    }
    const parts = name.toLowerCase().split(".");
    const ext = extOf(name);
    if (parts.length >= 3) {
      const prev = parts[parts.length - 2].trim();
      if (DOC_LOOKALIKE_EXT.has(prev) && (DANGEROUS_EXT.has(ext) || HTML_EXT.has(ext))) {
        findings.push({ level: "danger", title: "Double extension", detail: `"${name}" pretends to be a .${prev} but is really a .${ext}.` });
      }
    }
    if (/\s{4,}\.[a-z0-9]+$/i.test(name)) {
      findings.push({ level: "warning", title: "Extension pushed out of view", detail: "The filename has a long run of spaces before the extension, a trick to hide it." });
    }
    if (DANGEROUS_EXT.has(ext)) {
      findings.push({ level: "danger", title: `Executable or script file type (.${ext})`,
        detail: "This file type can run code on your computer. There is almost no legitimate reason to receive one in a chat." });
    } else if (MACRO_EXT.has(ext)) {
      findings.push({ level: "danger", title: `Macro-enabled Office file (.${ext})`, detail: "The extension itself declares that this document can contain macros." });
    } else if (HTML_EXT.has(ext)) {
      findings.push({ level: "warning", title: `Web page file (.${ext})`,
        detail: "HTML/SVG attachments open in your browser and are commonly used for fake login pages and \"HTML smuggling\"." });
    }
  }

  // ---------- ZIP ----------
  function parseZip(b) {
    const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
    const entries = [];
    let eocd = -1;
    for (let i = b.length - 22; i >= Math.max(0, b.length - 22 - 65535); i--) {
      if (dv.getUint32(i, true) === 0x06054b50) { eocd = i; break; }
    }
    const dec = new TextDecoder("utf-8");
    if (eocd !== -1) {
      let p = dv.getUint32(eocd + 16, true);
      const count = dv.getUint16(eocd + 10, true);
      for (let n = 0; n < count && p + 46 <= b.length; n++) {
        if (dv.getUint32(p, true) !== 0x02014b50) break;
        const flags = dv.getUint16(p + 8, true);
        const method = dv.getUint16(p + 10, true);
        const csize = dv.getUint32(p + 20, true);
        const usize = dv.getUint32(p + 24, true);
        const nlen = dv.getUint16(p + 28, true), xlen = dv.getUint16(p + 30, true), clen = dv.getUint16(p + 32, true);
        const lho = dv.getUint32(p + 42, true);
        const name = dec.decode(b.subarray(p + 46, p + 46 + nlen));
        entries.push({ name, flags, method, csize, usize, lho });
        p += 46 + nlen + xlen + clen;
      }
    }
    if (!entries.length) {
      // Damaged / truncated archive: fall back to scanning local headers.
      for (let p = 0; p + 30 <= b.length; ) {
        const q = indexOfBytes(b, [0x50, 0x4b, 0x03, 0x04], p);
        if (q === -1 || q + 30 > b.length) break;
        const flags = dv.getUint16(q + 6, true), method = dv.getUint16(q + 8, true);
        const csize = dv.getUint32(q + 18, true), usize = dv.getUint32(q + 22, true);
        const nlen = dv.getUint16(q + 26, true);
        entries.push({ name: dec.decode(b.subarray(q + 30, q + 30 + nlen)), flags, method, csize, usize, lho: q });
        p = q + 4;
      }
    }
    return entries;
  }

  async function readZipEntry(b, e) {
    const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
    const p = e.lho;
    if (p + 30 > b.length || dv.getUint32(p, true) !== 0x04034b50) return null;
    const start = p + 30 + dv.getUint16(p + 26, true) + dv.getUint16(p + 28, true);
    const data = b.subarray(start, start + e.csize);
    if (e.flags & 1) return null;
    if (e.method === 0) return data;
    if (e.method === 8) return inflate(data, "deflate-raw");
    return null;
  }

  // XML parts may be UTF-16, and attribute values may be quoted either way or use character references.
  function decodeXml(data) {
    if (data.length >= 2) {
      if ((data[0] === 0xff && data[1] === 0xfe) || (data[0] === 0x3c && data[1] === 0)) return new TextDecoder("utf-16le").decode(data);
      if ((data[0] === 0xfe && data[1] === 0xff) || (data[0] === 0 && data[1] === 0x3c)) return new TextDecoder("utf-16be").decode(data);
    }
    return new TextDecoder().decode(data);
  }
  const codePoint = (n) => (n > 0 && n <= 0x10ffff ? String.fromCodePoint(n) : "");
  const unescapeXml = (s) => s
    .replace(/&#x([0-9a-f]+);/gi, (_, h) => codePoint(parseInt(h, 16)))
    .replace(/&#(\d+);/g, (_, d) => codePoint(parseInt(d, 10)))
    .replace(/&quot;/g, '"').replace(/&apos;/g, "'").replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&amp;/g, "&");
  function xmlAttr(tag, name) {
    const m = new RegExp(`\\b${name}\\s*=\\s*(["'])(.*?)\\1`, "i").exec(tag);
    return m ? unescapeXml(m[2]) : "";
  }

  async function checkZip(b, findings, ext, depth = 0) {
    const entries = parseZip(b);
    const names = entries.map((e) => e.name);
    const lower = names.map((n) => n.toLowerCase());
    const isOOXML = lower.includes("[content_types].xml");
    const isODF = lower.includes("mimetype") && lower.some((n) => n === "content.xml");
    const kind = isOOXML ? "office" : isODF ? "odf" : "archive";
    let partsRead = 0, skipped = false;

    if (entries.some((e) => e.flags & 1)) {
      findings.push({ level: isOOXML ? "warning" : "danger", title: "Password-protected archive",
        detail: "Encrypted archives can't be scanned by any antivirus. Attackers send them with the password in the message for exactly that reason." });
    }

    if (isOOXML) {
      // The macro part can be given any file name, so also check how the package declares it
      // (here and in the relationships below).
      let macros = lower.some((n) => n.endsWith("vbaproject.bin"));
      const types = await readZipEntry(b, entries[lower.indexOf("[content_types].xml")]);
      if (types && /vnd\.ms-office\.vbaProject/i.test(unescapeXml(decodeXml(types)))) macros = true;
      if (lower.some((n) => /(^|\/)activex\//.test(n))) findings.push({ level: "warning", title: "Contains ActiveX controls", detail: "ActiveX controls can execute code when the document is opened." });
      const ole = names.filter((n) => /embeddings\/.*\.bin$/i.test(n) || /oleobject/i.test(n));
      if (ole.length) findings.push({ level: "warning", title: `Contains ${ole.length} embedded OLE object(s)`, detail: "Embedded objects can hide executables or scripts behind an icon you're invited to double-click." });
      if (lower.some((n) => n.endsWith(".xll") || n.includes("customui"))) findings.push({ level: "info", title: "Custom ribbon / add-in parts", detail: "Usually harmless, but sometimes used to trigger macros." });

      // Remote template injection & external links live in the .rels files.
      for (const e of entries) {
        // The declared size isn't trusted (inflate() caps the output), only the number of parts.
        if (!/\.rels$/i.test(e.name)) continue;
        if (++partsRead > MAX_ZIP_PARTS) { skipped = true; break; }
        const data = await readZipEntry(b, e);
        if (!data) continue;
        const rels = decodeXml(data).match(/<(?:[\w.-]+:)?Relationship\b[^>]*>/gi) || [];
        for (const r of rels) {
          const type = xmlAttr(r, "Type");
          const target = xmlAttr(r, "Target");
          if (/\/vbaProject$/i.test(type)) macros = true;
          if (!/^external$/i.test(xmlAttr(r, "TargetMode"))) continue;
          if (/attachedTemplate|oleObject|frame|subDocument/i.test(type)) {
            findings.push({ level: "danger", title: "Loads remote content when opened (template injection)",
              detail: `The document fetches "${target.slice(0, 120)}" when opened. This technique is used to pull in malicious macros or exploits after the file has passed scanning.` });
          } else if (/^(file:|\\\\)/i.test(target)) {
            findings.push({ level: "warning", title: "Links to a network share", detail: `Points to "${target.slice(0, 120)}". Opening network paths can leak your Windows password hash.` });
          }
        }
      }
      if (macros) {
        findings.push({ level: "danger", title: "Contains VBA macros",
          detail: "The document has an embedded macro project. Macros are the most common way malicious Office files infect computers. Do not click \"Enable content\"." });
        if (!MACRO_EXT.has(ext) && ext) findings.push({ level: "danger", title: "Macros hidden behind a normal extension", detail: `Macros inside a .${ext} file means the file was deliberately renamed.` });
      }
    } else if (isODF) {
      if (lower.some((n) => n.startsWith("basic/") || n.startsWith("scripts/"))) findings.push({ level: "danger", title: "OpenDocument file with macros", detail: "Contains Basic or script macros." });
    }

    // What's inside, by name. Office documents are zips too, so this runs for them as well:
    // otherwise adding a [Content_Types].xml to an archive would hide its contents from this check.
    const bad = [], nested = [], html = [];
    for (const n of names) {
      const base = n.split("/").pop();
      const x = extOf(base);
      if (DANGEROUS_EXT.has(x) || MACRO_EXT.has(x)) bad.push(n);
      else if (ARCHIVE_EXT.has(x)) nested.push(n);
      else if (HTML_EXT.has(x)) html.push(n);
      const sub = [];
      checkName(base, sub);
      for (const f of sub) if (/Double extension|text-direction/.test(f.title)) bad.push(n);
    }
    if (bad.length) findings.push({ level: "danger", title: `${kind === "archive" ? "Archive" : "Document"} contains executable or script files`, detail: [...new Set(bad)].slice(0, 10).join(", ") });
    if (kind === "archive") {
      if (nested.length) findings.push({ level: "warning", title: "Archive contains other archives", detail: "Nesting archives is a common way to slip past scanners: " + nested.slice(0, 5).join(", ") });
      if (html.length) findings.push({ level: "warning", title: "Archive contains web page files", detail: html.slice(0, 5).join(", ") });
      findings.push({ level: "info", title: `Archive with ${names.length} file(s)`, detail: names.slice(0, 15).join(", ") + (names.length > 15 ? ", \u2026" : "") });
    }

    // Look inside nested Office/zip entries, one level deep only (an archive can contain itself).
    if (depth < 1) {
      for (const e of entries) {
        const x = extOf(e.name);
        if (!["docx", "xlsx", "pptx", "docm", "xlsm", "pptm", "zip"].includes(x)) continue;
        if (e.csize > 20 * 1024 * 1024 || ++partsRead > MAX_ZIP_PARTS) { skipped = true; continue; }
        const data = await readZipEntry(b, e);
        if (!data) continue;
        const sub = [];
        await checkZip(data, sub, x, depth + 1);
        for (const f of sub) if (f.level !== "info") findings.push({ ...f, title: `${e.name}: ${f.title}` });
      }
    }
    if (skipped) {
      findings.push({ level: "warning", title: "Archive could not be fully inspected",
        detail: "It has more parts, or larger ones, than the scanner reads. Treat what wasn't inspected as untrusted." });
    }
    return { kind, entries: names.length };
  }

  // ---------- OLE (legacy .doc/.xls/.ppt) ----------
  function checkOle(b, findings) {
    if (hasBytes(b, utf16("EncryptedPackage"))) {
      findings.push({ level: "warning", title: "Password-protected Office document", detail: "The content is encrypted and cannot be inspected. Treat it as untrusted." });
    }
    if (hasBytes(b, utf16("_VBA_PROJECT")) || hasBytes(b, utf16("Macros")) || hasBytes(b, ascii("Attribute VB_"))) {
      findings.push({ level: "danger", title: "Contains VBA macros", detail: "Legacy Office file with a macro project. Do not enable editing or content." });
    }
    if (hasBytes(b, utf16("Equation Native"))) {
      findings.push({ level: "danger", title: "Contains an Equation Editor object", detail: "Used almost exclusively to exploit CVE-2017-11882 and related bugs." });
    }
    if (hasBytes(b, utf16("Ole10Native"))) {
      findings.push({ level: "warning", title: "Contains an embedded package object", detail: "Packaged objects can hide executables behind an icon." });
    }
    if (hasBytes(b, ascii("Excel 4.0")) || hasBytes(b, utf16("Excel 4.0"))) {
      findings.push({ level: "warning", title: "Possible Excel 4.0 (XLM) macros", detail: "Old-style macro sheets, popular with malware authors." });
    }
  }

  // ---------- RTF ----------
  function checkRtf(b, findings) {
    const s = latin1(b.subarray(0, Math.min(b.length, 20 * 1024 * 1024))).toLowerCase();
    if (/\\objdata|\\objemb|\\objlink|\\objautlink/.test(s)) {
      findings.push({ level: "danger", title: "RTF with embedded objects", detail: "Embedded OLE objects in RTF are a classic exploit vector (e.g. CVE-2017-0199, CVE-2017-11882)." });
    }
    if (/\\objupdate/.test(s)) findings.push({ level: "danger", title: "RTF object auto-updates on open", detail: "\\objupdate forces the embedded object to load without user interaction." });
    if (/equation\.3|0002ce02-0000-0000-c000-000000000046/.test(s)) findings.push({ level: "danger", title: "References the Equation Editor", detail: "Strong indicator of an exploit document." });
  }

  // ---------- PDF ----------
  async function checkPdf(b, findings) {
    const raw = latin1(b);
    // Undo "#xx" hex escaping in names (/J#61vaScript -> /JavaScript).
    const norm = (t) => t.replace(/\/[^\s\/<>\[\]\(\)]+/g, (m) => m.replace(/#([0-9a-f]{2})/gi, (_, h) => String.fromCharCode(parseInt(h, 16))));

    // Each piece of text is checked as it's decoded, so a file with many large streams
    // can't make the scanner build one enormous string.
    const KEYS = {
      js: /\/JavaScript\b|\/JS\b/, launch: /\/Launch\b/, embedded: /\/EmbeddedFile\b/, auto: /\/OpenAction\b|\/AA\b/,
      uri: /\/URI\b/, rich: /\/RichMedia\b|\/XFA\b/, submit: /\/SubmitForm\b/, encrypt: /\/Encrypt\b/
    };
    const seen = new Set();
    const uris = [];
    const inspect = (t) => {
      for (const k in KEYS) if (!seen.has(k) && KEYS[k].test(t)) seen.add(k);
      for (const x of t.matchAll(/\/URI\s*\(([^)]{1,300})\)/g)) { if (uris.length >= 1000) break; uris.push(x[1]); }
    };
    inspect(norm(raw));

    // Decompress Flate streams so keywords hidden in object streams are found too.
    let inflated = 0, total = 0, truncated = false, hidden = false;
    const re = /stream\r?\n/g;
    let m;
    while ((m = re.exec(raw))) {
      const start = m.index + m[0].length;
      let end = raw.indexOf("endstream", start);
      if (end === -1) break;
      const next = end;
      while (end > start && (raw[end - 1] === "\n" || raw[end - 1] === "\r")) end--;
      let dict = raw.slice(Math.max(0, m.index - 400), m.index);
      const prev = dict.lastIndexOf("endobj");
      if (prev !== -1) dict = dict.slice(prev);
      dict = norm(dict);
      let decoded = false;
      if (/FlateDecode/.test(dict) && end - start < MAX_INFLATE_BYTES) {
        if (inflated >= MAX_PDF_STREAMS || total >= MAX_PDF_INFLATE_TOTAL) { truncated = true; break; }
        const out = await inflate(b.subarray(start, end), "deflate");
        if (out) { inspect(norm(latin1(out))); inflated++; total += out.length; decoded = true; }
      }
      // Object streams hold the document's own objects; one that can't be read may hide a script.
      if (/\/ObjStm\b/.test(dict) && (!decoded || /\/Predictor\b/.test(dict))) hidden = true;
      re.lastIndex = next + 9;
    }

    const has = (...keys) => keys.some((k) => seen.has(k));
    if (has("js")) findings.push({ level: "danger", title: "PDF contains JavaScript", detail: "Legitimate documents almost never need scripts. Scripts in PDFs are used for exploits and redirects." });
    if (has("launch")) findings.push({ level: "danger", title: "PDF can launch programs", detail: "A /Launch action tries to run a command or file on your computer." });
    if (has("embedded")) findings.push({ level: "warning", title: "PDF has embedded files", detail: "Files hidden inside the PDF, sometimes executables or Office macros documents." });
    if (has("auto")) findings.push({ level: has("js", "launch", "uri") ? "warning" : "info", title: "PDF runs an action automatically when opened", detail: "Combined with scripts or links, this triggers behaviour without any click." });
    if (has("rich")) findings.push({ level: "warning", title: "PDF uses Flash/XFA forms", detail: "Rarely legitimate today; historically a frequent exploit target." });
    if (has("submit")) findings.push({ level: "warning", title: "PDF submits form data to a server", detail: "Can send whatever you type in the form to a remote address." });
    if (uris.length) {
      const hosts = [...new Set(uris.map((u) => { try { return new URL(u).hostname; } catch (_) { return u.slice(0, 60); } }))];
      findings.push({ level: "info", title: `PDF contains ${uris.length} link(s)`, detail: "Domains: " + hosts.slice(0, 8).join(", ") + ". Phishing PDFs often have a single big \"View document\" button pointing to a fake login page." });
    }
    // Anything the checks couldn't read counts against the file instead of being waved through.
    if (has("encrypt")) findings.push({ level: "warning", title: "PDF is encrypted", detail: "Encryption hides the contents from these checks, so they could not be inspected. Only open it if you expected a protected PDF from this person." });
    if (hidden) findings.push({ level: "warning", title: "PDF stores objects in a form that can't be inspected", detail: "Part of the document's structure is packed in a way the scanner can't decode, which can hide scripts." });
    if (truncated) findings.push({ level: "warning", title: "PDF could not be fully inspected", detail: "It has more compressed content than the scanner reads, so part of it was not checked." });
  }

  // ---------- HTML/SVG ----------
  function checkHtml(b, findings) {
    const s = latin1(b.subarray(0, Math.min(b.length, 10 * 1024 * 1024))).toLowerCase();
    if (/<script/.test(s)) findings.push({ level: "warning", title: "Web file contains scripts", detail: "Scripts in an attachment run in your browser as soon as you open it." });
    if (/atob\(|msSaveOrOpenBlob|new blob\(|\.download\s*=/.test(s)) findings.push({ level: "danger", title: "Builds and downloads a file on open (HTML smuggling)", detail: "The page assembles a hidden file in your browser to bypass download scanning." });
    if (/type\s*=\s*["']?password/.test(s)) findings.push({ level: "danger", title: "Contains a password field", detail: "An attachment asking for a password is a phishing page." });
    if (/<form[^>]+action\s*=\s*["']?https?:/.test(s)) findings.push({ level: "warning", title: "Form posts data to a remote server", detail: "Anything typed here is sent elsewhere." });
  }

  // ---------- main ----------
  async function analyze(bytes, filename) {
    const b = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
    const name = filename || "attachment";
    const ext = extOf(name);
    const findings = [];
    const type = detectType(b);

    checkName(name, findings);

    // Real type vs claimed extension.
    const execTypes = { pe: "Windows program", elf: "Linux program", macho: "macOS program", lnk: "Windows shortcut (.lnk)", iso: "disk image", dmg: "macOS disk image" };
    if (execTypes[type] && !DANGEROUS_EXT.has(ext)) {
      findings.push({ level: "danger", title: `This is actually a ${execTypes[type]}`, detail: `The file is named .${ext || "(none)"} but its contents are a ${execTypes[type]}.` });
    } else if (execTypes[type]) {
      // already covered by extension check
    } else if (ext && TYPE_FAMILY[type] && !TYPE_FAMILY[type].includes(ext) && !(type === "zip" && ARCHIVE_EXT.has(ext))) {
      findings.push({ level: "warning", title: "File type doesn't match its extension", detail: `Named .${ext} but the contents look like ${type.toUpperCase()}.` });
    }

    let extra = {};
    if (type === "zip") extra = await checkZip(b, findings, ext);
    else if (type === "ole") checkOle(b, findings);
    else if (type === "rtf") checkRtf(b, findings);
    else if (type === "pdf") await checkPdf(b, findings);
    else if (type === "html" || type === "svg" || type === "mht") checkHtml(b, findings);
    else if (["rar", "7z", "gzip", "cab"].includes(type)) {
      findings.push({ level: "warning", title: `${type.toUpperCase()} archive could not be inspected`, detail: "Contents of this archive format aren't checked locally. Use the VirusTotal lookup or open it in a sandbox." });
    }

    // Small Office/PDF file with nothing in it but a link is a phishing "lure" pattern, not flagged by default.
    const rank = { danger: 3, warning: 2, info: 1 };
    const worst = findings.reduce((a, f) => Math.max(a, rank[f.level]), 0);
    const verdict = worst === 3 ? "suspicious" : worst === 2 ? "caution" : "clean";

    return {
      filename: name,
      size: b.length,
      detectedType: type,
      sha256: await sha256Hex(b),
      verdict,
      findings: findings.sort((a, c) => rank[c.level] - rank[a.level]),
      ...extra
    };
  }

  const api = { analyze, detectType, parseZip, extOf };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  else root.AttachmentAnalyzer = api;
})(typeof globalThis !== "undefined" ? globalThis : this);
