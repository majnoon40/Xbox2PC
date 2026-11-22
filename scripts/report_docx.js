// Torrent Metadata Inspection Report — GTA6.Xbox.v1.0.2.1-CYBERLEEK
// English report, Profile A (Formal): Times New Roman body, pure black text.
// Cover: Recipe R1 (Pure Paragraph Left), palette DM-1 (Deep Cyan, tech).
// 3-section architecture: cover (no page#) -> front matter (TOC, no footer) -> body (Arabic from 1).
const {
  Document, Packer, Paragraph, TextRun, Table, TableRow, TableCell,
  ImageRun, PageBreak, Header, Footer, PageNumber, NumberFormat,
  AlignmentType, HeadingLevel, WidthType, BorderStyle, ShadingType,
  TableOfContents, SectionType, TableLayoutType,
} = require("docx");
const fs = require("fs");

// image-size v1/v2 compatibility
const _is = require("image-size");
const sizeOf = _is.imageSize || _is.default || _is;

// ── Palette: DM-1 Deep Cyan (tech) ──
const P = {
  bg: "162235", accent: "37DCF2",
  cover: { titleColor: "FFFFFF", subtitleColor: "B0B8C0", metaColor: "90989F", footerColor: "687078" },
  table: { headerBg: "1B6B7A", headerText: "FFFFFF", accentLine: "1B6B7A", innerLine: "C8DDE2", surface: "EDF3F5" },
  headings: "0A1628",
};

const NB = { style: BorderStyle.NONE, size: 0, color: "FFFFFF" };
const noBorders = { top: NB, bottom: NB, left: NB, right: NB };
const allNoBorders = { top: NB, bottom: NB, left: NB, right: NB, insideHorizontal: NB, insideVertical: NB };

// ── Verified facts ──
const BTIH = "465d6a0eac381e68ca77115f44f19f0c968b9590";
const TOTAL_BYTES = 223880932870;      // verified via libtorrent
const TOTAL_GIB = "208.51";
const NUM_FILES = 108;
const PIECE_LEN = 16777216;           // 16 MiB
const NUM_PIECES = 13345;
const CREATED_BY = "go.torrent";
const COMMENT = "dynamic metainfo from client";
const CREATED_STR = "2026-11-19 18:49:35 UTC";
const RELEASE_NAME = "GTA6.Xbox.v1.0.2.1-CYBERLEEK";

// ── Parse the exact manifest exported from libtorrent (source of truth for tables) ──
const manifest = JSON.parse(fs.readFileSync("/home/z/my-project/work/torrent-meta/manifest.json", "utf8"));
const listingPath = "/home/z/my-project/download/torrent_file_listing.txt";
const raw = fs.readFileSync(listingPath, "utf8");
const files = manifest.files.map((f) => {
  const line = raw.split("\n").find((l) => l.includes(f.path)) || "";
  const m = line.match(/([\d.]+) (B|KiB|MiB|GiB|TiB)\s/) || null;
  return { ...f, sizeStr: m ? `${m[1]} ${m[2]}` : `${f.bytes} B` };
});
if (files.length !== NUM_FILES) throw new Error(`expected ${NUM_FILES} files, parsed ${files.length}`);
let sumBytes = 0;
for (const f of files) sumBytes += f.bytes;
if (Math.abs(sumBytes - TOTAL_BYTES) > 1e3) throw new Error(`size mismatch: ${sumBytes} vs ${TOTAL_BYTES}`);

// extension summary
const extMap = new Map();
for (const f of files) {
  const base = f.path.split("/").pop();
  const dot = base.lastIndexOf(".");
  const ext = dot > 0 ? base.slice(dot + 1).toLowerCase() : "(none)";
  if (!extMap.has(ext)) extMap.set(ext, { count: 0, bytes: 0 });
  const e = extMap.get(ext);
  e.count++; e.bytes += f.bytes;
}
const extRows = [...extMap.entries()].sort((a, b) => b[1].bytes - a[1].bytes);
const top12 = [...files].sort((a, b) => b.bytes - a.bytes).slice(0, 12);
const gib = (n) => (n / 1024 ** 3).toFixed(2);

// ── Text helpers ──
const safeText = (v, ph) => (v === undefined || v === null || String(v) === "NaN" || String(v) === "undefined" || String(v) === "") ? (ph || "n/a") : String(v);
const EN = { ascii: "Times New Roman", hAnsi: "Times New Roman" };

function body(text, opts) {
  return new Paragraph({
    alignment: AlignmentType.LEFT,
    spacing: { line: 312, after: 120, ...(opts && opts.spacing) },
    children: [new TextRun({ text: safeText(text), size: 24, color: "000000", font: EN })],
  });
}
function h1(text) {
  return new Paragraph({
    heading: HeadingLevel.HEADING_1,
    alignment: AlignmentType.CENTER,
    spacing: { before: 360, after: 160, line: 312 },
    children: [new TextRun({ text: safeText(text), bold: true, size: 32, color: P.headings, font: EN })],
  });
}
function h2(text) {
  return new Paragraph({
    heading: HeadingLevel.HEADING_2,
    spacing: { before: 240, after: 120, line: 312 },
    children: [new TextRun({ text: safeText(text), bold: true, size: 30, color: P.headings, font: EN })],
  });
}
function caption(text) {
  return new Paragraph({
    keepNext: true,
    spacing: { before: 160, after: 80, line: 312 },
    children: [new TextRun({ text: safeText(text), bold: true, size: 21, color: "404040", font: EN })],
  });
}
function figCaption(text) {
  return new Paragraph({
    alignment: AlignmentType.CENTER,
    spacing: { before: 80, after: 160, line: 312 },
    children: [new TextRun({ text: safeText(text), size: 21, color: "606060", font: EN })],
  });
}

// Horizontal-Only business table (Profile A) — percentage widths, DM-1 table tokens
function dataTable(headerCells, dataRows, colPcts, opts) {
  const o = opts || {};
  const cellSize = o.small ? 17 : 21;
  const mkCell = (text, i, isHeader) => new TableCell({
    width: { size: colPcts[i], type: WidthType.PERCENTAGE },
    margins: { top: 60, bottom: 60, left: 120, right: 120 },
    shading: isHeader ? { type: ShadingType.CLEAR, fill: P.table.headerBg } : undefined,
    children: [new Paragraph({
      alignment: i === 0 && o.rightFirstCol !== false ? AlignmentType.RIGHT : AlignmentType.LEFT,
      spacing: { line: 276 },
      children: [new TextRun({
        text: safeText(text), size: cellSize, bold: !!isHeader,
        color: isHeader ? P.table.headerText : "000000", font: EN,
      })],
    })],
  });
  return new Table({
    width: { size: 100, type: WidthType.PERCENTAGE },
    layout: TableLayoutType.FIXED,
    borders: {
      top: { style: BorderStyle.SINGLE, size: 4, color: P.table.accentLine },
      bottom: { style: BorderStyle.SINGLE, size: 4, color: P.table.accentLine },
      left: NB, right: NB,
      insideHorizontal: { style: BorderStyle.SINGLE, size: 1, color: P.table.innerLine },
      insideVertical: NB,
    },
    rows: [
      new TableRow({
        tableHeader: true, cantSplit: true,
        children: headerCells.map((t, i) => mkCell(t, i, true)),
      }),
      ...dataRows.map((r) => new TableRow({
        cantSplit: true,
        children: r.map((t, i) => mkCell(t, i, false)),
      })),
    ],
  });
}

// ══════════════ COVER — Recipe R1 (mixed-width English title) ══════════════
function estimateTextWidth(text, pt) {
  let w = 0;
  for (const ch of text) {
    const c = ch.codePointAt(0);
    const cjk = (c >= 0x4e00 && c <= 0x9fff) || (c >= 0x3000 && c <= 0x303f) || (c >= 0xff00 && c <= 0xffef);
    w += cjk ? pt * 20 : pt * 11;
  }
  return w;
}
function calcTitleLayoutEN(title, maxWidthTwips, preferredPt = 40, minPt = 24) {
  let titlePt = preferredPt;
  while (titlePt >= minPt) {
    if (estimateTextWidth(title, titlePt) <= maxWidthTwips) return { titlePt, titleLines: [title] };
    const words = title.split(" ");
    const lines = [];
    let cur = "";
    for (const w of words) {
      const cand = cur ? cur + " " + w : w;
      if (estimateTextWidth(cand, titlePt) <= maxWidthTwips) cur = cand;
      else { if (cur) lines.push(cur); cur = w; }
    }
    if (cur) lines.push(cur);
    if (lines.length <= 3 && lines.every(l => estimateTextWidth(l, titlePt) <= maxWidthTwips)) {
      if (lines.length > 1 && lines[lines.length - 1].split(" ").length === 1 && lines.length <= 2) {
        // avoid single-word orphan on a 2-line split: shrink font and retry
        titlePt -= 2; continue;
      }
      return { titlePt, titleLines: lines };
    }
    titlePt -= 2;
  }
  const words = title.split(" ");
  const mid = Math.ceil(words.length / 2);
  return { titlePt: minPt, titleLines: [words.slice(0, mid).join(" "), words.slice(mid).join(" ")] };
}
function calcCoverSpacing(params) {
  const { titleLineCount = 1, titlePt = 36, hasSubtitle = false, hasEnglishLabel = false,
    metaLineCount = 0, fixedHeight = 800, pageHeight = 16838 } = params;
  const SAFETY = 1200;
  const usable = pageHeight - SAFETY;
  const titleHeight = titleLineCount * (titlePt * 23 + 200);
  const subtitleHeight = hasSubtitle ? (12 * 23 + 600) : 0;
  const englishLabelHeight = hasEnglishLabel ? (9 * 23 + 600) : 0;
  const metaHeight = metaLineCount * (10 * 23 + 100);
  const implicitParaHeight = 3 * 300;
  const contentHeight = titleHeight + subtitleHeight + englishLabelHeight + metaHeight + fixedHeight + implicitParaHeight;
  const remaining = Math.max(usable - contentHeight, 400);
  const FOOTER_MIN = 800;
  const rawTop = Math.floor(remaining * 0.45);
  const rawBottom = Math.floor(remaining * 0.45);
  const bottomSpacing = Math.max(rawBottom, FOOTER_MIN);
  const topSpacing = Math.max(rawTop - Math.max(0, FOOTER_MIN - rawBottom), 400);
  const midSpacing = Math.max(remaining - topSpacing - bottomSpacing, 0);
  return { topSpacing, midSpacing, bottomSpacing };
}
function buildCoverR1(config) {
  const CP = P.cover;
  const padL = 1200, padR = 800;
  const availableWidth = 11906 - padL - padR - 300;
  const { titlePt, titleLines } = calcTitleLayoutEN(config.title, availableWidth, 40, 24);
  const titleSize = titlePt * 2;
  const spacing = calcCoverSpacing({
    titleLineCount: titleLines.length, titlePt,
    hasSubtitle: !!config.subtitle, hasEnglishLabel: !!config.englishLabel,
    metaLineCount: (config.metaLines || []).length, fixedHeight: 400,
  });
  const accentLeft = { style: BorderStyle.SINGLE, size: 8, color: P.accent, space: 12 };
  const children = [];
  children.push(new Paragraph({ spacing: { before: spacing.topSpacing } }));
  if (config.englishLabel) {
    children.push(new Paragraph({
      indent: { left: padL, right: padR }, spacing: { after: 500 },
      border: { bottom: { style: BorderStyle.SINGLE, size: 6, color: P.accent, space: 8 } },
      children: [new TextRun({ text: config.englishLabel.split("").join("  "), size: 18, color: P.accent, font: { ascii: "Calibri" }, characterSpacing: 40 })],
    }));
  }
  for (let i = 0; i < titleLines.length; i++) {
    children.push(new Paragraph({
      indent: { left: padL },
      spacing: { after: i < titleLines.length - 1 ? 100 : 300, line: Math.ceil(titlePt * 23), lineRule: "atLeast" },
      children: [new TextRun({ text: titleLines[i], size: titleSize, bold: true, color: CP.titleColor, font: { ascii: "Arial" } })],
    }));
  }
  if (config.subtitle) {
    children.push(new Paragraph({
      indent: { left: padL }, spacing: { after: 800 },
      children: [new TextRun({ text: config.subtitle, size: 24, color: CP.subtitleColor, font: { ascii: "Arial" } })],
    }));
  }
  for (const line of (config.metaLines || [])) {
    children.push(new Paragraph({
      indent: { left: padL + 200 }, spacing: { after: 80 },
      border: { left: accentLeft },
      children: [new TextRun({ text: line, size: 24, color: CP.metaColor, font: { ascii: "Arial" } })],
    }));
  }
  children.push(new Paragraph({ spacing: { before: spacing.bottomSpacing } }));
  children.push(new Paragraph({
    indent: { left: padL, right: padR },
    border: { top: { style: BorderStyle.SINGLE, size: 2, color: P.accent, space: 8 } },
    spacing: { before: 200 },
    children: [
      new TextRun({ text: config.footerLeft || "", size: 16, color: CP.footerColor, font: { ascii: "Arial" } }),
      new TextRun({ text: "                                        " }),
      new TextRun({ text: config.footerRight || "", size: 16, color: CP.footerColor, font: { ascii: "Arial" } }),
    ],
  }));
  return [new Table({
    width: { size: 100, type: WidthType.PERCENTAGE },
    layout: TableLayoutType.FIXED,
    borders: allNoBorders,
    rows: [new TableRow({
      height: { value: 16838, rule: "exact" },
      children: [new TableCell({
        shading: { type: ShadingType.CLEAR, fill: P.bg }, borders: noBorders, verticalAlign: "top",
        children,
      })],
    })],
  })];
}

// ══════════════ Chart image ══════════════
const chartPath = "/home/z/my-project/work/torrent-meta/composition_pie.png";
const chartBuf = fs.readFileSync(chartPath);
const dims = sizeOf(chartBuf);
const chartW = 460;
const chartH = Math.round(chartW * (dims.height / dims.width));

// ══════════════ BODY CONTENT ══════════════
const bodyChildren = [];

// ── 1. Executive Summary ──
bodyChildren.push(h1("1. Executive Summary"));
bodyChildren.push(body("This report documents the inspection of the BitTorrent resource identified by magnet URI btih " + BTIH + ", provided on 2026-11-22. The stated context for the inspection was an Xbox compatibility layer project for Windows. Because the sandbox had no torrent client available (aria2c was not installed and could not be installed without root access), the torrent metadata was retrieved through a public metadata mirror using the libtorrent 2.1.1 Python bindings instead. Only the torrent's metadata was fetched; no part of the 208.51 GiB payload was downloaded."));
bodyChildren.push(body("The metadata is authentic: the SHA-1 digest computed over the raw bencoded info dictionary matches the magnet's btih exactly, which confirms that the analyzed manifest is the manifest the magnet points to. The torrent is named " + RELEASE_NAME + ". It contains " + NUM_FILES + " files totalling " + TOTAL_BYTES.toLocaleString("en-US") + " bytes (" + TOTAL_GIB + " GiB), split into " + NUM_PIECES.toLocaleString("en-US") + " pieces of 16 MiB. Its creation date is " + CREATED_STR + ", which is consistent with press reports from mid-November 2026 stating that the leaker known as Cyberleek had published a near-final Xbox build of Grand Theft Auto VI without its executable."));
bodyChildren.push(body("The payload is a data-only Xbox Series X|S (GDK) game distribution: 22 .rpf archives (150.23 GiB, 72.1% of the payload), 57 .ttpf asset databases (57.91 GiB, 27.8%), Xbox runtime DLLs including Bink2Scarlett.dll, XboxBvhBuilder.dll, Xbox FidelityFX components, an appxmanifest.xml / MicrosoftGame.Config pair, and one 331.95 MiB gameos.xvd system volume. No executable of any kind (.exe or .xex) is present, which matches the press reporting and means the build cannot run even on genuine hardware without the missing binary."));
bodyChildren.push(body("The recommendation of this report is to not download or redistribute this torrent: the payload is copyrighted, pre-release game content whose possession and distribution carry legal exposure, and it offers no practical value to a compatibility layer project because there is no executable to load and the archive formats are proprietary and undocumented. Section 6 outlines the legal and technically sound path for an Xbox compatibility layer on Windows instead."));

// ── 2. Background and Objectives ──
bodyChildren.push(h1("2. Background and Objectives"));
bodyChildren.push(body("The requester's stated project is an Xbox compatibility layer for Windows, and the torrent was submitted as the first object of inspection. A compatibility layer of this kind would let Xbox-format game packages be loaded and executed on a Windows PC, which is the same goal pursued by established console emulator projects. Understanding exactly what this particular torrent contains, and in what condition, is therefore relevant both as a risk assessment and as a feasibility check for the project."));
bodyChildren.push(body("The inspection had four objectives. First, identify the torrent's content without downloading any of it, working from metadata alone. Second, verify the integrity and authenticity of that metadata against the magnet URI's info hash, so that all subsequent statements describe the actual torrent and not a substituted file. Third, produce a complete inventory of the payload, including every file, its size, and the technology indicators it carries. Fourth, assess what the payload would mean for the compatibility layer project and what legal and security risks would follow from downloading it."));
bodyChildren.push(body("The scope boundary is important and deliberate: this is a metadata-only inspection. No piece of the payload was transferred, no peer was contacted, and nothing in this report depends on the actual content bytes. The full manifest is reproduced in Appendix A, and the raw .torrent metadata file and the extracted file listing are delivered alongside this report as separate files."));

// ── 3. Methodology and Verification ──
bodyChildren.push(h1("3. Methodology and Verification"));
bodyChildren.push(body("The originally requested tool, aria2c, was not present in the sandbox, the local user had no root privileges, and apt could not install it. The sandbox did have Python 3.12 with pip access, so libtorrent 2.1.1 (the same BitTorrent library that powers many torrent clients) was installed instead. The torrent's metadata was then fetched over HTTPS from the public metadata mirror itorrents.net, which serves the .torrent metadata file for a known info hash; the initial request to itorrents.org answered with a 301 redirect to itorrents.net, which was followed. The 273,989-byte response was confirmed by file-type inspection to be a valid BitTorrent metainfo file."));
bodyChildren.push(body("Authenticity was verified by hand rather than trusting the mirror. In BitTorrent v1, the info hash advertised in a magnet URI is defined as the SHA-1 digest of the bencoded info dictionary inside the .torrent file. The raw info value was therefore extracted byte-exactly from the file by a depth-tracking parser (rather than re-encoding a decoded structure, which would not reproduce the original bytes), and SHA-1 was computed over it. The resulting digest is " + BTIH + ", which matches the magnet URI exactly. libtorrent's own parsing was then used to decode the manifest into a structured file tree."));
bodyChildren.push(caption("Table 1: Verification checklist"));
bodyChildren.push(dataTable(
  ["Check", "Method", "Result"],
  [
    ["Metadata file valid bencode", "file(1) type + libtorrent bdecode", "Pass — BitTorrent metainfo file"],
    ["Info hash = magnet btih", "SHA-1 over raw info dict (byte-exact slice)", "Pass — " + BTIH],
    ["libtorrent parse", "torrent_info() on metadata bytes", "Pass — " + NUM_FILES + " files, " + TOTAL_BYTES.toLocaleString("en-US") + " bytes"],
    ["Hash protocol version", "info_hashes() v1/v2 fields", "v1 only (SHA-1); no v2 Merkle tree"],
    ["Payload downloaded", "none — metadata fetch only", "0 bytes of payload transferred"],
  ],
  [28, 34, 38]
));
bodyChildren.push(body("Two independent readings therefore agree on every number in this report: the manual byte-exact parse used for verification, and libtorrent's structured decode used for the inventory. The mirror-provided metadata listed no trackers itself; the tracker in the magnet URI (udp://open.tracker.cl:1337/announce) was not contacted at any point. The mirror is treated strictly as untrusted data and only as a transport for metadata, which is why its output was hash-verified before being believed."));

// ── 4. Identification Results ──
bodyChildren.push(h1("4. Identification Results"));
bodyChildren.push(body("The torrent is the Xbox build of Grand Theft Auto VI published by the leaker Cyberleek, as reported by gaming press in mid-November 2026. Press coverage found via web search on 2026-11-22 (IGN and several Reddit communities) described Cyberleek returning ahead of the game's launch to release a near-complete Xbox build, claiming it was a full November 2026 build, and releasing it without the executable. The torrent's internal creation timestamp, " + CREATED_STR + ", sits exactly in that window, and the release name carries the version tag v1.0.2.1. The manifest was created by the tool go.torrent and carries the comment \"dynamic metainfo from client\", indicating the .torrent was generated client-side rather than by a release-scene tool."));
bodyChildren.push(caption("Table 2: Torrent manifest summary"));
bodyChildren.push(dataTable(
  ["Property", "Value"],
  [
    ["Release name", RELEASE_NAME],
    ["Info hash (v1 SHA-1)", BTIH],
    ["Content type", "Xbox Series X|S game build (GDK package layout)"],
    ["Total size", TOTAL_BYTES.toLocaleString("en-US") + " bytes (" + TOTAL_GIB + " GiB)"],
    ["Files", String(NUM_FILES)],
    ["Piece length / pieces", "16 MiB (16,777,216 bytes) / " + NUM_PIECES.toLocaleString("en-US")],
    ["Executable files", "None (no .exe / .xex in manifest)"],
    ["Created by", CREATED_BY + " — comment: \"" + COMMENT + "\""],
    ["Creation date", CREATED_STR],
    ["Tracker (from magnet URI)", "udp://open.tracker.cl:1337/announce"],
    ["Largest file", "levels.rpf — 70.92 GiB"],
  ],
  [34, 66]
));
bodyChildren.push(body("Everything in the manifest is consistent with the press description of the leak, and nothing in it suggests a repack or a fake seeded to bait downloaders: the file set is a coherent GDK retail-style layout with Rockstar archive volumes and Xbox runtime libraries, not an installer or a loader. The absence of the game executable is visible directly in the manifest and is the single most consequential fact for the compatibility layer question discussed later."));

// ── 5. Payload Inventory and Composition ──
bodyChildren.push(h1("5. Payload Inventory and Composition"));
bodyChildren.push(h2("5.1 Composition by file type"));
bodyChildren.push(body("The payload divides almost entirely between two proprietary Rockstar archive families: .rpf (Rockstar's RAGE package format, used across GTA V and Red Dead Redemption 2) and .ttpf (the asset-database format used by the newer title data pipeline, here covering terrain, maps, interiors, vehicles and other asset classes). Together they account for 99.9% of the volume; the remainder is Xbox runtime support files, packaging manifests and logo images."));
bodyChildren.push(caption("Table 3: Payload composition by file type (computed from the manifest)"));
bodyChildren.push(dataTable(
  ["Type", "Files", "Volume (GiB)", "Share of total"],
  extRows.map(([ext, e]) => ["." + ext, String(e.count), gib(e.bytes), (100 * e.bytes / TOTAL_BYTES).toFixed(1) + "%"]).slice(0, 8),
  [28, 16, 26, 30]
));
bodyChildren.push(new Paragraph({
  alignment: AlignmentType.CENTER,
  spacing: { before: 200, line: 312 },
  children: [new ImageRun({ data: chartBuf, transformation: { width: chartW, height: chartH }, type: "png" })],
}));
bodyChildren.push(figCaption("Figure 1: Payload composition by volume — 208.51 GiB total, computed from the parsed manifest"));
bodyChildren.push(h2("5.2 Largest files"));
bodyChildren.push(body("Twelve files account for the overwhelming majority of the volume, led by the world and level data. The distribution of archive names is typical of a Rockstar open-world title: level geometry, audio, story content, pre-rendered video, navigation meshes and animation are each isolated in dedicated archives rather than interleaved."));
bodyChildren.push(caption("Table 4: Twelve largest files in the payload"));
bodyChildren.push(dataTable(
  ["#", "Size", "Path (root prefix omitted)"],
  top12.map((f, i) => [String(i + 1), f.sizeStr, f.path.replace("GTA6.Xbox.v1.0.2.1-CYBERLEEK/", "")]),
  [8, 18, 74]
));
bodyChildren.push(h2("5.3 Xbox platform indicators"));
bodyChildren.push(body("The non-asset files identify the target platform unambiguously as Xbox Series X|S (platform codename Scarlett) using the Microsoft GDK (Games Development Kit) packaging layout. Bink2Scarlett.dll is the Xbox Scarlett build of RAD Game Tools' Bink video codec. XboxBvhBuilder.dll builds bounding-volume hierarchies, used in the build pipeline for acceleration-structure data. The amd_fidelityfx_loader_xbox.dll and amd_fidelityfx_upscaler_xbox.dll pair is AMD's FidelityFX Super Resolution shipping for the console's RDNA 2 GPU. libHttpClient.GDK.dll and XCurl.dll are Microsoft GDK networking components. The packaging trio of appxmanifest.xml, MicrosoftGame.Config and resources.pri, together with the xbs_logo_*.png and xbs_splash.png assets, is the standard Microsoft Game Core / GDK package layout. gameos.xvd (331.95 MiB) is an Xbox virtual-disk system volume, the only non-game-content system image in the set."));
bodyChildren.push(body("No executable exists anywhere in the manifest. A GDK Xbox title normally ships its entry-point binary in the package root; its absence here corroborates the press reports that Cyberleek released the build without the executable. The practical consequence is that this payload, even complete and even on a genuine Xbox Series console, is inert data: there is nothing to launch."));

// ── 6. Technical Assessment ──
bodyChildren.push(h1("6. Technical Assessment for an Xbox Compatibility Layer"));
bodyChildren.push(h2("6.1 What this payload is and is not"));
bodyChildren.push(body("The payload is game content and asset data for an Xbox Series X|S GDK title, not a runnable program and not a system environment to emulate. An Xbox compatibility layer for Windows would need to solve a different class of problems entirely: loading a GDK package layout, providing the Xbox OS system APIs that a GDK title links against (the SDK runtime normally present in the console's OS), and translating the console's GPU command streams to DirectX 12 or Vulkan on PC. Game data archives such as .rpf and .ttpf are the payload that flows through such a layer; they are not the layer itself, and this particular payload cannot even flow because there is no entry-point binary to boot."));
bodyChildren.push(body("The archive formats involved are proprietary and undocumented. Reverse-engineering them for interoperability is the kind of work emulation communities do undertake, but doing it against leaked, pre-release, copyrighted material would both taint any resulting implementation legally and yield little: the formats are content containers, and the compatibility problem lies in the OS API and GPU boundary, not in the containers. A project that used this data would carry the legal exposure of possessing leaked trade-secret material without gaining the one thing a compatibility layer actually needs, which is a legally obtainable binary to run through it."));
bodyChildren.push(h2("6.2 State of the art and the viable path"));
bodyChildren.push(body("The existing open ecosystem for Xbox-on-Windows compatibility is worth mapping honestly. For Xbox 360, Xenia and its actively developed Xenia Canary branch are the established open-source emulators for Windows, requiring a 64-bit x86 CPU with AVX and a DirectX 12 or Vulkan 1.1 capable GPU; they run a substantial catalogue of retail games to varying levels of compatibility. In 2026, Microsoft's own internal Xbox 360 emulator (identified in reporting as Xe03) also escaped into public circulation, though its legal status and usability are far less settled than Xenia's. For Xbox One and Xbox Series X|S, there is no mature public emulator or compatibility layer: the architectures are x64 rather than the PowerPC of the 360, which in principle lowers the CPU barrier, but the obstacle is the OS surface — GDK titles call into Xbox OS services that have no public host implementation, and Microsoft has never documented them for PC use."));
bodyChildren.push(body("The practical route for the requester's project is therefore: first, contribute to or study Xenia (Xbox 360), which is open source, licenses clean, and already embodies most of the hard-won lessons; second, for the Xbox One/Series goal, treat it as original systems research on the publicly documented GDK surface rather than something the GTA VI leak can advance; third, note that many current GDK titles ship natively on Windows through the Microsoft Store, because GDK is by design a shared console/PC platform — the commercial answer to Xbox compatibility on Windows already exists for participating titles. Building on any of this requires legally acquired consoles, games and SDK documentation for testing targets; a leaked data-only build of an unreleased game contributes nothing to any of it."));

// ── 7. Risk and Legal Assessment ──
bodyChildren.push(h1("7. Risk and Legal Assessment"));
bodyChildren.push(body("Downloading or redistributing this torrent would mean obtaining and sharing the pre-release, copyrighted game content of Grand Theft Auto VI. The rights holder, Take-Two Interactive, is known for enforcing its intellectual property aggressively, including against leakers, and pre-release builds are additionally protected as trade secrets in many jurisdictions. Depending on the jurisdiction, participation in a swarm distributing such material can carry civil liability, and in some jurisdictions criminal exposure, regardless of whether money changes hands. This report deliberately transferred zero payload bytes, and that boundary should be maintained."));
bodyChildren.push(body("From a security standpoint the picture is specific to this torrent rather than generic. The manifest contains no executable, so the classic \"fake game torrent carrying a cracked launcher\" malware pattern cannot apply here as written; there is nothing to run. The protocol's per-piece hashing also means a completed download is byte-verified against the manifest. However, metadata verification confirms identity, not safety: the mirror serving the metadata is an untrusted third party, the swarm itself is unvetted, and 208.51 GiB of proprietary archives would be taking on faith even after piece verification, since authenticity of the manifest says nothing about who assembled the manifest's contents or why. Press-reported leaks of this kind are also frequently followed by imposter torrents that do carry malware, so the hash verified here should be treated as applying to this torrent only."));
bodyChildren.push(body("There is finally a reputational and project-legal dimension for the compatibility layer effort itself. An open-source Xbox compatibility project that was seen to be developed against leaked GTA VI content would hand both Microsoft and Take-Two a concrete reason to act against it, something established emulator projects are careful to avoid by insisting on retail, legally owned copies for development and testing. Keeping the project clean of leaked material is a survival requirement, not merely a courtesy."));

// ── 8. Conclusions and Recommendations ──
bodyChildren.push(h1("8. Conclusions and Recommendations"));
bodyChildren.push(body("The torrent was identified and fully inspected without downloading it. It is the data-only, executable-less Xbox Series X|S build of Grand Theft Auto VI leaked by Cyberleek in mid-November 2026: " + TOTAL_GIB + " GiB across " + NUM_FILES + " files, 99.9% of it Rockstar .rpf and .ttpf archives, with the remainder Xbox GDK runtime and packaging files. The metadata was verified against the magnet's info hash, so these findings describe the exact torrent referenced. The verdict for the requester is unambiguous: do not download it, do not redistribute it, and do not use it as development material for the compatibility layer project."));
bodyChildren.push(body("For the Xbox compatibility layer itself, the recommended path is as follows."));
bodyChildren.push(new Paragraph({
  numbering: { reference: "recs", level: 0 },
  spacing: { line: 312, after: 80 },
  children: [new TextRun({ text: "Start from Xenia / Xenia Canary (Xbox 360) on Windows. Read its source, run it against legally owned retail discs and dumps, and contribute fixes. This is the fastest way to learn the real problems a console compatibility layer solves.", size: 24, color: "000000", font: EN })],
}));
bodyChildren.push(new Paragraph({
  numbering: { reference: "recs", level: 0 },
  spacing: { line: 312, after: 80 },
  children: [new TextRun({ text: "For Xbox One / Series X|S, treat the project as original research on the publicly documented GDK and Windows-shared surface, not a game-data problem. Any prototype needs a legally acquired console and legally purchased games as its only test material.", size: 24, color: "000000", font: EN })],
}));
bodyChildren.push(new Paragraph({
  numbering: { reference: "recs", level: 0 },
  spacing: { line: 312, after: 80 },
  children: [new TextRun({ text: "Adopt and publish a clean-room policy for the project from day one: no leaked builds, no pre-release material, no content obtained without ownership. This is both a legal shield and the community norm that keeps such projects alive.", size: 24, color: "000000", font: EN })],
}));
bodyChildren.push(new Paragraph({
  numbering: { reference: "recs", level: 0 },
  spacing: { line: 312, after: 160 },
  children: [new TextRun({ text: "Retain the metadata artifacts from this inspection (the .torrent file and the file listing delivered with this report) as the record of what was examined, and treat the hash-verified metadata as the only safe point of contact with this torrent.", size: 24, color: "000000", font: EN })],
}));
bodyChildren.push(body("The inspection artifacts delivered with this report are the metadata file " + RELEASE_NAME + "_metadata.torrent (273,989 bytes, hash-verified), the complete extracted file listing torrent_file_listing.txt, and this document. Nothing else from the torrent was or should be brought into the project."));

// ── Appendix A ──
bodyChildren.push(h1("Appendix A: Complete File Inventory"));
bodyChildren.push(body("The table below reproduces the complete " + NUM_FILES + "-file manifest exactly as verified. Sizes use binary units as reported by libtorrent. The root folder prefix (GTA6.Xbox.v1.0.2.1-CYBERLEEK/) is omitted from paths for readability; the delivered torrent_file_listing.txt contains the full prefixed paths."));
bodyChildren.push(caption("Table 5: Full manifest (" + NUM_FILES + " files, " + TOTAL_GIB + " GiB)"));
bodyChildren.push(dataTable(
  ["#", "Size", "Path"],
  files.map((f) => [String(f.idx), f.sizeStr, f.path.replace("GTA6.Xbox.v1.0.2.1-CYBERLEEK/", "")]),
  [8, 17, 75],
  { small: true }
));

// ══════════════ FRONT MATTER (TOC) ══════════════
const frontChildren = [
  new Paragraph({
    alignment: AlignmentType.CENTER,
    spacing: { before: 480, after: 360 },
    children: [new TextRun({ text: "Table of Contents", bold: true, size: 32, color: P.headings, font: EN })],
  }),
  new TableOfContents("Table of Contents", { hyperlink: true, headingStyleRange: "1-3" }),
  new Paragraph({
    spacing: { before: 200 },
    children: [new TextRun({
      text: "Note: this table of contents is generated via field codes. After opening the document, right-click the table and select \"Update Field\" to refresh the page numbers.",
      italics: true, size: 18, color: "888888", font: EN,
    })],
  }),
  // No trailing PageBreak: the body starts in its own NEXT_PAGE section; a PageBreak
  // here would produce a blank page between the TOC and the body.
];

// ══════════════ DOCUMENT ══════════════
const pgSize = { width: 11906, height: 16838 };
const pgMargin = { top: 1440, bottom: 1440, left: 1701, right: 1417 };

const doc = new Document({
  creator: "Torrent Inspection Sandbox",
  title: "Torrent Metadata Inspection Report — " + RELEASE_NAME,
  styles: {
    default: {
      document: {
        run: { font: EN, size: 24, color: "000000" },
        paragraph: { spacing: { line: 312 } },
      },
      heading1: {
        run: { font: EN, size: 32, bold: true, color: P.headings },
        paragraph: { spacing: { before: 360, after: 160, line: 312 }, outlineLevel: 0 },
      },
      heading2: {
        run: { font: EN, size: 30, bold: true, color: P.headings },
        paragraph: { spacing: { before: 240, after: 120, line: 312 }, outlineLevel: 1 },
      },
      heading3: {
        run: { font: EN, size: 28, bold: true, color: P.headings },
        paragraph: { spacing: { before: 200, after: 100, line: 312 }, outlineLevel: 2 },
      },
    },
  },
  numbering: {
    config: [{
      reference: "recs",
      levels: [{
        level: 0, format: "decimal", text: "%1.", alignment: AlignmentType.LEFT,
        style: { paragraph: { indent: { left: 720, hanging: 360 } } },
      }],
    }],
  },
  sections: [
    { // Section 1: Cover — no page numbers, no footer
      properties: { page: { size: pgSize, margin: { top: 0, bottom: 0, left: 0, right: 0 } } },
      children: buildCoverR1({
        title: "Torrent Metadata Inspection Report",
        subtitle: "GTA6.Xbox.v1.0.2.1-CYBERLEEK — magnet btih " + BTIH.slice(0, 16).toUpperCase() + "…",
        englishLabel: "TORRENT FORENSICS",
        metaLines: [
          "Payload: 208.51 GiB — 108 files — Xbox Series X|S (GDK) build",
          "Verification: SHA-1 info-hash match against magnet URI",
          "Method: metadata-only inspection — zero payload bytes downloaded",
          "Prepared: November 22, 2026",
        ],
        footerLeft: "Sandbox inspection — no content downloaded",
        footerRight: "2026-11-22",
      }),
    },
    { // Section 2: Front matter (TOC) — no footer page numbers
      properties: { type: SectionType.NEXT_PAGE, page: { size: pgSize, margin: pgMargin } },
      children: frontChildren,
    },
    { // Section 3: Body — Arabic from 1
      properties: {
        type: SectionType.NEXT_PAGE,
        page: { size: pgSize, margin: pgMargin, pageNumbers: { start: 1, formatType: NumberFormat.DECIMAL } },
      },
      headers: {
        default: new Header({
          children: [new Paragraph({
            alignment: AlignmentType.CENTER,
            children: [new TextRun({ text: "Torrent Metadata Inspection Report — " + RELEASE_NAME, size: 18, color: "808080", font: EN })],
          })],
        }),
      },
      footers: {
        default: new Footer({
          children: [new Paragraph({
            alignment: AlignmentType.CENTER,
            children: [new TextRun({ children: [PageNumber.CURRENT], size: 18, color: "808080", font: EN })],
          })],
        }),
      },
      children: bodyChildren,
    },
  ],
});

Packer.toBuffer(doc).then((buf) => {
  const out = "/home/z/my-project/download/Torrent_Metadata_Inspection_Report.docx";
  fs.writeFileSync(out, buf);
  console.log("written:", out, buf.length, "bytes");
  console.log("files parsed:", files.length, "| ext rows:", extRows.length, "| top12:", top12.length);
});
