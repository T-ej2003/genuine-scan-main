import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  Document,
  HeadingLevel,
  Packer,
  Paragraph,
  TextRun,
} from "docx";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const repoRoot = path.resolve(__dirname, "..");
const inputPath = path.join(repoRoot, "docs", "USER_MANUAL.md");
const outputPath = path.join(repoRoot, "docs", "USER_MANUAL_v2.docx");

const stripInlineMd = (s) =>
  String(s)
    .replace(/\\*\\*/g, "")
    .replace(/`/g, "")
    .replace(/\\[(.*?)\\]\\((.*?)\\)/g, "$1 ($2)");

const toParagraphs = (markdown) => {
  const lines = String(markdown).split(/\r?\n/);
  const paras = [];

  for (const rawLine of lines) {
    const line = rawLine.trimEnd();
    const trimmed = line.trim();

    if (!trimmed) {
      paras.push(new Paragraph({ children: [new TextRun("")] }));
      continue;
    }

    // Images: ![alt](path)
    if (trimmed.startsWith("![") && trimmed.includes("](") && trimmed.endsWith(")")) {
      const alt = trimmed.slice(2).split("](")[0] || "Screenshot";
      const url = trimmed.split("](")[1]?.slice(0, -1) || "";
      paras.push(
        new Paragraph({
          children: [new TextRun({ text: `Screenshot: ${stripInlineMd(alt)} ${url ? `(${url})` : ""}` })],
        })
      );
      continue;
    }

    // Headings
    if (trimmed.startsWith("# ")) {
      paras.push(new Paragraph({ text: stripInlineMd(trimmed.slice(2)), heading: HeadingLevel.HEADING_1 }));
      continue;
    }
    if (trimmed.startsWith("## ")) {
      paras.push(new Paragraph({ text: stripInlineMd(trimmed.slice(3)), heading: HeadingLevel.HEADING_2 }));
      continue;
    }
    if (trimmed.startsWith("### ")) {
      paras.push(new Paragraph({ text: stripInlineMd(trimmed.slice(4)), heading: HeadingLevel.HEADING_3 }));
      continue;
    }

    // Bullets
    if (trimmed.startsWith("- ")) {
      paras.push(
        new Paragraph({
          text: stripInlineMd(trimmed.slice(2)),
          bullet: { level: 0 },
        })
      );
      continue;
    }

    // Ordered items: keep the visible numbering (docx numbering config is intentionally omitted)
    if (/^\\d+\\.\\s+/.test(trimmed)) {
      paras.push(new Paragraph({ text: stripInlineMd(trimmed) }));
      continue;
    }

    paras.push(new Paragraph({ text: stripInlineMd(trimmed) }));
  }

  return paras;
};

async function main() {
  const md = fs.readFileSync(inputPath, "utf8");
  const doc = new Document({
    sections: [
      {
        properties: {},
        children: toParagraphs(md),
      },
    ],
  });

  const buf = await Packer.toBuffer(doc);
  fs.writeFileSync(outputPath, buf);
  // eslint-disable-next-line no-console
  console.log(`Wrote ${path.relative(repoRoot, outputPath)}`);
}

main().catch((err) => {
  // eslint-disable-next-line no-console
  console.error(err);
  process.exit(1);
});

