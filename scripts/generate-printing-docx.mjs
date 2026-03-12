import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { Document, HeadingLevel, Packer, Paragraph, TextRun } from "docx";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const repoRoot = path.resolve(__dirname, "..");

const targets = [
  "docs/PRINTING_ARCHITECTURE_STANDARD.md",
  "docs/MANUFACTURER_PRINTER_SETUP_GUIDE.md",
  "docs/LIGHTSAIL_PRINTING_UPDATE_COMMANDS.md",
];

const stripInlineMd = (value) =>
  String(value)
    .replace(/\*\*/g, "")
    .replace(/`/g, "")
    .replace(/\[(.*?)\]\((.*?)\)/g, "$1 ($2)")
    .trim();

const codeBlockParagraphs = (lines, language) => {
  const paragraphs = [];
  if (language) {
    paragraphs.push(
      new Paragraph({
        spacing: { before: 120, after: 40 },
        children: [new TextRun({ text: `${language.toUpperCase()} code`, italics: true, color: "6b7280", size: 18 })],
      })
    );
  }

  for (const line of lines) {
    paragraphs.push(
      new Paragraph({
        spacing: { after: 20 },
        children: [new TextRun({ text: line || " ", font: "Menlo", size: 20, color: "111827" })],
      })
    );
  }

  paragraphs.push(new Paragraph({ children: [new TextRun("")] }));
  return paragraphs;
};

const markdownToParagraphs = (markdown) => {
  const lines = String(markdown).split(/\r?\n/);
  const paragraphs = [];
  let inCodeBlock = false;
  let codeLanguage = "";
  let codeLines = [];

  const flushCodeBlock = () => {
    if (!inCodeBlock) return;
    paragraphs.push(...codeBlockParagraphs(codeLines, codeLanguage));
    inCodeBlock = false;
    codeLanguage = "";
    codeLines = [];
  };

  for (const rawLine of lines) {
    const line = rawLine.trimEnd();
    const trimmed = line.trim();

    if (trimmed.startsWith("```")) {
      if (inCodeBlock) {
        flushCodeBlock();
      } else {
        inCodeBlock = true;
        codeLanguage = trimmed.slice(3).trim();
      }
      continue;
    }

    if (inCodeBlock) {
      codeLines.push(rawLine);
      continue;
    }

    if (!trimmed) {
      paragraphs.push(new Paragraph({ children: [new TextRun("")] }));
      continue;
    }

    if (trimmed.startsWith("# ")) {
      paragraphs.push(
        new Paragraph({
          heading: HeadingLevel.HEADING_1,
          spacing: { before: 240, after: 120 },
          children: [new TextRun(stripInlineMd(trimmed.slice(2)))],
        })
      );
      continue;
    }

    if (trimmed.startsWith("## ")) {
      paragraphs.push(
        new Paragraph({
          heading: HeadingLevel.HEADING_2,
          spacing: { before: 180, after: 100 },
          children: [new TextRun(stripInlineMd(trimmed.slice(3)))],
        })
      );
      continue;
    }

    if (trimmed.startsWith("### ")) {
      paragraphs.push(
        new Paragraph({
          heading: HeadingLevel.HEADING_3,
          spacing: { before: 140, after: 80 },
          children: [new TextRun(stripInlineMd(trimmed.slice(4)))],
        })
      );
      continue;
    }

    if (trimmed.startsWith("- ")) {
      paragraphs.push(
        new Paragraph({
          bullet: { level: 0 },
          spacing: { after: 50 },
          children: [new TextRun(stripInlineMd(trimmed.slice(2)))],
        })
      );
      continue;
    }

    if (/^\d+\.\s+/.test(trimmed)) {
      paragraphs.push(
        new Paragraph({
          spacing: { after: 50 },
          children: [new TextRun(stripInlineMd(trimmed))],
        })
      );
      continue;
    }

    paragraphs.push(
      new Paragraph({
        spacing: { after: 80 },
        children: [new TextRun(stripInlineMd(trimmed))],
      })
    );
  }

  flushCodeBlock();
  return paragraphs;
};

const extractTitle = (markdown, fallback) => {
  const match = String(markdown).match(/^#\s+(.+)$/m);
  return match ? stripInlineMd(match[1]) : fallback;
};

const toOutputPath = (inputPath) => {
  const relative = path.relative(repoRoot, inputPath).replace(/\.md$/i, ".docx");
  return path.join(repoRoot, "DOCUMENTS", relative);
};

const generateDocx = async (inputPath) => {
  const markdown = fs.readFileSync(inputPath, "utf8");
  const doc = new Document({
    title: extractTitle(markdown, path.basename(inputPath, ".md")),
    creator: "MSCQR",
    sections: [{ properties: {}, children: markdownToParagraphs(markdown) }],
  });
  const outputPath = toOutputPath(inputPath);
  fs.mkdirSync(path.dirname(outputPath), { recursive: true });
  fs.writeFileSync(outputPath, await Packer.toBuffer(doc));
  return path.relative(repoRoot, outputPath);
};

async function main() {
  const created = [];
  for (const relativePath of targets) {
    const inputPath = path.join(repoRoot, relativePath);
    if (!fs.existsSync(inputPath)) {
      throw new Error(`Missing markdown source: ${relativePath}`);
    }
    // eslint-disable-next-line no-await-in-loop
    created.push(await generateDocx(inputPath));
  }
  console.log(`Created ${created.length} printing DOCX files:\n${created.map((entry) => `- ${entry}`).join("\n")}`);
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
