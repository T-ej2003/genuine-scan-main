import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  AlignmentType,
  Document,
  HeadingLevel,
  ImageRun,
  Packer,
  Paragraph,
  TextRun,
} from "docx";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const repoRoot = path.resolve(__dirname, "..");
const outputRoot = path.join(repoRoot, "DOCUMENTS");

const SKIP_DIRS = new Set([
  ".git",
  "node_modules",
  "dist",
  "DOCUMENTS",
  "test-results",
]);

const stripInlineMd = (value) =>
  String(value)
    .replace(/\*\*/g, "")
    .replace(/`/g, "")
    .replace(/\[(.*?)\]\((.*?)\)/g, "$1 ($2)")
    .trim();

const isLikelyImageLine = (line) => /^!\[[^\]]*\]\([^\)]+\)\s*$/.test(line.trim());

const parseImageLine = (line) => {
  const match = line.trim().match(/^!\[([^\]]*)\]\(([^\)]+)\)$/);
  if (!match) return null;
  return {
    alt: stripInlineMd(match[1] || "Screenshot"),
    src: String(match[2] || "").trim(),
  };
};

const isPng = (buffer) => {
  if (!buffer || buffer.length < 24) return false;
  const sig = buffer.subarray(0, 8).toString("hex");
  return sig === "89504e470d0a1a0a";
};

const pngDimensions = (buffer) => {
  if (!isPng(buffer)) return null;
  const width = buffer.readUInt32BE(16);
  const height = buffer.readUInt32BE(20);
  if (!Number.isFinite(width) || !Number.isFinite(height) || width <= 0 || height <= 0) return null;
  return { width, height };
};

const fitDimensions = (width, height, maxWidth = 620, maxHeight = 380) => {
  if (!width || !height) return { width: maxWidth, height: Math.round(maxWidth * 0.6) };
  const scale = Math.min(maxWidth / width, maxHeight / height, 1);
  return {
    width: Math.max(1, Math.round(width * scale)),
    height: Math.max(1, Math.round(height * scale)),
  };
};

const imageParagraphs = (imageSpec, markdownDir) => {
  const rawSrc = imageSpec.src;
  const withoutQuery = rawSrc.split("?")[0].split("#")[0];
  const absPath = path.resolve(markdownDir, withoutQuery);

  if (!fs.existsSync(absPath)) {
    throw new Error(`Image not found for DOCX generation: ${path.relative(repoRoot, absPath)}`);
  }

  const data = fs.readFileSync(absPath);
  const dims = pngDimensions(data);
  const transformed = fitDimensions(dims?.width, dims?.height);

  return [
    new Paragraph({
      alignment: AlignmentType.CENTER,
      spacing: { before: 120, after: 80 },
      children: [
        new ImageRun({
          data,
          transformation: transformed,
        }),
      ],
    }),
    new Paragraph({
      alignment: AlignmentType.CENTER,
      spacing: { after: 220 },
      children: [
        new TextRun({
          text: imageSpec.alt || path.basename(withoutQuery),
          size: 20,
          color: "4b5563",
          italics: true,
        }),
      ],
    }),
  ];
};

const codeBlockParagraphs = (lines, language) => {
  const children = [];
  if (language) {
    children.push(
      new Paragraph({
        spacing: { before: 140, after: 60 },
        children: [
          new TextRun({
            text: `${language.toUpperCase()} code`,
            size: 18,
            color: "6b7280",
            italics: true,
          }),
        ],
      })
    );
  }

  for (const line of lines) {
    children.push(
      new Paragraph({
        spacing: { after: 20 },
        children: [
          new TextRun({
            text: line || " ",
            font: "Menlo",
            size: 20,
            color: "111827",
          }),
        ],
      })
    );
  }

  children.push(new Paragraph({ children: [new TextRun("")] }));
  return children;
};

const markdownToParagraphs = (markdown, markdownDir) => {
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
        codeLines = [];
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

    if (isLikelyImageLine(trimmed)) {
      const parsed = parseImageLine(trimmed);
      if (parsed) {
        paragraphs.push(...imageParagraphs(parsed, markdownDir));
        continue;
      }
    }

    if (trimmed === "---" || trimmed === "***") {
      paragraphs.push(
        new Paragraph({
          spacing: { before: 120, after: 120 },
          children: [new TextRun({ text: "________________________________________", color: "9ca3af" })],
        })
      );
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
          spacing: { before: 220, after: 100 },
          children: [new TextRun(stripInlineMd(trimmed.slice(3)))],
        })
      );
      continue;
    }

    if (trimmed.startsWith("### ")) {
      paragraphs.push(
        new Paragraph({
          heading: HeadingLevel.HEADING_3,
          spacing: { before: 180, after: 80 },
          children: [new TextRun(stripInlineMd(trimmed.slice(4)))],
        })
      );
      continue;
    }

    if (trimmed.startsWith("- ")) {
      paragraphs.push(
        new Paragraph({
          bullet: { level: 0 },
          spacing: { after: 60 },
          children: [new TextRun(stripInlineMd(trimmed.slice(2)))],
        })
      );
      continue;
    }

    if (/^\d+\.\s+/.test(trimmed)) {
      paragraphs.push(
        new Paragraph({
          spacing: { after: 60 },
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

const collectMarkdownFiles = (dir, result = []) => {
  const entries = fs.readdirSync(dir, { withFileTypes: true });

  for (const entry of entries) {
    if (entry.name.startsWith(".") && entry.name !== ".github") continue;
    if (SKIP_DIRS.has(entry.name)) continue;

    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      collectMarkdownFiles(fullPath, result);
      continue;
    }

    if (entry.isFile() && entry.name.endsWith(".md")) {
      result.push(fullPath);
    }
  }

  return result;
};

const extractTitle = (markdown, fallback) => {
  const match = String(markdown).match(/^#\s+(.+)$/m);
  return match ? stripInlineMd(match[1]) : fallback;
};

const toOutputPath = (inputPath) => {
  const relative = path.relative(repoRoot, inputPath).replace(/\.md$/i, ".docx");
  return path.join(outputRoot, relative);
};

const generateDocx = async (inputPath) => {
  const markdown = fs.readFileSync(inputPath, "utf8");
  const paragraphs = markdownToParagraphs(markdown, path.dirname(inputPath));
  const outputPath = toOutputPath(inputPath);
  const fallbackTitle = path.basename(inputPath, ".md");

  const doc = new Document({
    title: extractTitle(markdown, fallbackTitle),
    creator: "AuthenticQR",
    sections: [
      {
        properties: {},
        children: paragraphs,
      },
    ],
  });

  const buffer = await Packer.toBuffer(doc);
  fs.mkdirSync(path.dirname(outputPath), { recursive: true });
  fs.writeFileSync(outputPath, buffer);
  return path.relative(repoRoot, outputPath);
};

async function main() {
  fs.rmSync(outputRoot, { recursive: true, force: true });
  fs.mkdirSync(outputRoot, { recursive: true });

  const markdownFiles = collectMarkdownFiles(repoRoot).sort((a, b) => a.localeCompare(b));
  const created = [];

  for (const inputPath of markdownFiles) {
    // eslint-disable-next-line no-await-in-loop
    const written = await generateDocx(inputPath);
    created.push(written);
  }

  console.log(`Created ${created.length} DOCX files in DOCUMENTS:\n${created.map((p) => `- ${p}`).join("\n")}`);
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
