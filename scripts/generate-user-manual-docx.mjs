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
const docsRoot = path.join(repoRoot, "docs");

const DOC_TASKS = [
  { input: "USER_MANUAL.md", output: "USER_MANUAL_v2.docx" },
  { input: "SUPER_ADMIN_GUIDE.md", output: "SUPER_ADMIN_GUIDE.docx" },
  { input: "LICENSEE_ADMIN_GUIDE.md", output: "LICENSEE_ADMIN_GUIDE.docx" },
  { input: "MANUFACTURER_GUIDE.md", output: "MANUFACTURER_GUIDE.docx" },
  { input: "CUSTOMER_VERIFICATION_GUIDE.md", output: "CUSTOMER_VERIFICATION_GUIDE.docx" },
];

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

const markdownToParagraphs = (markdown, markdownDir) => {
  const lines = String(markdown).split(/\r?\n/);
  const paragraphs = [];

  for (const rawLine of lines) {
    const line = rawLine.trimEnd();
    const trimmed = line.trim();

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

  return paragraphs;
};

const generateDocx = async ({ input, output }) => {
  const inputPath = path.join(docsRoot, input);
  const outputPath = path.join(docsRoot, output);

  if (!fs.existsSync(inputPath)) {
    throw new Error(`Markdown source not found: ${path.relative(repoRoot, inputPath)}`);
  }

  const markdown = fs.readFileSync(inputPath, "utf8");
  const paragraphs = markdownToParagraphs(markdown, path.dirname(inputPath));

  const doc = new Document({
    title: path.basename(output, ".docx"),
    creator: "AuthenticQR",
    sections: [
      {
        properties: {},
        children: paragraphs,
      },
    ],
  });

  const buffer = await Packer.toBuffer(doc);
  fs.writeFileSync(outputPath, buffer);
  console.log(`Wrote ${path.relative(repoRoot, outputPath)}`);
};

async function main() {
  for (const task of DOC_TASKS) {
    await generateDocx(task);
  }
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
