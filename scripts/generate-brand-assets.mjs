import { readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { chromium } from "@playwright/test";

const repoRoot = process.cwd();
const publicDir = path.join(repoRoot, "public");
const brandDir = path.join(publicDir, "brand");
const wordmarkSvg = path.join(brandDir, "mscqr-wordmark.svg");
const markSvg = path.join(brandDir, "mscqr-logo-mark.svg");
const asSvgDataUrl = (filePath) => `data:image/svg+xml;base64,${readFileSync(filePath).toString("base64")}`;
const wordmarkDataUrl = asSvgDataUrl(wordmarkSvg);
const markDataUrl = asSvgDataUrl(markSvg);

const pngOutputs = [
  { path: path.join(publicDir, "favicon-16x16.png"), size: 16 },
  { path: path.join(publicDir, "favicon-32x32.png"), size: 32 },
  { path: path.join(publicDir, "favicon-48x48.png"), size: 48 },
  { path: path.join(publicDir, "apple-touch-icon.png"), size: 180 },
  { path: path.join(publicDir, "android-chrome-192x192.png"), size: 192 },
  { path: path.join(publicDir, "android-chrome-512x512.png"), size: 512 },
  { path: path.join(brandDir, "mscqr-logo-mark-512.png"), size: 512 },
  { path: path.join(brandDir, "mscqr-mark-512.png"), size: 512 },
];

const writeIco = (entries, outputPath) => {
  const headerSize = 6 + entries.length * 16;
  let imageOffset = headerSize;
  const header = Buffer.alloc(headerSize);
  header.writeUInt16LE(0, 0);
  header.writeUInt16LE(1, 2);
  header.writeUInt16LE(entries.length, 4);

  entries.forEach((entry, index) => {
    const offset = 6 + index * 16;
    header.writeUInt8(entry.size >= 256 ? 0 : entry.size, offset);
    header.writeUInt8(entry.size >= 256 ? 0 : entry.size, offset + 1);
    header.writeUInt8(0, offset + 2);
    header.writeUInt8(0, offset + 3);
    header.writeUInt16LE(1, offset + 4);
    header.writeUInt16LE(32, offset + 6);
    header.writeUInt32LE(entry.buffer.length, offset + 8);
    header.writeUInt32LE(imageOffset, offset + 12);
    imageOffset += entry.buffer.length;
  });

  writeFileSync(outputPath, Buffer.concat([header, ...entries.map((entry) => entry.buffer)]));
};

const wrapString = (value, width = 96) => {
  const lines = [];
  for (let index = 0; index < value.length; index += width) {
    lines.push(value.slice(index, index + width));
  }
  return lines.map((line) => `    "${line}",`).join("\n");
};

const renderMarkPng = async (page, outputPath, size) => {
  await page.setViewportSize({ width: size, height: size });
  await page.setContent(`
    <!doctype html>
    <html>
      <body style="margin:0;background:transparent">
        <div id="icon" style="width:${size}px;height:${size}px;display:flex;align-items:center;justify-content:center;background:transparent">
          <img src="${markDataUrl}" alt="" style="width:${size}px;height:${size}px;object-fit:contain" />
        </div>
      </body>
    </html>
  `);
  const buffer = await page.locator("#icon").screenshot({ omitBackground: true });
  writeFileSync(outputPath, buffer);
  return buffer;
};

const renderOgImage = async (page) => {
  await page.setViewportSize({ width: 1200, height: 630 });
  await page.setContent(`
    <!doctype html>
    <html>
      <body style="margin:0;background:#f8fafc">
        <main id="og" style="box-sizing:border-box;width:1200px;height:630px;padding:72px 84px;background:linear-gradient(135deg,#ffffff 0%,#eef6ff 48%,#ecfdf5 100%);font-family:Inter,Arial,sans-serif;color:#111827">
          <div style="display:flex;align-items:center;gap:34px">
            <img src="${markDataUrl}" alt="" style="width:172px;height:172px;object-fit:contain" />
            <img src="${wordmarkDataUrl}" alt="MSCQR" style="width:520px;height:auto;object-fit:contain" />
          </div>
          <div style="margin-top:74px;max-width:860px;font-size:54px;line-height:1.08;font-weight:760;letter-spacing:0">
            Garment authentication QR infrastructure
          </div>
          <div style="margin-top:28px;max-width:850px;font-size:27px;line-height:1.42;color:#475569">
            Secure label issuance, controlled printing, and customer verification workflows.
          </div>
        </main>
      </body>
    </html>
  `);
  const buffer = await page.locator("#og").screenshot({ type: "png" });
  writeFileSync(path.join(brandDir, "mscqr-og.png"), buffer);
};

const generateZplWordmark = async (page) => {
  const widthDots = 267;
  const heightDots = 60;
  const graphic = await page.evaluate(
    async ({ src, widthDots, heightDots }) => {
      const img = new Image();
      img.src = src;
      await img.decode();
      const canvas = document.createElement("canvas");
      canvas.width = widthDots;
      canvas.height = heightDots;
      const ctx = canvas.getContext("2d");
      if (!ctx) throw new Error("Canvas 2D context unavailable");
      ctx.clearRect(0, 0, widthDots, heightDots);
      ctx.drawImage(img, 0, 0, widthDots, heightDots);
      const pixels = ctx.getImageData(0, 0, widthDots, heightDots).data;
      const bytesPerRow = Math.ceil(widthDots / 8);
      const bytes = [];
      for (let y = 0; y < heightDots; y += 1) {
        for (let byteIndex = 0; byteIndex < bytesPerRow; byteIndex += 1) {
          let currentByte = 0;
          for (let bit = 0; bit < 8; bit += 1) {
            const x = byteIndex * 8 + bit;
            if (x >= widthDots) continue;
            const offset = (y * widthDots + x) * 4;
            const alpha = pixels[offset + 3];
            const red = pixels[offset];
            const green = pixels[offset + 1];
            const blue = pixels[offset + 2];
            const luminance = red * 0.2126 + green * 0.7152 + blue * 0.0722;
            if (alpha > 64 && luminance < 220) {
              currentByte |= 1 << (7 - bit);
            }
          }
          bytes.push(currentByte);
        }
      }
      return {
        widthDots,
        heightDots,
        bytesPerRow,
        totalBytes: bytes.length,
        data: bytes.map((value) => value.toString(16).padStart(2, "0").toUpperCase()).join(""),
      };
    },
    { src: wordmarkDataUrl, widthDots, heightDots },
  );

  const output = `// Generated by scripts/generate-brand-assets.mjs from public/brand/mscqr-wordmark.svg.
// Do not edit by hand.

export const MSCQR_WORDMARK_ZPL_GRAPHIC = {
  widthDots: ${graphic.widthDots},
  heightDots: ${graphic.heightDots},
  bytesPerRow: ${graphic.bytesPerRow},
  totalBytes: ${graphic.totalBytes},
  data: [
${wrapString(graphic.data)}
  ].join(""),
} as const;
`;
  writeFileSync(path.join(repoRoot, "backend", "src", "printing", "generated", "brandWordmarkZpl.ts"), output);
};

const browser = await chromium.launch();
try {
  const page = await browser.newPage({ deviceScaleFactor: 1 });
  const iconBuffers = [];
  for (const output of pngOutputs) {
    const buffer = await renderMarkPng(page, output.path, output.size);
    if ([16, 32, 48].includes(output.size) && output.path.includes("favicon")) {
      iconBuffers.push({ size: output.size, buffer });
    }
  }
  writeIco(iconBuffers, path.join(publicDir, "favicon.ico"));
  await renderOgImage(page);
  await generateZplWordmark(page);
} finally {
  await browser.close();
}

console.log("Generated MSCQR brand PNG, ICO, OpenGraph, and ZPL wordmark assets.");
