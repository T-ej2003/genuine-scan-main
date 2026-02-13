import { Response } from "express";
import archiver from "archiver";
import QRCode from "qrcode";
import os from "os";
import { PassThrough } from "stream";

type CsvValue = string | number | boolean | null | undefined;

export type QrZipTier = "standard" | "high" | "ultra";

export type QrZipProfile = {
  tier: QrZipTier;
  zipCompressionLevel: number;
  pngWidth: number;
  pngConcurrency: number;
  dbChunkSize: number;
};

export type QrZipEntry = {
  code: string;
  url: string;
  manifestValues: CsvValue[];
};

type StreamQrZipOptions = {
  res: Response;
  fileName: string;
  totalCount: number;
  manifestHeader: string[];
  entries: AsyncIterable<QrZipEntry>;
  profile?: QrZipProfile;
};

const clamp = (value: number, min: number, max: number) => Math.min(max, Math.max(min, value));

const envInt = (key: string, fallback: number) => {
  const raw = Number(process.env[key]);
  if (!Number.isFinite(raw)) return fallback;
  const normalized = Math.floor(raw);
  return normalized > 0 ? normalized : fallback;
};

const CPU_COUNT = Math.max(1, os.cpus().length);
const HIGH_THRESHOLD = envInt("QR_ZIP_HIGH_VOLUME_THRESHOLD", 100_000);
const ULTRA_THRESHOLD = envInt("QR_ZIP_ULTRA_VOLUME_THRESHOLD", 1_000_000);

const escapeCsv = (value: CsvValue): string => {
  if (value === null || value === undefined) return "";
  const s = String(value);
  return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
};

const safeCodeFilePart = (code: string) =>
  String(code || "")
    .trim()
    .replace(/[^\w.-]+/g, "_")
    .replace(/^_+|_+$/g, "")
    .slice(0, 180) || "qr";

const renderPng = (url: string, width: number) =>
  QRCode.toBuffer(url, {
    width,
    margin: 2,
    errorCorrectionLevel: "M",
    rendererOpts: {
      deflateLevel: 9,
      deflateStrategy: 3,
    },
  });

export const resolveQrZipProfile = (totalCount: number): QrZipProfile => {
  if (totalCount >= ULTRA_THRESHOLD) {
    return {
      tier: "ultra",
      zipCompressionLevel: clamp(envInt("QR_ZIP_ULTRA_LEVEL", 9), 1, 9),
      pngWidth: envInt("QR_ZIP_ULTRA_PNG_WIDTH", 512),
      pngConcurrency: clamp(envInt("QR_ZIP_ULTRA_PNG_CONCURRENCY", CPU_COUNT * 2), 2, 24),
      dbChunkSize: envInt("QR_ZIP_ULTRA_DB_CHUNK_SIZE", 10_000),
    };
  }

  if (totalCount >= HIGH_THRESHOLD) {
    return {
      tier: "high",
      zipCompressionLevel: clamp(envInt("QR_ZIP_HIGH_LEVEL", 8), 1, 9),
      pngWidth: envInt("QR_ZIP_HIGH_PNG_WIDTH", 640),
      pngConcurrency: clamp(envInt("QR_ZIP_HIGH_PNG_CONCURRENCY", Math.max(4, CPU_COUNT)), 2, 20),
      dbChunkSize: envInt("QR_ZIP_HIGH_DB_CHUNK_SIZE", 5_000),
    };
  }

  return {
    tier: "standard",
    zipCompressionLevel: clamp(envInt("QR_ZIP_STANDARD_LEVEL", 6), 1, 9),
    pngWidth: envInt("QR_ZIP_STANDARD_PNG_WIDTH", 768),
    pngConcurrency: clamp(envInt("QR_ZIP_STANDARD_PNG_CONCURRENCY", Math.min(8, Math.max(2, CPU_COUNT))), 2, 16),
    dbChunkSize: envInt("QR_ZIP_STANDARD_DB_CHUNK_SIZE", 2_000),
  };
};

export const streamQrZipToResponse = async ({
  res,
  fileName,
  totalCount,
  manifestHeader,
  entries,
  profile: explicitProfile,
}: StreamQrZipOptions) => {
  const profile = explicitProfile || resolveQrZipProfile(totalCount);

  res.setHeader("Content-Type", "application/zip");
  res.setHeader("Content-Disposition", `attachment; filename="${fileName}"`);
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("X-QR-ZIP-TIER", profile.tier);
  res.setHeader("X-QR-ZIP-PNG-WIDTH", String(profile.pngWidth));

  const archive = archiver("zip", {
    zlib: { level: profile.zipCompressionLevel },
  });

  const manifestStream = new PassThrough();
  archive.pipe(res);
  archive.append(manifestStream, { name: "manifest.csv" });
  manifestStream.write(`${manifestHeader.map(escapeCsv).join(",")}\n`);

  const waitForCompletion = new Promise<void>((resolve, reject) => {
    let settled = false;
    const complete = (err?: Error) => {
      if (settled) return;
      settled = true;
      archive.off("error", onError);
      archive.off("warning", onWarning);
      res.off("finish", onFinish);
      res.off("close", onClose);
      if (err) reject(err);
      else resolve();
    };

    const onError = (err: Error) => complete(err);
    const onWarning = (err: any) => {
      if (err?.code !== "ENOENT") complete(err instanceof Error ? err : new Error(String(err || "Archive warning")));
    };
    const onFinish = () => complete();
    const onClose = () => {
      if (!res.writableFinished) complete(new Error("Client disconnected during ZIP download"));
    };

    archive.on("error", onError);
    archive.on("warning", onWarning);
    res.on("finish", onFinish);
    res.on("close", onClose);
  });

  const flushBatch = async (batch: QrZipEntry[]) => {
    if (batch.length === 0) return;
    const rendered = await Promise.all(
      batch.map(async (entry) => {
        const png = await renderPng(entry.url, profile.pngWidth);
        return { entry, png };
      })
    );

    for (const item of rendered) {
      archive.append(item.png, { name: `png/${safeCodeFilePart(item.entry.code)}.png` });
      manifestStream.write(`${item.entry.manifestValues.map(escapeCsv).join(",")}\n`);
    }
  };

  try {
    const pending: QrZipEntry[] = [];
    for await (const entry of entries) {
      pending.push(entry);
      if (pending.length >= profile.pngConcurrency) {
        await flushBatch(pending.splice(0, pending.length));
      }
    }
    await flushBatch(pending);
    manifestStream.end();
    void archive.finalize();
    await waitForCompletion;
  } catch (error) {
    manifestStream.destroy(error as Error);
    archive.abort();
    throw error;
  }

  return profile;
};
