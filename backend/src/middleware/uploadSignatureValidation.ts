import fs from "fs/promises";
import path from "path";
import type { NextFunction, Request, Response } from "express";

type UploadedFile = Express.Multer.File & { path?: string; originalname?: string; mimetype?: string };

const PNG_SIGNATURE = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
const JPEG_SIGNATURE = Buffer.from([0xff, 0xd8, 0xff]);
const PDF_SIGNATURE = Buffer.from("%PDF-");

const startsWith = (buffer: Buffer, signature: Buffer) =>
  buffer.length >= signature.length && buffer.subarray(0, signature.length).equals(signature);

const detectMimeFromSignature = (buffer: Buffer) => {
  if (startsWith(buffer, PNG_SIGNATURE)) return "image/png";
  if (startsWith(buffer, JPEG_SIGNATURE)) return "image/jpeg";
  if (buffer.length >= 12 && buffer.subarray(0, 4).toString("ascii") === "RIFF" && buffer.subarray(8, 12).toString("ascii") === "WEBP") {
    return "image/webp";
  }
  if (startsWith(buffer, PDF_SIGNATURE)) return "application/pdf";
  return null;
};

const allowedExtensionsByMime: Record<string, string[]> = {
  "image/png": [".png"],
  "image/jpeg": [".jpg", ".jpeg"],
  "image/webp": [".webp"],
  "application/pdf": [".pdf"],
};

const normalizeMime = (value: string) => {
  const normalized = String(value || "").trim().toLowerCase();
  if (normalized === "image/jpg") return "image/jpeg";
  return normalized;
};

const collectUploadedFiles = (req: Request): UploadedFile[] => {
  const single = (req as Request & { file?: UploadedFile }).file;
  if (single) return [single];

  const many = (req as Request & { files?: UploadedFile[] | Record<string, UploadedFile[]> }).files;
  if (!many) return [];
  if (Array.isArray(many)) return many;
  return Object.values(many).flat();
};

const removeUploadedFile = async (file: UploadedFile) => {
  const filePath = String(file.path || "").trim();
  if (!filePath) return;
  await fs.unlink(filePath).catch(() => undefined);
};

export const enforceUploadedFileSignatures =
  (allowedMimes?: string[]) => async (req: Request, res: Response, next: NextFunction) => {
    const files = collectUploadedFiles(req);
    if (files.length === 0) return next();

    for (const file of files) {
      const filePath = String(file.path || "").trim();
      if (!filePath) {
        return res.status(400).json({ success: false, error: "Uploaded file is missing storage metadata" });
      }

      let handle: fs.FileHandle | null = null;
      try {
        handle = await fs.open(filePath, "r");
        const buffer = Buffer.alloc(32);
        const { bytesRead } = await handle.read(buffer, 0, buffer.length, 0);
        const header = buffer.subarray(0, bytesRead);
        const detectedMime = detectMimeFromSignature(header);
        const declaredMime = normalizeMime(file.mimetype || "");
        const extension = path.extname(String(file.originalname || file.filename || "")).toLowerCase();

        const allowedMimeSet = new Set((allowedMimes || Object.keys(allowedExtensionsByMime)).map((value) => normalizeMime(value)));
        const allowedExtensions = allowedExtensionsByMime[detectedMime || ""] || [];

        if (!detectedMime || !allowedMimeSet.has(detectedMime) || detectedMime !== declaredMime || (allowedExtensions.length > 0 && !allowedExtensions.includes(extension))) {
          await removeUploadedFile(file);
          return res.status(400).json({
            success: false,
            error: "Uploaded file content does not match the allowed file type.",
          });
        }
      } catch {
        await removeUploadedFile(file);
        return res.status(400).json({
          success: false,
          error: "Uploaded file could not be verified safely.",
        });
      } finally {
        await handle?.close().catch(() => undefined);
      }
    }

    return next();
  };
