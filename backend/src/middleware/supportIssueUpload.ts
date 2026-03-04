import fs from "fs";
import path from "path";
import multer from "multer";
import { randomUUID } from "crypto";

const uploadsRoot = path.resolve(__dirname, "../../uploads/support-issues");

const ensureDir = () => {
  if (!fs.existsSync(uploadsRoot)) {
    fs.mkdirSync(uploadsRoot, { recursive: true });
  }
};

const storage = multer.diskStorage({
  destination: (_req, _file, cb) => {
    ensureDir();
    cb(null, uploadsRoot);
  },
  filename: (_req, file, cb) => {
    const ext = path.extname(file.originalname || "").toLowerCase();
    cb(null, `${Date.now()}-${randomUUID()}${ext || ".png"}`);
  },
});

const allowedMimeTypes = new Set(["image/png", "image/jpeg", "image/jpg", "image/webp"]);

const fileFilter: multer.Options["fileFilter"] = (_req, file, cb) => {
  const mime = String(file.mimetype || "").toLowerCase();
  if (!allowedMimeTypes.has(mime)) return cb(new Error("Unsupported screenshot format"));
  cb(null, true);
};

export const supportIssueUpload = multer({
  storage,
  limits: {
    fileSize: Number(process.env.SUPPORT_REPORT_SCREENSHOT_MAX_BYTES || String(6 * 1024 * 1024)),
    files: 1,
  },
  fileFilter,
});

export const resolveSupportIssueUploadPath = (fileName: string) => path.resolve(uploadsRoot, fileName);
