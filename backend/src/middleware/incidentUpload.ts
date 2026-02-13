import fs from "fs";
import path from "path";
import multer from "multer";
import { randomUUID } from "crypto";

const uploadsRoot = path.resolve(__dirname, "../../uploads/incidents");

const ensureDir = () => {
  if (!fs.existsSync(uploadsRoot)) {
    fs.mkdirSync(uploadsRoot, { recursive: true });
  }
};

const allowedMimeTypes = new Set([
  "image/png",
  "image/jpeg",
  "image/jpg",
  "image/webp",
  "application/pdf",
]);

const storage = multer.diskStorage({
  destination: (_req, _file, cb) => {
    ensureDir();
    cb(null, uploadsRoot);
  },
  filename: (_req, file, cb) => {
    const ext = path.extname(file.originalname || "").toLowerCase();
    cb(null, `${Date.now()}-${randomUUID()}${ext || ""}`);
  },
});

const fileFilter: multer.Options["fileFilter"] = (_req, file, cb) => {
  if (!allowedMimeTypes.has(String(file.mimetype || "").toLowerCase())) {
    return cb(new Error("Unsupported file type"));
  }
  cb(null, true);
};

export const incidentReportUpload = multer({
  storage,
  limits: {
    fileSize: Number(process.env.INCIDENT_UPLOAD_MAX_BYTES || String(5 * 1024 * 1024)),
    files: Number(process.env.INCIDENT_UPLOAD_MAX_FILES || "4"),
  },
  fileFilter,
});

export const incidentEvidenceUpload = multer({
  storage,
  limits: {
    fileSize: Number(process.env.INCIDENT_EVIDENCE_MAX_BYTES || String(8 * 1024 * 1024)),
    files: 1,
  },
  fileFilter,
});

export const resolveUploadPath = (fileName: string) => path.resolve(uploadsRoot, fileName);
export const uploadsDirectory = uploadsRoot;
