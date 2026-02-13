"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.uploadsDirectory = exports.resolveUploadPath = exports.incidentEvidenceUpload = exports.incidentReportUpload = void 0;
const fs_1 = __importDefault(require("fs"));
const path_1 = __importDefault(require("path"));
const multer_1 = __importDefault(require("multer"));
const crypto_1 = require("crypto");
const uploadsRoot = path_1.default.resolve(__dirname, "../../uploads/incidents");
const ensureDir = () => {
    if (!fs_1.default.existsSync(uploadsRoot)) {
        fs_1.default.mkdirSync(uploadsRoot, { recursive: true });
    }
};
const allowedMimeTypes = new Set([
    "image/png",
    "image/jpeg",
    "image/jpg",
    "image/webp",
    "application/pdf",
]);
const storage = multer_1.default.diskStorage({
    destination: (_req, _file, cb) => {
        ensureDir();
        cb(null, uploadsRoot);
    },
    filename: (_req, file, cb) => {
        const ext = path_1.default.extname(file.originalname || "").toLowerCase();
        cb(null, `${Date.now()}-${(0, crypto_1.randomUUID)()}${ext || ""}`);
    },
});
const fileFilter = (_req, file, cb) => {
    if (!allowedMimeTypes.has(String(file.mimetype || "").toLowerCase())) {
        return cb(new Error("Unsupported file type"));
    }
    cb(null, true);
};
exports.incidentReportUpload = (0, multer_1.default)({
    storage,
    limits: {
        fileSize: Number(process.env.INCIDENT_UPLOAD_MAX_BYTES || String(5 * 1024 * 1024)),
        files: Number(process.env.INCIDENT_UPLOAD_MAX_FILES || "4"),
    },
    fileFilter,
});
exports.incidentEvidenceUpload = (0, multer_1.default)({
    storage,
    limits: {
        fileSize: Number(process.env.INCIDENT_EVIDENCE_MAX_BYTES || String(8 * 1024 * 1024)),
        files: 1,
    },
    fileFilter,
});
const resolveUploadPath = (fileName) => path_1.default.resolve(uploadsRoot, fileName);
exports.resolveUploadPath = resolveUploadPath;
exports.uploadsDirectory = uploadsRoot;
//# sourceMappingURL=incidentUpload.js.map