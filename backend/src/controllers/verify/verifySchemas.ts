import { Request, Response } from "express";
import { z } from "zod";

import { verifyCaptchaToken } from "../../services/captchaService";
import { randomOpaqueToken } from "../../utils/security";

export type VerifyClassification =
  | "FIRST_SCAN"
  | "LEGIT_REPEAT"
  | "SUSPICIOUS_DUPLICATE"
  | "BLOCKED_BY_SECURITY"
  | "NOT_READY_FOR_CUSTOMER_USE"
  | "NOT_FOUND";

export type VerificationProofSource = "SIGNED_LABEL" | "MANUAL_CODE_LOOKUP";

export type VerificationPublicOutcome =
  | "SIGNED_LABEL_ACTIVE"
  | "MANUAL_RECORD_FOUND"
  | "LIMITED_PROVENANCE"
  | "REVIEW_REQUIRED"
  | "BLOCKED"
  | "NOT_READY"
  | "NOT_FOUND"
  | "INTEGRITY_ERROR"
  | "PRINTER_SETUP_ONLY";

export type VerificationRiskDisposition = "CLEAR" | "MONITOR" | "REVIEW_REQUIRED" | "BLOCKED";

export type VerificationMessageKey =
  | "signed_label_active"
  | "signed_label_repeat"
  | "manual_record_found"
  | "manual_record_repeat"
  | "manual_record_signed_history"
  | "limited_provenance"
  | "review_required"
  | "blocked"
  | "replacement_required"
  | "not_ready"
  | "not_found"
  | "integrity_error"
  | "printer_setup_only";

export type VerificationNextActionKey =
  | "none"
  | "review_details"
  | "rescan_label"
  | "contact_support"
  | "report_concern"
  | "scan_active_replacement"
  | "try_again_later";

export type ScanSummary = {
  totalScans: number;
  firstVerifiedAt: string | null;
  latestVerifiedAt: string | null;
  firstVerifiedLocation: string | null;
  latestVerifiedLocation: string | null;
};

const INCIDENT_TYPES = ["counterfeit_suspected", "duplicate_scan", "tampered_label", "wrong_product", "other"] as const;

export type ReportIncidentType = (typeof INCIDENT_TYPES)[number];

export const reportFraudSchema = z
  .object({
    code: z.string().trim().max(128).optional(),
    qrCodeValue: z.string().trim().max(128).optional(),
    reason: z.string().trim().min(3).max(120).optional(),
    description: z.string().trim().max(2000).optional(),
    notes: z.string().trim().max(2000).optional(),
    incidentType: z.enum(INCIDENT_TYPES).optional(),
    contactEmail: z.string().trim().email().max(160).optional(),
    customerEmail: z.string().trim().email().max(160).optional(),
    consentToContact: z.union([z.boolean(), z.string()]).optional(),
    preferredContactMethod: z.enum(["email", "phone", "whatsapp", "none"]).optional(),
    observedStatus: z.string().trim().max(64).optional(),
    observedOutcome: z.string().trim().max(64).optional(),
    pageUrl: z.string().trim().max(1000).optional(),
    sessionId: z.string().trim().max(128).optional(),
    decisionId: z.string().trim().max(128).optional(),
    tags: z.union([z.string(), z.array(z.string())]).optional(),
    captchaToken: z.string().trim().max(4000).optional(),
  })
  .strict()
  .refine((value) => Boolean(String(value.code || value.qrCodeValue || "").trim()), {
    message: "Code is required",
    path: ["code"],
  });

export const productFeedbackSchema = z.object({
  code: z.string().trim().min(2).max(128),
  rating: z.number().int().min(1).max(5),
  satisfaction: z.enum(["very_satisfied", "satisfied", "neutral", "disappointed", "very_disappointed"]),
  notes: z.string().trim().max(1000).optional(),
  observedStatus: z.string().trim().max(64).optional(),
  observedOutcome: z.string().trim().max(64).optional(),
  pageUrl: z.string().trim().max(1000).optional(),
}).strict();

export const requestOtpSchema = z.object({
  email: z.string().trim().email().max(160),
}).strict();

export const verifyOtpSchema = z.object({
  challengeToken: z.string().trim().min(16),
  otp: z.string().trim().min(4).max(12),
}).strict();

export const createOwnershipTransferSchema = z.object({
  recipientEmail: z.string().trim().email().max(160).optional(),
}).strict();

export const cancelOwnershipTransferSchema = z.object({
  transferId: z.string().trim().min(6).optional(),
}).strict();

export const acceptOwnershipTransferSchema = z.object({
  token: z.string().trim().min(16),
}).strict();

const DEVICE_CLAIM_COOKIE = "gs_device_claim";
const DEVICE_CLAIM_COOKIE_MAX_AGE_MS = 1000 * 60 * 60 * 24 * 365;

const parseBoolEnv = (value: unknown, fallback = false) => {
  const normalized = String(value || "").trim().toLowerCase();
  if (["1", "true", "yes", "on"].includes(normalized)) return true;
  if (["0", "false", "no", "off"].includes(normalized)) return false;
  return fallback;
};

const parseIntEnv = (key: string, fallback: number, min = 1, max = 24 * 365) => {
  const raw = Number(String(process.env[key] || "").trim());
  if (!Number.isFinite(raw)) return fallback;
  return Math.max(min, Math.min(max, Math.floor(raw)));
};

const VERIFY_STEP_UP_REQUIRED_ON_SUSPICIOUS = parseBoolEnv(
  process.env.VERIFY_STEP_UP_REQUIRED_ON_SUSPICIOUS,
  true
);

export const OWNERSHIP_TRANSFER_TTL_HOURS = parseIntEnv("OWNERSHIP_TRANSFER_TTL_HOURS", 72, 1, 24 * 30);

export const verifyStepUpChallenge = async (req: Request) => {
  if (!VERIFY_STEP_UP_REQUIRED_ON_SUSPICIOUS) return { ok: true };
  const headers = (req as any)?.headers || {};
  const captchaToken = String(headers["x-captcha-token"] || (req.body as any)?.captchaToken || "").trim();
  if (!captchaToken) {
    return {
      ok: false,
      reason: "Suspicious activity challenge required. Sign in with verified identity or complete captcha and retry.",
    };
  }
  return verifyCaptchaToken(captchaToken, req.ip);
};

const deviceClaimCookieOptions = () => ({
  httpOnly: true,
  sameSite: "lax" as const,
  secure: parseBoolEnv(process.env.COOKIE_SECURE, process.env.NODE_ENV === "production"),
  path: "/",
  maxAge: DEVICE_CLAIM_COOKIE_MAX_AGE_MS,
});

export const getDeviceClaimTokenFromRequest = (req: Request) => {
  const cookies = (req as any).cookies as Record<string, string> | undefined;
  const raw = String(cookies?.[DEVICE_CLAIM_COOKIE] || "").trim();
  return raw || null;
};

export const ensureDeviceClaimToken = (req: Request, res: Response) => {
  const existing = getDeviceClaimTokenFromRequest(req);
  if (existing) return existing;
  const next = randomOpaqueToken(24);
  res.cookie(DEVICE_CLAIM_COOKIE, next, deviceClaimCookieOptions());
  return next;
};

export const parseBoolean = (value: unknown, fallback = false) => {
  if (typeof value === "boolean") return value;
  const normalized = String(value || "").trim().toLowerCase();
  if (["1", "true", "yes", "on"].includes(normalized)) return true;
  if (["0", "false", "no", "off"].includes(normalized)) return false;
  return fallback;
};

export const parseTags = (value: unknown) => {
  if (Array.isArray(value)) {
    return value.map((v) => String(v || "").trim()).filter(Boolean);
  }
  const raw = String(value || "").trim();
  if (!raw) return [] as string[];

  try {
    const parsed = JSON.parse(raw);
    if (Array.isArray(parsed)) {
      return parsed.map((v) => String(v || "").trim()).filter(Boolean);
    }
  } catch {
    // Fall through to comma-separated parsing.
  }

  return raw
    .split(",")
    .map((v) => v.trim())
    .filter(Boolean);
};
