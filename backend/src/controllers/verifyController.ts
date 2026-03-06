import { Request, Response } from "express";
import { IncidentActorType, OwnershipTransferStatus, Prisma, QRStatus } from "@prisma/client";
import { z } from "zod";

import prisma from "../config/database";
import { CustomerVerifyRequest } from "../middleware/customerVerifyAuth";
import { createAuditLog } from "../services/auditService";
import {
  createCustomerOtpChallenge,
  issueCustomerVerifyToken,
  maskEmail,
  verifyCustomerOtpChallenge,
} from "../services/customerVerifyAuthService";
import { sendAuthEmail } from "../services/auth/authEmailService";
import { getSuperadminAlertEmails, sendIncidentEmail } from "../services/incidentEmailService";
import { createIncidentFromReport } from "../services/incidentService";
import { evaluateScanAndEnforcePolicy } from "../services/policyEngineService";
import { buildVerifyUrl, recordScan } from "../services/qrService";
import { getScanInsight } from "../services/scanInsightService";
import { resolveDuplicateRiskProfile, resolveVerifyUxPolicy } from "../services/governanceService";
import { runTamperEvidenceChecks, summarizeTamperFindings } from "../services/tamperEvidenceService";
import { ticketSlaSnapshot } from "../services/supportWorkflowService";
import { assessDuplicateRisk, deriveAnomalyModelScore } from "../services/duplicateRiskService";
import { verifyCaptchaToken } from "../services/captchaService";
import { enforceIncidentRateLimit } from "../services/incidentRateLimitService";
import { hashIp, hashToken, normalizeUserAgent, randomOpaqueToken } from "../utils/security";
import { deriveRequestDeviceFingerprint } from "../utils/requestFingerprint";

type VerifyClassification =
  | "FIRST_SCAN"
  | "LEGIT_REPEAT"
  | "SUSPICIOUS_DUPLICATE"
  | "BLOCKED_BY_SECURITY"
  | "NOT_READY_FOR_CUSTOMER_USE";

type OwnershipStatus = {
  isClaimed: boolean;
  claimedAt: string | null;
  isOwnedByRequester: boolean;
  isClaimedByAnother: boolean;
  canClaim: boolean;
  state?: "unclaimed" | "owned_by_you" | "owned_by_someone_else" | "claim_not_available";
  matchMethod?: "user" | "device_token" | "ip_fallback" | null;
};

type OwnershipRecord = {
  id: string;
  userId: string | null;
  claimedAt: Date;
  deviceTokenHash: string | null;
  ipHash: string | null;
  userAgentHash: string | null;
  claimSource: string | null;
  linkedAt: Date | null;
};

type OwnershipTransferRecord = {
  id: string;
  qrCodeId: string;
  ownershipId: string;
  initiatedByCustomerId: string;
  initiatedByEmail: string | null;
  recipientEmail: string | null;
  status: OwnershipTransferStatus;
  expiresAt: Date;
  acceptedAt: Date | null;
  cancelledAt: Date | null;
  lastViewedAt: Date | null;
  createdAt: Date;
  updatedAt: Date;
};

type OwnershipTransferState =
  | "none"
  | "pending_owner_action"
  | "pending_buyer_action"
  | "ready_to_accept"
  | "accepted"
  | "cancelled"
  | "expired"
  | "invalid";

type OwnershipTransferStatusView = {
  state: OwnershipTransferState;
  active: boolean;
  canCreate: boolean;
  canCancel: boolean;
  canAccept: boolean;
  initiatedByYou: boolean;
  recipientEmailMasked: string | null;
  initiatedAt: string | null;
  expiresAt: string | null;
  acceptedAt: string | null;
  invalidReason?: string | null;
  transferId?: string | null;
  acceptUrl?: string | null;
};

type ScanSummary = {
  totalScans: number;
  firstVerifiedAt: string | null;
  latestVerifiedAt: string | null;
  firstVerifiedLocation: string | null;
  latestVerifiedLocation: string | null;
};

const INCIDENT_TYPES = ["counterfeit_suspected", "duplicate_scan", "tampered_label", "wrong_product", "other"] as const;

type ReportIncidentType = (typeof INCIDENT_TYPES)[number];

const reportFraudSchema = z
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
    tags: z.union([z.string(), z.array(z.string())]).optional(),
  })
  .refine((v) => Boolean(String(v.code || v.qrCodeValue || "").trim()), {
    message: "Code is required",
    path: ["code"],
  });

const productFeedbackSchema = z.object({
  code: z.string().trim().min(2).max(128),
  rating: z.number().int().min(1).max(5),
  satisfaction: z.enum(["very_satisfied", "satisfied", "neutral", "disappointed", "very_disappointed"]),
  notes: z.string().trim().max(1000).optional(),
  observedStatus: z.string().trim().max(64).optional(),
  observedOutcome: z.string().trim().max(64).optional(),
  pageUrl: z.string().trim().max(1000).optional(),
});

const requestOtpSchema = z.object({
  email: z.string().trim().email().max(160),
});

const verifyOtpSchema = z.object({
  challengeToken: z.string().trim().min(16),
  otp: z.string().trim().min(4).max(12),
});

const createOwnershipTransferSchema = z.object({
  recipientEmail: z.string().trim().email().max(160).optional(),
});

const cancelOwnershipTransferSchema = z.object({
  transferId: z.string().trim().min(6).optional(),
});

const acceptOwnershipTransferSchema = z.object({
  token: z.string().trim().min(16),
});

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
const OWNERSHIP_TRANSFER_TTL_HOURS = parseIntEnv("OWNERSHIP_TRANSFER_TTL_HOURS", 72, 1, 24 * 30);

const verifyStepUpChallenge = async (req: Request) => {
  if (!VERIFY_STEP_UP_REQUIRED_ON_SUSPICIOUS) return { ok: true };
  const captchaToken = String(req.headers["x-captcha-token"] || (req.body as any)?.captchaToken || "").trim();
  if (!captchaToken) {
    return {
      ok: false,
      reason: "Suspicious activity challenge required. Complete captcha and retry.",
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

const getDeviceClaimTokenFromRequest = (req: Request) => {
  const cookies = (req as any).cookies as Record<string, string> | undefined;
  const raw = String(cookies?.[DEVICE_CLAIM_COOKIE] || "").trim();
  return raw || null;
};

const ensureDeviceClaimToken = (req: Request, res: Response) => {
  const existing = getDeviceClaimTokenFromRequest(req);
  if (existing) return existing;
  const next = randomOpaqueToken(24);
  res.cookie(DEVICE_CLAIM_COOKIE, next, deviceClaimCookieOptions());
  return next;
};

const mapLicensee = (licensee: any) =>
  licensee
    ? {
        id: licensee.id,
        name: licensee.name,
        prefix: licensee.prefix,
        brandName: licensee.brandName,
        location: licensee.location,
        website: licensee.website,
        supportEmail: licensee.supportEmail,
        supportPhone: licensee.supportPhone,
      }
    : null;

const mapBatch = (batch: any) =>
  batch
    ? {
        id: batch.id,
        name: batch.name,
        printedAt: batch.printedAt,
        manufacturer: batch.manufacturer || null,
      }
    : null;

const normalizeCode = (value: string) => String(value || "").trim().toUpperCase();

const delay = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

const parseBoolean = (value: unknown, fallback = false) => {
  if (typeof value === "boolean") return value;
  const normalized = String(value || "").trim().toLowerCase();
  if (["1", "true", "yes", "on"].includes(normalized)) return true;
  if (["0", "false", "no", "off"].includes(normalized)) return false;
  return fallback;
};

const parseTags = (value: unknown) => {
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
    // fall through
  }

  return raw
    .split(",")
    .map((v) => v.trim())
    .filter(Boolean);
};

const toIso = (value: Date | string | null | undefined) => {
  if (!value) return null;
  const dt = value instanceof Date ? value : new Date(value);
  return Number.isFinite(dt.getTime()) ? dt.toISOString() : null;
};

const isQrReadyForCustomerUse = (status: QRStatus) => {
  return status === QRStatus.PRINTED || status === QRStatus.REDEEMED || status === QRStatus.SCANNED;
};

const statusNotReadyReason = (status: QRStatus) => {
  if (status === QRStatus.DORMANT || status === QRStatus.ACTIVE) {
    return "Code exists but has not been assigned to a finished product.";
  }
  if (status === QRStatus.ALLOCATED) {
    return "Code is allocated but the print lifecycle is not complete.";
  }
  if (status === QRStatus.ACTIVATED) {
    return "Code is awaiting print confirmation before customer use.";
  }
  return "Code is not ready for customer verification.";
};

const buildContainment = (qrCode: any) => ({
  qrUnderInvestigation: qrCode.underInvestigationAt
    ? {
        at: toIso(qrCode.underInvestigationAt),
        reason: qrCode.underInvestigationReason || null,
      }
    : null,
  batchSuspended: qrCode.batch?.suspendedAt
    ? {
        at: toIso(qrCode.batch.suspendedAt),
        reason: qrCode.batch.suspendedReason || null,
      }
    : null,
  orgSuspended: qrCode.licensee?.suspendedAt
    ? {
        at: toIso(qrCode.licensee.suspendedAt),
        reason: qrCode.licensee.suspendedReason || null,
      }
    : null,
});

const buildScanSummary = (params: {
  scanCount: number;
  scannedAt?: Date | null;
  scanInsight?: {
    firstScanAt?: string | null;
    firstScanLocation?: string | null;
    latestScanAt?: string | null;
    latestScanLocation?: string | null;
  } | null;
}): ScanSummary => {
  const firstVerifiedAt =
    params.scanInsight?.firstScanAt ||
    (params.scannedAt && Number.isFinite(params.scannedAt.getTime()) ? params.scannedAt.toISOString() : null);
  const latestVerifiedAt =
    params.scanInsight?.latestScanAt ||
    params.scanInsight?.firstScanAt ||
    (params.scannedAt && Number.isFinite(params.scannedAt.getTime()) ? params.scannedAt.toISOString() : null);

  return {
    totalScans: Number(params.scanCount || 0),
    firstVerifiedAt,
    latestVerifiedAt,
    firstVerifiedLocation: params.scanInsight?.firstScanLocation || null,
    latestVerifiedLocation: params.scanInsight?.latestScanLocation || null,
  };
};

const buildVerificationTimeline = (params: {
  scanSummary: ScanSummary;
  classification: VerifyClassification;
  reasons: string[];
}) => {
  const firstSeen = params.scanSummary.firstVerifiedAt || null;
  const latestSeen = params.scanSummary.latestVerifiedAt || null;
  const anomalyReason =
    params.classification === "SUSPICIOUS_DUPLICATE" || params.classification === "BLOCKED_BY_SECURITY"
      ? params.reasons[0] || "Anomaly indicators detected."
      : null;

  return {
    firstSeen,
    latestSeen,
    anomalyReason,
    visualSignal:
      params.classification === "FIRST_SCAN" || params.classification === "LEGIT_REPEAT"
        ? "stable"
        : params.classification === "SUSPICIOUS_DUPLICATE"
          ? "warning"
          : "critical",
  };
};

const buildRiskExplanation = (params: {
  classification: VerifyClassification;
  reasons: string[];
  scanSummary: ScanSummary;
  ownershipStatus: OwnershipStatus;
}) => {
  if (params.classification === "SUSPICIOUS_DUPLICATE") {
    return {
      level: "elevated",
      title: "Duplicate risk signals detected",
      details: params.reasons,
      recommendedAction: "Review seller source and report suspected counterfeit if this is unexpected.",
    };
  }

  if (params.classification === "BLOCKED_BY_SECURITY") {
    return {
      level: "high",
      title: "Blocked by security controls",
      details: params.reasons,
      recommendedAction: "Do not use this product until support confirms resolution.",
    };
  }

  if (params.ownershipStatus.isClaimedByAnother) {
    return {
      level: "medium",
      title: "Ownership conflict detected",
      details: ["This code is already claimed by another account."],
      recommendedAction: "Treat as potential duplicate and submit a report for investigation.",
    };
  }

  return {
    level: "low",
    title: "No high-risk anomaly detected",
    details: params.reasons,
    recommendedAction: params.scanSummary.totalScans > 1 ? "Keep purchase proof and monitor future scans." : "No action required.",
  };
};

const buildOwnershipStatus = (params: {
  ownership: OwnershipRecord | null;
  customerUserId?: string | null;
  deviceTokenHash?: string | null;
  ipHash?: string | null;
  isReady: boolean;
  isBlocked: boolean;
  allowClaim?: boolean;
}): OwnershipStatus => {
  const ownership = params.ownership;
  const customerUserId = String(params.customerUserId || "").trim();
  const deviceTokenHash = String(params.deviceTokenHash || "").trim();
  const allowClaim = params.allowClaim !== false;

  const claimUnavailable = !params.isReady || params.isBlocked || !allowClaim;

  if (!ownership) {
    return {
      isClaimed: false,
      claimedAt: null,
      isOwnedByRequester: false,
      isClaimedByAnother: false,
      canClaim: !claimUnavailable,
      state: claimUnavailable ? "claim_not_available" : "unclaimed",
      matchMethod: null,
    };
  }

  let isOwnedByRequester = false;
  let matchMethod: OwnershipStatus["matchMethod"] = null;

  if (customerUserId && ownership.userId === customerUserId) {
    isOwnedByRequester = true;
    matchMethod = "user";
  } else if (deviceTokenHash && ownership.deviceTokenHash && ownership.deviceTokenHash === deviceTokenHash) {
    isOwnedByRequester = true;
    matchMethod = "device_token";
  }

  return {
    isClaimed: true,
    claimedAt: ownership.claimedAt.toISOString(),
    isOwnedByRequester,
    // Avoid false conflicts for anonymous users: only hard-conflict when identity evidence exists.
    isClaimedByAnother: !isOwnedByRequester && (Boolean(customerUserId) || Boolean(deviceTokenHash)),
    canClaim: false,
    state: isOwnedByRequester ? "owned_by_you" : "owned_by_someone_else",
    matchMethod,
  };
};

let ownershipStorageWarningLogged = false;

const isOwnershipStorageMissingError = (error: unknown) => {
  if (!(error instanceof Prisma.PrismaClientKnownRequestError)) return false;
  if (error.code !== "P2021" && error.code !== "P2022") return false;

  const meta = (error.meta || {}) as Record<string, unknown>;
  const metaInfo = `${String(meta.table || "")} ${String(meta.modelName || "")} ${String(meta.column || "")}`.toLowerCase();
  if (metaInfo.includes("ownership")) return true;

  return String(error.message || "").toLowerCase().includes("ownership");
};

const loadOwnershipByQrCodeId = async (qrCodeId: string): Promise<OwnershipRecord | null> => {
  try {
    return await prisma.ownership.findUnique({
      where: { qrCodeId },
      select: {
        id: true,
        userId: true,
        claimedAt: true,
        deviceTokenHash: true,
        ipHash: true,
        userAgentHash: true,
        claimSource: true,
        linkedAt: true,
      },
    });
  } catch (error) {
    if (isOwnershipStorageMissingError(error)) {
      if (!ownershipStorageWarningLogged) {
        ownershipStorageWarningLogged = true;
        console.warn(
          "[verify] Ownership table is unavailable. Continuing verification without ownership data. Apply ownership migrations."
        );
      }
      return null;
    }
    throw error;
  }
};

const expirePendingOwnershipTransfers = async (where?: Prisma.OwnershipTransferWhereInput) => {
  await prisma.ownershipTransfer.updateMany({
    where: {
      status: OwnershipTransferStatus.PENDING,
      expiresAt: { lt: new Date() },
      ...(where || {}),
    },
    data: {
      status: OwnershipTransferStatus.EXPIRED,
    },
  });
};

const loadPendingOwnershipTransferForQr = async (qrCodeId: string): Promise<OwnershipTransferRecord | null> => {
  try {
    await expirePendingOwnershipTransfers({ qrCodeId });
    return await prisma.ownershipTransfer.findFirst({
      where: {
        qrCodeId,
        status: OwnershipTransferStatus.PENDING,
      },
      orderBy: [{ createdAt: "desc" }, { id: "desc" }],
      select: {
        id: true,
        qrCodeId: true,
        ownershipId: true,
        initiatedByCustomerId: true,
        initiatedByEmail: true,
        recipientEmail: true,
        status: true,
        expiresAt: true,
        acceptedAt: true,
        cancelledAt: true,
        lastViewedAt: true,
        createdAt: true,
        updatedAt: true,
      },
    });
  } catch (error) {
    if (error instanceof Prisma.PrismaClientKnownRequestError && (error.code === "P2021" || error.code === "P2022")) {
      return null;
    }
    throw error;
  }
};

const loadOwnershipTransferByRawToken = async (rawToken: string): Promise<OwnershipTransferRecord | null> => {
  const token = String(rawToken || "").trim();
  if (!token) return null;

  try {
    const tokenHash = hashToken(token);
    await expirePendingOwnershipTransfers({ tokenHash });
    const transfer = await prisma.ownershipTransfer.findUnique({
      where: { tokenHash },
      select: {
        id: true,
        qrCodeId: true,
        ownershipId: true,
        initiatedByCustomerId: true,
        initiatedByEmail: true,
        recipientEmail: true,
        status: true,
        expiresAt: true,
        acceptedAt: true,
        cancelledAt: true,
        lastViewedAt: true,
        createdAt: true,
        updatedAt: true,
      },
    });
    if (transfer && transfer.status === OwnershipTransferStatus.PENDING) {
      await prisma.ownershipTransfer.update({
        where: { id: transfer.id },
        data: { lastViewedAt: new Date() },
      });
    }
    return transfer;
  } catch (error) {
    if (error instanceof Prisma.PrismaClientKnownRequestError && (error.code === "P2021" || error.code === "P2022")) {
      return null;
    }
    throw error;
  }
};

const buildOwnershipTransferLink = (code: string, rawToken: string) => {
  const url = new URL(buildVerifyUrl(code));
  url.searchParams.set("transfer", rawToken);
  return url.toString();
};

const createOwnershipTransferView = (params: {
  code: string;
  transfer: OwnershipTransferRecord | null;
  rawToken?: string | null;
  customerUserId?: string | null;
  ownershipStatus: OwnershipStatus;
  isReady: boolean;
  isBlocked: boolean;
  transferRequested?: boolean;
}): OwnershipTransferStatusView => {
  const transfer = params.transfer;
  const initiatedByYou = Boolean(
    transfer &&
      params.customerUserId &&
      transfer.initiatedByCustomerId &&
      transfer.initiatedByCustomerId === params.customerUserId
  );
  const tokenMatched = Boolean(transfer && params.rawToken);

  if (!transfer) {
    return {
      state: params.transferRequested ? "invalid" : "none",
      active: false,
      canCreate: Boolean(
        params.isReady &&
          !params.isBlocked &&
          params.ownershipStatus.isOwnedByRequester &&
          params.customerUserId
      ),
      canCancel: false,
      canAccept: false,
      initiatedByYou: false,
      recipientEmailMasked: null,
      initiatedAt: null,
      expiresAt: null,
      acceptedAt: null,
      invalidReason: params.transferRequested ? "Transfer link is invalid or has expired." : null,
      transferId: null,
      acceptUrl: null,
    };
  }

  const canAccept =
    tokenMatched &&
    transfer.status === OwnershipTransferStatus.PENDING &&
    Boolean(params.customerUserId) &&
    transfer.initiatedByCustomerId !== params.customerUserId &&
    !params.ownershipStatus.isOwnedByRequester &&
    params.isReady &&
    !params.isBlocked;

  let state: OwnershipTransferState = "pending_buyer_action";
  if (transfer.status === OwnershipTransferStatus.ACCEPTED) state = "accepted";
  else if (transfer.status === OwnershipTransferStatus.CANCELLED) state = "cancelled";
  else if (transfer.status === OwnershipTransferStatus.EXPIRED) state = "expired";
  else if (canAccept) state = "ready_to_accept";
  else if (initiatedByYou) state = "pending_owner_action";
  else if (tokenMatched) state = "pending_buyer_action";

  return {
    state,
    active: transfer.status === OwnershipTransferStatus.PENDING,
    canCreate: false,
    canCancel: initiatedByYou && transfer.status === OwnershipTransferStatus.PENDING,
    canAccept,
    initiatedByYou,
    recipientEmailMasked: transfer.recipientEmail ? maskEmail(transfer.recipientEmail) : null,
    initiatedAt: transfer.createdAt.toISOString(),
    expiresAt: transfer.expiresAt.toISOString(),
    acceptedAt: transfer.acceptedAt?.toISOString() || null,
    invalidReason: null,
    transferId: transfer.id,
    acceptUrl: tokenMatched && params.rawToken ? buildOwnershipTransferLink(params.code, params.rawToken) : null,
  };
};

const buildSecurityContainmentReasons = (containment: ReturnType<typeof buildContainment>) => {
  const reasons: string[] = [];
  if (containment.qrUnderInvestigation?.reason) reasons.push(`QR containment: ${containment.qrUnderInvestigation.reason}`);
  if (containment.batchSuspended?.reason) reasons.push(`Batch containment: ${containment.batchSuspended.reason}`);
  if (containment.orgSuspended?.reason) reasons.push(`Organization containment: ${containment.orgSuspended.reason}`);
  return reasons;
};

const inferIncidentType = (input: { reason?: string; incidentType?: ReportIncidentType }): ReportIncidentType => {
  if (input.incidentType) return input.incidentType;
  const reason = String(input.reason || "").toLowerCase();
  if (reason.includes("mismatch")) return "wrong_product";
  if (reason.includes("used") || reason.includes("duplicate")) return "duplicate_scan";
  if (reason.includes("seller") || reason.includes("fake") || reason.includes("counterfeit")) return "counterfeit_suspected";
  return "other";
};

const incidentSummaryText = (incident: any) =>
  [
    `Incident ID: ${incident.id}`,
    `QR Code: ${incident.qrCodeValue}`,
    `Severity: ${incident.severity}`,
    `Status: ${incident.status}`,
    `Description: ${incident.description}`,
  ]
    .filter(Boolean)
    .join("\n");

const buildFraudVerificationSnapshot = async (normalizedCode: string) => {
  const qrCode = await prisma.qRCode.findUnique({
    where: { code: normalizedCode },
  });

  if (!qrCode) {
    const emptySummary: ScanSummary = {
      totalScans: 0,
      firstVerifiedAt: null,
      latestVerifiedAt: null,
      firstVerifiedLocation: null,
      latestVerifiedLocation: null,
    };

    const emptyOwnership: OwnershipStatus = {
      isClaimed: false,
      claimedAt: null,
      isOwnedByRequester: false,
      isClaimedByAnother: false,
      canClaim: false,
    };

    return {
      classification: "NOT_READY_FOR_CUSTOMER_USE" as VerifyClassification,
      reasons: ["Code not found in registry."],
      scanSummary: emptySummary,
      ownershipStatus: emptyOwnership,
    };
  }

  const scanInsight = await getScanInsight(qrCode.id, null, {
    licenseeId: qrCode.licenseeId || null,
  });
  const scanSummary = buildScanSummary({
    scanCount: Number(qrCode.scanCount || 0),
    scannedAt: qrCode.scannedAt,
    scanInsight,
  });

  const isBlocked = qrCode.status === QRStatus.BLOCKED;
  const isReady = isQrReadyForCustomerUse(qrCode.status);
  const ownership = await loadOwnershipByQrCodeId(qrCode.id);

  const ownershipStatus = buildOwnershipStatus({
    ownership,
    isReady,
    isBlocked,
  });

  if (isBlocked) {
    return {
      classification: "BLOCKED_BY_SECURITY" as VerifyClassification,
      reasons: ["Code is blocked by security policy or containment controls."],
      scanSummary,
      ownershipStatus,
    };
  }

  if (!isReady) {
    return {
      classification: "NOT_READY_FOR_CUSTOMER_USE" as VerifyClassification,
      reasons: [statusNotReadyReason(qrCode.status)],
      scanSummary,
      ownershipStatus,
    };
  }

  if (scanSummary.totalScans <= 1) {
    return {
      classification: "FIRST_SCAN" as VerifyClassification,
      reasons: ["First successful verification recorded."],
      scanSummary,
      ownershipStatus,
    };
  }

  const riskProfile = await resolveDuplicateRiskProfile(qrCode.licenseeId || null);
  const anomalyModelScore = deriveAnomalyModelScore({ scanSignals: scanInsight.signals });

  const duplicateRisk = assessDuplicateRisk({
    scanCount: scanSummary.totalScans,
    scanSignals: scanInsight.signals,
    ownershipStatus,
    latestScanAt: scanInsight.latestScanAt,
    previousScanAt: scanInsight.previousScanAt,
    anomalyModelScore: Math.round(anomalyModelScore * riskProfile.anomalyWeight),
    tenantRiskLevel: riskProfile.tenantRiskLevel,
    productRiskLevel: riskProfile.productRiskLevel,
  });

  return {
    classification: duplicateRisk.classification as VerifyClassification,
    reasons: duplicateRisk.reasons,
    scanSummary,
    ownershipStatus,
  };
};

const mapUploadedEvidence = (files: Express.Multer.File[]) => {
  return files.map((file) => {
    const fileName = String(file.filename || "").trim();
    return {
      fileUrl: fileName ? `/api/incidents/evidence-files/${encodeURIComponent(fileName)}` : null,
      storageKey: fileName || null,
      fileType: String(file.mimetype || "application/octet-stream"),
    };
  });
};

export const requestCustomerEmailOtp = async (req: Request, res: Response) => {
  try {
    const parsed = requestOtpSchema.safeParse(req.body || {});
    if (!parsed.success) {
      return res.status(400).json({
        success: false,
        error: parsed.error.errors[0]?.message || "Invalid email address",
      });
    }

    const challenge = createCustomerOtpChallenge(parsed.data.email);

    const subject = "Your AuthenticQR sign-in code";
    const text =
      `Use this one-time code to continue product protection sign-in: ${challenge.otp}\n\n` +
      `This code expires in 10 minutes. If you did not request this code, you can ignore this message.`;

    const emailResult = await sendAuthEmail({
      toAddress: challenge.email,
      subject,
      text,
      template: "verify_customer_email_otp",
      actorUserId: null,
      ipHash: null,
      userAgent: req.get("user-agent") || undefined,
    });

    if (!emailResult.delivered) {
      return res.status(500).json({
        success: false,
        error: emailResult.error || "Could not send OTP email",
      });
    }

    await createAuditLog({
      action: "VERIFY_CUSTOMER_OTP_SENT",
      entityType: "CustomerVerifyAuth",
      entityId: challenge.email,
      details: {
        maskedEmail: maskEmail(challenge.email),
        expiresAt: challenge.expiresAt,
      },
      ipAddress: req.ip,
      userAgent: req.get("user-agent") || undefined,
    });

    return res.json({
      success: true,
      data: {
        challengeToken: challenge.challengeToken,
        expiresAt: challenge.expiresAt,
        maskedEmail: maskEmail(challenge.email),
      },
    });
  } catch (error) {
    console.error("requestCustomerEmailOtp error:", error);
    return res.status(500).json({
      success: false,
      error: "Could not start email verification",
    });
  }
};

export const verifyCustomerEmailOtp = async (req: Request, res: Response) => {
  try {
    const parsed = verifyOtpSchema.safeParse(req.body || {});
    if (!parsed.success) {
      return res.status(400).json({
        success: false,
        error: parsed.error.errors[0]?.message || "Invalid OTP payload",
      });
    }

    const identity = verifyCustomerOtpChallenge({
      challengeToken: parsed.data.challengeToken,
      otp: parsed.data.otp,
    });

    const token = issueCustomerVerifyToken(identity);

    await createAuditLog({
      action: "VERIFY_CUSTOMER_OTP_VERIFIED",
      entityType: "CustomerVerifyAuth",
      entityId: identity.userId,
      details: {
        maskedEmail: maskEmail(identity.email),
      },
      ipAddress: req.ip,
      userAgent: req.get("user-agent") || undefined,
    });

    return res.json({
      success: true,
      data: {
        token,
        customer: {
          userId: identity.userId,
          email: identity.email,
          maskedEmail: maskEmail(identity.email),
        },
      },
    });
  } catch (error: any) {
    return res.status(400).json({
      success: false,
      error: error?.message || "Invalid OTP code",
    });
  }
};

export const verifyQRCode = async (req: CustomerVerifyRequest, res: Response) => {
  try {
    const { code } = req.params;

    if (!code || code.length < 2) {
      return res.status(400).json({
        success: false,
        error: "Invalid QR code format",
      });
    }

    const normalizedCode = normalizeCode(code);
    const defaultVerifyUxPolicy = await resolveVerifyUxPolicy(null);

    const qrCode = await prisma.qRCode.findUnique({
      where: { code: normalizedCode },
      include: {
        licensee: {
          select: {
            id: true,
            name: true,
            prefix: true,
            brandName: true,
            location: true,
            website: true,
            supportEmail: true,
            supportPhone: true,
            suspendedAt: true,
            suspendedReason: true,
          },
        },
        batch: {
          select: {
            id: true,
            name: true,
            printedAt: true,
            suspendedAt: true,
            suspendedReason: true,
            manufacturer: { select: { id: true, name: true, email: true, location: true, website: true } },
          },
        },
      },
    });

    if (!qrCode) {
      await delay(150 + Math.floor(Math.random() * 150));
      const reasons = ["Code not found in registry."];
      const emptySummary: ScanSummary = {
        totalScans: 0,
        firstVerifiedAt: null,
        latestVerifiedAt: null,
        firstVerifiedLocation: null,
        latestVerifiedLocation: null,
      };
      const emptyOwnership: OwnershipStatus = {
        isClaimed: false,
        claimedAt: null,
        isOwnedByRequester: false,
        isClaimedByAnother: false,
        canClaim: false,
      };
      await createAuditLog({
        action: "VERIFY_FAILED",
        entityType: "QRCode",
        entityId: normalizedCode,
        details: { reason: "Code not found" },
        ipAddress: req.ip,
      });

      return res.json({
        success: true,
        data: {
          isAuthentic: false,
          message: "This QR code is not registered in our system.",
          code: normalizedCode,
          classification: "NOT_READY_FOR_CUSTOMER_USE",
          reasons,
          scanSummary: emptySummary,
          ownershipStatus: emptyOwnership,
          ownershipTransfer: {
            state: "none",
            active: false,
            canCreate: false,
            canCancel: false,
            canAccept: false,
            initiatedByYou: false,
            recipientEmailMasked: null,
            initiatedAt: null,
            expiresAt: null,
            acceptedAt: null,
            invalidReason: null,
            transferId: null,
            acceptUrl: null,
          },
          verificationTimeline: buildVerificationTimeline({
            scanSummary: emptySummary,
            classification: "NOT_READY_FOR_CUSTOMER_USE",
            reasons,
          }),
          riskExplanation: buildRiskExplanation({
            classification: "NOT_READY_FOR_CUSTOMER_USE",
            reasons,
            scanSummary: emptySummary,
            ownershipStatus: emptyOwnership,
          }),
          verifyUxPolicy: defaultVerifyUxPolicy,
          isBlocked: false,
          isReady: false,
          totalScans: 0,
          firstVerifiedAt: null,
          latestVerifiedAt: null,
          riskScore: 70,
          riskSignals: null,
        },
      });
    }

    const verifyUxPolicy = await resolveVerifyUxPolicy(qrCode.licenseeId || null);
    const riskProfile = await resolveDuplicateRiskProfile(qrCode.licenseeId || null);

    const customerUserId = req.customer?.userId || null;
    const requestedTransferToken = String(req.query.transfer || "").trim() || null;
    const requestDeviceFingerprint = deriveRequestDeviceFingerprint(req);
    const deviceClaimToken = getDeviceClaimTokenFromRequest(req);
    const deviceTokenHash = deviceClaimToken ? hashToken(deviceClaimToken) : null;
    const requesterIpHash = hashIp(req.ip);
    const containment = buildContainment(qrCode);
    const scanInsight = await getScanInsight(qrCode.id, requestDeviceFingerprint, {
      currentIpAddress: req.ip || null,
      licenseeId: qrCode.licenseeId || null,
    });
    const baseScanSummary = buildScanSummary({
      scanCount: Number(qrCode.scanCount || 0),
      scannedAt: qrCode.scannedAt,
      scanInsight,
    });

    const qrBlocked = qrCode.status === QRStatus.BLOCKED;
    const qrReady = isQrReadyForCustomerUse(qrCode.status);
    const baseOwnership = await loadOwnershipByQrCodeId(qrCode.id);
    const baseOwnershipStatus = buildOwnershipStatus({
      ownership: baseOwnership,
      customerUserId,
      deviceTokenHash,
      ipHash: requesterIpHash,
      isReady: qrReady,
      isBlocked: qrBlocked,
      allowClaim: verifyUxPolicy.allowOwnershipClaim,
    });
    const baseOwnershipTransfer = createOwnershipTransferView({
      code: qrCode.code,
      transfer: requestedTransferToken
        ? await loadOwnershipTransferByRawToken(requestedTransferToken)
        : await loadPendingOwnershipTransferForQr(qrCode.id),
      rawToken: requestedTransferToken,
      customerUserId,
      ownershipStatus: baseOwnershipStatus,
      isReady: qrReady,
      isBlocked: qrBlocked,
      transferRequested: Boolean(requestedTransferToken),
    });

    const basePayload = {
      code: qrCode.code,
      status: qrCode.status,
      containment,
      licensee: mapLicensee(qrCode.licensee),
      batch: mapBatch(qrCode.batch),
      batchName: qrCode.batch?.name || null,
      printedAt: qrCode.batch?.printedAt || null,
      scanCount: baseScanSummary.totalScans,
      firstScanAt: scanInsight.firstScanAt,
      firstScanLocation: scanInsight.firstScanLocation,
      latestScanAt: scanInsight.latestScanAt,
      latestScanLocation: scanInsight.latestScanLocation,
      previousScanAt: scanInsight.previousScanAt,
      previousScanLocation: scanInsight.previousScanLocation,
      scanSignals: scanInsight.signals,
    };

    if (qrCode.status === QRStatus.BLOCKED) {
      const reasons = [
        "This QR code has been blocked due to fraud or recall.",
        ...buildSecurityContainmentReasons(containment),
      ];
      const verificationTimeline = buildVerificationTimeline({
        scanSummary: baseScanSummary,
        classification: "BLOCKED_BY_SECURITY",
        reasons,
      });
      const riskExplanation = buildRiskExplanation({
        classification: "BLOCKED_BY_SECURITY",
        reasons,
        scanSummary: baseScanSummary,
        ownershipStatus: baseOwnershipStatus,
      });

      return res.json({
        success: true,
        data: {
          ...basePayload,
          isAuthentic: false,
          message: "This QR code has been blocked due to fraud or recall.",
          classification: "BLOCKED_BY_SECURITY" as VerifyClassification,
          reasons,
          scanSummary: baseScanSummary,
          ownershipStatus: baseOwnershipStatus,
          ownershipTransfer: baseOwnershipTransfer,
          verificationTimeline,
          riskExplanation,
          verifyUxPolicy,
          isBlocked: true,
          isReady: false,
          totalScans: baseScanSummary.totalScans,
          firstVerifiedAt: baseScanSummary.firstVerifiedAt,
          latestVerifiedAt: baseScanSummary.latestVerifiedAt,
          riskScore: 100,
          riskSignals: null,
        },
      });
    }

    if (qrCode.status === QRStatus.DORMANT || qrCode.status === QRStatus.ACTIVE || qrCode.status === QRStatus.ALLOCATED || qrCode.status === QRStatus.ACTIVATED) {
      const message =
        qrCode.status === QRStatus.ALLOCATED
          ? "This QR code is allocated but not yet printed."
          : qrCode.status === QRStatus.ACTIVATED
            ? "This QR code has not been activated (print not confirmed)."
            : "This QR code has not been assigned to a product yet.";
      const reasons = [statusNotReadyReason(qrCode.status)];
      const verificationTimeline = buildVerificationTimeline({
        scanSummary: baseScanSummary,
        classification: "NOT_READY_FOR_CUSTOMER_USE",
        reasons,
      });
      const riskExplanation = buildRiskExplanation({
        classification: "NOT_READY_FOR_CUSTOMER_USE",
        reasons,
        scanSummary: baseScanSummary,
        ownershipStatus: baseOwnershipStatus,
      });

      return res.json({
        success: true,
        data: {
          ...basePayload,
          isAuthentic: false,
          message,
          classification: "NOT_READY_FOR_CUSTOMER_USE" as VerifyClassification,
          reasons,
          scanSummary: baseScanSummary,
          ownershipStatus: baseOwnershipStatus,
          ownershipTransfer: baseOwnershipTransfer,
          verificationTimeline,
          riskExplanation,
          verifyUxPolicy,
          isBlocked: false,
          isReady: false,
          totalScans: baseScanSummary.totalScans,
          firstVerifiedAt: baseScanSummary.firstVerifiedAt,
          latestVerifiedAt: baseScanSummary.latestVerifiedAt,
          riskScore: 70,
          riskSignals: null,
        },
      });
    }

    const toNum = (v: any) => {
      const n = parseFloat(String(v));
      return Number.isFinite(n) ? n : null;
    };

    const latitude = toNum(req.query.lat);
    const longitude = toNum(req.query.lon);
    const accuracy = toNum(req.query.acc);

    const { isFirstScan, qrCode: updated } = await recordScan(normalizedCode, {
      ipAddress: req.ip,
      userAgent: req.get("user-agent") || null,
      device: requestDeviceFingerprint,
      latitude,
      longitude,
      accuracy,
    });

    await createAuditLog({
      action: "VERIFY_SUCCESS",
      entityType: "QRCode",
      entityId: qrCode.id,
      details: {
        isFirstScan,
        scanCount: updated.scanCount ?? 0,
      },
      ipAddress: req.ip,
    });

    const policy = await evaluateScanAndEnforcePolicy({
      qrCodeId: updated.id,
      code: updated.code,
      licenseeId: updated.licenseeId,
      batchId: updated.batchId ?? null,
      manufacturerId: updated.batch?.manufacturer?.id || null,
      scanCount: updated.scanCount ?? 0,
      scannedAt: new Date(),
      latitude,
      longitude,
      ipAddress: req.ip,
      userAgent: req.get("user-agent") || null,
    });

    const blockedByPolicy = Boolean(policy.autoBlockedQr || policy.autoBlockedBatch);
    const finalStatus = blockedByPolicy ? QRStatus.BLOCKED : updated.status;
    const isBlocked = blockedByPolicy || finalStatus === QRStatus.BLOCKED;
    const isReady = isQrReadyForCustomerUse(finalStatus);

    const firstScanTime = updated.scannedAt ? new Date(updated.scannedAt) : null;
    const postScanInsight = await getScanInsight(updated.id, requestDeviceFingerprint, {
      currentIpAddress: req.ip || null,
      licenseeId: updated.licenseeId || null,
    });
    const postScanSummary = buildScanSummary({
      scanCount: Number(updated.scanCount || 0),
      scannedAt: firstScanTime,
      scanInsight: postScanInsight,
    });

    const runtimeContainment = buildContainment(updated);

    const hasContainment =
      Boolean(runtimeContainment.qrUnderInvestigation) ||
      Boolean(runtimeContainment.batchSuspended) ||
      Boolean(runtimeContainment.orgSuspended);

    const warningMessage = blockedByPolicy
      ? "This code has been auto-blocked by security policy due to anomaly detection."
      : hasContainment
        ? "This product is currently under investigation. Please review details and contact support if needed."
        : !isFirstScan && postScanSummary.firstVerifiedAt
          ? `Already verified before. First verification was on ${postScanSummary.firstVerifiedAt}.`
          : null;

    const ownership = await loadOwnershipByQrCodeId(updated.id);

    const ownershipStatus = buildOwnershipStatus({
      ownership,
      customerUserId,
      deviceTokenHash,
      ipHash: requesterIpHash,
      isReady,
      isBlocked,
      allowClaim: verifyUxPolicy.allowOwnershipClaim,
    });
    const ownershipTransfer = createOwnershipTransferView({
      code: updated.code,
      transfer: requestedTransferToken
        ? await loadOwnershipTransferByRawToken(requestedTransferToken)
        : await loadPendingOwnershipTransferForQr(updated.id),
      rawToken: requestedTransferToken,
      customerUserId,
      ownershipStatus,
      isReady,
      isBlocked,
      transferRequested: Boolean(requestedTransferToken),
    });

    const anomalyModelScore = deriveAnomalyModelScore({
      scanSignals: postScanInsight.signals,
      policy,
    });

    const duplicateRisk = assessDuplicateRisk({
      scanCount: postScanSummary.totalScans,
      scanSignals: postScanInsight.signals,
      policy,
      ownershipStatus,
      customerUserId,
      latestScanAt: postScanInsight.latestScanAt,
      previousScanAt: postScanInsight.previousScanAt,
      anomalyModelScore: Math.round(anomalyModelScore * riskProfile.anomalyWeight),
      tenantRiskLevel: riskProfile.tenantRiskLevel,
      productRiskLevel: riskProfile.productRiskLevel,
    });

    let classification: VerifyClassification;
    let reasons: string[];
    let riskScore = duplicateRisk.riskScore;
    let riskSignals: Record<string, any> | null = duplicateRisk.signals;

    if (isBlocked) {
      classification = "BLOCKED_BY_SECURITY";
      reasons = [
        blockedByPolicy
          ? "Security policy auto-blocked this code after anomaly detection."
          : "This code is blocked by security controls.",
        ...buildSecurityContainmentReasons(runtimeContainment),
      ];
      riskScore = 100;
      riskSignals = null;
    } else if (isFirstScan) {
      classification = "FIRST_SCAN";
      reasons = ["First successful customer verification recorded."];
      riskScore = 4;
      riskSignals = null;
    } else {
      classification = duplicateRisk.classification;
      reasons = duplicateRisk.reasons;
    }

    if (ownershipStatus.isClaimedByAnother && !isBlocked) {
      classification = "SUSPICIOUS_DUPLICATE";
      if (!reasons.includes("Ownership is already claimed by another account.")) {
        reasons.unshift("Ownership is already claimed by another account.");
      }
      riskScore = Math.max(riskScore, 70);
    }

    const verificationTimeline = buildVerificationTimeline({
      scanSummary: postScanSummary,
      classification,
      reasons,
    });
    const riskExplanation = buildRiskExplanation({
      classification,
      reasons,
      scanSummary: postScanSummary,
      ownershipStatus,
    });
    const stepUpRequired = classification === "SUSPICIOUS_DUPLICATE" && !customerUserId;

    return res.json({
      success: true,
      data: {
        isAuthentic: !isBlocked,
        message: isBlocked
          ? "Blocked code."
          : isFirstScan
            ? "This is a genuine product."
            : "Already verified. Please review scan details below.",
        code: updated.code,
        status: finalStatus,
        containment: runtimeContainment,

        licensee: mapLicensee(updated.licensee),
        batch: mapBatch(updated.batch),

        batchName: updated.batch?.name || null,
        printedAt: updated.batch?.printedAt || null,

        firstScanned: firstScanTime ? firstScanTime.toISOString() : null,
        scanCount: updated.scanCount ?? 0,
        isFirstScan,
        firstScanAt: postScanInsight.firstScanAt,
        firstScanLocation: postScanInsight.firstScanLocation,
        latestScanAt: postScanInsight.latestScanAt,
        latestScanLocation: postScanInsight.latestScanLocation,
        previousScanAt: postScanInsight.previousScanAt,
        previousScanLocation: postScanInsight.previousScanLocation,
        scanSignals: postScanInsight.signals,

        classification,
        reasons,
        scanSummary: postScanSummary,
        ownershipStatus,
        ownershipTransfer,
        verificationTimeline,
        riskExplanation,
        verifyUxPolicy,
        isBlocked,
        isReady,
        totalScans: postScanSummary.totalScans,
        firstVerifiedAt: postScanSummary.firstVerifiedAt,
        latestVerifiedAt: postScanSummary.latestVerifiedAt,
        riskScore,
        riskThreshold: duplicateRisk.threshold,
        riskSignals,
        challenge: {
          required: stepUpRequired,
          methods: stepUpRequired ? ["EMAIL_OTP", "CAPTCHA"] : [],
        },

        warningMessage,
        policy,
      },
    });
  } catch (error) {
    console.error("Verify error:", error);
    return res.status(500).json({
      success: false,
      error: "Verification service unavailable",
    });
  }
};

export const claimProductOwnership = async (req: CustomerVerifyRequest, res: Response) => {
  try {
    const normalizedCode = normalizeCode(req.params.code || "");
    if (!normalizedCode || normalizedCode.length < 2) {
      return res.status(400).json({
        success: false,
        error: "Invalid QR code format",
      });
    }

    const qrCode = await prisma.qRCode.findUnique({
      where: { code: normalizedCode },
      select: {
        id: true,
        code: true,
        status: true,
        licenseeId: true,
      },
    });

    if (!qrCode) {
      return res.status(404).json({
        success: false,
        error: "QR code not found",
      });
    }

    const verifyUxPolicy = await resolveVerifyUxPolicy(qrCode.licenseeId || null);
    const isBlocked = qrCode.status === QRStatus.BLOCKED;
    const isReady = isQrReadyForCustomerUse(qrCode.status);
    const allowClaim = verifyUxPolicy.allowOwnershipClaim !== false;
    const customerUserId = req.customer?.userId || null;
    const deviceClaimToken = ensureDeviceClaimToken(req, res);
    const deviceTokenHash = deviceClaimToken ? hashToken(deviceClaimToken) : null;
    const requesterIpHash = hashIp(req.ip);
    const normalizedUa = normalizeUserAgent(req.get("user-agent") || null);
    const requesterUserAgentHash = normalizedUa ? hashToken(`ua:${normalizedUa}`) : null;

    const buildClaimResponse = (ownership: OwnershipRecord | null) => {
      const ownershipStatus = buildOwnershipStatus({
        ownership,
        customerUserId,
        deviceTokenHash,
        ipHash: requesterIpHash,
        isReady,
        isBlocked,
        allowClaim,
      });
      return {
        ownershipStatus,
        claimTimestamp: ownership?.claimedAt?.toISOString?.() || null,
      };
    };

    if (isBlocked || !isReady || !allowClaim) {
      return res.status(409).json({
        success: false,
        error: isBlocked
          ? "Claim not allowed for blocked products"
          : !isReady
            ? "Claim is available only after product activation"
            : "Claiming is currently disabled by policy",
      });
    }

    const existingOwnership = await loadOwnershipByQrCodeId(qrCode.id);
    if (existingOwnership) {
      const currentStatus = buildClaimResponse(existingOwnership).ownershipStatus;
      if (currentStatus.isOwnedByRequester) {
        if (customerUserId && !existingOwnership.userId) {
          const linked = await prisma.ownership.update({
            where: { qrCodeId: qrCode.id },
            data: {
              userId: customerUserId,
              linkedAt: new Date(),
              claimSource: "DEVICE_AND_USER",
            },
            select: {
              id: true,
              userId: true,
              claimedAt: true,
              deviceTokenHash: true,
              ipHash: true,
              userAgentHash: true,
              claimSource: true,
              linkedAt: true,
            },
          });

          await createAuditLog({
            action: "VERIFY_CLAIM_LINKED_TO_USER",
            entityType: "Ownership",
            entityId: qrCode.id,
            licenseeId: qrCode.licenseeId || undefined,
            ipAddress: req.ip,
            userAgent: req.get("user-agent") || undefined,
            details: {
              qrCodeId: qrCode.id,
              customerUserId,
            },
          });

          return res.json({
            success: true,
            data: {
              claimResult: "LINKED_TO_SIGNED_IN_ACCOUNT",
              message: "Device claim linked to your signed-in account.",
              ...buildClaimResponse(linked),
            },
          });
        }

        return res.json({
          success: true,
          data: {
            claimResult: "ALREADY_OWNED_BY_YOU",
            message: "This product is already owned by you on this device/account.",
            ...buildClaimResponse(existingOwnership),
          },
        });
      }

      await createAuditLog({
        action: "VERIFY_CLAIM_CONFLICT",
        entityType: "Ownership",
        entityId: qrCode.id,
        licenseeId: qrCode.licenseeId || undefined,
        ipAddress: req.ip,
        userAgent: req.get("user-agent") || undefined,
        details: {
          qrCodeId: qrCode.id,
          requesterUserId: customerUserId,
          hasDeviceToken: Boolean(deviceTokenHash),
          existingOwnership: true,
        },
      });

      const stepUp = await verifyStepUpChallenge(req);
      if (!stepUp.ok) {
        return res.status(403).json({
          success: false,
          error: stepUp.reason || "Suspicious ownership conflict requires challenge verification.",
          challenge: {
            required: true,
            methods: ["CAPTCHA"],
          },
        });
      }

      return res.json({
        success: true,
        data: {
          claimResult: "OWNED_BY_ANOTHER_USER",
          conflict: true,
          classification: "SUSPICIOUS_DUPLICATE",
          reasons: [
            "Ownership is already claimed by another account or device.",
            "If this is unexpected, report suspected counterfeit immediately.",
          ],
          warningMessage: "Ownership conflict detected. Treat this product as potential duplicate until reviewed.",
          ...buildClaimResponse(existingOwnership),
        },
      });
    }

    let createdOwnership: OwnershipRecord | null = null;
    try {
      createdOwnership = await prisma.ownership.create({
        data: {
          qrCodeId: qrCode.id,
          userId: customerUserId || null,
          deviceTokenHash,
          ipHash: requesterIpHash,
          userAgentHash: requesterUserAgentHash,
          claimSource: customerUserId ? "USER" : "DEVICE",
        },
        select: {
          id: true,
          userId: true,
          claimedAt: true,
          deviceTokenHash: true,
          ipHash: true,
          userAgentHash: true,
          claimSource: true,
          linkedAt: true,
        },
      });
    } catch (error: any) {
      if (isOwnershipStorageMissingError(error)) {
        return res.status(503).json({
          success: false,
          error: "Ownership feature is temporarily unavailable. Please retry after maintenance.",
        });
      }

      if (error instanceof Prisma.PrismaClientKnownRequestError && error.code === "P2002") {
        const existing = await loadOwnershipByQrCodeId(qrCode.id);
        if (existing) {
          const stepUp = await verifyStepUpChallenge(req);
          if (!stepUp.ok) {
            return res.status(403).json({
              success: false,
              error: stepUp.reason || "Suspicious ownership conflict requires challenge verification.",
              challenge: {
                required: true,
                methods: ["CAPTCHA"],
              },
            });
          }
          return res.json({
            success: true,
            data: {
              claimResult: "OWNED_BY_ANOTHER_USER",
              conflict: true,
              classification: "SUSPICIOUS_DUPLICATE",
              reasons: [
                "Ownership is already claimed by another account or device.",
                "If this is unexpected, report suspected counterfeit immediately.",
              ],
              warningMessage: "Ownership conflict detected. Treat this product as potential duplicate until reviewed.",
              ...buildClaimResponse(existing),
            },
          });
        }
      }
      throw error;
    }

    await createAuditLog({
      action: "VERIFY_CLAIM_SUCCESS",
      entityType: "Ownership",
      entityId: qrCode.id,
      licenseeId: qrCode.licenseeId || undefined,
      ipAddress: req.ip,
      userAgent: req.get("user-agent") || undefined,
      details: {
        qrCodeId: qrCode.id,
        customerUserId,
        claimSource: customerUserId ? "USER" : "DEVICE",
      },
    });

    return res.status(201).json({
      success: true,
      data: {
        claimResult: customerUserId ? "CLAIMED_USER" : "CLAIMED_DEVICE",
        message: customerUserId
          ? "Product ownership claimed and linked to your account."
          : "Product ownership claimed on this device.",
        ...buildClaimResponse(createdOwnership),
      },
    });
  } catch (error) {
    console.error("claimProductOwnership error:", error);
    return res.status(500).json({
      success: false,
      error: "Failed to claim ownership",
    });
  }
};

export const linkDeviceClaimToCustomer = async (req: CustomerVerifyRequest, res: Response) => {
  try {
    const customer = req.customer;
    if (!customer) {
      return res.status(401).json({
        success: false,
        error: "Customer authentication required",
      });
    }

    const normalizedCode = normalizeCode(req.params.code || "");
    if (!normalizedCode || normalizedCode.length < 2) {
      return res.status(400).json({
        success: false,
        error: "Invalid QR code format",
      });
    }

    const qrCode = await prisma.qRCode.findUnique({
      where: { code: normalizedCode },
      select: {
        id: true,
        status: true,
        licenseeId: true,
      },
    });
    if (!qrCode) {
      return res.status(404).json({
        success: false,
        error: "QR code not found",
      });
    }

    const verifyUxPolicy = await resolveVerifyUxPolicy(qrCode.licenseeId || null);
    const allowClaim = verifyUxPolicy.allowOwnershipClaim !== false;
    const isBlocked = qrCode.status === QRStatus.BLOCKED;
    const isReady = isQrReadyForCustomerUse(qrCode.status);

    if (!allowClaim || isBlocked || !isReady) {
      return res.status(409).json({
        success: false,
        error: "Ownership linking is not available for this product state.",
      });
    }

    const deviceClaimToken = getDeviceClaimTokenFromRequest(req);
    const deviceTokenHash = deviceClaimToken ? hashToken(deviceClaimToken) : null;
    const requesterIpHash = hashIp(req.ip);

    const existingOwnership = await loadOwnershipByQrCodeId(qrCode.id);
    if (!existingOwnership) {
      return res.status(404).json({
        success: false,
        error: "No device claim exists for this product yet.",
      });
    }

    if (existingOwnership.userId && existingOwnership.userId === customer.userId) {
      return res.json({
        success: true,
        data: {
          linkResult: "ALREADY_LINKED",
          message: "Ownership is already linked to your account.",
          ownershipStatus: buildOwnershipStatus({
            ownership: existingOwnership,
            customerUserId: customer.userId,
            deviceTokenHash,
            ipHash: requesterIpHash,
            isReady,
            isBlocked,
            allowClaim,
          }),
        },
      });
    }

    if (existingOwnership.userId && existingOwnership.userId !== customer.userId) {
      const stepUp = await verifyStepUpChallenge(req);
      if (!stepUp.ok) {
        return res.status(403).json({
          success: false,
          error: stepUp.reason || "Suspicious ownership link requires challenge verification.",
          challenge: {
            required: true,
            methods: ["CAPTCHA"],
          },
        });
      }
      return res.status(409).json({
        success: false,
        error: "Ownership is already linked to another account.",
      });
    }

    const ownershipStatus = buildOwnershipStatus({
      ownership: existingOwnership,
      customerUserId: null,
      deviceTokenHash,
      ipHash: requesterIpHash,
      isReady,
      isBlocked,
      allowClaim,
    });

    if (!ownershipStatus.isOwnedByRequester) {
      const stepUp = await verifyStepUpChallenge(req);
      if (!stepUp.ok) {
        return res.status(403).json({
          success: false,
          error: stepUp.reason || "Ownership linking challenge required.",
          challenge: {
            required: true,
            methods: ["CAPTCHA"],
          },
        });
      }
      return res.status(409).json({
        success: false,
        error: "Current device could not prove ownership for linking.",
      });
    }

    const linked = await prisma.ownership.update({
      where: { qrCodeId: qrCode.id },
      data: {
        userId: customer.userId,
        linkedAt: new Date(),
        claimSource: "DEVICE_AND_USER",
      },
      select: {
        id: true,
        userId: true,
        claimedAt: true,
        deviceTokenHash: true,
        ipHash: true,
        userAgentHash: true,
        claimSource: true,
        linkedAt: true,
      },
    });

    await createAuditLog({
      action: "VERIFY_CLAIM_LINKED_TO_USER",
      entityType: "Ownership",
      entityId: qrCode.id,
      licenseeId: qrCode.licenseeId || undefined,
      ipAddress: req.ip,
      userAgent: req.get("user-agent") || undefined,
      details: {
        qrCodeId: qrCode.id,
        customerUserId: customer.userId,
      },
    });

    return res.json({
      success: true,
      data: {
        linkResult: "LINKED",
        message: "Device claim linked to your account.",
        ownershipStatus: buildOwnershipStatus({
          ownership: linked,
          customerUserId: customer.userId,
          deviceTokenHash,
          ipHash: requesterIpHash,
          isReady,
          isBlocked,
          allowClaim,
        }),
      },
    });
  } catch (error) {
    console.error("linkDeviceClaimToCustomer error:", error);
    return res.status(500).json({
      success: false,
      error: "Failed to link claim",
    });
  }
};

export const createOwnershipTransfer = async (req: CustomerVerifyRequest, res: Response) => {
  try {
    const customer = req.customer;
    if (!customer) {
      return res.status(401).json({ success: false, error: "Customer authentication required" });
    }

    const parsed = createOwnershipTransferSchema.safeParse(req.body || {});
    if (!parsed.success) {
      return res.status(400).json({
        success: false,
        error: parsed.error.errors[0]?.message || "Invalid ownership transfer payload",
      });
    }

    const normalizedCode = normalizeCode(req.params.code || "");
    if (!normalizedCode || normalizedCode.length < 2) {
      return res.status(400).json({ success: false, error: "Invalid QR code format" });
    }

    const qrCode = await prisma.qRCode.findUnique({
      where: { code: normalizedCode },
      select: {
        id: true,
        code: true,
        status: true,
        licenseeId: true,
      },
    });
    if (!qrCode) {
      return res.status(404).json({ success: false, error: "QR code not found" });
    }

    const verifyUxPolicy = await resolveVerifyUxPolicy(qrCode.licenseeId || null);
    const allowClaim = verifyUxPolicy.allowOwnershipClaim !== false;
    const isBlocked = qrCode.status === QRStatus.BLOCKED;
    const isReady = isQrReadyForCustomerUse(qrCode.status);
    if (!allowClaim || isBlocked || !isReady) {
      return res.status(409).json({
        success: false,
        error: "Ownership transfer is not available for this product state.",
      });
    }

    const deviceClaimToken = getDeviceClaimTokenFromRequest(req);
    const deviceTokenHash = deviceClaimToken ? hashToken(deviceClaimToken) : null;
    const requesterIpHash = hashIp(req.ip);

    let ownership = await loadOwnershipByQrCodeId(qrCode.id);
    if (!ownership) {
      return res.status(409).json({
        success: false,
        error: "Claim ownership before starting a resale transfer.",
      });
    }

    let ownershipStatus = buildOwnershipStatus({
      ownership,
      customerUserId: customer.userId,
      deviceTokenHash,
      ipHash: requesterIpHash,
      isReady,
      isBlocked,
      allowClaim,
    });

    if (!ownershipStatus.isOwnedByRequester) {
      return res.status(403).json({
        success: false,
        error: "Only the current signed-in owner can start a transfer.",
      });
    }

    if (ownership.userId !== customer.userId) {
      ownership = await prisma.ownership.update({
        where: { qrCodeId: qrCode.id },
        data: {
          userId: customer.userId,
          linkedAt: new Date(),
          claimSource: "DEVICE_AND_USER",
        },
        select: {
          id: true,
          userId: true,
          claimedAt: true,
          deviceTokenHash: true,
          ipHash: true,
          userAgentHash: true,
          claimSource: true,
          linkedAt: true,
        },
      });
      ownershipStatus = buildOwnershipStatus({
        ownership,
        customerUserId: customer.userId,
        deviceTokenHash,
        ipHash: requesterIpHash,
        isReady,
        isBlocked,
        allowClaim,
      });
    }

    await expirePendingOwnershipTransfers({ qrCodeId: qrCode.id });
    await prisma.ownershipTransfer.updateMany({
      where: {
        qrCodeId: qrCode.id,
        status: OwnershipTransferStatus.PENDING,
      },
      data: {
        status: OwnershipTransferStatus.CANCELLED,
        cancelledAt: new Date(),
      },
    });

    const rawToken = randomOpaqueToken(32);
    const expiresAt = new Date(Date.now() + OWNERSHIP_TRANSFER_TTL_HOURS * 60 * 60 * 1000);
    const recipientEmail = parsed.data.recipientEmail?.trim().toLowerCase() || null;
    const normalizedUa = normalizeUserAgent(req.get("user-agent") || null);

    const transfer = await prisma.ownershipTransfer.create({
      data: {
        qrCodeId: qrCode.id,
        ownershipId: ownership.id,
        initiatedByCustomerId: customer.userId,
        initiatedByEmail: customer.email,
        recipientEmail,
        tokenHash: hashToken(rawToken),
        status: OwnershipTransferStatus.PENDING,
        expiresAt,
        metadata: {
          requestedFromIpHash: requesterIpHash,
          requestedUserAgentHash: normalizedUa ? hashToken(`ua:${normalizedUa}`) : null,
        },
      },
      select: {
        id: true,
        qrCodeId: true,
        ownershipId: true,
        initiatedByCustomerId: true,
        initiatedByEmail: true,
        recipientEmail: true,
        status: true,
        expiresAt: true,
        acceptedAt: true,
        cancelledAt: true,
        lastViewedAt: true,
        createdAt: true,
        updatedAt: true,
      },
    });

    const transferLink = buildOwnershipTransferLink(qrCode.code, rawToken);

    await createAuditLog({
      action: "VERIFY_TRANSFER_CREATED",
      entityType: "OwnershipTransfer",
      entityId: transfer.id,
      licenseeId: qrCode.licenseeId || undefined,
      ipAddress: req.ip,
      userAgent: req.get("user-agent") || undefined,
      details: {
        qrCodeId: qrCode.id,
        recipientEmail: recipientEmail || null,
        expiresAt: expiresAt.toISOString(),
      },
    });

    const emailJobs: Promise<any>[] = [];
    if (recipientEmail) {
      emailJobs.push(
        sendAuthEmail({
          toAddress: recipientEmail,
          subject: "MSCQR ownership transfer ready to accept",
          text:
            `A current owner started a product transfer for QR ${qrCode.code}.\n\n` +
            `Open this secure link to review and accept the transfer:\n${transferLink}\n\n` +
            `This link expires at ${expiresAt.toISOString()}.`,
          template: "verify_transfer_recipient",
          licenseeId: qrCode.licenseeId || null,
          userAgent: req.get("user-agent") || undefined,
        })
      );
    }
    if (customer.email) {
      emailJobs.push(
        sendAuthEmail({
          toAddress: customer.email,
          subject: "MSCQR ownership transfer created",
          text:
            `Your transfer for QR ${qrCode.code} is active.\n\n` +
            `Share this secure link with the next owner:\n${transferLink}\n\n` +
            `It expires at ${expiresAt.toISOString()}.`,
          template: "verify_transfer_sender",
          licenseeId: qrCode.licenseeId || null,
          userAgent: req.get("user-agent") || undefined,
        })
      );
    }
    await Promise.allSettled(emailJobs);

    return res.status(201).json({
      success: true,
      data: {
        message: "Ownership transfer created. Share the secure acceptance link with the next owner.",
        transferLink,
        transferToken: rawToken,
        ownershipStatus,
        ownershipTransfer: createOwnershipTransferView({
          code: qrCode.code,
          transfer,
          rawToken,
          customerUserId: customer.userId,
          ownershipStatus,
          isReady,
          isBlocked,
          transferRequested: true,
        }),
      },
    });
  } catch (error) {
    console.error("createOwnershipTransfer error:", error);
    return res.status(500).json({ success: false, error: "Failed to create ownership transfer" });
  }
};

export const cancelOwnershipTransfer = async (req: CustomerVerifyRequest, res: Response) => {
  try {
    const customer = req.customer;
    if (!customer) {
      return res.status(401).json({ success: false, error: "Customer authentication required" });
    }

    const parsed = cancelOwnershipTransferSchema.safeParse(req.body || {});
    if (!parsed.success) {
      return res.status(400).json({
        success: false,
        error: parsed.error.errors[0]?.message || "Invalid cancellation payload",
      });
    }

    const normalizedCode = normalizeCode(req.params.code || "");
    if (!normalizedCode || normalizedCode.length < 2) {
      return res.status(400).json({ success: false, error: "Invalid QR code format" });
    }

    const qrCode = await prisma.qRCode.findUnique({
      where: { code: normalizedCode },
      select: { id: true, code: true, licenseeId: true, status: true },
    });
    if (!qrCode) {
      return res.status(404).json({ success: false, error: "QR code not found" });
    }

    await expirePendingOwnershipTransfers({ qrCodeId: qrCode.id });
    const transfer = await prisma.ownershipTransfer.findFirst({
      where: {
        qrCodeId: qrCode.id,
        status: OwnershipTransferStatus.PENDING,
        ...(parsed.data.transferId ? { id: parsed.data.transferId } : {}),
      },
      orderBy: [{ createdAt: "desc" }, { id: "desc" }],
      select: {
        id: true,
        qrCodeId: true,
        ownershipId: true,
        initiatedByCustomerId: true,
        initiatedByEmail: true,
        recipientEmail: true,
        status: true,
        expiresAt: true,
        acceptedAt: true,
        cancelledAt: true,
        lastViewedAt: true,
        createdAt: true,
        updatedAt: true,
      },
    });

    if (!transfer) {
      return res.status(404).json({ success: false, error: "No active transfer found for this product." });
    }
    if (transfer.initiatedByCustomerId !== customer.userId) {
      return res.status(403).json({ success: false, error: "Only the transfer initiator can cancel it." });
    }

    const cancelled = await prisma.ownershipTransfer.update({
      where: { id: transfer.id },
      data: {
        status: OwnershipTransferStatus.CANCELLED,
        cancelledAt: new Date(),
      },
      select: {
        id: true,
        qrCodeId: true,
        ownershipId: true,
        initiatedByCustomerId: true,
        initiatedByEmail: true,
        recipientEmail: true,
        status: true,
        expiresAt: true,
        acceptedAt: true,
        cancelledAt: true,
        lastViewedAt: true,
        createdAt: true,
        updatedAt: true,
      },
    });

    await createAuditLog({
      action: "VERIFY_TRANSFER_CANCELLED",
      entityType: "OwnershipTransfer",
      entityId: cancelled.id,
      licenseeId: qrCode.licenseeId || undefined,
      ipAddress: req.ip,
      userAgent: req.get("user-agent") || undefined,
      details: {
        qrCodeId: qrCode.id,
      },
    });

    await Promise.allSettled(
      [cancelled.initiatedByEmail, cancelled.recipientEmail]
        .filter(Boolean)
        .map((email) =>
          sendAuthEmail({
            toAddress: String(email),
            subject: "MSCQR ownership transfer cancelled",
            text: `The pending ownership transfer for QR ${qrCode.code} has been cancelled.`,
            template: "verify_transfer_cancelled",
            licenseeId: qrCode.licenseeId || null,
            userAgent: req.get("user-agent") || undefined,
          })
        )
    );

    return res.json({
      success: true,
      data: {
        message: "Ownership transfer cancelled.",
        ownershipTransfer: createOwnershipTransferView({
          code: qrCode.code,
          transfer: cancelled,
          customerUserId: customer.userId,
          ownershipStatus: {
            isClaimed: true,
            claimedAt: null,
            isOwnedByRequester: true,
            isClaimedByAnother: false,
            canClaim: false,
            state: "owned_by_you",
            matchMethod: "user",
          },
          isReady: isQrReadyForCustomerUse(qrCode.status),
          isBlocked: qrCode.status === QRStatus.BLOCKED,
        }),
      },
    });
  } catch (error) {
    console.error("cancelOwnershipTransfer error:", error);
    return res.status(500).json({ success: false, error: "Failed to cancel ownership transfer" });
  }
};

export const acceptOwnershipTransfer = async (req: CustomerVerifyRequest, res: Response) => {
  try {
    const customer = req.customer;
    if (!customer) {
      return res.status(401).json({ success: false, error: "Customer authentication required" });
    }

    const parsed = acceptOwnershipTransferSchema.safeParse(req.body || {});
    if (!parsed.success) {
      return res.status(400).json({
        success: false,
        error: parsed.error.errors[0]?.message || "Invalid transfer acceptance payload",
      });
    }

    const transfer = await loadOwnershipTransferByRawToken(parsed.data.token);
    if (!transfer || transfer.status !== OwnershipTransferStatus.PENDING) {
      return res.status(404).json({ success: false, error: "Transfer link is invalid or has expired." });
    }
    if (transfer.initiatedByCustomerId === customer.userId) {
      return res.status(409).json({ success: false, error: "The current owner cannot accept their own transfer." });
    }

    const qrCode = await prisma.qRCode.findUnique({
      where: { id: transfer.qrCodeId },
      select: {
        id: true,
        code: true,
        status: true,
        licenseeId: true,
      },
    });
    if (!qrCode) {
      return res.status(404).json({ success: false, error: "QR code not found" });
    }

    const isBlocked = qrCode.status === QRStatus.BLOCKED;
    const isReady = isQrReadyForCustomerUse(qrCode.status);
    if (isBlocked || !isReady) {
      return res.status(409).json({
        success: false,
        error: "This product is not in a transferable state.",
      });
    }

    const normalizedUa = normalizeUserAgent(req.get("user-agent") || null);
    const requesterIpHash = hashIp(req.ip);

    const result = await prisma.$transaction(async (tx) => {
      const currentTransfer = await tx.ownershipTransfer.findUnique({
        where: { id: transfer.id },
      });
      if (!currentTransfer || currentTransfer.status !== OwnershipTransferStatus.PENDING) {
        throw new Error("Transfer link is no longer active.");
      }

      const updatedOwnership = await tx.ownership.update({
        where: { id: transfer.ownershipId },
        data: {
          userId: customer.userId,
          linkedAt: new Date(),
          claimedAt: new Date(),
          ipHash: requesterIpHash,
          userAgentHash: normalizedUa ? hashToken(`ua:${normalizedUa}`) : null,
          claimSource: "USER_TRANSFERRED",
        },
      select: {
        id: true,
        userId: true,
        claimedAt: true,
          deviceTokenHash: true,
          ipHash: true,
          userAgentHash: true,
          claimSource: true,
          linkedAt: true,
        },
      });

      const acceptedTransfer = await tx.ownershipTransfer.update({
        where: { id: transfer.id },
        data: {
          status: OwnershipTransferStatus.ACCEPTED,
          acceptedAt: new Date(),
        },
        select: {
          id: true,
          qrCodeId: true,
          ownershipId: true,
          initiatedByCustomerId: true,
          initiatedByEmail: true,
          recipientEmail: true,
          status: true,
          expiresAt: true,
          acceptedAt: true,
          cancelledAt: true,
          lastViewedAt: true,
          createdAt: true,
          updatedAt: true,
        },
      });

      await tx.ownershipTransfer.updateMany({
        where: {
          qrCodeId: transfer.qrCodeId,
          status: OwnershipTransferStatus.PENDING,
          id: { not: transfer.id },
        },
        data: {
          status: OwnershipTransferStatus.CANCELLED,
          cancelledAt: new Date(),
        },
      });

      return { updatedOwnership, acceptedTransfer };
    });

    await createAuditLog({
      action: "VERIFY_TRANSFER_ACCEPTED",
      entityType: "OwnershipTransfer",
      entityId: transfer.id,
      licenseeId: qrCode.licenseeId || undefined,
      ipAddress: req.ip,
      userAgent: req.get("user-agent") || undefined,
      details: {
        qrCodeId: qrCode.id,
        recipientCustomerId: customer.userId,
      },
    });

    await Promise.allSettled(
      [transfer.initiatedByEmail, customer.email, transfer.recipientEmail]
        .filter(Boolean)
        .map((email) =>
          sendAuthEmail({
            toAddress: String(email),
            subject: "MSCQR ownership transfer accepted",
            text: `The ownership transfer for QR ${qrCode.code} has been accepted successfully.`,
            template: "verify_transfer_accepted",
            licenseeId: qrCode.licenseeId || null,
            userAgent: req.get("user-agent") || undefined,
          })
        )
    );

    const ownershipStatus = buildOwnershipStatus({
      ownership: result.updatedOwnership,
      customerUserId: customer.userId,
      isReady,
      isBlocked,
      allowClaim: true,
    });

    return res.json({
      success: true,
      data: {
        message: "Ownership transfer accepted. This product is now linked to your signed-in account.",
        code: qrCode.code,
        ownershipStatus,
        ownershipTransfer: createOwnershipTransferView({
          code: qrCode.code,
          transfer: result.acceptedTransfer,
          customerUserId: customer.userId,
          ownershipStatus,
          isReady,
          isBlocked,
        }),
      },
    });
  } catch (error: any) {
    console.error("acceptOwnershipTransfer error:", error);
    return res.status(500).json({
      success: false,
      error: error?.message || "Failed to accept ownership transfer",
    });
  }
};

export const reportFraud = async (req: Request, res: Response) => {
  try {
    const parsed = reportFraudSchema.safeParse(req.body || {});
    if (!parsed.success) {
      return res.status(400).json({
        success: false,
        error: parsed.error.errors[0]?.message || "Invalid report payload",
      });
    }

    const payload = parsed.data;
    const normalizedCode = normalizeCode(payload.code || payload.qrCodeValue || "");
    const fingerprint = deriveRequestDeviceFingerprint(req, { allowClientHint: false });
    const rateLimit = enforceIncidentRateLimit({
      ip: req.ip,
      qrCode: normalizedCode,
      deviceFp: fingerprint,
    });
    if (rateLimit.blocked) {
      res.setHeader("Retry-After", String(rateLimit.retryAfterSec));
      return res.status(429).json({
        success: false,
        error: "Too many reports submitted. Please try again later.",
      });
    }

    const captchaToken = String(req.headers["x-captcha-token"] || req.body?.captchaToken || "").trim();
    const captcha = await verifyCaptchaToken(captchaToken, req.ip);
    if (!captcha.ok) {
      return res.status(400).json({
        success: false,
        error: captcha.reason || "Captcha verification failed",
      });
    }

    const incidentType = inferIncidentType({
      reason: payload.reason,
      incidentType: payload.incidentType,
    });

    const snapshot = await buildFraudVerificationSnapshot(normalizedCode);

    const metadataLines = [
      `Classification: ${snapshot.classification}`,
      `Reasons: ${snapshot.reasons.join(" | ") || "n/a"}`,
      `Scan summary: total=${snapshot.scanSummary.totalScans}, first=${snapshot.scanSummary.firstVerifiedAt || "n/a"}, latest=${snapshot.scanSummary.latestVerifiedAt || "n/a"}`,
      `Ownership: claimed=${String(snapshot.ownershipStatus.isClaimed)}, ownedByRequester=${String(snapshot.ownershipStatus.isOwnedByRequester)}`,
    ];

    const userDescription =
      String(payload.description || "").trim() ||
      String(payload.notes || "").trim() ||
      String(payload.reason || "").trim() ||
      "Suspected counterfeit report from verify page.";

    const finalDescription = `${userDescription}\n\n--- Verification metadata ---\n${metadataLines.join("\n")}`.slice(0, 2000);

    const uploadedFiles = Array.isArray(req.files) ? (req.files as Express.Multer.File[]) : [];
    const uploadRecords = mapUploadedEvidence(uploadedFiles);

    const tags = [
      ...parseTags(payload.tags),
      "verify_fraud_report",
      `classification_${snapshot.classification.toLowerCase()}`,
      snapshot.ownershipStatus.isClaimed ? "ownership_claimed" : "ownership_unclaimed",
    ].slice(0, 10);

    const customerEmail = String(payload.contactEmail || payload.customerEmail || "").trim() || undefined;

    const incident = await createIncidentFromReport(
      {
        qrCodeValue: normalizedCode,
        incidentType,
        description: finalDescription,
        consentToContact: parseBoolean(payload.consentToContact, Boolean(customerEmail)),
        customerEmail,
        preferredContactMethod: customerEmail ? "email" : payload.preferredContactMethod || "none",
        tags,
      },
      {
        actorType: IncidentActorType.CUSTOMER,
        ipAddress: req.ip,
        userAgent: req.get("user-agent") || undefined,
      },
      uploadRecords
    );

    const evidenceRows = await prisma.incidentEvidence.findMany({
      where: { incidentId: incident.id },
      select: {
        id: true,
        incidentId: true,
        storageKey: true,
        fileType: true,
      },
    });
    const tamperFindings = await runTamperEvidenceChecks(evidenceRows);
    const tamperSummary = summarizeTamperFindings(tamperFindings);

    if (tamperSummary.hasWarnings) {
      const nextTags = Array.from(new Set([...(incident.tags || []), "tamper_check_warning"]));
      await prisma.incident.update({
        where: { id: incident.id },
        data: { tags: nextTags },
      });
    }

    const supportTicket = await prisma.supportTicket.findUnique({
      where: { incidentId: incident.id },
      select: {
        id: true,
        referenceCode: true,
        status: true,
        slaDueAt: true,
      },
    });

    const superadminEmails = await getSuperadminAlertEmails();
    const alertSubject = `[Incident][${incident.severity}] New fraud report ${incident.id}`;
    const alertBody = incidentSummaryText(incident);

    for (const email of superadminEmails) {
      await sendIncidentEmail({
        incidentId: incident.id,
        licenseeId: incident.licenseeId || null,
        toAddress: email,
        subject: alertSubject,
        text: alertBody,
        senderMode: "system",
        template: "superadmin_alert",
      });
    }

    return res.status(201).json({
      success: true,
      data: {
        reportId: incident.id,
        supportTicketRef: supportTicket?.referenceCode || null,
        supportTicketStatus: supportTicket?.status || null,
        supportTicketSla: supportTicket ? ticketSlaSnapshot(supportTicket.slaDueAt) : null,
        message: "Fraud report submitted successfully.",
        classification: snapshot.classification,
        reasons: snapshot.reasons,
        scanSummary: snapshot.scanSummary,
        ownershipStatus: snapshot.ownershipStatus,
        tamperChecks: {
          summary: tamperSummary.summary,
          highestRisk: tamperSummary.highestRisk,
          hasWarnings: tamperSummary.hasWarnings,
        },
      },
    });
  } catch (error) {
    console.error("reportFraud error:", error);
    return res.status(500).json({
      success: false,
      error: "Failed to submit fraud report",
    });
  }
};

export const submitProductFeedback = async (req: Request, res: Response) => {
  try {
    const parsed = productFeedbackSchema.safeParse(req.body || {});
    if (!parsed.success) {
      return res.status(400).json({
        success: false,
        error: parsed.error.errors[0]?.message || "Invalid feedback payload",
      });
    }

    const payload = parsed.data;
    const normalizedCode = payload.code.toUpperCase();
    const feedbackRate = enforceIncidentRateLimit({
      ip: req.ip,
      qrCode: normalizedCode,
      deviceFp: deriveRequestDeviceFingerprint(req, { allowClientHint: false }),
    });
    if (feedbackRate.blocked) {
      res.setHeader("Retry-After", String(feedbackRate.retryAfterSec));
      return res.status(429).json({
        success: false,
        error: "Too many feedback attempts. Please try again later.",
      });
    }

    const qrCode = await prisma.qRCode.findUnique({
      where: { code: normalizedCode },
      select: {
        id: true,
        code: true,
        licenseeId: true,
        batchId: true,
        batch: {
          select: {
            manufacturerId: true,
          },
        },
      },
    });

    const feedbackLog = await createAuditLog({
      action: "CUSTOMER_PRODUCT_FEEDBACK",
      entityType: "CustomerFeedback",
      entityId: qrCode?.id || normalizedCode,
      licenseeId: qrCode?.licenseeId || undefined,
      ipAddress: req.ip,
      details: {
        code: normalizedCode,
        rating: payload.rating,
        satisfaction: payload.satisfaction,
        notes: payload.notes || null,
        observedStatus: payload.observedStatus || null,
        observedOutcome: payload.observedOutcome || null,
        qrCodeId: qrCode?.id || null,
        batchId: qrCode?.batchId || null,
        manufacturerId: qrCode?.batch?.manufacturerId || null,
        pageUrl: payload.pageUrl || null,
        userAgent: req.get("user-agent") || null,
        submittedAt: new Date().toISOString(),
      },
    });

    return res.status(201).json({
      success: true,
      data: {
        feedbackId: feedbackLog.id,
        message: "Feedback submitted successfully.",
      },
    });
  } catch (error) {
    console.error("submitProductFeedback error:", error);
    return res.status(500).json({
      success: false,
      error: "Failed to submit product feedback",
    });
  }
};
