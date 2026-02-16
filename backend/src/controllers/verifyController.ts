import { Request, Response } from "express";
import { IncidentActorType, Prisma, QRStatus } from "@prisma/client";
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
import { recordScan } from "../services/qrService";
import { getScanInsight } from "../services/scanInsightService";
import { resolveVerifyUxPolicy } from "../services/governanceService";
import { runTamperEvidenceChecks, summarizeTamperFindings } from "../services/tamperEvidenceService";
import { ticketSlaSnapshot } from "../services/supportWorkflowService";

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
};

type OwnershipRecord = {
  userId: string;
  claimedAt: Date;
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

const deriveDuplicateReasons = (params: {
  scanCount: number;
  scanSignals?: {
    distinctDeviceCount24h?: number;
    recentScanCount10m?: number;
    distinctCountryCount24h?: number;
  } | null;
  policy?: any;
}) => {
  const reasons: string[] = [];
  const scanSignals = params.scanSignals || null;
  const policy = params.policy || null;
  const triggered = policy?.triggered || {};
  const alerts = Array.isArray(policy?.alerts) ? policy.alerts : [];

  if (Number(scanSignals?.distinctDeviceCount24h ?? 0) > 1) {
    reasons.push("Multiple devices scanned this code recently.");
  }
  if (Number(scanSignals?.recentScanCount10m ?? 0) >= 3) {
    reasons.push("A short burst of scans was detected.");
  }
  if (Number(scanSignals?.distinctCountryCount24h ?? 0) > 1) {
    reasons.push("Recent scans came from different countries.");
  }
  if (params.scanCount >= 4 || triggered.multiScan) {
    reasons.push("High repeat-scan volume was detected.");
  }
  if (triggered.geoDrift) {
    reasons.push("Scan geography drift exceeded policy threshold.");
  }
  if (triggered.velocitySpike) {
    reasons.push("Scan velocity exceeded policy threshold.");
  }

  for (const alert of alerts) {
    const message = String(alert?.message || "").trim();
    if (!message) continue;
    if (!reasons.includes(message)) reasons.push(message);
  }

  return reasons.slice(0, 6);
};

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
  isReady: boolean;
  isBlocked: boolean;
}): OwnershipStatus => {
  const ownership = params.ownership;
  const customerUserId = String(params.customerUserId || "").trim();

  if (!ownership) {
    return {
      isClaimed: false,
      claimedAt: null,
      isOwnedByRequester: false,
      isClaimedByAnother: false,
      canClaim: params.isReady && !params.isBlocked && Boolean(customerUserId),
    };
  }

  const isOwnedByRequester = Boolean(customerUserId) && ownership.userId === customerUserId;

  return {
    isClaimed: true,
    claimedAt: ownership.claimedAt.toISOString(),
    isOwnedByRequester,
    isClaimedByAnother: !isOwnedByRequester,
    canClaim: false,
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
        userId: true,
        claimedAt: true,
      },
    });
  } catch (error) {
    if (isOwnershipStorageMissingError(error)) {
      if (!ownershipStorageWarningLogged) {
        ownershipStorageWarningLogged = true;
        console.warn(
          "[verify] Ownership table is unavailable. Continuing verification without ownership data. Apply migration 20260216183000_add_verify_ownership."
        );
      }
      return null;
    }
    throw error;
  }
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

  const scanInsight = await getScanInsight(qrCode.id, null);
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

  const duplicateReasons = deriveDuplicateReasons({
    scanCount: scanSummary.totalScans,
    scanSignals: scanInsight.signals,
  });

  return {
    classification: duplicateReasons.length ? ("SUSPICIOUS_DUPLICATE" as VerifyClassification) : ("LEGIT_REPEAT" as VerifyClassification),
    reasons: duplicateReasons.length ? duplicateReasons : ["Repeat scans match expected customer re-verification behavior."],
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
        },
      });
    }

    const verifyUxPolicy = await resolveVerifyUxPolicy(qrCode.licenseeId || null);

    const customerUserId = req.customer?.userId || null;
    const containment = buildContainment(qrCode);
    const scanInsight = await getScanInsight(qrCode.id, (req.query.device as string | undefined) || null);
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
      isReady: qrReady,
      isBlocked: qrBlocked,
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
          verificationTimeline,
          riskExplanation,
          verifyUxPolicy,
          isBlocked: true,
          isReady: false,
          totalScans: baseScanSummary.totalScans,
          firstVerifiedAt: baseScanSummary.firstVerifiedAt,
          latestVerifiedAt: baseScanSummary.latestVerifiedAt,
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
          verificationTimeline,
          riskExplanation,
          verifyUxPolicy,
          isBlocked: false,
          isReady: false,
          totalScans: baseScanSummary.totalScans,
          firstVerifiedAt: baseScanSummary.firstVerifiedAt,
          latestVerifiedAt: baseScanSummary.latestVerifiedAt,
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
      device: (req.query.device as string | undefined) || null,
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
    const postScanInsight = await getScanInsight(updated.id, (req.query.device as string | undefined) || null);
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
      isReady,
      isBlocked,
    });

    const duplicateReasons = deriveDuplicateReasons({
      scanCount: postScanSummary.totalScans,
      scanSignals: postScanInsight.signals,
      policy,
    });

    let classification: VerifyClassification;
    let reasons: string[];

    if (isBlocked) {
      classification = "BLOCKED_BY_SECURITY";
      reasons = [
        blockedByPolicy
          ? "Security policy auto-blocked this code after anomaly detection."
          : "This code is blocked by security controls.",
        ...buildSecurityContainmentReasons(runtimeContainment),
      ];
    } else if (isFirstScan) {
      classification = "FIRST_SCAN";
      reasons = ["First successful customer verification recorded."];
    } else if (duplicateReasons.length > 0) {
      classification = "SUSPICIOUS_DUPLICATE";
      reasons = duplicateReasons;
    } else {
      classification = "LEGIT_REPEAT";
      reasons = ["Repeat verification pattern matches normal customer behavior."];
    }

    if (ownershipStatus.isClaimedByAnother && customerUserId && !isBlocked) {
      classification = "SUSPICIOUS_DUPLICATE";
      if (!reasons.includes("Ownership is already claimed by another account.")) {
        reasons.unshift("Ownership is already claimed by another account.");
      }
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
        verificationTimeline,
        riskExplanation,
        verifyUxPolicy,
        isBlocked,
        isReady,
        totalScans: postScanSummary.totalScans,
        firstVerifiedAt: postScanSummary.firstVerifiedAt,
        latestVerifiedAt: postScanSummary.latestVerifiedAt,

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

    const isBlocked = qrCode.status === QRStatus.BLOCKED;
    const isReady = isQrReadyForCustomerUse(qrCode.status);
    const existingOwnership = await loadOwnershipByQrCodeId(qrCode.id);

    const buildClaimResponse = (ownership: { userId: string; claimedAt: Date } | null) => {
      const ownershipStatus = buildOwnershipStatus({
        ownership,
        customerUserId: customer.userId,
        isReady,
        isBlocked,
      });
      return {
        ownershipStatus,
        claimTimestamp: ownership?.claimedAt?.toISOString?.() || null,
      };
    };

    if (isBlocked || !isReady) {
      return res.status(409).json({
        success: false,
        error: isBlocked
          ? "Claim not allowed for blocked products"
          : "Claim is available only after product activation",
      });
    }

    if (existingOwnership) {
      if (existingOwnership.userId === customer.userId) {
        return res.json({
          success: true,
          data: {
            claimResult: "ALREADY_OWNED_BY_YOU",
            message: "This product is already owned by your account.",
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
          requesterUserId: customer.userId,
          existingOwnership: true,
        },
      });

      return res.json({
        success: true,
        data: {
          claimResult: "OWNED_BY_ANOTHER_USER",
          conflict: true,
          classification: "SUSPICIOUS_DUPLICATE",
          reasons: [
            "Ownership is already claimed by another account.",
            "If this is unexpected, report suspected counterfeit immediately.",
          ],
          warningMessage: "Ownership conflict detected. Treat this product as potential duplicate until reviewed.",
          ...buildClaimResponse(existingOwnership),
        },
      });
    }

    let createdOwnership: { userId: string; claimedAt: Date } | null = null;

    try {
      const created = await prisma.ownership.create({
        data: {
          qrCodeId: qrCode.id,
          userId: customer.userId,
        },
        select: {
          userId: true,
          claimedAt: true,
        },
      });
      createdOwnership = created;
    } catch (error: any) {
      if (isOwnershipStorageMissingError(error)) {
        return res.status(503).json({
          success: false,
          error: "Ownership feature is temporarily unavailable. Please retry after maintenance.",
        });
      }

      if (error instanceof Prisma.PrismaClientKnownRequestError && error.code === "P2002") {
        const existing = await loadOwnershipByQrCodeId(qrCode.id);

        if (existing && existing.userId === customer.userId) {
          createdOwnership = existing;
        } else {
          return res.json({
            success: true,
            data: {
              claimResult: "OWNED_BY_ANOTHER_USER",
              conflict: true,
              classification: "SUSPICIOUS_DUPLICATE",
              reasons: [
                "Ownership is already claimed by another account.",
                "If this is unexpected, report suspected counterfeit immediately.",
              ],
              warningMessage: "Ownership conflict detected. Treat this product as potential duplicate until reviewed.",
              ...buildClaimResponse(existing),
            },
          });
        }
      } else {
        throw error;
      }
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
        customerUserId: customer.userId,
      },
    });

    return res.status(201).json({
      success: true,
      data: {
        claimResult: "CLAIMED",
        message: "Product ownership claimed successfully.",
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
