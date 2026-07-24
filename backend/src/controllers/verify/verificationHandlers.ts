import { randomUUID } from "crypto";
import { Response } from "express";
import { z } from "zod";

import { CustomerVerifyRequest } from "../../middleware/customerVerifyAuth";
import { getB01PreAuthPrisma } from "../../rls-waves/session-b/b01/runtimeClients";
import {
  verifyRawQr,
  verifySignedQr,
  type VerifyRawQrRow,
} from "../../rls-waves/session-b/b02/publicBoundaryRepository";
import {
  hashToken as hashQrToken,
  isPrinterTestQrId,
  verifyQrToken,
} from "../../services/qrTokenService";
import { deriveRequestDeviceFingerprint, hashIp, hashToken, normalizeCode } from "./shared";

const paramsSchema = z.object({ code: z.string().trim().max(128).optional() }).strict();
const querySchema = z.object({
  t: z.string().trim().min(16).max(4096).optional(),
  transfer: z.string().trim().max(512).optional(),
  device: z.string().trim().max(256).optional(),
  lat: z.union([z.string().trim().max(40), z.number()]).optional(),
  lon: z.union([z.string().trim().max(40), z.number()]).optional(),
  acc: z.union([z.string().trim().max(40), z.number()]).optional(),
}).strict();

const messageFor = (key: string) => ({
  "verification.first_scan": "MSCQR verified this released label for the first time.",
  "verification.repeat": "MSCQR verified this released label again.",
  "verification.changed_context": "This label was verified from a different context. Check the product and report a concern if anything looks wrong.",
  "verification.blocked": "This label is not valid for verification.",
  "verification.not_ready": "This label is not ready for customer verification.",
  "verification.not_found": "This code could not be verified.",
}[key] || "Verification completed.");

export const buildPublicVerificationResponse = (
  row: VerifyRawQrRow,
  customerAuthenticated: boolean
) => {
  const publicStatus = {
    AUTHENTIC: "verified", AUTHENTIC_REPEAT: "verified", REVIEW: "review_needed",
    BLOCKED: "blocked", NOT_READY: "not_ready", NOT_FOUND: "not_found",
  }[row.result] || "not_found";
  const firstScan = row.messageKey === "verification.first_scan";
  return ({
  isAuthentic: row.result === "AUTHENTIC" || row.result === "AUTHENTIC_REPEAT",
  messageKey: row.messageKey,
  nextActionKey: row.nextAction,
  message: messageFor(row.messageKey),
  code: row.maskedCode,
  maskedCode: row.maskedCode,
  brandName: row.brandName,
  publicStatus,
  status: publicStatus,
  scanStatus: firstScan ? "first_successful_scan" : "previously_scanned",
  riskSignalStatus: row.result === "REVIEW" ? "needs_brand_review"
    : row.result === "BLOCKED" ? "brand_action_required"
      : row.result === "NOT_READY" ? "activation_not_complete"
        : row.result === "NOT_FOUND" ? "not_assessed" : "clear",
  isFirstScan: firstScan,
  copyableCodeCaveat: "A QR code can be copied. MSCQR also checks release state and verification history.",
  licensee: {
    name: row.brandName,
    brandName: row.brandName,
    website: row.brandWebsite,
    supportEmail: row.brandSupportEmail,
    supportPhone: row.brandSupportPhone,
  },
  batch: {
    manufacturer: {
      name: row.manufacturerName,
      website: row.manufacturerWebsite,
    },
  },
  manufacturerName: row.manufacturerName,
  manufacturerWebsite: row.manufacturerWebsite,
  printedAt: row.printedAt,
  scanSummary: {
    firstVerifiedAt: row.firstVerifiedAt,
    latestVerifiedAt: row.latestVerifiedAt,
  },
  ownershipStatus: {
    isClaimed: false,
    isOwnedByRequester: false,
    isClaimedByAnother: false,
    canClaim: row.ownershipClaimAvailable,
  },
  sessionStartToken: row.sessionStartToken,
  challenge: {
    required: row.result === "REVIEW" && !customerAuthenticated,
    completed: row.result === "REVIEW" && customerAuthenticated,
  },
  verifyUxPolicy: {
    showTimelineCard: true,
    showRiskCards: false,
    allowOwnershipClaim: row.ownershipClaimAvailable,
    allowFraudReport: true,
    mobileCameraAssist: true,
  },
  });
};

const publicFailure = (res: Response, status: number, error: string) =>
  res.status(status).json({ success: false, error });

export const verifyQRCode = async (req: CustomerVerifyRequest, res: Response) => {
  const params = paramsSchema.safeParse(req.params || {});
  const query = querySchema.safeParse(req.query || {});
  if (!params.success || !query.success) return publicFailure(res, 400, "Invalid verification request");

  const code = normalizeCode(params.data.code || "");
  const token = query.data.t || null;
  if (!token && !code) return publicFailure(res, 400, "Invalid QR code format");
  if (!token && !/^[A-Za-z0-9][A-Za-z0-9_-]{7,127}$/.test(code)) {
    return publicFailure(res, 400, "Invalid QR code format");
  }

  const checkedAt = new Date();
  const requestId = String((req as CustomerVerifyRequest & { requestId?: string }).requestId || randomUUID());
  const actorIpHash = hashIp(req.ip);
  const fingerprint = deriveRequestDeviceFingerprint(req);
  const actorDeviceHash = fingerprint ? hashToken(`device:${fingerprint}`) : null;

  try {
    const db = getB01PreAuthPrisma();
    const row = token
      ? await (() => {
          const verified = verifyQrToken(token);
          const payload = verified.payload;
          if (isPrinterTestQrId(payload.qr_id)) {
            return Promise.resolve({
              result: "AUTHENTIC",
              messageKey: "verification.first_scan",
              nextAction: "NONE",
              verificationMethod: "SIGNED_LABEL",
              maskedCode: "PRINTER_SETUP_TEST",
              brandName: "MSCQR",
              brandWebsite: "https://mscqr.com",
              brandSupportEmail: null,
              brandSupportPhone: null,
              manufacturerName: null,
              manufacturerWebsite: null,
              printedAt: null,
              firstVerifiedAt: checkedAt,
              latestVerifiedAt: checkedAt,
              ownershipClaimAvailable: false,
              sessionStartToken: null,
            });
          }
          return verifySignedQr(db, {
            tokenDigest: hashQrToken(token),
            qrId: payload.qr_id,
            licenseeId: payload.licensee_id,
            batchId: payload.batch_id,
            manufacturerId: payload.manufacturer_id || null,
            nonce: payload.nonce,
            replayEpoch: payload.epoch || 1,
            keyVersion: payload.kid || verified.signing.keyVersion,
            issuedAt: new Date(payload.iat * 1000),
            expiresAt: new Date((payload.exp || 0) * 1000),
            checkedAt,
            requestId,
            actorIpHash,
            actorDeviceHash,
          });
        })()
      : await verifyRawQr(db, { requestedCode: code, checkedAt, requestId, actorIpHash, actorDeviceHash });
    if (!row) return publicFailure(res, 404, "Requested information is unavailable.");
    return res.json({
      success: true,
      data: buildPublicVerificationResponse(row, Boolean(req.customer)),
    });
  } catch (error) {
    const message = String(error instanceof Error ? error.message : error);
    if (token && /PUBLIC_VERIFICATION_(?:SIGNED_)?INVALID/.test(message)) {
      return publicFailure(res, 400, "Request could not be verified.");
    }
    return res.status(503).json({
      success: false,
      degraded: true,
      code: "PUBLIC_VERIFICATION_UNAVAILABLE",
      error: "Verification is temporarily unavailable.",
    });
  }
};
