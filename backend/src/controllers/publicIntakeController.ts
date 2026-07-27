import { Request, Response } from "express";
import { randomUUID } from "crypto";
import { z } from "zod";

import { sanitizeUnknownInput } from "../middleware/requestSanitizer";
import { createAuditLogSafely } from "../services/auditService";
import {
  sendPublicSupportAcknowledgement,
  sendPublicSupportAdminNotification,
  sendRequestAccessAcknowledgement,
  sendRequestAccessAdminNotification,
  toDeliveryStatus,
} from "../services/supportIntakeMailService";
import { normalizeEmailAddress } from "../utils/email";
import { isPrismaMissingTableError, warnStorageUnavailableOnce } from "../utils/prismaStorageGuard";
import { isB02AuthorizationError, withB02AuthenticatedRequest } from "../rls-waves/session-b/b02/authenticatedBoundary";
import {
  listRequestAccessRows as listRequestAccessRowsThroughBoundary,
  updateRequestAccessRow as updateRequestAccessRowThroughBoundary,
} from "../rls-waves/session-b/b02/authenticatedRepositories";
import {
  b02IdempotencyDigest,
  completePublicSupportDelivery,
  completeRequestAccessDelivery,
  submitPublicSupport as submitPublicSupportThroughBoundary,
  submitRequestAccess as submitRequestAccessThroughBoundary,
} from "../rls-waves/session-b/b02/publicBoundaryRepository";
import { getB01PreAuthPrisma } from "../rls-waves/session-b/b01/runtimeClients";

const nullableTrimmed = (max: number) => z.string().trim().max(max).optional().or(z.literal(""));
const honeypotSchema = z.string().max(0).optional().or(z.literal(""));

const requestAccessSchema = z
  .object({
    fullName: z.string().trim().min(2).max(120),
    workEmail: z.string().trim().email().max(160).transform((value) => normalizeEmailAddress(value) as string),
    companyName: z.string().trim().min(2).max(160),
    role: z.string().trim().min(2).max(120),
    country: z.string().trim().min(2).max(120),
    monthlyGarmentVolume: z.string().trim().min(1).max(80),
    message: z.string().trim().min(10).max(3000),
    sourcePage: nullableTrimmed(500),
    referrer: nullableTrimmed(1200),
    website: honeypotSchema,
    companyUrl: honeypotSchema,
  })
  .strict();

const publicSupportSchema = z
  .object({
    name: z.string().trim().min(2).max(120),
    email: z.string().trim().email().max(160).transform((value) => normalizeEmailAddress(value) as string),
    issueType: z.enum(["verification_result", "scan_problem", "product_concern", "platform_access", "privacy", "other"]),
    title: z.string().trim().min(5).max(160),
    message: z.string().trim().min(10).max(4000),
    verificationCode: nullableTrimmed(160),
    productReference: nullableTrimmed(160),
    sourcePath: nullableTrimmed(500),
    pageUrl: nullableTrimmed(1200),
    website: honeypotSchema,
    companyUrl: honeypotSchema,
  })
  .strict();

const requestAccessStatusSchema = z
  .object({
    status: z.enum(["NEW", "REVIEWING", "CONTACTED", "QUALIFIED", "CLOSED"]).optional(),
    internalNote: z.string().trim().max(4000).nullable().optional(),
    assignedToUserId: z.string().uuid().nullable().optional(),
  })
  .strict()
  .refine((value) => Object.keys(value).length > 0, "No changes provided");

const requestAccessListSchema = z
  .object({
    status: z.enum(["NEW", "REVIEWING", "CONTACTED", "QUALIFIED", "CLOSED"]).optional(),
    limit: z.coerce.number().int().min(1).max(100).optional(),
    offset: z.coerce.number().int().min(0).max(2000).optional(),
  })
  .strict();

const parseBody = <T>(schema: z.ZodType<T>, body: unknown) => {
  const sanitized = sanitizeUnknownInput(body || {}, "body");
  return schema.safeParse(sanitized);
};

const safeEmailError = (value?: string | null) => String(value || "").slice(0, 80) || null;

export const submitPublicRequestAccess = async (req: Request, res: Response) => {
  try {
    const parsed = parseBody(requestAccessSchema, req.body || {});
    if (!parsed.success) {
      return res.status(400).json({ success: false, error: parsed.error.errors[0]?.message || "Invalid request" });
    }

    const data = parsed.data;
    {
      const submittedAt = new Date();
      const requestId = String((req as Request & { requestId?: string }).requestId || randomUUID()).trim();
      const idempotencyDigest = b02IdempotencyDigest({
        workflow: "submit-request-access",
        workEmail: data.workEmail,
        companyName: data.companyName,
        message: data.message,
      });
      const accepted = await submitRequestAccessThroughBoundary(getB01PreAuthPrisma(), {
        fullName: data.fullName,
        workEmail: data.workEmail,
        companyName: data.companyName,
        roleTitle: data.role,
        country: data.country,
        monthlyVolume: data.monthlyGarmentVolume,
        message: data.message,
        sourcePage: data.sourcePage?.trim() || null,
        referrer: data.referrer?.trim() || null,
        submittedAt,
        requestId,
        idempotencyDigest,
      });
      if (!accepted?.accepted) {
        return res.status(503).json({ success: false, error: "Request access intake is temporarily unavailable." });
      }
      if (!accepted.deliveryRequired) {
        return res.status(201).json({
          success: true,
          data: {
            referenceCode: accepted.publicReference,
            status: "NEW",
            emailDeliveryStatus: "SKIPPED",
            acknowledgementEmailDeliveryStatus: "SKIPPED",
            message: accepted.message,
          },
        });
      }
      const [adminMail, ackMail] = await Promise.all([
        sendRequestAccessAdminNotification({
          referenceCode: accepted.publicReference,
          fullName: data.fullName,
          workEmail: data.workEmail,
          companyName: data.companyName,
          roleTitle: data.role,
          country: data.country,
          monthlyGarmentVolume: data.monthlyGarmentVolume,
          message: data.message,
          sourcePage: data.sourcePage?.trim() || null,
        }),
        sendRequestAccessAcknowledgement({
          referenceCode: accepted.publicReference,
          fullName: data.fullName,
          workEmail: data.workEmail,
          companyName: data.companyName,
        }),
      ]);
      await completeRequestAccessDelivery(getB01PreAuthPrisma(), {
        idempotencyDigest,
        adminStatus: toDeliveryStatus(adminMail),
        adminError: safeEmailError(adminMail.errorCode),
        acknowledgementStatus: toDeliveryStatus(ackMail),
        acknowledgementError: safeEmailError(ackMail.errorCode),
        completedAt: new Date(),
        requestId,
      });
      return res.status(201).json({
        success: true,
        data: {
          referenceCode: accepted.publicReference,
          status: "NEW",
          emailDeliveryStatus: toDeliveryStatus(adminMail),
          acknowledgementEmailDeliveryStatus: toDeliveryStatus(ackMail),
          message: accepted.message,
        },
      });
    }
  } catch (error) {
    if (isPrismaMissingTableError(error, ["requestaccess"])) {
      warnStorageUnavailableOnce("request-access-storage", "[request-access] request access storage unavailable.");
      return res.status(503).json({ success: false, error: "Request access intake is temporarily unavailable." });
    }
    console.error("submitPublicRequestAccess error:", error);
    return res.status(500).json({ success: false, error: "Could not submit request access form." });
  }
};

export const submitPublicSupportIssue = async (req: Request, res: Response) => {
  try {
    const parsed = parseBody(publicSupportSchema, req.body || {});
    if (!parsed.success) {
      return res.status(400).json({ success: false, error: parsed.error.errors[0]?.message || "Invalid support request" });
    }

    const data = parsed.data;
    {
      const submittedAt = new Date();
      const requestId = String((req as Request & { requestId?: string }).requestId || randomUUID()).trim();
      const idempotencyDigest = b02IdempotencyDigest({
        workflow: "submit-public-support",
        publicEmail: data.email,
        issueType: data.issueType,
        title: data.title,
        message: data.message,
        verificationCode: data.verificationCode?.trim() || null,
      });
      const accepted = await submitPublicSupportThroughBoundary(getB01PreAuthPrisma(), {
        publicName: data.name,
        publicEmail: data.email,
        issueType: data.issueType,
        title: data.title,
        description: data.message,
        verifiedCode: data.verificationCode?.trim() || null,
        productReference: data.productReference?.trim() || null,
        sourcePath: data.sourcePath?.trim() || "/help/support",
        pageUrl: data.pageUrl?.trim() || null,
        submittedAt,
        requestId,
        idempotencyDigest,
      });
      if (!accepted?.accepted) {
        return res.status(503).json({ success: false, error: "Support intake is temporarily unavailable." });
      }
      if (!accepted.deliveryRequired) {
        return res.status(201).json({
          success: true,
          data: {
            referenceCode: accepted.publicReference,
            status: "OPEN",
            emailDeliveryStatus: "SKIPPED",
            acknowledgementEmailDeliveryStatus: "SKIPPED",
            message: accepted.message,
          },
        });
      }
      const safeVerificationCode = data.verificationCode
        ? `${"*".repeat(Math.max(4, data.verificationCode.length - 4))}${data.verificationCode.slice(-4)}`
        : null;
      const [adminMail, ackMail] = await Promise.all([
        sendPublicSupportAdminNotification({
          referenceCode: accepted.publicReference,
          name: data.name,
          email: data.email,
          issueType: data.issueType,
          title: data.title,
          message: data.message,
          verificationCode: safeVerificationCode,
          productReference: data.productReference?.trim() || null,
          sourcePath: data.sourcePath?.trim() || "/help/support",
        }),
        sendPublicSupportAcknowledgement({
          referenceCode: accepted.publicReference,
          name: data.name,
          email: data.email,
          title: data.title,
        }),
      ]);
      await completePublicSupportDelivery(getB01PreAuthPrisma(), {
        idempotencyDigest,
        adminStatus: toDeliveryStatus(adminMail),
        adminError: safeEmailError(adminMail.errorCode),
        acknowledgementStatus: toDeliveryStatus(ackMail),
        acknowledgementError: safeEmailError(ackMail.errorCode),
        completedAt: new Date(),
        requestId,
      });
      return res.status(201).json({
        success: true,
        data: {
          referenceCode: accepted.publicReference,
          status: "OPEN",
          emailDeliveryStatus: toDeliveryStatus(adminMail),
          acknowledgementEmailDeliveryStatus: toDeliveryStatus(ackMail),
          message: accepted.message,
        },
      });
    }
  } catch (error) {
    if (isPrismaMissingTableError(error, ["supportissuereport"])) {
      warnStorageUnavailableOnce("public-support-storage", "[support] public support storage unavailable.");
      return res.status(503).json({ success: false, error: "Support intake is temporarily unavailable." });
    }
    console.error("submitPublicSupportIssue error:", error);
    return res.status(500).json({ success: false, error: "Could not submit support request." });
  }
};

export const listRequestAccessRecords = async (req: Request, res: Response) => {
  try {
    const parsed = requestAccessListSchema.safeParse(req.query || {});
    if (!parsed.success) {
      return res.status(400).json({ success: false, error: parsed.error.errors[0]?.message || "Invalid filters" });
    }
    const limit = parsed.data.limit ?? 50;
    const offset = parsed.data.offset ?? 0;
    const data = await withB02AuthenticatedRequest(
      req as Request & { user?: any },
      { purpose: "request-access-read", assurance: "mfa-verified" },
      async (tx) => {
        const [records, total] = await listRequestAccessRowsThroughBoundary(tx, {
          status: parsed.data.status,
          limit,
          offset,
        });
        return { records, total, limit, offset };
      }
    );
    return res.json({ success: true, data });
  } catch (error) {
    if (isB02AuthorizationError(error)) {
      return res.status(403).json({ success: false, error: "Request access authorization is stale or insufficient." });
    }
    if (isPrismaMissingTableError(error, ["requestaccess"])) {
      warnStorageUnavailableOnce("request-access-list-storage", "[request-access] request access list storage unavailable.");
      return res.status(503).json({
        success: false,
        error: "Request access records are temporarily unavailable. Run the latest database migration and retry.",
      });
    }
    console.error("listRequestAccessRecords error:", error);
    return res.status(500).json({ success: false, error: "Failed to load request access records" });
  }
};

export const patchRequestAccessRecord = async (req: Request, res: Response) => {
  try {
    const authReq = req as any;
    const id = String(req.params.id || "").trim();
    if (!id) return res.status(400).json({ success: false, error: "Request access ID is required" });
    const parsed = requestAccessStatusSchema.safeParse(req.body || {});
    if (!parsed.success) {
      return res.status(400).json({ success: false, error: parsed.error.errors[0]?.message || "Invalid request access update" });
    }

    const updated = await withB02AuthenticatedRequest(
      req as Request & { user?: any },
      { purpose: "request-access-update", assurance: "mfa-verified" },
      (tx, context) => updateRequestAccessRowThroughBoundary(tx, {
        id,
        actorUserId: context.userId,
        status: parsed.data.status,
        internalNote: parsed.data.internalNote,
        assignedToUserId: parsed.data.assignedToUserId,
      })
    );
    if (!updated) return res.status(404).json({ success: false, error: "Request access record not found" });
    await createAuditLogSafely({
      userId: authReq.user?.userId,
      action: "REQUEST_ACCESS_UPDATED",
      entityType: "RequestAccess",
      entityId: id,
      ipAddress: req.ip,
      userAgent: req.get("user-agent") || undefined,
      details: {
        status: updated.status,
        assignedToUserId: updated.assignedToUserId,
        internalNoteChanged: parsed.data.internalNote !== undefined,
      },
    });

    return res.json({ success: true, data: updated });
  } catch (error) {
    if (isB02AuthorizationError(error)) {
      return res.status(403).json({ success: false, error: "Request access authorization is stale or insufficient." });
    }
    if (isPrismaMissingTableError(error, ["requestaccess"])) {
      warnStorageUnavailableOnce("request-access-update-storage", "[request-access] request access update storage unavailable.");
      return res.status(503).json({
        success: false,
        error: "Request access records are temporarily unavailable. Run the latest database migration and retry.",
      });
    }
    console.error("patchRequestAccessRecord error:", error);
    return res.status(500).json({ success: false, error: "Failed to update request access record" });
  }
};
