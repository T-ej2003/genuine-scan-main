import { Request, Response } from "express";
import { z } from "zod";

import prisma from "../config/database";
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

const makeReferenceCode = (prefix: string) => {
  const date = new Date().toISOString().slice(2, 10).replace(/-/g, "");
  const random = Math.random().toString(36).slice(2, 8).toUpperCase();
  return `${prefix}-${date}-${random}`;
};

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

    const referenceCode = makeReferenceCode("RA");
    const data = parsed.data;

    const created = await prisma.requestAccess.create({
      data: {
        referenceCode,
        fullName: data.fullName,
        workEmail: data.workEmail,
        companyName: data.companyName,
        roleTitle: data.role,
        country: data.country,
        monthlyGarmentVolume: data.monthlyGarmentVolume,
        message: data.message,
        sourcePage: data.sourcePage?.trim() || null,
        referrer: data.referrer?.trim() || null,
      },
    });

    const [adminMail, ackMail] = await Promise.all([
      sendRequestAccessAdminNotification({
        referenceCode,
        fullName: created.fullName,
        workEmail: created.workEmail,
        companyName: created.companyName,
        roleTitle: created.roleTitle,
        country: created.country,
        monthlyGarmentVolume: created.monthlyGarmentVolume,
        message: created.message,
        sourcePage: created.sourcePage,
      }),
      sendRequestAccessAcknowledgement({
        referenceCode,
        fullName: created.fullName,
        workEmail: created.workEmail,
        companyName: created.companyName,
      }),
    ]);

    await prisma.requestAccess.update({
      where: { id: created.id },
      data: {
        adminEmailDeliveryStatus: toDeliveryStatus(adminMail),
        adminEmailErrorCode: safeEmailError(adminMail.errorCode),
        acknowledgementEmailDeliveryStatus: toDeliveryStatus(ackMail),
        acknowledgementEmailErrorCode: safeEmailError(ackMail.errorCode),
      },
    });

    await createAuditLogSafely({
      action: "REQUEST_ACCESS_SUBMITTED",
      entityType: "RequestAccess",
      entityId: created.id,
      ipAddress: req.ip,
      userAgent: req.get("user-agent") || undefined,
      details: {
        referenceCode,
        companyName: created.companyName,
        adminEmailDeliveryStatus: toDeliveryStatus(adminMail),
        acknowledgementEmailDeliveryStatus: toDeliveryStatus(ackMail),
      },
    });

    return res.status(201).json({
      success: true,
      data: {
        referenceCode,
        status: created.status,
        emailDeliveryStatus: toDeliveryStatus(adminMail),
        acknowledgementEmailDeliveryStatus: toDeliveryStatus(ackMail),
        message:
          adminMail.delivered || adminMail.errorCode === "EMAIL_DRY_RUN"
            ? "Request received. MSCQR will review your access request."
            : "Request received. Email notification could not be confirmed, but the MSCQR team can review it in the platform console.",
      },
    });
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

    const referenceCode = makeReferenceCode("SUP");
    const data = parsed.data;
    const created = await prisma.supportIssueReport.create({
      data: {
        referenceCode,
        publicName: data.name,
        publicEmail: data.email,
        issueType: data.issueType,
        title: data.title,
        description: data.message,
        verificationCode: data.verificationCode?.trim() || null,
        productReference: data.productReference?.trim() || null,
        sourcePath: data.sourcePath?.trim() || "/help/support",
        pageUrl: data.pageUrl?.trim() || null,
        priority: data.issueType === "verification_result" || data.issueType === "product_concern" ? "P2" : "P3",
        autoDetected: false,
        diagnostics: {
          publicIntake: true,
          issueType: data.issueType,
        },
      } as any,
    });

    const [adminMail, ackMail] = await Promise.all([
      sendPublicSupportAdminNotification({
        referenceCode,
        name: data.name,
        email: data.email,
        issueType: data.issueType,
        title: data.title,
        message: data.message,
        verificationCode: data.verificationCode,
        productReference: data.productReference,
        sourcePath: data.sourcePath,
      }),
      sendPublicSupportAcknowledgement({
        referenceCode,
        name: data.name,
        email: data.email,
        title: data.title,
      }),
    ]);

    await prisma.supportIssueReport.update({
      where: { id: created.id },
      data: {
        emailDeliveryStatus: toDeliveryStatus(adminMail),
        emailErrorCode: safeEmailError(adminMail.errorCode),
        acknowledgementEmailDeliveryStatus: toDeliveryStatus(ackMail),
        acknowledgementEmailErrorCode: safeEmailError(ackMail.errorCode),
      },
    });

    await createAuditLogSafely({
      action: "PUBLIC_SUPPORT_ISSUE_SUBMITTED",
      entityType: "SupportIssueReport",
      entityId: created.id,
      ipAddress: req.ip,
      userAgent: req.get("user-agent") || undefined,
      details: {
        referenceCode,
        issueType: data.issueType,
        emailDeliveryStatus: toDeliveryStatus(adminMail),
        acknowledgementEmailDeliveryStatus: toDeliveryStatus(ackMail),
      },
    });

    return res.status(201).json({
      success: true,
      data: {
        referenceCode,
        status: created.status,
        emailDeliveryStatus: toDeliveryStatus(adminMail),
        acknowledgementEmailDeliveryStatus: toDeliveryStatus(ackMail),
        message:
          adminMail.delivered || adminMail.errorCode === "EMAIL_DRY_RUN"
            ? "Support request received. Keep this reference for follow-up."
            : "Support request received. Email notification could not be confirmed, but MSCQR operators can review it in the platform console.",
      },
    });
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
    const where = parsed.data.status ? { status: parsed.data.status } : {};
    const [records, total] = await Promise.all([
      prisma.requestAccess.findMany({
        where,
        orderBy: [{ createdAt: "desc" }],
        take: limit,
        skip: offset,
        include: {
          assignedToUser: { select: { id: true, name: true, email: true } },
          reviewedByUser: { select: { id: true, name: true, email: true } },
        },
      }),
      prisma.requestAccess.count({ where }),
    ]);
    return res.json({ success: true, data: { records, total, limit, offset } });
  } catch (error) {
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

    const existing = await prisma.requestAccess.findUnique({ where: { id } });
    if (!existing) return res.status(404).json({ success: false, error: "Request access record not found" });

    const updateData: any = {};
    if (parsed.data.status) updateData.status = parsed.data.status;
    if (parsed.data.internalNote !== undefined) updateData.internalNote = parsed.data.internalNote || null;
    if (parsed.data.assignedToUserId !== undefined) updateData.assignedToUserId = parsed.data.assignedToUserId || null;
    if (parsed.data.status && parsed.data.status !== existing.status) {
      updateData.reviewedAt = new Date();
      updateData.reviewedByUserId = authReq.user?.userId || null;
    }

    const updated = await prisma.requestAccess.update({
      where: { id },
      data: updateData,
      include: {
        assignedToUser: { select: { id: true, name: true, email: true } },
        reviewedByUser: { select: { id: true, name: true, email: true } },
      },
    });

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
    console.error("patchRequestAccessRecord error:", error);
    return res.status(500).json({ success: false, error: "Failed to update request access record" });
  }
};
