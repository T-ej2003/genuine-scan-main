//backend/src/controllers/licenseeController.ts
import { Response } from "express";
import { z } from "zod";
import { Prisma, UserRole } from "@prisma/client";
import prisma from "../config/database";
import { AuthRequest } from "../middleware/auth";
import { createAuditLogInTransaction } from "../services/auditService";
import { randomUUID } from "crypto";
import { hashPassword } from "../services/auth/passwordService";
import { createInvite } from "../services/auth/inviteService";
import { hashIp, normalizeUserAgent } from "../utils/security";
import { isValidEmailAddress, normalizeEmailAddress } from "../utils/email";
import { extractIdempotencyKey } from "../services/idempotencyService";
import { maskEmailForLog } from "../services/mailTransportService";
import { withCanonicalDbContext } from "../lib/canonicalDbContext";
import {
  AdministrationAccessError,
  administrationPurposes,
  buildAdministrationBoundary,
  createLicenseeInTransaction,
  deleteLicenseeInTransaction,
  installAdministrationResultScope,
  updateLicenseeInTransaction,
} from "../rls-waves/session-c/c01/administrationRepository";

const prefixSchema = z
  .string()
  .trim()
  .min(1)
  .max(5)
  .transform((s) => s.toUpperCase())
  .refine((s) => /^[A-Z0-9]+$/.test(s), "Prefix must be A–Z / 0–9 only");

const optionalEmailSchema = (label: string) =>
  z
    .union([
      z.literal(""),
      z
        .string()
        .trim()
        .min(3, `Invalid ${label}`)
        .max(320, `Invalid ${label}`)
        .refine((value) => isValidEmailAddress(value), `Invalid ${label}`)
        .transform((value) => normalizeEmailAddress(value) as string),
    ])
    .optional();

const adminSchema = z.object({
  name: z.string().trim().min(2, "Admin name must be at least 2 characters"),
  email: z
    .string()
    .trim()
    .min(3, "Invalid admin email")
    .max(320, "Invalid admin email")
    .refine((value) => isValidEmailAddress(value), "Invalid admin email")
    .transform((value) => normalizeEmailAddress(value) as string),
  password: z.string().min(6, "Admin password must be at least 6 characters").optional(),
  sendInvite: z.boolean().optional(),
}).strict();

// Format A (legacy)
const createLicenseeLegacy = z.object({
  name: z.string().trim().min(2, "Name must be at least 2 characters"),
  prefix: prefixSchema,
  description: z.string().trim().max(300).optional().or(z.literal("")),
  brandName: z.string().trim().max(120).optional().or(z.literal("")),
  location: z.string().trim().max(200).optional().or(z.literal("")),
  website: z.string().trim().max(200).optional().or(z.literal("")),
  supportEmail: optionalEmailSchema("support email"),
  supportPhone: z.string().trim().max(40).optional().or(z.literal("")),
  isActive: z.boolean().optional(),
  admin: adminSchema.optional(),
}).strict();

// Format B (new)
const createLicenseeWithAdmin = z.object({
  licensee: z.object({
    name: z.string().trim().min(2),
    prefix: prefixSchema,
    description: z.string().trim().max(300).optional().or(z.literal("")),
    brandName: z.string().trim().max(120).optional().or(z.literal("")),
    location: z.string().trim().max(200).optional().or(z.literal("")),
    website: z.string().trim().max(200).optional().or(z.literal("")),
    supportEmail: optionalEmailSchema("support email"),
    supportPhone: z.string().trim().max(40).optional().or(z.literal("")),
    isActive: z.boolean().optional(),
  }).strict(),
  admin: adminSchema,
}).strict();

const createLicenseeSchema = z.union([createLicenseeLegacy, createLicenseeWithAdmin]);

const updateLicenseeSchema = z.object({
  name: z.string().trim().min(2).optional(),
  description: z.string().trim().max(300).optional().or(z.literal("")),
  brandName: z.string().trim().max(120).optional().or(z.literal("")),
  location: z.string().trim().max(200).optional().or(z.literal("")),
  website: z.string().trim().max(200).optional().or(z.literal("")),
  supportEmail: optionalEmailSchema("support email"),
  supportPhone: z.string().trim().max(40).optional().or(z.literal("")),
  isActive: z.boolean().optional(),
}).strict();

const licenseeIdParamSchema = z.object({
  id: z.string().uuid("Invalid licensee id"),
}).strict();

type CreateLicenseeInput = z.infer<typeof createLicenseeSchema>;

const isNewFormat = (data: CreateLicenseeInput): data is z.infer<typeof createLicenseeWithAdmin> => {
  return typeof (data as any).licensee === "object" && typeof (data as any).admin === "object";
};

const escapeCsv = (v: any) => {
  if (v === null || v === undefined) return "";
  const s = String(v);
  return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
};

const mapIdempotencyError = (error: unknown) => {
  const msg = String((error as any)?.message || "");
  if (msg === "IDEMPOTENCY_KEY_IN_PROGRESS") {
    return { status: 409, error: "A matching create request is already in progress. Please wait a moment and refresh." };
  }
  if (msg === "IDEMPOTENCY_KEY_PAYLOAD_MISMATCH") {
    return { status: 409, error: "This request was already used for different details. Please retry from the form." };
  }
  if (msg === "IDEMPOTENCY_KEY_REQUIRED") {
    return { status: 400, error: "A request idempotency key is required." };
  }
  return null;
};

const licenseeConflictMessage = (target?: unknown) => {
  const fields = Array.isArray(target) ? target.map(String) : [String(target || "")];
  if (fields.some((field) => field.includes("prefix"))) return "A brand with this prefix already exists.";
  if (fields.some((field) => field.includes("email"))) return "An admin with this email already exists.";
  return "A brand or admin with these details already exists.";
};

const administrationRequestId = (req: AuthRequest) =>
  String((req as AuthRequest & { requestId?: string }).requestId || "").trim();

const administrationErrorResponse = (error: unknown) => {
  if (error instanceof AdministrationAccessError) {
    return { status: error.statusCode, error: error.message };
  }
  const message = String((error as any)?.meta?.message || (error as any)?.message || "");
  if (/SESSION_C_DUPLICATE_LICENSEE_OR_ADMIN/.test(message)) {
    return { status: 409, error: "A brand or admin with these details already exists." };
  }
  if (/SESSION_C_LICENSEE_LINKED_DATA/.test(message)) {
    return { status: 400, error: "Licensee has linked data. Deactivate it instead of hard deleting." };
  }
  if (/SESSION_C_LICENSEE_NOT_FOUND/.test(message)) {
    return { status: 404, error: "Licensee not found" };
  }
  if (/SESSION_C_(DISABLED_OR_STALE_ACTOR|STALE_PLATFORM_SCOPE|WRONG_ROLE|INVALID_CONTEXT|FOREIGN_SCOPE)/.test(message)) {
    return { status: 403, error: "Administration authority is stale or invalid." };
  }
  if (/SESSION_C_IDEMPOTENCY_(CONFLICT|IN_PROGRESS)/.test(message)) {
    return { status: 409, error: "This request conflicts with an existing operation." };
  }
  if (/40001|could not serialize access/i.test(message)) {
    return { status: 409, error: "This administration change conflicted with another request. Please retry." };
  }
  return null;
};

const buildLicenseeCreateResponse = (params: { created: boolean; licensee: any; adminUser: any; adminInvite: any; warning?: string | null }) => {
  const inviteCreated = Boolean(params.adminInvite?.inviteId || params.adminInvite?.inviteLink);
  const emailSent = params.adminInvite?.emailSent === true || params.adminInvite?.emailDelivered === true;
  const emailErrorCode = params.adminInvite?.emailErrorCode || params.adminInvite?.deliveryError || null;
  const emailDiagnostic = params.adminInvite?.emailDiagnostic || null;
  const emailAttempted = Boolean(params.adminInvite?.emailAttempted ?? params.adminInvite?.attempted ?? emailErrorCode ?? emailSent);
  const message = inviteCreated
    ? emailSent
      ? "Brand created and invite email was accepted by the mail provider."
      : "Brand created, but invite email delivery could not be confirmed."
    : params.warning
      ? "Brand created, but invite could not be generated."
      : "Brand created.";

  return {
    success: true,
    data: {
      ok: true,
      created: params.created,
      entity: params.licensee,
      licensee: params.licensee,
      adminUser: params.adminUser,
      adminInvite: params.adminInvite,
      invite: params.adminInvite
        ? {
            created: inviteCreated,
            emailAttempted,
            emailSent,
            emailErrorCode,
            emailDiagnostic,
            inviteLink: params.adminInvite.inviteLink || null,
            inviteId: params.adminInvite.inviteId || null,
            expiresAt: params.adminInvite.expiresAt || null,
          }
        : {
            created: false,
            emailAttempted: false,
            emailSent: false,
            emailErrorCode: params.warning ? "UNKNOWN_EMAIL_ERROR" : null,
            emailDiagnostic: params.warning || null,
            inviteLink: null,
          },
      message,
      warning: params.warning || null,
    },
  };
};

export const createLicensee = async (req: AuthRequest, res: Response) => {
  try {
    if (req.user?.role !== UserRole.SUPER_ADMIN && req.user?.role !== UserRole.PLATFORM_SUPER_ADMIN) {
      return res.status(403).json({ success: false, error: "Insufficient permissions" });
    }

    const parsed = createLicenseeSchema.safeParse(req.body);
    if (!parsed.success) {
      const first = parsed.error.errors[0];
      const fieldPath = first?.path?.join(".") || "";
      const errorMessage =
        fieldPath.endsWith("supportEmail")
          ? "Invalid support email. Use a valid address like user@chester.ac.uk."
          : first?.message || "Invalid input";
      return res.status(400).json({ success: false, error: errorMessage });
    }

    const payload = parsed.data;
    const licenseePayload = isNewFormat(payload) ? payload.licensee : payload;
    const adminPayload = isNewFormat(payload) ? payload.admin : payload.admin;

    if (!adminPayload) {
      return res.status(400).json({
        success: false,
        error: "Admin credentials are required when creating a licensee.",
      });
    }

    const prefix = licenseePayload.prefix.toUpperCase();

    const email = adminPayload.email.toLowerCase();
    const sendInvite = Boolean(adminPayload.sendInvite);
    const adminPassword = String(adminPayload.password || "").trim();

    if (!sendInvite && adminPassword.length < 6) {
      return res.status(400).json({
        success: false,
        error: "Admin password must be at least 6 characters when invite mode is disabled.",
      });
    }

    const boundary = buildAdministrationBoundary(req.user!, {
      purpose: administrationPurposes.createLicensee,
      requestId: administrationRequestId(req),
    });
    const passwordHash = sendInvite ? null : await hashPassword(adminPassword);
    const result = await withCanonicalDbContext(
      prisma,
      boundary.context,
      async (tx, installedContext) => {
        const created = await createLicenseeInTransaction<any>(tx, {
          id: randomUUID(),
          idempotencyKey: extractIdempotencyKey(req.headers as any, req.body as any),
          licensee: {
            name: licenseePayload.name,
            prefix,
            description: licenseePayload.description?.trim() || null,
            brandName: licenseePayload.brandName?.trim() || null,
            location: licenseePayload.location?.trim() || null,
            website: licenseePayload.website?.trim() || null,
            supportEmail: licenseePayload.supportEmail?.trim().toLowerCase() || null,
            supportPhone: licenseePayload.supportPhone?.trim() || null,
            isActive: licenseePayload.isActive ?? true,
          },
          admin: {
            email,
            name: adminPayload.name,
            passwordHash,
            sendInvite,
          },
        });
        const scopedContext = await installAdministrationResultScope(tx, installedContext, {
          licenseeId: created.licensee?.id,
          organizationId: created.licensee?.orgId,
        });
        if (!created.replayed) {
          await createAuditLogInTransaction(tx, scopedContext, {
            action: sendInvite ? "CREATE_LICENSEE_WITH_ADMIN_INVITE" : "CREATE_LICENSEE_WITH_ADMIN",
            entityType: "Licensee",
            entityId: created.licensee.id,
            details: {
              workflowId: "workflow-http-backend-src-controllers-licensee-controller-ts-create-licensee",
              requestId: scopedContext.requestId,
              purposeCode: scopedContext.purpose,
              licenseeName: created.licensee.name,
              prefix: created.licensee.prefix,
              adminEmail: maskEmailForLog(email),
              sendInvite,
            },
            ipAddress: req.ip,
            userAgent: req.get("user-agent"),
          });
        }
        return created;
      },
      { isolationLevel: Prisma.TransactionIsolationLevel.Serializable }
    );

    let adminInvite: any = result.adminInvite || null;
    let warning: string | null = null;
    if (sendInvite && !result.replayed && !adminInvite) {
      try {
        adminInvite = await createInvite({
          email,
          name: adminPayload.name,
          role: UserRole.LICENSEE_ADMIN,
          licenseeId: result.licensee.id,
          allowExistingInvitedUser: true,
          createdByUserId: req.user!.userId,
          ipHash: hashIp(req.ip),
          userAgent: normalizeUserAgent(req.get("user-agent")),
        });
      } catch (inviteError: any) {
        console.error("createLicensee invite creation failed:", { name: inviteError?.name, code: inviteError?.code });
        warning = "INVITE_CREATE_FAILED";
      }
    }

    const out = {
      ...result,
      adminInvite,
      warning,
    };
    const responsePayload = buildLicenseeCreateResponse({
      created: !result.replayed,
      licensee: out.licensee,
      adminUser: out.adminUser,
      adminInvite: out.adminInvite,
      warning: out.warning,
    });
    return res.status(result.replayed ? 200 : 201).json(responsePayload);
  } catch (e: any) {
    const mapped = administrationErrorResponse(e);
    if (mapped) return res.status(mapped.status).json({ success: false, error: mapped.error });
    if (e instanceof Prisma.PrismaClientKnownRequestError && e.code === "P2002") {
      return res.status(409).json({ success: false, error: licenseeConflictMessage(e.meta?.target), code: "DUPLICATE_LICENSEE_OR_ADMIN" });
    }
    console.error("createLicensee error:", { name: e?.name, code: e?.code });
    return res.status(500).json({ success: false, error: "Brand could not be created. Please retry or contact support." });
  }
};

export const getLicensees = async (_req: AuthRequest, res: Response) => {
  try {
    const now = new Date();
    const licensees = await prisma.licensee.findMany({
      orderBy: { createdAt: "desc" },
      include: {
        _count: { select: { users: true, qrCodes: true, batches: true } },
        qrRanges: {
          orderBy: { createdAt: "desc" },
          take: 1,
          select: { id: true, startCode: true, endCode: true, totalCodes: true, createdAt: true },
        },
        users: {
          where: {
            role: { in: [UserRole.LICENSEE_ADMIN, UserRole.ORG_ADMIN] },
            deletedAt: null,
          },
          orderBy: { createdAt: "asc" },
          select: {
            id: true,
            name: true,
            email: true,
            role: true,
            status: true,
            isActive: true,
            createdAt: true,
          },
          take: 5,
        },
        invites: {
          where: {
            role: { in: [UserRole.LICENSEE_ADMIN, UserRole.ORG_ADMIN] },
            usedAt: null,
            expiresAt: { gt: now },
          },
          orderBy: { createdAt: "desc" },
          select: {
            id: true,
            email: true,
            expiresAt: true,
            createdAt: true,
          },
          take: 1,
        },
      },
    });

    const data = licensees.map((l) => {
      const primaryAdmin = l.users?.[0] || null;
      const pendingInvite = l.invites?.[0] || null;
      return {
        ...l,
        latestRange: l.qrRanges?.[0] ?? null,
        adminOnboarding: {
          state: pendingInvite ? "PENDING" : primaryAdmin ? "ACTIVE" : "UNASSIGNED",
          adminUser: primaryAdmin,
          pendingInvite: pendingInvite
            ? {
                id: pendingInvite.id,
                email: pendingInvite.email,
                expiresAt: pendingInvite.expiresAt,
                createdAt: pendingInvite.createdAt,
              }
            : null,
        },
        qrRanges: undefined,
        users: undefined,
        invites: undefined,
      };
    });

    return res.json({ success: true, data });
  } catch (e) {
    console.error("getLicensees error:", e);
    return res.status(500).json({ success: false, error: "Internal server error" });
  }
};

export const getLicensee = async (req: AuthRequest, res: Response) => {
  try {
    const paramsParsed = licenseeIdParamSchema.safeParse(req.params || {});
    if (!paramsParsed.success) {
      return res.status(400).json({ success: false, error: paramsParsed.error.errors[0]?.message || "Invalid licensee id" });
    }
    const { id } = paramsParsed.data;

    const licensee = await prisma.licensee.findUnique({
      where: { id },
      include: {
        _count: { select: { users: true, qrCodes: true, batches: true } },
        qrRanges: { orderBy: { createdAt: "desc" } },
        users: {
          select: { id: true, name: true, email: true, role: true, isActive: true, createdAt: true },
        },
      },
    });

    if (!licensee) return res.status(404).json({ success: false, error: "Licensee not found" });

    return res.json({ success: true, data: licensee });
  } catch (e) {
    console.error("getLicensee error:", e);
    return res.status(500).json({ success: false, error: "Internal server error" });
  }
};

export const updateLicensee = async (req: AuthRequest, res: Response) => {
  try {
    const paramsParsed = licenseeIdParamSchema.safeParse(req.params || {});
    if (!paramsParsed.success) {
      return res.status(400).json({ success: false, error: paramsParsed.error.errors[0]?.message || "Invalid licensee id" });
    }
    const { id } = paramsParsed.data;

    const parsed = updateLicenseeSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ success: false, error: parsed.error.errors[0].message });
    }

    const data: any = {};
    if (parsed.data.name !== undefined) data.name = parsed.data.name;
    if (parsed.data.description !== undefined) {
      data.description = parsed.data.description?.trim() ? parsed.data.description.trim() : null;
    }
    if (parsed.data.brandName !== undefined) {
      data.brandName = parsed.data.brandName?.trim() ? parsed.data.brandName.trim() : null;
    }
    if (parsed.data.location !== undefined) {
      data.location = parsed.data.location?.trim() ? parsed.data.location.trim() : null;
    }
    if (parsed.data.website !== undefined) {
      data.website = parsed.data.website?.trim() ? parsed.data.website.trim() : null;
    }
    if (parsed.data.supportEmail !== undefined) {
      data.supportEmail = parsed.data.supportEmail?.trim()
        ? parsed.data.supportEmail.trim().toLowerCase()
        : null;
    }
    if (parsed.data.supportPhone !== undefined) {
      data.supportPhone = parsed.data.supportPhone?.trim() ? parsed.data.supportPhone.trim() : null;
    }
    if (parsed.data.isActive !== undefined) data.isActive = parsed.data.isActive;

    const boundary = buildAdministrationBoundary(req.user!, {
      purpose: administrationPurposes.updateLicensee,
      requestId: administrationRequestId(req),
      targetLicenseeId: id,
    });
    const updated = await withCanonicalDbContext(
      prisma,
      boundary.context,
      async (tx, installedContext) => {
        const result = await updateLicenseeInTransaction<any>(tx, { id, patch: data });
        const scopedContext = await installAdministrationResultScope(tx, installedContext, {
          licenseeId: result.licensee?.id,
          organizationId: result.licensee?.orgId,
        });
        await createAuditLogInTransaction(tx, scopedContext, {
          action: "UPDATE_LICENSEE",
          entityType: "Licensee",
          entityId: id,
          details: {
            workflowId: "workflow-http-backend-src-controllers-licensee-controller-ts-update-licensee",
            requestId: scopedContext.requestId,
            purposeCode: scopedContext.purpose,
            changed: Object.keys(data),
          },
          ipAddress: req.ip,
          userAgent: req.get("user-agent"),
        });
        return result.licensee;
      },
      { isolationLevel: Prisma.TransactionIsolationLevel.Serializable }
    );

    return res.json({ success: true, data: updated });
  } catch (e: any) {
    const mapped = administrationErrorResponse(e);
    if (mapped) return res.status(mapped.status).json({ success: false, error: mapped.error });
    console.error("updateLicensee error:", e);
    return res.status(500).json({ success: false, error: e.message || "Internal server error" });
  }
};

export const deleteLicensee = async (req: AuthRequest, res: Response) => {
  try {
    const paramsParsed = licenseeIdParamSchema.safeParse(req.params || {});
    if (!paramsParsed.success) {
      return res.status(400).json({ success: false, error: paramsParsed.error.errors[0]?.message || "Invalid licensee id" });
    }
    const { id } = paramsParsed.data;

    const boundary = buildAdministrationBoundary(req.user!, {
      purpose: administrationPurposes.deleteLicensee,
      requestId: administrationRequestId(req),
      targetLicenseeId: id,
    });
    const deleted = await withCanonicalDbContext(
      prisma,
      boundary.context,
      async (tx, installedContext) => {
        const result = await deleteLicenseeInTransaction<any>(tx, { id });
        const scopedContext = await installAdministrationResultScope(tx, installedContext, {
          licenseeId: result.licenseeId,
          organizationId: result.organizationId,
        });
        await createAuditLogInTransaction(tx, scopedContext, {
          action: "HARD_DELETE_LICENSEE",
          entityType: "Licensee",
          entityId: id,
          details: {
            workflowId: "workflow-http-backend-src-controllers-licensee-controller-ts-delete-licensee",
            requestId: scopedContext.requestId,
            purposeCode: scopedContext.purpose,
          },
          ipAddress: req.ip,
          userAgent: req.get("user-agent"),
        });
        return { deletedId: id };
      },
      { isolationLevel: Prisma.TransactionIsolationLevel.Serializable }
    );

    return res.json({ success: true, data: deleted });
  } catch (e: any) {
    const mapped = administrationErrorResponse(e);
    if (mapped) return res.status(mapped.status).json({ success: false, error: mapped.error });
    console.error("deleteLicensee error:", e);
    return res.status(500).json({ success: false, error: e.message || "Internal server error" });
  }
};

export { resendLicenseeAdminInvite } from "./licenseeInviteController";

export const exportLicenseesCsv = async (_req: AuthRequest, res: Response) => {
  try {
    const licensees = await prisma.licensee.findMany({
      orderBy: { createdAt: "desc" },
      include: {
        _count: { select: { users: true, qrCodes: true, batches: true } },
        qrRanges: {
          orderBy: { createdAt: "desc" },
          take: 1,
          select: { startCode: true, endCode: true, totalCodes: true },
        },
      },
    });

    const header = [
      "id",
      "name",
      "prefix",
      "isActive",
      "description",
      "usersCount",
      "batchesCount",
      "qrCodesCount",
      "latestRangeStart",
      "latestRangeEnd",
      "latestRangeTotal",
      "createdAt",
    ];

    const rows = licensees.map((l) => {
      const latest = l.qrRanges?.[0];
      return [
        l.id,
        l.name,
        l.prefix,
        l.isActive,
        l.description ?? "",
        l._count.users,
        l._count.batches,
        l._count.qrCodes,
        latest?.startCode ?? "",
        latest?.endCode ?? "",
        latest?.totalCodes ?? "",
        l.createdAt.toISOString(),
      ].map(escapeCsv);
    });

    const csv = header.join(",") + "\n" + rows.map((r) => r.join(",")).join("\n");

    res.setHeader("Content-Type", "text/csv; charset=utf-8");
    res.setHeader("Content-Disposition", `attachment; filename="licensees.csv"`);

    return res.status(200).send(csv);
  } catch (e) {
    console.error("exportLicenseesCsv error:", e);
    return res.status(500).json({ success: false, error: "Internal server error" });
  }
};
