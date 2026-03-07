//backend/src/controllers/licenseeController.ts
import { Response } from "express";
import { z } from "zod";
import prisma from "../config/database";
import { AuthRequest } from "../middleware/auth";
import { UserRole } from "@prisma/client";
import { createAuditLog } from "../services/auditService";
import { randomUUID } from "crypto";
import { hashPassword } from "../services/auth/passwordService";
import { createInvite } from "../services/auth/inviteService";
import { hashIp, normalizeUserAgent } from "../utils/security";
import { isValidEmailAddress, normalizeEmailAddress } from "../utils/email";

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
});

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
});

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
  }),
  admin: adminSchema,
});

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
});

type CreateLicenseeInput = z.infer<typeof createLicenseeSchema>;

const isNewFormat = (data: CreateLicenseeInput): data is z.infer<typeof createLicenseeWithAdmin> => {
  return typeof (data as any).licensee === "object" && typeof (data as any).admin === "object";
};

const escapeCsv = (v: any) => {
  if (v === null || v === undefined) return "";
  const s = String(v);
  return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
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

    const exists = await prisma.licensee.findUnique({ where: { prefix } });
    if (exists) {
      return res.status(409).json({ success: false, error: "Prefix already in use" });
    }

    const email = adminPayload.email.toLowerCase();
    const sendInvite = Boolean(adminPayload.sendInvite);
    const adminPassword = String(adminPayload.password || "").trim();

    if (!sendInvite && adminPassword.length < 6) {
      return res.status(400).json({
        success: false,
        error: "Admin password must be at least 6 characters when invite mode is disabled.",
      });
    }

    const existingUser = await prisma.user.findUnique({ where: { email } });
    if (existingUser) {
      return res.status(409).json({ success: false, error: "Admin email already in use" });
    }

    const result = await prisma.$transaction(async (tx) => {
      const id = randomUUID();

      await tx.organization.create({
        data: {
          id,
          name: licenseePayload.name,
          isActive: licenseePayload.isActive ?? true,
        },
      });

      const lic = await tx.licensee.create({
        data: {
          id,
          orgId: id,
          name: licenseePayload.name,
          prefix,
          description: licenseePayload.description?.trim() ? licenseePayload.description.trim() : null,
          brandName: licenseePayload.brandName?.trim() ? licenseePayload.brandName.trim() : null,
          location: licenseePayload.location?.trim() ? licenseePayload.location.trim() : null,
          website: licenseePayload.website?.trim() ? licenseePayload.website.trim() : null,
          supportEmail: licenseePayload.supportEmail?.trim()
            ? licenseePayload.supportEmail.trim().toLowerCase()
            : null,
          supportPhone: licenseePayload.supportPhone?.trim() ? licenseePayload.supportPhone.trim() : null,
          isActive: licenseePayload.isActive ?? true,
        },
      });

      const adminUser = sendInvite
        ? null
        : await tx.user.create({
            data: {
              email,
              name: adminPayload.name,
              passwordHash: await hashPassword(adminPassword),
              role: UserRole.LICENSEE_ADMIN,
              licenseeId: lic.id,
              orgId: lic.orgId,
              status: "ACTIVE",
              isActive: true,
              deletedAt: null,
            },
            select: {
              id: true,
              email: true,
              name: true,
              role: true,
              licenseeId: true,
              isActive: true,
              status: true,
              createdAt: true,
            },
          });

      return { licensee: lic, adminUser };
    });

    await createAuditLog({
      userId: req.user!.userId,
      licenseeId: result.licensee.id,
      orgId: result.licensee.orgId,
      action: sendInvite ? "CREATE_LICENSEE_WITH_ADMIN_INVITE" : "CREATE_LICENSEE_WITH_ADMIN",
      entityType: "Licensee",
      entityId: result.licensee.id,
      details: {
        licenseeName: result.licensee.name,
        prefix: result.licensee.prefix,
        adminEmail: email,
        sendInvite,
      },
      ipAddress: req.ip,
      userAgent: req.get("user-agent"),
    });

    let adminInvite: any = null;
    let warning: string | null = null;
    if (sendInvite) {
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
        warning = inviteError?.message || "Licensee created, but invite generation failed.";
      }
    }

    const out = {
      ...result,
      adminInvite,
      warning,
    };

    return res.status(201).json({ success: true, data: out });
  } catch (e: any) {
    console.error("createLicensee error:", e);
    return res.status(500).json({ success: false, error: e?.message || "Internal server error" });
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
    const { id } = req.params;

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
    const { id } = req.params;

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

    const updated = await prisma.licensee.update({ where: { id }, data });

    await createAuditLog({
      userId: req.user?.userId,
      licenseeId: updated.id,
      action: "UPDATE_LICENSEE",
      entityType: "Licensee",
      entityId: id,
      details: { changed: Object.keys(data) },
      ipAddress: req.ip,
    });

    return res.json({ success: true, data: updated });
  } catch (e: any) {
    console.error("updateLicensee error:", e);
    return res.status(500).json({ success: false, error: e.message || "Internal server error" });
  }
};

export const deleteLicensee = async (req: AuthRequest, res: Response) => {
  try {
    const { id } = req.params;

    const [users, batches, ranges, codes] = await Promise.all([
      prisma.user.count({ where: { licenseeId: id } }),
      prisma.batch.count({ where: { licenseeId: id } }),
      prisma.qRRange.count({ where: { licenseeId: id } }),
      prisma.qRCode.count({ where: { licenseeId: id } }),
    ]);

    if (users || batches || ranges || codes) {
      return res.status(400).json({
        success: false,
        error: "Licensee has linked data. Deactivate it instead of hard deleting.",
      });
    }

    await prisma.licensee.delete({ where: { id } });

    await createAuditLog({
      userId: req.user?.userId,
      action: "HARD_DELETE_LICENSEE",
      entityType: "Licensee",
      entityId: id,
      details: {},
      ipAddress: req.ip,
    });

    return res.json({ success: true, data: { deletedId: id } });
  } catch (e: any) {
    console.error("deleteLicensee error:", e);
    return res.status(500).json({ success: false, error: e.message || "Internal server error" });
  }
};

const resendInviteSchema = z.object({
  email: z
    .string()
    .trim()
    .min(3, "Invalid email")
    .max(320, "Invalid email")
    .refine((value) => isValidEmailAddress(value), "Invalid email")
    .transform((value) => normalizeEmailAddress(value) as string)
    .optional(),
});

export const resendLicenseeAdminInvite = async (req: AuthRequest, res: Response) => {
  try {
    if (req.user?.role !== UserRole.SUPER_ADMIN && req.user?.role !== UserRole.PLATFORM_SUPER_ADMIN) {
      return res.status(403).json({ success: false, error: "Insufficient permissions" });
    }

    const { id } = req.params;
    const parsed = resendInviteSchema.safeParse(req.body || {});
    if (!parsed.success) {
      return res.status(400).json({ success: false, error: parsed.error.errors[0]?.message || "Invalid request" });
    }

    const licensee = await prisma.licensee.findUnique({
      where: { id },
      select: { id: true, name: true, orgId: true, isActive: true },
    });
    if (!licensee) return res.status(404).json({ success: false, error: "Licensee not found" });
    if (!licensee.isActive) return res.status(409).json({ success: false, error: "Licensee is inactive" });

    const requestedEmail = String(parsed.data.email || "").trim().toLowerCase();
    const existingAdmin =
      (await prisma.user.findFirst({
        where: {
          licenseeId: id,
          role: { in: [UserRole.LICENSEE_ADMIN, UserRole.ORG_ADMIN] },
          status: "INVITED",
          ...(requestedEmail ? { email: requestedEmail } : {}),
        },
        orderBy: { createdAt: "asc" },
        select: {
          id: true,
          name: true,
          email: true,
          role: true,
          status: true,
        },
      })) ||
      (await prisma.user.findFirst({
        where: {
          licenseeId: id,
          role: { in: [UserRole.LICENSEE_ADMIN, UserRole.ORG_ADMIN] },
          ...(requestedEmail ? { email: requestedEmail } : {}),
        },
        orderBy: { createdAt: "asc" },
        select: {
          id: true,
          name: true,
          email: true,
          role: true,
          status: true,
        },
      }));

    if (!existingAdmin) {
      return res.status(404).json({
        success: false,
        error: "No licensee admin user found. Create one first.",
      });
    }

    const invite = await createInvite({
      email: existingAdmin.email,
      name: existingAdmin.name || undefined,
      role: existingAdmin.role,
      licenseeId: id,
      allowExistingInvitedUser: true,
      createdByUserId: req.user!.userId,
      ipHash: hashIp(req.ip),
      userAgent: normalizeUserAgent(req.get("user-agent")),
    });

    await createAuditLog({
      userId: req.user!.userId,
      licenseeId: id,
      orgId: licensee.orgId || undefined,
      action: "RESEND_LICENSEE_ADMIN_INVITE",
      entityType: "Invite",
      entityId: invite.inviteId,
      details: {
        licenseeName: licensee.name,
        adminEmail: existingAdmin.email,
      },
      ipAddress: req.ip,
      userAgent: req.get("user-agent"),
    });

    return res.json({
      success: true,
      data: invite,
    });
  } catch (e: any) {
    const msg = String(e?.message || "Failed to resend invite");
    const isConflict = /already active|different|disabled|not required/i.test(msg);
    return res.status(isConflict ? 409 : 500).json({ success: false, error: msg });
  }
};

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
