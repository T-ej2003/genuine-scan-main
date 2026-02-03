//backend/src/controllers/licenseeController.ts
import { Response } from "express";
import { z } from "zod";
import bcrypt from "bcryptjs";
import prisma from "../config/database";
import { AuthRequest } from "../middleware/auth";
import { UserRole } from "@prisma/client";
import { createAuditLog } from "../services/auditService";

const prefixSchema = z
  .string()
  .trim()
  .min(1)
  .max(5)
  .transform((s) => s.toUpperCase())
  .refine((s) => /^[A-Z0-9]+$/.test(s), "Prefix must be A–Z / 0–9 only");

const adminSchema = z.object({
  name: z.string().trim().min(2, "Admin name must be at least 2 characters"),
  email: z.string().trim().email("Invalid admin email").transform((s) => s.toLowerCase()),
  password: z.string().min(6, "Admin password must be at least 6 characters"),
});

// Format A (legacy)
const createLicenseeLegacy = z.object({
  name: z.string().trim().min(2, "Name must be at least 2 characters"),
  prefix: prefixSchema,
  description: z.string().trim().max(300).optional().or(z.literal("")),
  brandName: z.string().trim().max(120).optional().or(z.literal("")),
  location: z.string().trim().max(200).optional().or(z.literal("")),
  website: z.string().trim().max(200).optional().or(z.literal("")),
  supportEmail: z.string().trim().email().optional().or(z.literal("")),
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
    supportEmail: z.string().trim().email().optional().or(z.literal("")),
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
  supportEmail: z.string().trim().email().optional().or(z.literal("")),
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
    if (req.user?.role !== UserRole.SUPER_ADMIN) {
      return res.status(403).json({ success: false, error: "Insufficient permissions" });
    }

    const parsed = createLicenseeSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ success: false, error: parsed.error.errors[0].message });
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
    const existingUser = await prisma.user.findUnique({ where: { email } });
    if (existingUser) {
      return res.status(409).json({ success: false, error: "Admin email already in use" });
    }

    const result = await prisma.$transaction(async (tx) => {
      const lic = await tx.licensee.create({
        data: {
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

      const passwordHash = await bcrypt.hash(adminPayload.password, 12);

      const adminUser = await tx.user.create({
        data: {
          email,
          name: adminPayload.name,
          passwordHash,
          role: UserRole.LICENSEE_ADMIN,
          licenseeId: lic.id,
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
          createdAt: true,
        },
      });

      await createAuditLog({
        userId: req.user!.userId,
        licenseeId: lic.id,
        action: "CREATE_LICENSEE_WITH_ADMIN",
        entityType: "Licensee",
        entityId: lic.id,
        details: { licenseeName: lic.name, prefix: lic.prefix, adminEmail: adminUser.email },
        ipAddress: req.ip,
      });

      return { licensee: lic, adminUser };
    });

    return res.status(201).json({ success: true, data: result });
  } catch (e: any) {
    console.error("createLicensee error:", e);
    return res.status(500).json({ success: false, error: e?.message || "Internal server error" });
  }
};

export const getLicensees = async (_req: AuthRequest, res: Response) => {
  try {
    const licensees = await prisma.licensee.findMany({
      orderBy: { createdAt: "desc" },
      include: {
        _count: { select: { users: true, qrCodes: true, batches: true } },
        qrRanges: {
          orderBy: { createdAt: "desc" },
          take: 1,
          select: { id: true, startCode: true, endCode: true, totalCodes: true, createdAt: true },
        },
      },
    });

    const data = licensees.map((l) => ({
      ...l,
      latestRange: l.qrRanges?.[0] ?? null,
      qrRanges: undefined,
    }));

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
