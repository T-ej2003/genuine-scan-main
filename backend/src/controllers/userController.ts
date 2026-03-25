// File: backend/src/controllers/userController.ts

import { Response } from "express";
import { z } from "zod";
import { Prisma, UserRole } from "@prisma/client";
import prisma from "../config/database";
import { AuthRequest } from "../middleware/auth";
import { createAuditLog } from "../services/auditService";
import { hashPassword } from "../services/auth/passwordService";
import { isValidEmailAddress, normalizeEmailAddress } from "../utils/email";
import {
  MANUFACTURER_ROLES,
  assertUserCanAccessLicensee,
  isManufacturerRole,
  isPlatformRole,
  normalizeLinkedLicensees,
  upsertManufacturerLicenseeLink,
} from "../services/manufacturerScopeService";

/**
 * Notes:
 * - Manufacturers are Users with role=MANUFACTURER
 * - Soft delete => isActive=false + deletedAt=now()
 * - Restore => isActive=true + deletedAt=null
 * - Hard delete => SUPER_ADMIN only (unassign batches first)
 *
 * IMPORTANT (routes):
 * - If you want LICENSEE_ADMIN to create manufacturers, your route should be:
 *   POST /users -> requireAnyAdmin + enforceTenantIsolation
 * - Your current routes file shows SUPER_ADMIN only; controller still supports safe tenant checks.
 */

const normalizedEmailSchema = z
  .string()
  .trim()
  .min(3, "Invalid email")
  .max(320, "Invalid email")
  .refine((value) => isValidEmailAddress(value), "Invalid email")
  .transform((value) => normalizeEmailAddress(value) as string);

const createUserSchema = z.object({
  email: normalizedEmailSchema,
  password: z.string().min(6),
  name: z.string().min(2),
  role: z.enum([
    "LICENSEE_ADMIN",
    "ORG_ADMIN",
    "MANUFACTURER",
    "MANUFACTURER_ADMIN",
    "MANUFACTURER_USER",
  ]),
  licenseeId: z.string().uuid().optional(),
  location: z.string().trim().max(200).optional(),
  website: z.string().trim().max(200).optional(),
}).strict();

const updateUserSchema = z.object({
  name: z.string().min(2).optional(),
  email: normalizedEmailSchema.optional(),
  password: z.string().min(6).optional(),
  isActive: z.boolean().optional(),
  licenseeId: z.string().uuid().optional(), // SUPER_ADMIN only
  location: z.string().trim().max(200).optional(),
  website: z.string().trim().max(200).optional(),
}).strict();

const userIdParamSchema = z.object({
  id: z.string().uuid("Invalid user id"),
}).strict();

const deleteUserQuerySchema = z.object({
  hard: z.enum(["true", "false"]).optional(),
}).strict();

/* ===================== HELPERS ===================== */

const canonicalizeRole = (role: UserRole): UserRole => {
  if (role === UserRole.SUPER_ADMIN || role === UserRole.PLATFORM_SUPER_ADMIN) return UserRole.SUPER_ADMIN;
  if (role === UserRole.LICENSEE_ADMIN || role === UserRole.ORG_ADMIN) return UserRole.LICENSEE_ADMIN;
  if (
    role === UserRole.MANUFACTURER ||
    role === UserRole.MANUFACTURER_ADMIN ||
    role === UserRole.MANUFACTURER_USER
  ) {
    return UserRole.MANUFACTURER;
  }
  return role;
};

const ensureAuth = (req: AuthRequest) => {
  const role = req.user?.role;
  const userId = req.user?.userId;
  if (!role || !userId) return null;
  return { role, userId };
};

const isPlatform = (role: UserRole) => isPlatformRole(role);

const getTenantLicenseeId = (req: AuthRequest) => {
  // if your middleware sets (req as any).licenseeId you can support it
  return (req as any).licenseeId || req.user?.licenseeId || null;
};

const serializeScopedUser = (row: {
  id: string;
  email: string;
  name: string;
  role: UserRole;
  licenseeId: string | null;
  isActive: boolean;
  deletedAt: Date | null;
  createdAt: Date;
  location?: string | null;
  website?: string | null;
  licensee?: { id?: string; name: string; prefix: string; brandName?: string | null } | null;
  manufacturerLicenseeLinks?: Array<{
    licenseeId: string;
    isPrimary?: boolean | null;
    licensee?: { id: string; name: string; prefix: string; brandName?: string | null; orgId?: string | null } | null;
  }>;
}, scopedLicenseeId?: string | null) => {
  const linkedLicensees = normalizeLinkedLicensees(row.manufacturerLicenseeLinks || []);
  const scopedLicensee =
    linkedLicensees.find((entry) => entry.id === scopedLicenseeId) ||
    linkedLicensees.find((entry) => entry.isPrimary) ||
    linkedLicensees[0] ||
    (row.licensee
      ? {
          id: row.licensee.id || row.licenseeId || "",
          name: row.licensee.name,
          prefix: row.licensee.prefix,
          brandName: row.licensee.brandName ?? null,
        }
      : null);

  return {
    id: row.id,
    email: row.email,
    name: row.name,
    role: row.role,
    licenseeId: scopedLicensee?.id || row.licenseeId,
    isActive: row.isActive,
    deletedAt: row.deletedAt,
    createdAt: row.createdAt,
    location: row.location ?? null,
    website: row.website ?? null,
    licensee: scopedLicensee
      ? {
          id: scopedLicensee.id,
          name: scopedLicensee.name,
          prefix: scopedLicensee.prefix,
          brandName: scopedLicensee.brandName ?? null,
        }
      : null,
    linkedLicensees: linkedLicensees.length ? linkedLicensees : undefined,
  };
};

const assertManufacturerTarget = async (id: string) => {
  const target = await prisma.user.findUnique({
    where: { id },
    select: {
      id: true,
      role: true,
      licenseeId: true,
      email: true,
      name: true,
      isActive: true,
      deletedAt: true,
      createdAt: true,
      orgId: true,
      location: true,
      website: true,
      manufacturerLicenseeLinks: {
        include: {
          licensee: {
            select: {
              id: true,
              name: true,
              prefix: true,
              brandName: true,
              orgId: true,
            },
          },
        },
        orderBy: [{ isPrimary: "desc" }, { createdAt: "asc" }],
      },
    },
  });

  if (!target) return { ok: false as const, status: 404, error: "User not found" };
  if (!isManufacturerRole(target.role)) {
    return { ok: false as const, status: 400, error: "Target must be a manufacturer user" };
  }

  return { ok: true as const, target };
};

const targetHasLicenseeLink = (
  target: {
    licenseeId: string | null;
    manufacturerLicenseeLinks: Array<{ licenseeId: string }>;
  },
  licenseeId: string | null | undefined
) => {
  const normalized = String(licenseeId || "").trim();
  if (!normalized) return false;
  return (
    target.licenseeId === normalized ||
    target.manufacturerLicenseeLinks.some((row) => row.licenseeId === normalized)
  );
};

/* ===================== CREATE USER ===================== */

export const createUser = async (req: AuthRequest, res: Response) => {
  try {
    const auth = ensureAuth(req);
    if (!auth) return res.status(401).json({ success: false, error: "Not authenticated" });

    const parsed = createUserSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ success: false, error: parsed.error.errors[0].message });
    }

    const email = parsed.data.email;
    const name = parsed.data.name.trim();
    const password = parsed.data.password.trim();
    const role = canonicalizeRole(parsed.data.role as UserRole);

    // Tenant logic:
    // - SUPER_ADMIN: can create LICENSEE_ADMIN or MANUFACTURER for any licenseeId (required)
    // - LICENSEE_ADMIN: should only create MANUFACTURER under own licensee (licenseeId ignored)
    const actorLicenseeId = getTenantLicenseeId(req);

    let effectiveLicenseeId: string | null = null;

    if (isPlatform(auth.role)) {
      effectiveLicenseeId = parsed.data.licenseeId || null;
      if (!effectiveLicenseeId) {
        return res.status(400).json({ success: false, error: "licenseeId is required for super admin createUser" });
      }
    } else {
      // non-super: must be tenant scoped
      if (!actorLicenseeId) {
        return res.status(403).json({ success: false, error: "No licensee association found" });
      }
      effectiveLicenseeId = actorLicenseeId;

      // non-super cannot create licensee users
      if (!isManufacturerRole(role)) {
        return res.status(403).json({ success: false, error: "Only super users can create licensee users" });
      }
    }

    if (!effectiveLicenseeId) {
      return res.status(400).json({ success: false, error: "licenseeId is required" });
    }
    const lic = await prisma.licensee.findUnique({ where: { id: effectiveLicenseeId }, select: { id: true, orgId: true } });
    if (!lic) return res.status(404).json({ success: false, error: "Licensee not found" });
    if (!lic.orgId) return res.status(500).json({ success: false, error: "Licensee org not configured" });

    const passwordHash = await hashPassword(password);

    const licenseeId = effectiveLicenseeId || undefined;
    const created = await prisma.$transaction(async (tx) => {
      const row = await tx.user.create({
        data: {
          email,
          passwordHash,
          emailVerifiedAt: new Date(),
          name,
          role,
          licenseeId,
          orgId: lic.orgId,
          isActive: true,
          deletedAt: null,
          location: parsed.data.location?.trim() ? parsed.data.location.trim() : null,
          website: parsed.data.website?.trim() ? parsed.data.website.trim() : null,
        },
        select: {
          id: true,
          email: true,
          name: true,
          role: true,
          licenseeId: true,
          isActive: true,
          deletedAt: true,
          createdAt: true,
          location: true,
          website: true,
          licensee: { select: { id: true, name: true, prefix: true, brandName: true } },
          manufacturerLicenseeLinks: {
            include: {
              licensee: { select: { id: true, name: true, prefix: true, brandName: true, orgId: true } },
            },
          },
        },
      });
      if (isManufacturerRole(role) && licenseeId) {
        await upsertManufacturerLicenseeLink(tx, {
          manufacturerId: row.id,
          licenseeId,
          makePrimary: true,
        });
        row.manufacturerLicenseeLinks = await tx.manufacturerLicenseeLink.findMany({
          where: { manufacturerId: row.id },
          include: {
            licensee: { select: { id: true, name: true, prefix: true, brandName: true, orgId: true } },
          },
        });
      }
      return row;
    });

    await createAuditLog({
      userId: auth.userId,
      action: "CREATE_USER",
      entityType: "User",
      entityId: created.id,
      details: { email, name, role, licenseeId },
      ipAddress: req.ip,
    });

    return res.status(201).json({ success: true, data: serializeScopedUser(created, licenseeId || null) });
  } catch (e: any) {
    // nice error for unique constraint (email)
    if (e instanceof Prisma.PrismaClientKnownRequestError && e.code === "P2002") {
      return res.status(409).json({ success: false, error: "Email already exists" });
    }
    console.error("createUser error:", e);
    return res.status(500).json({ success: false, error: "Internal server error" });
  }
};

/* ===================== GET USERS ===================== */

export const getUsers = async (req: AuthRequest, res: Response) => {
  try {
    const auth = ensureAuth(req);
    if (!auth) return res.status(401).json({ success: false, error: "Not authenticated" });

    const queryLicenseeId = (req.query.licenseeId as string | undefined) || undefined;
    const includeInactive = String(req.query.includeInactive || "false").toLowerCase() === "true";
    const roleFilter = (req.query.role as UserRole | undefined) || undefined;
    const effectiveLicenseeId = isPlatform(auth.role) ? queryLicenseeId : getTenantLicenseeId(req) || undefined;

    const where: any = {};
    if (roleFilter && isManufacturerRole(roleFilter)) {
      where.role = { in: MANUFACTURER_ROLES };
      if (effectiveLicenseeId) {
        where.OR = [
          { licenseeId: effectiveLicenseeId },
          { manufacturerLicenseeLinks: { some: { licenseeId: effectiveLicenseeId } } },
        ];
      }
    } else {
      if (effectiveLicenseeId) where.licenseeId = effectiveLicenseeId;
      if (roleFilter) where.role = roleFilter;
    }
    if (!includeInactive) where.isActive = true;

    const users = await prisma.user.findMany({
      where,
      select: {
        id: true,
        email: true,
        name: true,
        role: true,
        licenseeId: true,
        isActive: true,
        deletedAt: true,
        createdAt: true,
        location: true,
        website: true,
        licensee: { select: { id: true, name: true, prefix: true, brandName: true } },
        manufacturerLicenseeLinks: {
          include: {
            licensee: { select: { id: true, name: true, prefix: true, brandName: true, orgId: true } },
          },
          orderBy: [{ isPrimary: "desc" }, { createdAt: "asc" }],
        },
      },
      orderBy: { createdAt: "desc" },
    });

    return res.json({
      success: true,
      data: users.map((row) => serializeScopedUser(row, effectiveLicenseeId || null)),
    });
  } catch (e) {
    console.error("getUsers error:", e);
    return res.status(500).json({ success: false, error: "Internal server error" });
  }
};

/* ===================== GET MANUFACTURERS ===================== */

export const getManufacturers = async (req: AuthRequest, res: Response) => {
  try {
    const auth = ensureAuth(req);
    if (!auth) return res.status(401).json({ success: false, error: "Not authenticated" });

    const includeInactive = String(req.query.includeInactive || "false").toLowerCase() === "true";
    const licenseeId = isPlatform(auth.role)
      ? ((req.query.licenseeId as string | undefined) || undefined)
      : (getTenantLicenseeId(req) || undefined);

    const where: any = { role: { in: MANUFACTURER_ROLES } };
    if (licenseeId) {
      where.OR = [
        { licenseeId },
        { manufacturerLicenseeLinks: { some: { licenseeId } } },
      ];
    }
    if (!includeInactive) where.isActive = true;

    const manufacturers = await prisma.user.findMany({
      where,
      select: {
        id: true,
        email: true,
        name: true,
        role: true,
        licenseeId: true,
        isActive: true,
        deletedAt: true,
        createdAt: true,
        location: true,
        website: true,
        licensee: { select: { id: true, name: true, prefix: true, brandName: true } },
        manufacturerLicenseeLinks: {
          include: {
            licensee: { select: { id: true, name: true, prefix: true, brandName: true, orgId: true } },
          },
          orderBy: [{ isPrimary: "desc" }, { createdAt: "asc" }],
        },
      },
      orderBy: { name: "asc" },
    });

    return res.json({
      success: true,
      data: manufacturers.map((row) => serializeScopedUser(row, licenseeId || null)),
    });
  } catch (e) {
    console.error("getManufacturers error:", e);
    return res.status(500).json({ success: false, error: "Internal server error" });
  }
};

/* ===================== UPDATE USER (MANUFACTURERS only) ===================== */

export const updateUser = async (req: AuthRequest, res: Response) => {
  try {
    const auth = ensureAuth(req);
    if (!auth) return res.status(401).json({ success: false, error: "Not authenticated" });

    const parsed = updateUserSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ success: false, error: parsed.error.errors[0].message });
    }

    const paramsParsed = userIdParamSchema.safeParse(req.params || {});
    if (!paramsParsed.success) {
      return res.status(400).json({ success: false, error: paramsParsed.error.errors[0]?.message || "Invalid user id" });
    }
    const targetId = paramsParsed.data.id;
    const t = await assertManufacturerTarget(targetId);
    if (!t.ok) return res.status(t.status).json({ success: false, error: t.error });

    const actorLicenseeId = getTenantLicenseeId(req);
    if (!isPlatform(auth.role)) {
      if (!actorLicenseeId) {
        return res.status(403).json({ success: false, error: "No licensee association found" });
      }
      const allowed = await assertUserCanAccessLicensee(req.user!, actorLicenseeId);
      if (!allowed || !targetHasLicenseeLink(t.target, actorLicenseeId)) {
        return res.status(403).json({ success: false, error: "Access denied to this tenant" });
      }
    }

    const data: any = { ...parsed.data };

    // only super can change tenant
    if (!isPlatform(auth.role)) delete data.licenseeId;

    // password -> passwordHash
    if (data.password) {
      data.passwordHash = await hashPassword(String(data.password));
      delete data.password;
    }

    // keep deletedAt consistent with isActive
    if (typeof data.isActive === "boolean") {
      data.deletedAt = data.isActive ? null : new Date();
    }

    // normalize email
    if (data.email) data.email = String(data.email).trim().toLowerCase();

    const updated = await prisma.$transaction(async (tx) => {
      let nextLicenseeId = t.target.licenseeId;
      if (isPlatform(auth.role) && data.licenseeId) {
        const nextLicensee = await tx.licensee.findUnique({
          where: { id: data.licenseeId },
          select: { id: true, orgId: true },
        });
        if (!nextLicensee) {
          throw new Error("Licensee not found");
        }
        await upsertManufacturerLicenseeLink(tx, {
          manufacturerId: targetId,
          licenseeId: nextLicensee.id,
          makePrimary: true,
        });
        data.orgId = nextLicensee.orgId;
        nextLicenseeId = nextLicensee.id;
      }

      const row = await tx.user.update({
        where: { id: targetId },
        data,
        select: {
          id: true,
          email: true,
          name: true,
          role: true,
          licenseeId: true,
          isActive: true,
          deletedAt: true,
          createdAt: true,
          location: true,
          website: true,
          licensee: { select: { id: true, name: true, prefix: true, brandName: true } },
          manufacturerLicenseeLinks: {
            include: {
              licensee: { select: { id: true, name: true, prefix: true, brandName: true, orgId: true } },
            },
            orderBy: [{ isPrimary: "desc" }, { createdAt: "asc" }],
          },
        },
      });

      return serializeScopedUser(row, actorLicenseeId || nextLicenseeId || null);
    });

    await createAuditLog({
      userId: auth.userId,
      action: "UPDATE_USER",
      entityType: "User",
      entityId: updated.id,
      details: { changed: Object.keys(parsed.data) },
      ipAddress: req.ip,
    });

    return res.json({ success: true, data: updated });
  } catch (e: any) {
    if (e instanceof Prisma.PrismaClientKnownRequestError && e.code === "P2002") {
      return res.status(409).json({ success: false, error: "Email already exists" });
    }
    console.error("updateUser error:", e);
    return res.status(500).json({ success: false, error: "Internal server error" });
  }
};

/* ===================== DELETE USER (MANUFACTURERS only) ===================== */

export const deleteUser = async (req: AuthRequest, res: Response) => {
  try {
    const auth = ensureAuth(req);
    if (!auth) return res.status(401).json({ success: false, error: "Not authenticated" });

    const paramsParsed = userIdParamSchema.safeParse(req.params || {});
    if (!paramsParsed.success) {
      return res.status(400).json({ success: false, error: paramsParsed.error.errors[0]?.message || "Invalid user id" });
    }
    const queryParsed = deleteUserQuerySchema.safeParse(req.query || {});
    if (!queryParsed.success) {
      return res.status(400).json({ success: false, error: queryParsed.error.errors[0]?.message || "Invalid delete query" });
    }

    const targetId = paramsParsed.data.id;
    const hard = queryParsed.data.hard === "true";

    const t = await assertManufacturerTarget(targetId);
    if (!t.ok) return res.status(t.status).json({ success: false, error: t.error });

    const actorLicenseeId = getTenantLicenseeId(req);
    if (!isPlatform(auth.role)) {
      if (!actorLicenseeId || !targetHasLicenseeLink(t.target, actorLicenseeId)) {
        return res.status(403).json({ success: false, error: "Access denied to this tenant" });
      }
    }

    if (hard) {
      if (!isPlatform(auth.role)) {
        return res.status(403).json({ success: false, error: "Only super admin can hard delete" });
      }

      const tx = await prisma.$transaction(async (pr) => {
        const unassigned = await pr.batch.updateMany({
          where: { manufacturerId: targetId },
          data: { manufacturerId: null },
        });

        await pr.user.delete({ where: { id: targetId } });

        return { unassignedBatches: unassigned.count };
      });

      await createAuditLog({
        userId: auth.userId,
        action: "HARD_DELETE_MANUFACTURER",
        entityType: "User",
        entityId: targetId,
        details: { email: t.target.email, name: t.target.name, ...tx },
        ipAddress: req.ip,
      });

      return res.json({ success: true, data: { deletedId: targetId, hard: true, ...tx } });
    }

    if (!isPlatform(auth.role) && actorLicenseeId) {
      const scopedBatchCount = await prisma.batch.count({
        where: { manufacturerId: targetId, licenseeId: actorLicenseeId },
      });
      if (scopedBatchCount > 0) {
        return res.status(409).json({
          success: false,
          error: "This manufacturer still has batches assigned under your licensee. Reassign or close those batches before unlinking.",
        });
      }

      const updated = await prisma.$transaction(async (tx) => {
        await tx.manufacturerLicenseeLink.delete({
          where: {
            manufacturerId_licenseeId: {
              manufacturerId: targetId,
              licenseeId: actorLicenseeId,
            },
          },
        });

        const remainingLinks = await tx.manufacturerLicenseeLink.findMany({
          where: { manufacturerId: targetId },
          orderBy: [{ isPrimary: "desc" }, { createdAt: "asc" }],
        });

        if (remainingLinks.length === 0) {
          await tx.user.update({
            where: { id: targetId },
            data: { isActive: false, deletedAt: new Date(), licenseeId: null },
          });
        } else if (!remainingLinks.some((row) => row.isPrimary)) {
          await upsertManufacturerLicenseeLink(tx, {
            manufacturerId: targetId,
            licenseeId: remainingLinks[0].licenseeId,
            makePrimary: true,
          });
          await tx.user.update({
            where: { id: targetId },
            data: { licenseeId: remainingLinks[0].licenseeId },
          });
        }

        return { deletedId: targetId, hard: false, unlinkedLicenseeId: actorLicenseeId };
      });

      await createAuditLog({
        userId: auth.userId,
        licenseeId: actorLicenseeId,
        action: "UNLINK_MANUFACTURER_FROM_LICENSEE",
        entityType: "User",
        entityId: targetId,
        details: { email: t.target.email, name: t.target.name, licenseeId: actorLicenseeId },
        ipAddress: req.ip,
      });

      return res.json({ success: true, data: updated });
    }

    const updated = await prisma.user.update({
      where: { id: targetId },
      data: { isActive: false, deletedAt: new Date() },
      select: { id: true, isActive: true, deletedAt: true },
    });

    await createAuditLog({
      userId: auth.userId,
      action: "SOFT_DELETE_MANUFACTURER",
      entityType: "User",
      entityId: targetId,
      details: { email: t.target.email, name: t.target.name },
      ipAddress: req.ip,
    });

    return res.json({ success: true, data: { deletedId: targetId, hard: false, ...updated } });
  } catch (e) {
    console.error("deleteUser error:", e);
    return res.status(500).json({ success: false, error: "Internal server error" });
  }
};

/* ===================== Convenience Manufacturer Endpoints ===================== */

export const deactivateManufacturer = async (req: AuthRequest, res: Response) => {
  req.query.hard = "false";
  return deleteUser(req, res);
};

export const restoreManufacturer = async (req: AuthRequest, res: Response) => {
  try {
    const auth = ensureAuth(req);
    if (!auth) return res.status(401).json({ success: false, error: "Not authenticated" });

    const paramsParsed = userIdParamSchema.safeParse(req.params || {});
    if (!paramsParsed.success) {
      return res.status(400).json({ success: false, error: paramsParsed.error.errors[0]?.message || "Invalid user id" });
    }
    const targetId = paramsParsed.data.id;
    const t = await assertManufacturerTarget(targetId);
    if (!t.ok) return res.status(t.status).json({ success: false, error: t.error });

    const actorLicenseeId = getTenantLicenseeId(req);
    if (!isPlatform(auth.role)) {
      if (!actorLicenseeId) {
        return res.status(403).json({ success: false, error: "No licensee association found" });
      }

      const updated = await prisma.$transaction(async (tx) => {
        await upsertManufacturerLicenseeLink(tx, {
          manufacturerId: targetId,
          licenseeId: actorLicenseeId,
          makePrimary: !t.target.licenseeId,
        });
        return tx.user.update({
          where: { id: targetId },
          data: { isActive: true, deletedAt: null, licenseeId: t.target.licenseeId || actorLicenseeId },
          select: { id: true, isActive: true, deletedAt: true },
        });
      });

      await createAuditLog({
        userId: auth.userId,
        licenseeId: actorLicenseeId,
        action: "RESTORE_MANUFACTURER_LINK",
        entityType: "User",
        entityId: targetId,
        details: { email: t.target.email, name: t.target.name, licenseeId: actorLicenseeId },
        ipAddress: req.ip,
      });

      return res.json({ success: true, data: updated });
    }

    const updated = await prisma.user.update({
      where: { id: targetId },
      data: { isActive: true, deletedAt: null },
      select: { id: true, isActive: true, deletedAt: true },
    });

    await createAuditLog({
      userId: auth.userId,
      action: "RESTORE_MANUFACTURER",
      entityType: "User",
      entityId: targetId,
      details: { email: t.target.email, name: t.target.name },
      ipAddress: req.ip,
    });

    return res.json({ success: true, data: updated });
  } catch (e) {
    console.error("restoreManufacturer error:", e);
    return res.status(500).json({ success: false, error: "Internal server error" });
  }
};

export const hardDeleteManufacturer = async (req: AuthRequest, res: Response) => {
  req.query.hard = "true";
  return deleteUser(req, res);
};
