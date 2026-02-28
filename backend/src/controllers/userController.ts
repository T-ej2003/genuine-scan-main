// File: backend/src/controllers/userController.ts

import { Response } from "express";
import { z } from "zod";
import { Prisma, UserRole } from "@prisma/client";
import prisma from "../config/database";
import { AuthRequest } from "../middleware/auth";
import { createAuditLog } from "../services/auditService";
import { hashPassword } from "../services/auth/passwordService";
import { isValidEmailAddress, normalizeEmailAddress } from "../utils/email";

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
});

const updateUserSchema = z.object({
  name: z.string().min(2).optional(),
  email: normalizedEmailSchema.optional(),
  password: z.string().min(6).optional(),
  isActive: z.boolean().optional(),
  licenseeId: z.string().uuid().optional(), // SUPER_ADMIN only
  location: z.string().trim().max(200).optional(),
  website: z.string().trim().max(200).optional(),
});

/* ===================== HELPERS ===================== */

const MANUFACTURER_ROLES: UserRole[] = [
  UserRole.MANUFACTURER,
  UserRole.MANUFACTURER_ADMIN,
  UserRole.MANUFACTURER_USER,
];

const isManufacturerRole = (role: UserRole) => MANUFACTURER_ROLES.includes(role);

const ensureAuth = (req: AuthRequest) => {
  const role = req.user?.role;
  const userId = req.user?.userId;
  if (!role || !userId) return null;
  return { role, userId };
};

const isPlatform = (role: UserRole) => role === UserRole.SUPER_ADMIN || role === UserRole.PLATFORM_SUPER_ADMIN;

const getTenantLicenseeId = (req: AuthRequest) => {
  // if your middleware sets (req as any).licenseeId you can support it
  return (req as any).licenseeId || req.user?.licenseeId || null;
};

const enforceTenantForTarget = (
  actorRole: UserRole,
  actorLicenseeId: string | null,
  targetLicenseeId: string | null
) => {
  if (isPlatform(actorRole)) return { ok: true as const };

  if (!actorLicenseeId) {
    return { ok: false as const, status: 403, error: "No licensee association found" };
  }
  if (!targetLicenseeId || String(actorLicenseeId) !== String(targetLicenseeId)) {
    return { ok: false as const, status: 403, error: "Access denied to this tenant" };
  }
  return { ok: true as const };
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
    },
  });

  if (!target) return { ok: false as const, status: 404, error: "User not found" };
  if (!isManufacturerRole(target.role)) {
    return { ok: false as const, status: 400, error: "Target must be a manufacturer user" };
  }

  return { ok: true as const, target };
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
    const role = parsed.data.role as UserRole;

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

      // non-super cannot create licensee admins
      if (!isManufacturerRole(role)) {
        return res.status(403).json({ success: false, error: "Only platform admin can create org admin users" });
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
    const created = await prisma.user.create({
      data: {
        email,
        passwordHash,
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
      },
    });

    await createAuditLog({
      userId: auth.userId,
      action: "CREATE_USER",
      entityType: "User",
      entityId: created.id,
      details: { email, name, role, licenseeId },
      ipAddress: req.ip,
    });

    return res.status(201).json({ success: true, data: created });
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
    if (effectiveLicenseeId) where.licenseeId = effectiveLicenseeId;
    if (roleFilter) where.role = roleFilter;
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
        licensee: { select: { name: true, prefix: true } },
      },
      orderBy: { createdAt: "desc" },
    });

    return res.json({ success: true, data: users });
  } catch (e) {
    console.error("getUsers error:", e);
    return res.status(500).json({ success: false, error: "Internal server error" });
  }
};

/* ===================== GET MANUFACTURERS ===================== */

export const getManufacturers = async (req: AuthRequest, res: Response) => {
  let includeInactive = false;
  let licenseeId: string | undefined;
  try {
    const auth = ensureAuth(req);
    if (!auth) return res.status(401).json({ success: false, error: "Not authenticated" });

    includeInactive = String(req.query.includeInactive || "false").toLowerCase() === "true";

    licenseeId = isPlatform(auth.role)
      ? ((req.query.licenseeId as string | undefined) || undefined)
      : (getTenantLicenseeId(req) || undefined);

    const where: any = { role: { in: [UserRole.MANUFACTURER, UserRole.MANUFACTURER_ADMIN, UserRole.MANUFACTURER_USER] } };
    if (licenseeId) where.licenseeId = licenseeId;
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
        licensee: { select: { name: true, prefix: true } },
      },
      orderBy: { name: "asc" },
    });

    return res.json({ success: true, data: manufacturers });
  } catch (e) {
    console.error("getManufacturers error:", e);
    try {
      // Fallback for schema mismatch or older DB: return minimal fields
      const fallbackWhere: any = { role: { in: [UserRole.MANUFACTURER, UserRole.MANUFACTURER_ADMIN, UserRole.MANUFACTURER_USER] } };
      if (licenseeId) fallbackWhere.licenseeId = licenseeId;
      if (!includeInactive) fallbackWhere.isActive = true;
      const fallback = await prisma.user.findMany({
        where: fallbackWhere,
        select: {
          id: true,
          email: true,
          name: true,
          role: true,
          licenseeId: true,
          isActive: true,
          deletedAt: true,
          createdAt: true,
          licensee: { select: { name: true, prefix: true } },
        },
        orderBy: { name: "asc" },
      });
      return res.json({ success: true, data: fallback });
    } catch (fallbackErr) {
      console.error("getManufacturers fallback error:", fallbackErr);
      return res.status(500).json({ success: false, error: "Internal server error" });
    }
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

    const targetId = req.params.id;
    const t = await assertManufacturerTarget(targetId);
    if (!t.ok) return res.status(t.status).json({ success: false, error: t.error });

    const tenantCheck = enforceTenantForTarget(auth.role, getTenantLicenseeId(req), t.target.licenseeId || null);
    if (!tenantCheck.ok) return res.status(tenantCheck.status).json({ success: false, error: tenantCheck.error });

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

    const updated = await prisma.user.update({
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
      },
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

    const targetId = req.params.id;
    const hard = String(req.query.hard || "false").toLowerCase() === "true";

    const t = await assertManufacturerTarget(targetId);
    if (!t.ok) return res.status(t.status).json({ success: false, error: t.error });

    const tenantCheck = enforceTenantForTarget(auth.role, getTenantLicenseeId(req), t.target.licenseeId || null);
    if (!tenantCheck.ok) return res.status(tenantCheck.status).json({ success: false, error: tenantCheck.error });

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

    const targetId = req.params.id;
    const t = await assertManufacturerTarget(targetId);
    if (!t.ok) return res.status(t.status).json({ success: false, error: t.error });

    const tenantCheck = enforceTenantForTarget(auth.role, getTenantLicenseeId(req), t.target.licenseeId || null);
    if (!tenantCheck.ok) return res.status(tenantCheck.status).json({ success: false, error: tenantCheck.error });

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
