// File: backend/src/controllers/userController.ts

import { Response } from "express";
import { z } from "zod";
import { Prisma, UserRole } from "@prisma/client";
import prisma from "../config/database";
import { AuthRequest } from "../middleware/auth";
import { hashPassword } from "../services/auth/passwordService";
import { isValidEmailAddress, normalizeEmailAddress } from "../utils/email";
import { hashIp, normalizeUserAgent } from "../utils/security";
import {
  MANUFACTURER_ROLES,
  isManufacturerRole,
  isPlatformRole,
  normalizeLinkedLicensees,
} from "../services/manufacturerScopeService";
import { buildScopedUserWhere, resolveRequestedLicenseeScope } from "../services/accessControlService";
import {
  AdministrationAccessError,
  createUser as createUserBoundary,
  deleteUser as deleteUserBoundary,
  restoreManufacturer as restoreManufacturerBoundary,
  updateUser as updateUserBoundary,
} from "../rls-waves/session-c/c01/administrationRepository";
import { isTenantDirectoryDenied, readUserDirectory } from "../rls-waves/session-a/tenantDirectoryRepository";

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
    "MANUFACTURER_ADMIN",
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

const parsePagination = (query: Record<string, unknown>, defaults?: { limit?: number; max?: number }) => {
  const fallbackLimit = defaults?.limit ?? 100;
  const maxLimit = defaults?.max ?? 500;
  const limit = Math.min(parseInt(String(query.limit ?? fallbackLimit), 10) || fallbackLimit, maxLimit);
  const offset = Math.max(0, parseInt(String(query.offset ?? "0"), 10) || 0);
  return { limit, offset };
};

/* ===================== HELPERS ===================== */

const ensureAuth = (req: AuthRequest) => {
  const role = req.user?.role;
  const userId = req.user?.userId;
  if (!role || !userId) return null;
  return { role, userId };
};

const isPlatform = (role: UserRole) => isPlatformRole(role);

const isScopeError = (error: unknown) =>
  error instanceof Error && /access denied|no licensee association/i.test(error.message);

const administrationRequestId = (req: AuthRequest) =>
  String((req as AuthRequest & { requestId?: string }).requestId || "").trim();

const administrationErrorResponse = (error: unknown) => {
  if (error instanceof AdministrationAccessError) {
    return { status: error.statusCode, error: error.message };
  }
  const message = String((error as any)?.meta?.message || (error as any)?.message || "");
  if (/SESSION_C_USER_NOT_FOUND/.test(message)) return { status: 404, error: "User not found" };
  if (/SESSION_C_LICENSEE_NOT_FOUND/.test(message)) return { status: 404, error: "Licensee not found" };
  if (/SESSION_C_FOREIGN_SCOPE/.test(message)) return { status: 403, error: "Access denied to this tenant" };
  if (/SESSION_C_(DISABLED_OR_STALE_ACTOR|STALE_PLATFORM_SCOPE|WRONG_ROLE|INVALID_CONTEXT)/.test(message)) {
    return { status: 403, error: "Administration authority is stale or invalid." };
  }
  if (/SESSION_C_ASSIGNED_BATCHES/.test(message)) {
    return { status: 409, error: "This manufacturer still has assigned batches. Reassign or close them before unlinking." };
  }
  if (/SESSION_C_DUPLICATE_USER/.test(message)) return { status: 409, error: "Email already exists" };
  if (/SESSION_C_STALE_STATE/.test(message)) return { status: 409, error: "The account changed; refresh and retry." };
  return null;
};

const getRequestedLicenseeId = (req: AuthRequest) =>
  String(req.body?.licenseeId || req.query?.licenseeId || req.params?.licenseeId || "").trim() || null;

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

    const requestedLicenseeId = parsed.data.licenseeId || null;
    const effectiveLicenseeId = isPlatform(auth.role)
      ? requestedLicenseeId
      : String(req.user?.licenseeId || "").trim() || null;
    if (!isPlatform(auth.role) && role !== UserRole.MANUFACTURER_ADMIN) {
      return res.status(403).json({ success: false, error: "Only super users can create licensee users" });
    }

    if (!effectiveLicenseeId) {
      return res.status(400).json({ success: false, error: "licenseeId is required" });
    }
    const passwordHash = await hashPassword(password);
    const createdResult = await createUserBoundary<any>(
      String(req.databaseSessionCapability || ""),
      administrationRequestId(req),
      {
        email, passwordHash, name, role, licenseeId: effectiveLicenseeId,
        location: parsed.data.location?.trim() || null,
        website: parsed.data.website?.trim() || null,
        audit: { ipHash: hashIp(req.ip), userAgent: normalizeUserAgent(req.get("user-agent")) },
      }
    );
    const created = createdResult.user;

    return res.status(201).json({ success: true, data: serializeScopedUser(created, effectiveLicenseeId) });
  } catch (e: any) {
    const mapped = administrationErrorResponse(e);
    if (mapped) return res.status(mapped.status).json({ success: false, error: mapped.error });
    if (isScopeError(e)) {
      return res.status(403).json({ success: false, error: "Access denied" });
    }
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
    const rawRoleFilter = String(req.query.role || "").trim();
    const roleFilter = rawRoleFilter === "MANUFACTURER"
      ? UserRole.MANUFACTURER_ADMIN
      : Object.values(UserRole).includes(rawRoleFilter as UserRole)
        ? rawRoleFilter as UserRole
        : undefined;
    const { limit, offset } = parsePagination(req.query as Record<string, unknown>);

    const { users, total } = await readUserDirectory({
      capability: String(req.databaseSessionCapability || ""),
      requestId: administrationRequestId(req),
      requestedLicenseeId: queryLicenseeId,
      includeInactive,
      roleFilter,
      limit,
      offset,
    });

    return res.json({
      success: true,
      data: users,
      meta: { total, limit, offset },
    });
  } catch (e) {
    if (isTenantDirectoryDenied(e)) {
      return res.status(404).json({ success: false, error: "Users not found" });
    }
    if (isScopeError(e)) {
      return res.status(404).json({ success: false, error: "Users not found" });
    }
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
    const licenseeId = (req.query.licenseeId as string | undefined) || undefined;
    const { limit, offset } = parsePagination(req.query as Record<string, unknown>);

    const { users: manufacturers, total } = await readUserDirectory({
      capability: String(req.databaseSessionCapability || ""),
      requestId: administrationRequestId(req),
      requestedLicenseeId: licenseeId,
      includeInactive,
      roleFilter: UserRole.MANUFACTURER_ADMIN,
      limit,
      offset,
    });

    return res.json({
      success: true,
      data: manufacturers,
      meta: { total, limit, offset },
    });
  } catch (e) {
    if (isTenantDirectoryDenied(e) || isScopeError(e)) {
      return res.status(404).json({ success: false, error: "Manufacturers not found" });
    }
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

    const data: any = { ...parsed.data };

    // only super can change tenant
    if (!isPlatform(auth.role)) delete data.licenseeId;

    // password -> passwordHash
    if (data.password) {
      data.passwordHash = await hashPassword(String(data.password));
      delete data.password;
    }

    // normalize email
    if (data.email) data.email = String(data.email).trim().toLowerCase();

    const targetLicenseeId = String(
      (isPlatform(auth.role) ? data.licenseeId : req.user?.licenseeId) || ""
    ).trim() || null;
    const result = await updateUserBoundary<any>(String(req.databaseSessionCapability || ""), administrationRequestId(req), {
      id: targetId, patch: data,
      requestedLicenseeId: targetLicenseeId,
      audit: { changed: Object.keys(parsed.data), ipHash: hashIp(req.ip), userAgent: normalizeUserAgent(req.get("user-agent")) },
    });
    const updated = serializeScopedUser(result.user, result.scopedLicenseeId || result.licenseeId);

    return res.json({ success: true, data: updated });
  } catch (e: any) {
    const mapped = administrationErrorResponse(e);
    if (mapped) return res.status(mapped.status).json({ success: false, error: mapped.error });
    if (isScopeError(e)) {
      return res.status(404).json({ success: false, error: "User not found" });
    }
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
    if (hard && !isPlatform(auth.role)) {
      return res.status(403).json({ success: false, error: "Only super admin can hard delete" });
    }
    const targetLicenseeId = String(req.user?.licenseeId || "").trim() || null;
    const result = await deleteUserBoundary<any>(String(req.databaseSessionCapability || ""), administrationRequestId(req), {
      id: targetId, hard, licenseeId: targetLicenseeId,
      audit: { ipHash: hashIp(req.ip), userAgent: normalizeUserAgent(req.get("user-agent")) },
    });
    const deleted = result.response;

    return res.json({ success: true, data: deleted });
  } catch (e) {
    const mapped = administrationErrorResponse(e);
    if (mapped) return res.status(mapped.status).json({ success: false, error: mapped.error });
    if (isScopeError(e)) {
      return res.status(404).json({ success: false, error: "User not found" });
    }
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
    const targetLicenseeId = String(req.user?.licenseeId || "").trim() || null;
    const result = await restoreManufacturerBoundary<any>(String(req.databaseSessionCapability || ""), administrationRequestId(req), {
      id: targetId, licenseeId: targetLicenseeId,
      audit: { ipHash: hashIp(req.ip), userAgent: normalizeUserAgent(req.get("user-agent")) },
    });
    const restored = result.response;

    return res.json({ success: true, data: restored });
  } catch (e) {
    const mapped = administrationErrorResponse(e);
    if (mapped) return res.status(mapped.status).json({ success: false, error: mapped.error });
    if (isScopeError(e)) {
      return res.status(404).json({ success: false, error: "User not found" });
    }
    console.error("restoreManufacturer error:", e);
    return res.status(500).json({ success: false, error: "Internal server error" });
  }
};

export const hardDeleteManufacturer = async (req: AuthRequest, res: Response) => {
  req.query.hard = "true";
  return deleteUser(req, res);
};
