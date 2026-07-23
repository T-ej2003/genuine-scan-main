import { createHash, randomUUID } from "node:crypto";

import { Prisma, UserRole } from "@prisma/client";

import prisma from "../config/database";
import { CanonicalDbContext, CanonicalTransactionClient } from "../lib/canonicalDbContext";
import { AuthRequest } from "../middleware/auth";
import { getAdminStepUpWindowMinutes } from "./auth/authService";
import { summarizeQrStatusCounts } from "./qrStatusMetrics";
import { getOrComputeVersionedCache } from "./versionedCacheService";

const DASHBOARD_CACHE_NAMESPACE = "dashboard-snapshot";
const DASHBOARD_CACHE_TTL_SEC = 20;
const DASHBOARD_PURPOSE = "dashboard-snapshot-read";
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const REQUEST_ID = /^[A-Za-z0-9._:-]{1,128}$/;

const manufacturerRoles = new Set<UserRole>([
  UserRole.MANUFACTURER,
  UserRole.MANUFACTURER_ADMIN,
  UserRole.MANUFACTURER_USER,
]);
const tenantRoles = new Set<UserRole>([UserRole.LICENSEE_ADMIN, UserRole.ORG_ADMIN]);
const platformRoles = new Set<UserRole>([UserRole.SUPER_ADMIN, UserRole.PLATFORM_SUPER_ADMIN]);

export type DashboardSnapshot = {
  totalQRCodes: number;
  activeLicensees: number;
  manufacturers: number;
  totalBatches: number;
  qr: {
    total: number;
    byStatus: Record<string, number>;
  } & ReturnType<typeof summarizeQrStatusCounts>;
};

type DashboardBoundary = {
  databaseSessionCapability: string;
  context: CanonicalDbContext;
  auditId: string;
  requestedLicenseeId: string | null;
  routeSurface: "GET /api/dashboard/stats" | "GET /api/events/dashboard";
};

type DashboardDataRow = {
  total_qr_codes: bigint | number | string;
  active_licensees: bigint | number | string;
  manufacturers: bigint | number | string;
  total_batches: bigint | number | string;
  dormant: bigint | number | string;
  active: bigint | number | string;
  activated: bigint | number | string;
  allocated: bigint | number | string;
  printed: bigint | number | string;
  redeemed: bigint | number | string;
  blocked: bigint | number | string;
  scanned: bigint | number | string;
  rollup_authoritative: boolean;
};

export class DashboardSnapshotAccessError extends Error {
  constructor(message = "Access denied to dashboard snapshot") {
    super(message);
  }
}

const routeSurface = (req: AuthRequest): DashboardBoundary["routeSurface"] => {
  const path = String(req.originalUrl || req.path || "").split("?", 1)[0].replace(/\/$/, "");
  if (path === "/api/dashboard/stats" || path === "/dashboard/stats") return "GET /api/dashboard/stats";
  if (path === "/api/events/dashboard" || path === "/events/dashboard") return "GET /api/events/dashboard";
  throw new DashboardSnapshotAccessError();
};

const normalizeLicenseeSelector = (raw: unknown) => {
  if (raw == null || raw === "") return null;
  if (typeof raw !== "string") throw new DashboardSnapshotAccessError();
  const normalized = raw.trim();
  if (!UUID.test(normalized)) throw new DashboardSnapshotAccessError();
  return normalized.toLowerCase();
};
const requestedLicensee = (req: AuthRequest) => normalizeLicenseeSelector(req.query?.licenseeId);

export const buildDashboardSnapshotBoundary = (
  req: AuthRequest,
  now = Date.now(),
  selectorOverride?: string | null
): DashboardBoundary => {
  const user = req.user;
  const userId = String(user?.userId || "").trim().toLowerCase();
  const requestId = String((req as AuthRequest & { requestId?: string }).requestId || "").trim();
  const databaseSessionCapability = String(req.databaseSessionCapability || "").trim();
  if (!user || !UUID.test(userId) || user.sessionStage !== "ACTIVE" || !REQUEST_ID.test(requestId) || !/^[A-Za-z0-9_-]{43}$/.test(databaseSessionCapability)) {
    throw new DashboardSnapshotAccessError();
  }

  const selector = selectorOverride === undefined ? requestedLicensee(req) : normalizeLicenseeSelector(selectorOverride);
  const tenant = tenantRoles.has(user.role);
  const manufacturer = manufacturerRoles.has(user.role);
  const platform = platformRoles.has(user.role);
  if (!tenant && !manufacturer && !platform) throw new DashboardSnapshotAccessError();

  const claimedLicenseeId = String(user.licenseeId || "").trim().toLowerCase();
  const claimedOrganizationId = String(user.orgId || "").trim().toLowerCase();
  if (tenant) {
    if (!UUID.test(claimedLicenseeId) || !UUID.test(claimedOrganizationId) || selector && selector !== claimedLicenseeId) {
      throw new DashboardSnapshotAccessError();
    }
  }
  if (platform || manufacturer) {
    const verifiedAt = Date.parse(String(user.mfaVerifiedAt || ""));
    const ageMs = now - verifiedAt;
    if (
      (platform && (claimedLicenseeId || claimedOrganizationId)) ||
      user.authAssurance !== "ADMIN_MFA" ||
      !Number.isFinite(verifiedAt) ||
      ageMs < -60_000 ||
      ageMs > getAdminStepUpWindowMinutes() * 60_000
    ) {
      throw new DashboardSnapshotAccessError();
    }
  } else if (user.authAssurance !== "PASSWORD" && user.authAssurance !== "ADMIN_MFA") {
    throw new DashboardSnapshotAccessError();
  }

  return {
    databaseSessionCapability,
    auditId: randomUUID(),
    requestedLicenseeId: selector,
    routeSurface: routeSurface(req),
    context: {
      userId,
      role: user.role,
      organizationId: tenant ? claimedOrganizationId : null,
      licenseeId: tenant ? claimedLicenseeId : selector,
      manufacturerId: manufacturer ? userId : null,
      authAssurance: user.authAssurance === "ADMIN_MFA" ? "mfa-verified" : "password-verified",
      requestId,
      purpose: DASHBOARD_PURPOSE,
    },
  };
};

const count = (value: bigint | number | string, field: string) => {
  const normalized = Number(value);
  if (!Number.isSafeInteger(normalized) || normalized < 0) {
    throw new Error(`Dashboard snapshot returned an invalid ${field} count`);
  }
  return normalized;
};

export const loadInventoryAggregate = async (
  tx: CanonicalTransactionClient,
  boundary: DashboardBoundary,
  expectedScopeFingerprint: string
): Promise<DashboardSnapshot> => {
  const [row] = await tx.$queryRaw<DashboardDataRow[]>`
    SELECT *
    FROM app_rls.dashboard_snapshot_data(
      ${boundary.databaseSessionCapability},
      ${DASHBOARD_PURPOSE},
      ${boundary.context.requestId},
      ${boundary.auditId},
      ${boundary.requestedLicenseeId},
      ${boundary.routeSurface},
      ${expectedScopeFingerprint}
    )
  `;
  if (!row) throw new Error("Dashboard snapshot function returned no result");

  const allStatuses = {
    DORMANT: count(row.dormant, "dormant"),
    ACTIVE: count(row.active, "active"),
    ACTIVATED: count(row.activated, "activated"),
    ALLOCATED: count(row.allocated, "allocated"),
    PRINTED: count(row.printed, "printed"),
    REDEEMED: count(row.redeemed, "redeemed"),
    BLOCKED: count(row.blocked, "blocked"),
    SCANNED: count(row.scanned, "scanned"),
  };
  if (typeof row.rollup_authoritative !== "boolean") throw new Error("Dashboard snapshot returned an invalid rollup mode");
  const byStatus = row.rollup_authoritative
    ? allStatuses
    : Object.fromEntries(Object.entries(allStatuses).filter(([, value]) => value > 0));
  const totalQRCodes = count(row.total_qr_codes, "QR code");
  return {
    totalQRCodes,
    activeLicensees: count(row.active_licensees, "active licensee"),
    manufacturers: count(row.manufacturers, "manufacturer"),
    totalBatches: count(row.total_batches, "batch"),
    qr: { total: totalQRCodes, byStatus, ...summarizeQrStatusCounts(byStatus) },
  };
};

export const computeDashboardSnapshot = async (
  tx: CanonicalTransactionClient,
  boundary: DashboardBoundary,
  options: { scopeOnly?: boolean } = {}
): Promise<DashboardSnapshot | null> => {
  const [scope] = await tx.$queryRaw<Array<{ scope_fingerprint: string }>>`
    SELECT scope_fingerprint
    FROM app_rls.dashboard_snapshot_scope(
      ${boundary.databaseSessionCapability},
      ${DASHBOARD_PURPOSE},
      ${boundary.context.requestId},
      ${boundary.auditId},
      ${boundary.requestedLicenseeId},
      ${boundary.routeSurface}
    )
  `;
  const fingerprint = String(scope?.scope_fingerprint || "");
  if (!/^[0-9a-f]{32}$/i.test(fingerprint)) throw new DashboardSnapshotAccessError();
  if (options.scopeOnly) return null;
  const cacheKey = createHash("sha256").update(`v1:${fingerprint}`).digest("hex");
  return getOrComputeVersionedCache(DASHBOARD_CACHE_NAMESPACE, cacheKey, DASHBOARD_CACHE_TTL_SEC, () =>
    loadInventoryAggregate(tx, boundary, fingerprint)
  );
};

export const getDashboardSnapshot = async (req: AuthRequest) => {
  const boundary = buildDashboardSnapshotBoundary(req);
  try {
    const snapshot = await prisma.$transaction(
      (tx) => computeDashboardSnapshot(tx as CanonicalTransactionClient, boundary),
      { isolationLevel: Prisma.TransactionIsolationLevel.RepeatableRead }
    );
    if (!snapshot) throw new Error("Dashboard snapshot function returned no result");
    return snapshot;
  } catch (error) {
    if (error instanceof DashboardSnapshotAccessError || /dashboard access denied|AUTH_SESSION_CAPABILITY_DENIED/i.test(String((error as Error)?.message))) {
      throw new DashboardSnapshotAccessError();
    }
    throw error;
  }
};

export const canDeliverDashboardAuditDelta = async (req: AuthRequest, eventLicenseeId: unknown) => {
  try {
    if (!req.user) return false;
    const originalSelector = requestedLicensee(req);
    if (eventLicenseeId == null || eventLicenseeId === "") {
      if (originalSelector || !platformRoles.has(req.user.role)) return false;
      const boundary = buildDashboardSnapshotBoundary(req);
      await prisma.$transaction(
        (tx) => computeDashboardSnapshot(tx as CanonicalTransactionClient, boundary, { scopeOnly: true }),
        { isolationLevel: Prisma.TransactionIsolationLevel.RepeatableRead }
      );
      return true;
    }

    const eventScope = String(eventLicenseeId).trim().toLowerCase();
    if (!UUID.test(eventScope) || originalSelector && originalSelector !== eventScope) return false;
    const boundary = buildDashboardSnapshotBoundary(req, Date.now(), eventScope);
    await prisma.$transaction(
      (tx) => computeDashboardSnapshot(tx as CanonicalTransactionClient, boundary, { scopeOnly: true }),
      { isolationLevel: Prisma.TransactionIsolationLevel.RepeatableRead }
    );
    return true;
  } catch {
    return false;
  }
};
