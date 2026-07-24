import { randomUUID } from "node:crypto";

import { Prisma, UserRole } from "@prisma/client";

import prisma from "../config/database";
import { CanonicalDbContext, CanonicalTransactionClient } from "../lib/canonicalDbContext";
import {
  BatchOperationalRepositoryBoundary,
  listBatchOperationalSummaries,
} from "./batchAllocationService";
import {
  categorizeStagingRlsBatchReadFailure,
  classifyStagingRlsBatchReadContext,
  recordStagingRlsBatchReadProof,
} from "../observability/stagingRlsBatchReadProof";
import { AuthenticatedSessionClaims } from "../types";
import { getAdminStepUpWindowMinutes } from "./auth/authService";
import { requireAuthenticatedSessionCapability } from "./auth/authenticatedSessionCapabilityService";

const BATCH_OPERATIONAL_READ_PURPOSE = "batch-operational-read";
export const BATCH_OPERATIONAL_READ_TRANSACTION_OPTIONS = {
  isolationLevel: Prisma.TransactionIsolationLevel.RepeatableRead,
  maxWait: 5_000,
  timeout: 15_000,
} as const;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const REQUEST_ID = /^[A-Za-z0-9._:-]{1,128}$/;

const tenantRoles = new Set<UserRole>([UserRole.LICENSEE_ADMIN, UserRole.ORG_ADMIN]);
const manufacturerRoles = new Set<UserRole>([
  UserRole.MANUFACTURER,
  UserRole.MANUFACTURER_ADMIN,
  UserRole.MANUFACTURER_USER,
]);
const platformRoles = new Set<UserRole>([UserRole.SUPER_ADMIN, UserRole.PLATFORM_SUPER_ADMIN]);

export type BatchOperationalRouteSurface =
  | "GET /api/qr/batches"
  | "GET /api/qr/batches/:id/allocation-map";

export class BatchOperationalReadAccessError extends Error {
  constructor() {
    super("Access denied to batch operational read");
  }
}

export const assertBatchOperationalCapabilityActor = async (
  db: CanonicalTransactionClient,
  boundary: BatchOperationalRepositoryBoundary,
  user: AuthenticatedSessionClaims
) => {
  const actor = await requireAuthenticatedSessionCapability(db, {
    capability: boundary.databaseSessionCapability,
    purpose: boundary.purpose,
    requestId: boundary.requestId,
  });
  if (actor.userId !== user.userId || actor.role !== user.role) {
    throw new BatchOperationalReadAccessError();
  }
};

export const runBatchOperationalReadTransaction = async <T>(
  callback: (db: CanonicalTransactionClient) => Promise<T>
) => {
  for (let attempt = 0; ; attempt += 1) {
    try {
      return await prisma.$transaction(
        (tx) => callback(tx as CanonicalTransactionClient),
        BATCH_OPERATIONAL_READ_TRANSACTION_OPTIONS
      );
    } catch (error) {
      const code = String((error as { meta?: { code?: unknown }; code?: unknown })?.meta?.code ||
        (error as { code?: unknown })?.code || "");
      if (code !== "40001" || attempt === 1) throw error;
    }
  }
};

const optionalUuid = (value: unknown) => {
  if (value == null || value === "") return null;
  if (typeof value !== "string") throw new BatchOperationalReadAccessError();
  const normalized = value.trim().toLowerCase();
  if (!UUID.test(normalized)) throw new BatchOperationalReadAccessError();
  return normalized;
};

const requiredUuid = (value: unknown) => {
  const normalized = optionalUuid(value);
  if (!normalized) throw new BatchOperationalReadAccessError();
  return normalized;
};

const requireFreshMfa = (user: AuthenticatedSessionClaims, now: number) => {
  const verifiedAt = Date.parse(String(user.mfaVerifiedAt || ""));
  const ageMs = now - verifiedAt;
  if (
    user.authAssurance !== "ADMIN_MFA" ||
    !Number.isFinite(verifiedAt) ||
    ageMs < -60_000 ||
    ageMs > getAdminStepUpWindowMinutes() * 60_000
  ) {
    throw new BatchOperationalReadAccessError();
  }
};

export const buildBatchOperationalReadBoundary = (
  params: {
    user: AuthenticatedSessionClaims;
    requestedLicenseeId: unknown;
    requestId: unknown;
    routeSurface: BatchOperationalRouteSurface;
    batchId?: unknown;
    databaseSessionCapability: unknown;
  },
  now = Date.now()
): {
  context: CanonicalDbContext;
  repository: BatchOperationalRepositoryBoundary;
  where: Prisma.BatchWhereInput;
  batchId: string | null;
} => {
  const user = params.user;
  const userId = requiredUuid(user?.userId);
  const requestId = String(params.requestId || "").trim();
  const databaseSessionCapability = String(params.databaseSessionCapability || "").trim();
  const requestedLicenseeId = optionalUuid(params.requestedLicenseeId);
  const batchId = params.routeSurface === "GET /api/qr/batches/:id/allocation-map"
    ? requiredUuid(params.batchId)
    : null;
  if (user.sessionStage !== "ACTIVE" || !REQUEST_ID.test(requestId) || !/^[A-Za-z0-9_-]{43}$/.test(databaseSessionCapability)) {
    throw new BatchOperationalReadAccessError();
  }

  const tenant = tenantRoles.has(user.role);
  const manufacturer = manufacturerRoles.has(user.role);
  const platform = platformRoles.has(user.role);
  if (!tenant && !manufacturer && !platform) throw new BatchOperationalReadAccessError();

  let organizationId: string | null = null;
  let licenseeId: string | null = null;
  let manufacturerId: string | null = null;
  let where: Prisma.BatchWhereInput;

  if (tenant) {
    licenseeId = requiredUuid(user.licenseeId);
    organizationId = requiredUuid(user.orgId);
    if (requestedLicenseeId && requestedLicenseeId !== licenseeId) {
      throw new BatchOperationalReadAccessError();
    }
    if (user.authAssurance !== "PASSWORD" && user.authAssurance !== "ADMIN_MFA") {
      throw new BatchOperationalReadAccessError();
    }
    where = { licenseeId };
  } else if (manufacturer) {
    requireFreshMfa(user, now);
    manufacturerId = userId;
    licenseeId = requestedLicenseeId;
    where = { manufacturerId, ...(licenseeId ? { licenseeId } : {}) };
  } else {
    requireFreshMfa(user, now);
    if (user.licenseeId || user.orgId || !requestedLicenseeId) {
      throw new BatchOperationalReadAccessError();
    }
    licenseeId = requestedLicenseeId;
    where = { licenseeId };
  }

  const auditId = randomUUID();
  return {
    batchId,
    where,
    repository: {
      databaseSessionCapability,
      requestId,
      purpose: BATCH_OPERATIONAL_READ_PURPOSE,
      auditId,
      requestedLicenseeId,
      routeSurface: params.routeSurface,
      focusBatchId: batchId,
    },
    context: {
      userId,
      role: user.role,
      organizationId,
      licenseeId,
      manufacturerId,
      authAssurance: user.authAssurance === "ADMIN_MFA" ? "mfa-verified" : "password-verified",
      requestId,
      purpose: BATCH_OPERATIONAL_READ_PURPOSE,
    },
  };
};

type LoadBatchListPayloadParams = {
  user: AuthenticatedSessionClaims;
  requestedLicenseeId: unknown;
  requestId: unknown;
  limit: number;
  offset: number;
  databaseSessionCapability: unknown;
};

export const listScopedBatchReadPayload = async (params: LoadBatchListPayloadParams) => {
  const startedAt = process.hrtime.bigint();
  const contextClass = classifyStagingRlsBatchReadContext(params.user);
  try {
    const boundary = buildBatchOperationalReadBoundary({
      ...params,
      routeSurface: "GET /api/qr/batches",
    });
    const payload = await runBatchOperationalReadTransaction(
      async (db) => {
        await assertBatchOperationalCapabilityActor(db, boundary.repository, params.user);
        return listBatchOperationalSummaries({
          boundary: boundary.repository,
          limit: params.limit,
          offset: params.offset,
          db,
        });
      }
    );
    recordStagingRlsBatchReadProof({
      flagEnabled: true,
      contextClass,
      durationMs: Number(process.hrtime.bigint() - startedAt) / 1_000_000,
      rowCount: payload.rows.length,
      success: true,
    });
    return payload;
  } catch (error) {
    recordStagingRlsBatchReadProof({
      flagEnabled: true,
      contextClass,
      durationMs: Number(process.hrtime.bigint() - startedAt) / 1_000_000,
      rowCount: 0,
      success: false,
      failureCategory: categorizeStagingRlsBatchReadFailure(error),
    });
    throw error;
  }
};
