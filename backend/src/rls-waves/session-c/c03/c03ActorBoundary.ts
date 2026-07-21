import { Prisma, UserRole } from "@prisma/client";

import prisma from "../../../config/database";
import {
  CanonicalAssurance,
  CanonicalDbContext,
  installCanonicalDbContext,
  withCanonicalDbContext,
} from "../../../lib/canonicalDbContext";
import { getAdminStepUpWindowMinutes } from "../../../services/auth/authService";
import { AuthenticatedSessionClaims } from "../../../types";

export const C03_ACTOR_SCOPE_FUNCTION = "app_rls.c03_revalidate_actor_scope";
export const C03_PLATFORM_SCOPE_FUNCTION = "app_rls.c03_revalidate_platform_actor_scope";

export const C03_RESOURCE_SCOPE_FUNCTIONS = {
  incident: "app_rls.c03_revalidate_incident_actor_scope",
  policyRule: "app_rls.c03_revalidate_policy_rule_actor_scope",
  compliancePackJob: "app_rls.c03_revalidate_compliance_pack_job_actor_scope",
  incidentEvidence: "app_rls.c03_revalidate_incident_evidence_actor_scope",
  incidentEvidenceStorage: "app_rls.c03_revalidate_incident_evidence_storage_actor_scope",
  sensitiveActionApproval: "app_rls.c03_revalidate_sensitive_approval_actor_scope",
} as const;

export type C03RequiredAssurance = "password-verified" | "mfa-verified" | "step-up-verified";

export class C03AccessError extends Error {
  constructor(message: string, readonly statusCode = 403) {
    super(message);
  }
}

export type C03ActorBoundary = {
  user: AuthenticatedSessionClaims;
  requestId: string;
  purpose: string;
  licenseeId: string;
  allowedRoles: readonly UserRole[];
  requiredAssurance: C03RequiredAssurance;
};

export type C03ResourceBoundary = Omit<C03ActorBoundary, "licenseeId"> & {
  resourceId: string;
  resourceType: keyof typeof C03_RESOURCE_SCOPE_FUNCTIONS;
};

export type C03PlatformBoundary = Omit<C03ActorBoundary, "licenseeId">;

export const c03RequestId = (request: { requestId?: unknown; get?: (name: string) => string | undefined }) =>
  String(request.requestId || request.get?.("x-request-id") || "").trim();

type RevalidatedActorRow = {
  userId: string;
  role: string;
  organizationId: string;
  licenseeId: string;
};

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const platformRoles = new Set<UserRole>([UserRole.SUPER_ADMIN, UserRole.PLATFORM_SUPER_ADMIN]);
const manufacturerRoles = new Set<UserRole>([
  UserRole.MANUFACTURER,
  UserRole.MANUFACTURER_ADMIN,
  UserRole.MANUFACTURER_USER,
]);

const requireFreshMfa = (user: AuthenticatedSessionClaims) => {
  if (user.authAssurance !== "ADMIN_MFA") throw new C03AccessError("Fresh administrator MFA is required");
  const verifiedAt = Date.parse(String(user.mfaVerifiedAt || ""));
  if (!Number.isFinite(verifiedAt) || Date.now() - verifiedAt > getAdminStepUpWindowMinutes() * 60_000) {
    throw new C03AccessError("Fresh administrator MFA is required");
  }
};

const buildInitialContext = (
  boundary: Omit<C03ActorBoundary, "licenseeId"> & { licenseeId?: string | null }
): CanonicalDbContext => {
  const userId = String(boundary.user?.userId || "").trim();
  const requestId = String(boundary.requestId || "").trim();
  const purpose = String(boundary.purpose || "").trim();
  const requestedLicenseeId = String(boundary.licenseeId || "").trim();
  if (!userId || !requestId || boundary.user?.sessionStage !== "ACTIVE") {
    throw new C03AccessError("Authenticated actor context is required", 401);
  }
  if (!purpose || purpose.length > 240) throw new C03AccessError("A bounded C03 purpose is required", 400);
  if (!boundary.allowedRoles.includes(boundary.user.role)) throw new C03AccessError("Access denied");
  const claimedLicenseeId = String(boundary.user.licenseeId || "").trim();
  const platformActor = platformRoles.has(boundary.user.role);
  if (platformActor && (claimedLicenseeId || boundary.user.orgId)) {
    throw new C03AccessError("Platform actor context is inconsistent");
  }
  if (requestedLicenseeId && !UUID_RE.test(requestedLicenseeId)) {
    throw new C03AccessError("A valid bounded licensee scope is required", 400);
  }
  if (!platformActor) {
    if (!UUID_RE.test(claimedLicenseeId)) throw new C03AccessError("A valid actor licensee scope is required");
    if (requestedLicenseeId && claimedLicenseeId !== requestedLicenseeId) {
      throw new C03AccessError("Access denied to this licensee");
    }
  }
  if (boundary.requiredAssurance !== "password-verified") requireFreshMfa(boundary.user);
  if (boundary.user.authAssurance !== "PASSWORD" && boundary.user.authAssurance !== "ADMIN_MFA") {
    throw new C03AccessError("Unsupported authentication assurance");
  }

  const assurance: CanonicalAssurance =
    boundary.requiredAssurance === "step-up-verified"
      ? "step-up-verified"
      : boundary.user.authAssurance === "ADMIN_MFA"
        ? "mfa-verified"
        : "password-verified";

  return {
    userId,
    role: String(boundary.user.role),
    organizationId: boundary.user.orgId || null,
    licenseeId: requestedLicenseeId || (platformActor ? null : claimedLicenseeId),
    manufacturerId: manufacturerRoles.has(boundary.user.role) ? userId : null,
    authAssurance: assurance,
    requestId,
    purpose,
  };
};

const revalidatePlatformActor = async (
  tx: Prisma.TransactionClient,
  boundary: C03PlatformBoundary,
  context: CanonicalDbContext
) => {
  const roles = JSON.stringify(boundary.allowedRoles.map(String));
  const rows = await tx.$queryRaw<Array<{ userId: string; role: string }>>`
    SELECT actor.user_id AS "userId", actor.role
      FROM app_rls.c03_revalidate_platform_actor_scope(
        ${roles}::jsonb,
        ${boundary.requiredAssurance},
        ${context.purpose}
      ) AS actor
  `;
  if (rows.length !== 1 || rows[0].userId !== context.userId || rows[0].role !== context.role) {
    throw new C03AccessError("Platform actor is no longer authorized");
  }
  return installCanonicalDbContext(tx, context);
};

const requireRevalidatedActor = (
  rows: RevalidatedActorRow[],
  context: CanonicalDbContext
): RevalidatedActorRow => {
  if (rows.length !== 1) throw new C03AccessError("Actor or active licensee scope is no longer authorized");
  const actor = rows[0];
  if (
    actor.userId !== context.userId ||
    actor.role !== context.role ||
    !UUID_RE.test(String(actor.licenseeId || "")) ||
    !UUID_RE.test(String(actor.organizationId || "")) ||
    (context.licenseeId && actor.licenseeId !== context.licenseeId)
  ) {
    throw new C03AccessError("Actor or active licensee scope is no longer authorized");
  }
  return actor;
};

const revalidateActorAndScope = async (
  tx: Prisma.TransactionClient,
  boundary: C03ActorBoundary,
  context: CanonicalDbContext
) => {
  const allowedRolesJson = JSON.stringify(boundary.allowedRoles.map(String));
  const rows = await tx.$queryRaw<RevalidatedActorRow[]>`
    SELECT
      actor.user_id AS "userId",
      actor.role,
      actor.organization_id AS "organizationId",
      actor.licensee_id AS "licenseeId"
    FROM app_rls.c03_revalidate_actor_scope(
      ${context.licenseeId},
      ${allowedRolesJson}::jsonb,
      ${boundary.requiredAssurance},
      ${context.purpose}
    ) AS actor
  `;
  const actor = requireRevalidatedActor(rows, context);

  return installCanonicalDbContext(tx, {
    ...context,
    organizationId: actor.organizationId,
  });
};

const revalidateResourceActorAndScope = async (
  tx: Prisma.TransactionClient,
  boundary: C03ResourceBoundary,
  context: CanonicalDbContext
) => {
  const resourceId = String(boundary.resourceId || "").trim();
  if (
    boundary.resourceType === "incidentEvidenceStorage"
      ? !resourceId || resourceId.length > 1000 || resourceId.includes("\0")
      : !UUID_RE.test(resourceId)
  ) {
    throw new C03AccessError("A valid resource identifier is required", 400);
  }
  const roles = JSON.stringify(boundary.allowedRoles.map(String));
  const args = [resourceId, roles, boundary.requiredAssurance, context.purpose] as const;
  let rows: RevalidatedActorRow[];
  switch (boundary.resourceType) {
    case "incident":
      rows = await tx.$queryRaw`
        SELECT actor.user_id AS "userId", actor.role,
               actor.organization_id AS "organizationId", actor.licensee_id AS "licenseeId"
          FROM app_rls.c03_revalidate_incident_actor_scope(
            ${args[0]}, ${args[1]}::jsonb, ${args[2]}, ${args[3]}
          ) AS actor
      `;
      break;
    case "policyRule":
      rows = await tx.$queryRaw`
        SELECT actor.user_id AS "userId", actor.role,
               actor.organization_id AS "organizationId", actor.licensee_id AS "licenseeId"
          FROM app_rls.c03_revalidate_policy_rule_actor_scope(
            ${args[0]}, ${args[1]}::jsonb, ${args[2]}, ${args[3]}
          ) AS actor
      `;
      break;
    case "compliancePackJob":
      rows = await tx.$queryRaw`
        SELECT actor.user_id AS "userId", actor.role,
               actor.organization_id AS "organizationId", actor.licensee_id AS "licenseeId"
          FROM app_rls.c03_revalidate_compliance_pack_job_actor_scope(
            ${args[0]}, ${args[1]}::jsonb, ${args[2]}, ${args[3]}
          ) AS actor
      `;
      break;
    case "incidentEvidence":
      rows = await tx.$queryRaw`
        SELECT actor.user_id AS "userId", actor.role,
               actor.organization_id AS "organizationId", actor.licensee_id AS "licenseeId"
          FROM app_rls.c03_revalidate_incident_evidence_actor_scope(
            ${args[0]}, ${args[1]}::jsonb, ${args[2]}, ${args[3]}
          ) AS actor
      `;
      break;
    case "incidentEvidenceStorage":
      rows = await tx.$queryRaw`
        SELECT actor.user_id AS "userId", actor.role,
               actor.organization_id AS "organizationId", actor.licensee_id AS "licenseeId"
          FROM app_rls.c03_revalidate_incident_evidence_storage_actor_scope(
            ${args[0]}, ${args[1]}::jsonb, ${args[2]}, ${args[3]}
          ) AS actor
      `;
      break;
    case "sensitiveActionApproval":
      rows = await tx.$queryRaw`
        SELECT actor.user_id AS "userId", actor.role,
               actor.organization_id AS "organizationId", actor.licensee_id AS "licenseeId"
          FROM app_rls.c03_revalidate_sensitive_approval_actor_scope(
            ${args[0]}, ${args[1]}::jsonb, ${args[2]}, ${args[3]}
          ) AS actor
      `;
      break;
  }
  const actor = requireRevalidatedActor(rows, context);
  return installCanonicalDbContext(tx, {
    ...context,
    organizationId: actor.organizationId,
    licenseeId: actor.licenseeId,
  });
};

export const withC03ActorTransaction = async <T>(
  boundary: C03ActorBoundary,
  callback: (tx: Prisma.TransactionClient, context: CanonicalDbContext) => Promise<T>,
  isolationLevel: Prisma.TransactionIsolationLevel = Prisma.TransactionIsolationLevel.Serializable
) => {
  const initialContext = buildInitialContext(boundary);
  return withCanonicalDbContext(
    prisma,
    initialContext,
    async (tx) => callback(tx, await revalidateActorAndScope(tx, boundary, initialContext)),
    { isolationLevel }
  );
};

export const withC03ResourceTransaction = async <T>(
  boundary: C03ResourceBoundary,
  callback: (tx: Prisma.TransactionClient, context: CanonicalDbContext) => Promise<T>,
  isolationLevel: Prisma.TransactionIsolationLevel = Prisma.TransactionIsolationLevel.Serializable
) => {
  const initialContext = buildInitialContext(boundary);
  return withCanonicalDbContext(
    prisma,
    initialContext,
    async (tx) => callback(tx, await revalidateResourceActorAndScope(tx, boundary, initialContext)),
    { isolationLevel }
  );
};

export const withC03PlatformTransaction = async <T>(
  boundary: C03PlatformBoundary,
  callback: (tx: Prisma.TransactionClient, context: CanonicalDbContext) => Promise<T>,
  isolationLevel: Prisma.TransactionIsolationLevel = Prisma.TransactionIsolationLevel.Serializable
) => {
  const initialContext = buildInitialContext(boundary);
  if (initialContext.licenseeId || initialContext.organizationId || initialContext.manufacturerId) {
    throw new C03AccessError("A global platform boundary cannot install tenant scope");
  }
  return withCanonicalDbContext(
    prisma,
    initialContext,
    async (tx) => callback(tx, await revalidatePlatformActor(tx, boundary, initialContext)),
    { isolationLevel }
  );
};
