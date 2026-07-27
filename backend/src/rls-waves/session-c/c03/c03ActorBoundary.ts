import { Prisma, UserRole } from "@prisma/client";

import prisma from "../../../config/database";
import { CanonicalAssurance, CanonicalDbContext } from "../../../lib/canonicalDbContext";

export const C03_ACTOR_SCOPE_FUNCTION = "app_rls.c03_require_authenticated_actor";
export const C03_PLATFORM_SCOPE_FUNCTION = C03_ACTOR_SCOPE_FUNCTION;

export const C03_RESOURCE_SCOPE_FUNCTIONS = {
  incident: "app_auth.require_authenticated_session",
  policyRule: "app_auth.require_authenticated_session",
  compliancePackJob: "app_rls.c03_revalidate_compliance_pack_job_actor_scope",
  incidentEvidence: "app_auth.require_authenticated_session",
  incidentEvidenceStorage: "app_rls.c03_get_incident_evidence_file_by_storage_key",
  sensitiveActionApproval: "app_rls.c03_bind_sensitive_approval_actor",
} as const;

export type C03RequiredAssurance = "password-verified" | "mfa-verified" | "step-up-verified";

export class C03AccessError extends Error {
  constructor(message: string, readonly statusCode = 403) {
    super(message);
  }
}

const c03DatabaseAccessErrors = {
  C03_INCIDENT_DENIED: ["Incident not found", 404],
} as const;

export const c03AccessErrorFromDatabase = (error: any): C03AccessError | null => {
  if (error?.code !== "P2010" || error?.meta?.code !== "42501") return null;
  const match = /^ERROR:\s+(C03_[A-Z0-9_]+)(?:\r?\n|$)/.exec(String(error?.meta?.message || ""));
  const mapped = match?.[1] && c03DatabaseAccessErrors[match[1] as keyof typeof c03DatabaseAccessErrors];
  return mapped ? new C03AccessError(mapped[0], mapped[1]) : null;
};

type C03CapabilityBoundary = {
  databaseSessionCapability: string;
  requestId: string;
  purpose: string;
  allowedRoles: readonly UserRole[];
  requiredAssurance: C03RequiredAssurance;
};

export type C03ActorBoundary = C03CapabilityBoundary & { licenseeId: string };

export type C03ResourceBoundary = C03CapabilityBoundary & {
  resourceId: string;
  resourceType: keyof typeof C03_RESOURCE_SCOPE_FUNCTIONS;
};

export type C03PlatformBoundary = C03CapabilityBoundary;

export type C03VerifiedDbContext = CanonicalDbContext & {
  databaseSessionCapability: string;
  sessionId: string;
};

export const c03CanonicalDbContext = (context: CanonicalDbContext): CanonicalDbContext => ({
  userId: context.userId,
  role: context.role,
  organizationId: platformRoles.has(context.role as UserRole) ? null : context.organizationId ?? null,
  licenseeId: platformRoles.has(context.role as UserRole) ? null : context.licenseeId ?? null,
  manufacturerId: context.manufacturerId ?? null,
  authAssurance: context.authAssurance,
  requestId: context.requestId,
  purpose: context.purpose,
});

export const c03RequestId = (request: { requestId?: unknown; get?: (name: string) => string | undefined }) =>
  String(request.requestId || request.get?.("x-request-id") || "").trim();

export const c03DatabaseSessionCapability = (request: { databaseSessionCapability?: unknown }) =>
  String(request.databaseSessionCapability || "").trim();

type VerifiedActorRow = {
  sessionId: string;
  userId: string;
  role: string;
  organizationId: string | null;
  licenseeId: string | null;
  assurance: string;
};

type VerifiedResourceScopeRow = {
  userId: string;
  role: string;
  organizationId: string | null;
  licenseeId: string | null;
};

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const CAPABILITY_RE = /^[A-Za-z0-9_-]{43}$/;
const REQUEST_RE = /^[A-Za-z0-9._:-]{1,128}$/;
const platformRoles = new Set<UserRole>([UserRole.SUPER_ADMIN, UserRole.PLATFORM_SUPER_ADMIN]);
const manufacturerRoles = new Set<UserRole>([
  UserRole.MANUFACTURER,
  UserRole.MANUFACTURER_ADMIN,
  UserRole.MANUFACTURER_USER,
]);

const verifyCapability = async (
  tx: Prisma.TransactionClient,
  boundary: C03CapabilityBoundary
): Promise<C03VerifiedDbContext> => {
  const capability = String(boundary.databaseSessionCapability || "").trim();
  const requestId = String(boundary.requestId || "").trim();
  const purpose = String(boundary.purpose || "").trim();
  if (!CAPABILITY_RE.test(capability)) throw new C03AccessError("Authenticated database session is required", 401);
  if (!REQUEST_RE.test(requestId)) throw new C03AccessError("A bounded C03 request ID is required", 400);
  if (!purpose || purpose.length > 240) throw new C03AccessError("A bounded C03 purpose is required", 400);

  const rows = await tx.$queryRaw<VerifiedActorRow[]>`
    SELECT
      actor.session_id AS "sessionId",
      actor.user_id AS "userId",
      actor.role,
      actor.organization_id AS "organizationId",
      actor.licensee_id AS "licenseeId",
      actor.assurance
    FROM app_rls.c03_require_authenticated_actor(${capability}, ${purpose}, ${requestId}) AS actor
  `;
  if (rows.length !== 1) throw new C03AccessError("Authenticated database session is no longer valid", 401);
  const actor = rows[0];
  const role = actor.role as UserRole;
  if (!boundary.allowedRoles.includes(role)) throw new C03AccessError("Access denied");
  const assurance: CanonicalAssurance = actor.assurance === "ADMIN_MFA" ? "mfa-verified" : "password-verified";
  if (boundary.requiredAssurance !== "password-verified" && assurance !== "mfa-verified") {
    throw new C03AccessError("Fresh administrator MFA is required");
  }
  if (!["PASSWORD", "ADMIN_MFA"].includes(actor.assurance)) {
    throw new C03AccessError("Unsupported authentication assurance");
  }

  return {
    databaseSessionCapability: capability,
    sessionId: actor.sessionId,
    userId: actor.userId,
    role,
    organizationId: actor.organizationId || null,
    licenseeId: actor.licenseeId || null,
    manufacturerId: manufacturerRoles.has(role) ? actor.userId : null,
    authAssurance: assurance,
    requestId,
    purpose,
  };
};

const requireLicenseeSelector = (selector: string, actor: C03VerifiedDbContext) => {
  if (!UUID_RE.test(selector)) throw new C03AccessError("A valid bounded licensee scope is required", 400);
  if (!platformRoles.has(actor.role as UserRole) && actor.licenseeId !== selector) {
    throw new C03AccessError("Access denied to this licensee");
  }
  return { ...actor, licenseeId: selector };
};

const requireResourceSelector = (boundary: C03ResourceBoundary) => {
  const selector = String(boundary.resourceId || "").trim();
  if (boundary.resourceType === "incidentEvidenceStorage") {
    if (!selector || selector.length > 1000 || selector.includes("\0")) {
      throw new C03AccessError("A valid resource identifier is required", 400);
    }
  } else if (!UUID_RE.test(selector)) {
    throw new C03AccessError("A valid resource identifier is required", 400);
  }
};

const withCapabilityTransaction = <T>(
  boundary: C03CapabilityBoundary,
  callback: (tx: Prisma.TransactionClient, context: C03VerifiedDbContext) => Promise<T>,
  isolationLevel: Prisma.TransactionIsolationLevel,
  narrow?: (context: C03VerifiedDbContext) => C03VerifiedDbContext
) => prisma.$transaction(async (tx) => {
  const verified = await verifyCapability(tx, boundary);
  return callback(tx, narrow ? narrow(verified) : verified);
}, { isolationLevel }).catch((error) => {
  throw c03AccessErrorFromDatabase(error) || error;
});

export const withC03ActorTransaction = <T>(
  boundary: C03ActorBoundary,
  callback: (tx: Prisma.TransactionClient, context: C03VerifiedDbContext) => Promise<T>,
  isolationLevel: Prisma.TransactionIsolationLevel = Prisma.TransactionIsolationLevel.Serializable
): Promise<T> => withCapabilityTransaction<T>(
  boundary,
  callback,
  isolationLevel,
  (context) => requireLicenseeSelector(String(boundary.licenseeId || "").trim(), context)
);

export const withC03ResourceTransaction = <T>(
  boundary: C03ResourceBoundary,
  callback: (tx: Prisma.TransactionClient, context: C03VerifiedDbContext) => Promise<T>,
  isolationLevel: Prisma.TransactionIsolationLevel = Prisma.TransactionIsolationLevel.Serializable
): Promise<T> => {
  requireResourceSelector(boundary);
  return withCapabilityTransaction<T>(boundary, async (tx, context) => {
    if (boundary.resourceType === "compliancePackJob") {
      const rows = await tx.$queryRaw<VerifiedResourceScopeRow[]>`
        SELECT
          scope.user_id AS "userId",
          scope.role,
          scope.organization_id AS "organizationId",
          scope.licensee_id AS "licenseeId"
        FROM app_rls.c03_revalidate_compliance_pack_job_actor_scope(
          ${context.databaseSessionCapability}, ${context.purpose}, ${context.requestId}, ${boundary.resourceId}
        ) AS scope
      `;
      const scope = rows[0];
      if (
        rows.length !== 1 || scope.userId !== context.userId || scope.role !== context.role ||
        (!platformRoles.has(context.role as UserRole) &&
          (scope.organizationId !== context.organizationId || scope.licenseeId !== context.licenseeId))
      ) {
        throw new C03AccessError("Access denied to this compliance job");
      }
      return callback(tx, {
        ...context,
        organizationId: scope.organizationId,
        licenseeId: scope.licenseeId,
      });
    }
    if (boundary.resourceType === "sensitiveActionApproval") {
      const rows = await tx.$queryRaw<VerifiedResourceScopeRow[]>`
        SELECT
          scope.user_id AS "userId",
          scope.role,
          scope.organization_id AS "organizationId",
          scope.licensee_id AS "licenseeId"
        FROM app_rls.c03_bind_sensitive_approval_actor(
          ${context.databaseSessionCapability}, ${context.purpose}, ${context.requestId}, ${boundary.resourceId}
        ) AS scope
      `;
      const scope = rows[0];
      if (rows.length !== 1 || scope.userId !== context.userId || scope.role !== context.role) {
        throw new C03AccessError("Access denied to this sensitive approval");
      }
      return callback(tx, {
        ...context,
        organizationId: scope.organizationId,
        licenseeId: scope.licenseeId,
      });
    }
    return callback(tx, context);
  }, isolationLevel);
};

export const withC03PlatformTransaction = <T>(
  boundary: C03PlatformBoundary,
  callback: (tx: Prisma.TransactionClient, context: C03VerifiedDbContext) => Promise<T>,
  isolationLevel: Prisma.TransactionIsolationLevel = Prisma.TransactionIsolationLevel.Serializable
): Promise<T> => withCapabilityTransaction<T>(boundary, async (tx, context) => {
  if (!platformRoles.has(context.role as UserRole) || context.licenseeId || context.organizationId) {
    throw new C03AccessError("A global platform boundary requires an unscoped platform actor");
  }
  return callback(tx, context);
}, isolationLevel);
