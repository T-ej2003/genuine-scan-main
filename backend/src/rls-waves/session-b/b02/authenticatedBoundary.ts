import { Prisma, PrismaClient, UserRole } from "@prisma/client";
import { Request } from "express";

import prisma from "../../../config/database";
import {
  CanonicalAssurance,
  CanonicalDbContext,
  installCanonicalDbContext,
} from "../../../lib/canonicalDbContext";
import {
  CustomerVerifyIdentity,
  deriveCustomerVerifyUserId,
  normalizeCustomerVerifyEmail,
} from "../../../services/customerVerifyAuthService";
import { getAdminStepUpWindowMinutes } from "../../../services/auth/authService";
import { AuthenticatedSessionClaims } from "../../../types";
import {
  isB02ManufacturerRole,
  loadB02ActiveAuthSession,
  loadB02AuthenticatedActorSelf,
  loadB02ManufacturerScope,
} from "./actorRevalidationRepository";

type TransactionRunner = Pick<PrismaClient, "$transaction">;
export type B02TransactionClient = Prisma.TransactionClient;
type RequestWithId = Request & { requestId?: string };

export const b02BoundariesEnabled = () =>
  ["1", "true", "yes", "on"].includes(
    String(process.env.MSCQR_RLS_B02_BOUNDARIES_ENABLED || "").trim().toLowerCase()
  );

export const isB02AuthorizationError = (error: unknown) =>
  error instanceof Error && error.message.startsWith("B02 ");

const required = (value: unknown, label: string) => {
  const normalized = String(value || "").trim();
  if (!normalized) throw new Error(`B02 database boundary requires ${label}`);
  return normalized;
};

const requestIdFrom = (req: RequestWithId) =>
  required(req.requestId || req.get("x-request-id"), "a request ID");

const platformRoles = new Set<UserRole>([UserRole.SUPER_ADMIN, UserRole.PLATFORM_SUPER_ADMIN]);

export type B02AuthenticatedPurpose =
  | "request-access-read"
  | "request-access-update"
  | "support-ticket-read"
  | "support-ticket-update"
  | "support-ticket-message"
  | "support-issue-create"
  | "support-issue-read"
  | "support-issue-respond"
  | "support-issue-screenshot"
  | "customer-trust-read"
  | "customer-trust-write"
  | "customer-verification-intake"
  | "customer-verification-reveal"
  | "customer-webauthn-read"
  | "customer-webauthn-write"
  | "verification-decision-read"
  | "verification-decision-write"
  | "support-workflow-write";

export type B02RequiredAssurance = "password-verified" | "mfa-verified";

const authenticatedPurposes = new Set<B02AuthenticatedPurpose>([
  "request-access-read", "request-access-update", "support-ticket-read", "support-ticket-update",
  "support-ticket-message", "support-issue-create", "support-issue-read", "support-issue-respond",
  "support-issue-screenshot", "customer-trust-read", "customer-trust-write",
  "customer-verification-intake", "customer-verification-reveal", "customer-webauthn-read",
  "customer-webauthn-write", "verification-decision-read", "verification-decision-write",
  "support-workflow-write",
]);

const authenticatedAssurances = new Set<B02RequiredAssurance>(["password-verified", "mfa-verified"]);

const finitePastDate = (value: Date | null, checkedAt: Date) =>
  value instanceof Date && Number.isFinite(value.getTime()) && value.getTime() <= checkedAt.getTime()
    ? value
    : null;

const sessionAssurance = (
  session: { authenticatedAt: Date | null; mfaVerifiedAt: Date | null },
  requiredAssurance: B02RequiredAssurance,
  checkedAt: Date
): CanonicalAssurance => {
  const authenticatedAt = finitePastDate(session.authenticatedAt, checkedAt);
  if (!authenticatedAt) throw new Error("B02 authenticated session has no valid password assurance");
  const mfaVerifiedAt = finitePastDate(session.mfaVerifiedAt, checkedAt);
  if (requiredAssurance === "mfa-verified") {
    const oldestAccepted = checkedAt.getTime() - getAdminStepUpWindowMinutes() * 60_000;
    if (!mfaVerifiedAt || mfaVerifiedAt.getTime() < oldestAccepted) {
      throw new Error("B02 authenticated session requires fresh MFA assurance");
    }
    return "mfa-verified";
  }
  return mfaVerifiedAt ? "mfa-verified" : "password-verified";
};

export type B02CustomerPurpose =
  | "customer-trust-read"
  | "customer-trust-write"
  | "customer-verification-intake"
  | "customer-verification-reveal"
  | "customer-webauthn-read"
  | "customer-webauthn-write";

export type B02CustomerRequiredAssurance = "password-verified" | "step-up-verified";

const customerPurposes = new Set<B02CustomerPurpose>([
  "customer-trust-read", "customer-trust-write", "customer-verification-intake",
  "customer-verification-reveal", "customer-webauthn-read", "customer-webauthn-write",
]);

const customerAssurances = new Set<B02CustomerRequiredAssurance>(["password-verified", "step-up-verified"]);

const customerAssurance = (
  customer: CustomerVerifyIdentity,
  requiredAssurance: B02CustomerRequiredAssurance,
  checkedAt: Date
): CanonicalAssurance => {
  if (customer.authStrength !== "PASSKEY") {
    if (requiredAssurance === "step-up-verified") {
      throw new Error("B02 customer operation requires passkey assurance");
    }
    return "password-verified";
  }
  const verifiedAt = customer.webauthnVerifiedAt ? new Date(customer.webauthnVerifiedAt) : null;
  const oldestAccepted = checkedAt.getTime() - getAdminStepUpWindowMinutes() * 60_000;
  if (!verifiedAt || !Number.isFinite(verifiedAt.getTime()) || verifiedAt.getTime() > checkedAt.getTime()) {
    throw new Error("B02 passkey customer proof is invalid");
  }
  if (verifiedAt.getTime() < oldestAccepted) {
    if (requiredAssurance === "step-up-verified") {
      throw new Error("B02 customer operation requires fresh passkey assurance");
    }
    return "password-verified";
  }
  return "step-up-verified";
};

export const withB02AuthenticatedRequest = async <T>(
  req: RequestWithId & { user?: AuthenticatedSessionClaims },
  requirement: { purpose: B02AuthenticatedPurpose; assurance: B02RequiredAssurance },
  callback: (tx: Prisma.TransactionClient, context: CanonicalDbContext) => Promise<T>,
  runner: TransactionRunner = prisma
) => {
  const claims = req.user;
  if (!claims) throw new Error("B02 authenticated actor is required");
  const userId = required(claims.userId, "a signed user ID");
  const sessionId = required(claims.sessionId, "a signed session ID");
  const requestId = requestIdFrom(req);
  if (!authenticatedPurposes.has(requirement.purpose) || !authenticatedAssurances.has(requirement.assurance)) {
    throw new Error("B02 authenticated operation requirement is unsupported");
  }
  const operationPurpose = requirement.purpose;
  const requiredAssurance = requirement.assurance;
  const checkedAt = new Date();
  return runner.$transaction(async (tx) => {
    await installCanonicalDbContext(tx, {
      userId,
      role: "AUTHENTICATED_ACTOR_BOOTSTRAP",
      organizationId: null,
      licenseeId: null,
      manufacturerId: null,
      authAssurance: "none",
      requestId,
      purpose: "actor-revalidation",
    });

    // The bootstrap role is deliberately restricted to this fixed actor-self projection.
    const actor = await loadB02AuthenticatedActorSelf(tx, userId);
    if (!actor) throw new Error("B02 authenticated actor is no longer active");

    const databaseLicenseeId = actor.licenseeId || null;
    const databaseOrganizationId = actor.orgId || null;
    await installCanonicalDbContext(tx, {
      userId: actor.id,
      role: actor.role,
      organizationId: isB02ManufacturerRole(actor.role) ? null : databaseOrganizationId,
      licenseeId: isB02ManufacturerRole(actor.role) ? null : databaseLicenseeId,
      manufacturerId: isB02ManufacturerRole(actor.role) ? actor.id : null,
      authAssurance: "none",
      requestId,
      purpose: "session-revalidation",
    });

    const session = await loadB02ActiveAuthSession(tx, { sessionId, userId: actor.id, checkedAt });
    if (!session) throw new Error("B02 authenticated session is stale or revoked");
    if (session.orgId && databaseOrganizationId && session.orgId !== databaseOrganizationId) {
      throw new Error("B02 authenticated session organization scope changed");
    }
    const authAssurance = sessionAssurance(session, requiredAssurance, checkedAt);

    let licenseeId = databaseLicenseeId;
    let organizationId = databaseOrganizationId;
    let manufacturerId: string | null = null;
    if (platformRoles.has(actor.role)) {
      licenseeId = null;
      organizationId = null;
    } else if (isB02ManufacturerRole(actor.role)) {
      manufacturerId = actor.id;
      await installCanonicalDbContext(tx, {
        userId: actor.id,
        role: actor.role,
        organizationId: null,
        licenseeId: null,
        manufacturerId,
        authAssurance,
        requestId,
        purpose: "scope-revalidation",
      });
      const scope = await loadB02ManufacturerScope(tx, {
        manufacturerId,
        requestedLicenseeId: claims.licenseeId,
        requestedOrganizationId: claims.orgId,
        requestedScopeVersion: claims.scopeVersion,
      });
      licenseeId = scope.licenseeId;
      organizationId = scope.organizationId;
    } else {
      const claimedLicenseeId = String(claims.licenseeId || "").trim();
      const claimedOrganizationId = String(claims.orgId || "").trim();
      if ((claimedLicenseeId && claimedLicenseeId !== databaseLicenseeId) ||
          (claimedOrganizationId && claimedOrganizationId !== databaseOrganizationId)) {
        throw new Error("B02 authenticated actor tenant scope changed");
      }
    }

    const context: CanonicalDbContext = {
      userId: actor.id,
      role: actor.role,
      organizationId,
      licenseeId,
      manufacturerId,
      authAssurance,
      requestId,
      purpose: operationPurpose,
    };
    await installCanonicalDbContext(tx, context);
    return callback(tx, context);
  });
};

export const withB02CustomerRequest = async <T>(
  req: RequestWithId & { customer?: CustomerVerifyIdentity },
  requirement: { purpose: B02CustomerPurpose; assurance: B02CustomerRequiredAssurance },
  callback: (tx: Prisma.TransactionClient, context: CanonicalDbContext) => Promise<T>,
  runner: TransactionRunner = prisma
) => {
  const customer = req.customer;
  if (!customer) throw new Error("B02 customer actor is required");
  const email = normalizeCustomerVerifyEmail(required(customer.email, "a signed customer email"));
  const userId = required(customer.userId, "a signed customer user ID");
  if (deriveCustomerVerifyUserId(email) !== userId) {
    throw new Error("B02 customer identity binding is invalid");
  }
  const requestId = requestIdFrom(req);
  if (!customerPurposes.has(requirement.purpose) || !customerAssurances.has(requirement.assurance)) {
    throw new Error("B02 customer operation requirement is unsupported");
  }
  const checkedAt = new Date();
  return runner.$transaction(async (tx) => {
    // Customer accounts are stateless today. This fixed bootstrap authority may only reach
    // B02 repositories whose predicates bind every row to this derived customer user ID.
    const context: CanonicalDbContext = {
      userId,
      role: "CUSTOMER",
      organizationId: null,
      licenseeId: null,
      manufacturerId: null,
      authAssurance: customerAssurance(customer, requirement.assurance, checkedAt),
      requestId,
      purpose: requirement.purpose,
    };
    await installCanonicalDbContext(tx, context);
    return callback(tx, context);
  });
};
