import { Prisma, PrismaClient } from "@prisma/client";
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
import { isCanonicalAuthDenial, withDatabaseAuthenticatedSession } from "../b01/canonicalAuthContext";
import { isRecentMfaDenial, requireRecentMfaSession } from "../b01/authenticatedSecurityRepository";

type TransactionRunner = Pick<PrismaClient, "$transaction">;
export type B02TransactionClient = Prisma.TransactionClient;
type RequestWithId = Request & { requestId?: string };

export const isB02AuthorizationError = (error: unknown) =>
  error instanceof Error && error.message.startsWith("B02 ");

const required = (value: unknown, label: string) => {
  const normalized = String(value || "").trim();
  if (!normalized) throw new Error(`B02 database boundary requires ${label}`);
  return normalized;
};

const requestIdFrom = (req: RequestWithId) =>
  required(req.requestId || req.get("x-request-id"), "a request ID");

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
  req: RequestWithId & { user?: AuthenticatedSessionClaims; databaseSessionCapability?: string | null },
  requirement: { purpose: B02AuthenticatedPurpose; assurance: B02RequiredAssurance },
  callback: (tx: Prisma.TransactionClient, context: CanonicalDbContext) => Promise<T>,
  runner: TransactionRunner = prisma
) => {
  const claims = req.user;
  if (!claims) throw new Error("B02 authenticated actor is required");
  const sessionId = required(claims.sessionId, "a signed session ID");
  const capability = required(req.databaseSessionCapability, "a database session capability");
  const requestId = requestIdFrom(req);
  if (!authenticatedPurposes.has(requirement.purpose) || !authenticatedAssurances.has(requirement.assurance)) {
    throw new Error("B02 authenticated operation requirement is unsupported");
  }
  try {
    return await withDatabaseAuthenticatedSession(claims, {
      capability,
      requestId,
      purpose: requirement.purpose,
    }, async (tx, verified) => {
      if (requirement.assurance === "mfa-verified") {
        await requireRecentMfaSession({
          sessionId,
          checkedAt: new Date(),
          maxAgeMinutes: getAdminStepUpWindowMinutes(),
        }, tx);
      }
      const context: CanonicalDbContext = { ...verified, purpose: requirement.purpose };
      await installCanonicalDbContext(tx, context);
      return callback(tx, context);
    }, runner);
  } catch (error) {
    if (
      isCanonicalAuthDenial(error) ||
      isRecentMfaDenial(error) ||
      (error instanceof Error && /AUTH_SESSION_CAPABILITY|RECENT_MFA_DENIED/.test(error.message))
    ) {
      throw new Error("B02 authenticated capability is stale or insufficient");
    }
    throw error;
  }
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
