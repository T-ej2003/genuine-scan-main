import { Prisma } from "@prisma/client";

import {
  installCanonicalDbContext,
  type CanonicalAssurance,
  type CanonicalDbContext,
} from "../../../lib/canonicalDbContext";
import type { AuthenticatedSessionClaims } from "../../../types";
import { revalidateAuthenticatedActor } from "./actorRevalidationRepository";
import { getB01AuthenticatedPrisma } from "./runtimeClients";
import { requireAuthenticatedSessionCapability } from "../../../services/auth/authenticatedSessionCapabilityService";

export class CanonicalAuthDenial extends Error {
  constructor() {
    super("AUTHENTICATED_SESSION_DENIED");
    this.name = "CanonicalAuthDenial";
  }
}

export const isCanonicalAuthDenial = (error: unknown): error is CanonicalAuthDenial =>
  error instanceof CanonicalAuthDenial;

const required = (value: unknown, label: string) => {
  const normalized = String(value || "").trim();
  if (!normalized) throw new Error(`B01 database boundary requires ${label}`);
  return normalized;
};

const assurance = (value: string): CanonicalAssurance => {
  if (value === "password-verified" || value === "mfa-bootstrap" || value === "mfa-verified" || value === "step-up-verified") {
    return value;
  }
  throw new Error("B01 actor revalidation returned unsupported assurance");
};

export const withCanonicalAuthClaims = <T>(
  claims: AuthenticatedSessionClaims,
  input: { requestId: string; purpose: string },
  callback: (tx: Prisma.TransactionClient, context: CanonicalDbContext) => Promise<T>
) => {
  const userId = required(claims.userId, "an actor user ID");
  const sessionId = required(claims.sessionId, "an authenticated session ID");
  const requestId = required(input.requestId, "a request ID");
  const purpose = required(input.purpose, "a purpose");
  return getB01AuthenticatedPrisma().$transaction(async (tx) => {
    const actor = await revalidateAuthenticatedActor(tx, {
      userId,
      sessionId,
      requestedLicenseeId: claims.licenseeId || null,
      requestedOrganizationId: claims.orgId || null,
      checkedAt: new Date(),
      requestId,
    });
    if (!actor) throw new CanonicalAuthDenial();
    const context: CanonicalDbContext = {
      userId: actor.userId,
      role: actor.role,
      organizationId: actor.organizationId,
      licenseeId: actor.licenseeId,
      manufacturerId: actor.manufacturerId,
      authAssurance: assurance(actor.authAssurance),
      requestId,
      purpose,
    };
    await installCanonicalDbContext(tx, context);
    return callback(tx, context);
  });
};

export const withDatabaseAuthenticatedSession = <T>(
  claims: AuthenticatedSessionClaims,
  input: { capability: string; requestId: string; purpose: string },
  callback: (tx: Prisma.TransactionClient, context: CanonicalDbContext) => Promise<T>,
  runner: Pick<ReturnType<typeof getB01AuthenticatedPrisma>, "$transaction"> = getB01AuthenticatedPrisma()
): Promise<T> => {
  const expectedUserId = required(claims.userId, "an actor user ID");
  const capability = required(input.capability, "a database session capability");
  if (!/^[A-Za-z0-9_-]{43}$/.test(capability)) throw new CanonicalAuthDenial();
  const requestId = required(input.requestId, "a request ID");
  const purpose = required(input.purpose, "a purpose");
  return runner.$transaction(async (tx) => {
    const verified = await requireAuthenticatedSessionCapability(tx, { capability, purpose, requestId });
    if (verified.userId !== expectedUserId || verified.sessionId !== required(claims.sessionId, "an authenticated session ID")) {
      throw new CanonicalAuthDenial();
    }
    const actor = await revalidateAuthenticatedActor(tx, {
      userId: expectedUserId,
      sessionId: verified.sessionId,
      requestedLicenseeId: claims.licenseeId || null,
      requestedOrganizationId: claims.orgId || null,
      checkedAt: new Date(),
      requestId,
    });
    if (!actor || actor.userId !== expectedUserId) throw new CanonicalAuthDenial();
    const context: CanonicalDbContext = {
      userId: actor.userId,
      role: actor.role,
      organizationId: actor.organizationId,
      licenseeId: actor.licenseeId,
      manufacturerId: actor.manufacturerId,
      authAssurance: assurance(actor.authAssurance),
      requestId,
      purpose,
    };
    return callback(tx, context);
  });
};
