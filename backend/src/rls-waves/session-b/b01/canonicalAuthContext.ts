import { Prisma } from "@prisma/client";

import {
  installCanonicalDbContext,
  type CanonicalAssurance,
  type CanonicalDbContext,
} from "../../../lib/canonicalDbContext";
import type { AuthenticatedSessionClaims } from "../../../types";
import { revalidateAuthenticatedActor } from "./actorRevalidationRepository";
import { getB01AuthenticatedPrisma } from "./runtimeClients";

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
