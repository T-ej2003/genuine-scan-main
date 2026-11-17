import { Prisma } from "@prisma/client";
import { performance } from "node:perf_hooks";

import {
  installCanonicalDbContext,
  type CanonicalAssurance,
  type CanonicalDbContext,
  type CanonicalTransactionClient,
  validateCanonicalDbContext,
} from "../../../lib/canonicalDbContext";
import type { AuthenticatedSessionClaims } from "../../../types";
import { revalidateAuthenticatedActor } from "./actorRevalidationRepository";
import { getB01AuthenticatedPrisma } from "./runtimeClients";
import { requireAuthenticatedSessionCapability } from "../../../services/auth/authenticatedSessionCapabilityService";
import { logger } from "../../../utils/logger";
import { isValidRequestId } from "../../../utils/requestId";

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
  runner: Pick<ReturnType<typeof getB01AuthenticatedPrisma>, "$transaction"> = getB01AuthenticatedPrisma(),
  options?: { isolationLevel?: Prisma.TransactionIsolationLevel; maxWait?: number; timeout?: number }
): Promise<T> => {
  const expectedUserId = required(claims.userId, "an actor user ID");
  const capability = required(input.capability, "a database session capability");
  if (!/^[A-Za-z0-9_-]{43}$/.test(capability)) throw new CanonicalAuthDenial();
  const requestId = required(input.requestId, "a request ID");
  const purpose = required(input.purpose, "a purpose");
  const startedAt = performance.now();
  let callbackStartedAt: number | null = null;
  let capabilityMs: number | null = null;
  let actorRevalidationMs: number | null = null;
  let failureCode: string | null = null;
  let failed = false;
  return (async () => {
  try {
    return await runner.$transaction(async (tx) => {
      callbackStartedAt = performance.now();
      let verified;
      const capabilityStartedAt = performance.now();
      try {
        verified = await requireAuthenticatedSessionCapability(tx, { capability, purpose, requestId });
      } catch (error) {
        const sqlError = error as { code?: unknown; meta?: { code?: unknown; message?: unknown }; message?: unknown };
        if (sqlError?.code === "P2010" && sqlError.meta?.code === "42501" &&
            /\bAUTH_SESSION_CAPABILITY_DENIED\b/.test(String(sqlError.meta.message || sqlError.message || ""))) {
          throw new CanonicalAuthDenial();
        }
        throw error;
      } finally {
        capabilityMs = performance.now() - capabilityStartedAt;
      }
      if (verified.userId !== expectedUserId || verified.sessionId !== required(claims.sessionId, "an authenticated session ID")) {
        throw new CanonicalAuthDenial();
      }
      const actorStartedAt = performance.now();
      let actor;
      try {
        actor = await revalidateAuthenticatedActor(tx, {
          userId: expectedUserId,
          sessionId: verified.sessionId,
          requestedLicenseeId: claims.licenseeId || null,
          requestedOrganizationId: claims.orgId || null,
          checkedAt: new Date(),
          requestId,
        });
      } finally {
        actorRevalidationMs = performance.now() - actorStartedAt;
      }
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
    }, options);
  } catch (error) {
    failed = true;
    failureCode = String((error as { code?: unknown })?.code || "") || null;
    throw error;
  } finally {
    const finishedAt = performance.now();
    const elapsedMs = finishedAt - startedAt;
    if (isValidRequestId(requestId) && (failureCode === "P2028" || elapsedMs >= 1000)) {
      const rounded = (value: number | null) => value === null ? null : Math.round(value * 10) / 10;
      try {
        logger.info(JSON.stringify({
          event: "auth_transaction_timing",
          requestId,
          purpose,
          outcome: failed ? "error" : "ok",
          errorCode: failureCode === "P2028" ? "P2028" : failureCode ? "OTHER" : null,
          p2028Phase: failureCode === "P2028"
            ? callbackStartedAt === null ? "acquisition" : "execution"
            : null,
          elapsedMs: rounded(elapsedMs),
          acquisitionMs: rounded(callbackStartedAt === null ? elapsedMs : callbackStartedAt - startedAt),
          transactionExecutionMs: rounded(callbackStartedAt === null ? null : finishedAt - callbackStartedAt),
          capabilityMs: rounded(capabilityMs),
          actorRevalidationMs: rounded(actorRevalidationMs),
        }));
      } catch {
        // Diagnostics must not change authentication outcomes.
      }
    }
  }
  })();
};

const platformRoles = new Set(["SUPER_ADMIN", "PLATFORM_SUPER_ADMIN"]);

export const withDatabaseAuthenticatedSelection = <T>(
  claims: AuthenticatedSessionClaims,
  input: {
    capability: string;
    requestId: string;
    purpose: string;
    context: CanonicalDbContext;
  },
  callback: (tx: CanonicalTransactionClient, context: CanonicalDbContext) => Promise<T>,
  runner: Pick<ReturnType<typeof getB01AuthenticatedPrisma>, "$transaction"> = getB01AuthenticatedPrisma(),
  options?: { isolationLevel?: Prisma.TransactionIsolationLevel; maxWait?: number; timeout?: number }
) => withDatabaseAuthenticatedSession(claims, input, async (tx, verified) => {
  const selected = validateCanonicalDbContext(input.context);
  const isPlatform = platformRoles.has(verified.role);
  if (
    selected.userId !== verified.userId ||
    selected.role !== verified.role ||
    selected.organizationId !== verified.organizationId ||
    selected.manufacturerId !== verified.manufacturerId ||
    selected.authAssurance !== verified.authAssurance ||
    selected.requestId !== verified.requestId ||
    selected.purpose !== verified.purpose ||
    (!isPlatform && selected.licenseeId !== verified.licenseeId)
  ) {
    throw new CanonicalAuthDenial();
  }
  const context = await installCanonicalDbContext(tx, {
    ...verified,
    licenseeId: isPlatform ? selected.licenseeId : verified.licenseeId,
  });
  return callback(tx as CanonicalTransactionClient, context);
}, runner, options);
