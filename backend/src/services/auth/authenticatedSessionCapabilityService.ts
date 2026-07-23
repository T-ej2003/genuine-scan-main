import { createHash } from "crypto";
import { Prisma } from "@prisma/client";

import { randomOpaqueToken } from "../../utils/security";

export const AUTHENTICATED_SESSION_CAPABILITY_BYTES = 32;
export const AUTHENTICATED_SESSION_HASH_VERSION = "sha256-v1";

const capability = (value: unknown) => {
  const normalized = String(value || "").trim();
  if (!/^[A-Za-z0-9_-]{43}$/.test(normalized)) {
    throw new Error("AUTHENTICATED_SESSION_CAPABILITY_INVALID");
  }
  return normalized;
};

export const hashAuthenticatedSessionCapability = (raw: string) =>
  createHash("sha256").update(capability(raw), "utf8").digest("hex");

export const newAuthenticatedSessionCapability = () => randomOpaqueToken(AUTHENTICATED_SESSION_CAPABILITY_BYTES);

type CapabilityDb = Pick<Prisma.TransactionClient, "$queryRaw">;

export const supportsAuthenticatedSessionCapability = (db: unknown): db is CapabilityDb =>
  Boolean(db && typeof (db as { $queryRaw?: unknown }).$queryRaw === "function");

export const createAuthenticatedSessionCapability = async (
  db: CapabilityDb,
  input: {
    refreshTokenId: string;
    refreshTokenHash: string;
    assurance: "PASSWORD" | "ADMIN_MFA";
    expiresAt: Date;
    now?: Date;
  }
) => {
  const rawCapability = newAuthenticatedSessionCapability();
  const rows = await db.$queryRaw<Array<{ id: string; expiresAt: Date }>>`
    SELECT * FROM app_auth.issue_authenticated_session_capability(
      ${input.refreshTokenId}, ${input.refreshTokenHash}, ${rawCapability}, ${input.assurance}, ${input.expiresAt}::timestamp without time zone
    )
  `;
  if (rows.length !== 1 || rows[0].id !== input.refreshTokenId || !(rows[0].expiresAt instanceof Date)) {
    throw new Error("AUTHENTICATED_SESSION_CAPABILITY_ISSUE_FAILED");
  }
  const row = rows[0];
  return { row, rawCapability };
};

export const requireAuthenticatedSessionCapability = async (
  db: CapabilityDb,
  input: { capability: string; purpose: string; requestId: string }
) => {
  const rows = await db.$queryRaw<Array<{
    sessionId: string;
    userId: string;
    role: string;
    organizationId: string | null;
    licenseeId: string | null;
    assurance: "PASSWORD" | "ADMIN_MFA";
  }>>`
    SELECT * FROM app_auth.require_authenticated_session(
      ${capability(input.capability)}, ${input.purpose}, ${input.requestId}
    )
  `;
  if (rows.length !== 1 || !rows[0].sessionId || !rows[0].userId) {
    throw new Error("AUTH_SESSION_CAPABILITY_DENIED");
  }
  return rows[0];
};

export const revokeAuthenticatedSessionByRefreshToken = async (
  db: CapabilityDb,
  input: { capability: string; refreshTokenId: string; reason: string; requestId: string }
) => {
  const rows = await db.$queryRaw<Array<{ revoked: boolean }>>`
    SELECT * FROM app_auth.revoke_authenticated_session_capability(
      ${capability(input.capability)}, ${input.refreshTokenId}, ${input.reason}, ${input.requestId}
    )
  `;
  if (rows.length !== 1 || typeof rows[0].revoked !== "boolean") {
    throw new Error("AUTHENTICATED_SESSION_CAPABILITY_REVOKE_FAILED");
  }
  return rows[0].revoked;
};

export const revokeAuthenticatedSessionsForUser = async (
  db: CapabilityDb,
  input: { capability: string; reason: string; requestId: string }
) => {
  const rows = await db.$queryRaw<Array<{ revokedCount: number }>>`
    SELECT * FROM app_auth.revoke_all_authenticated_session_capabilities(
      ${capability(input.capability)}, ${input.reason}, ${input.requestId}
    )
  `;
  if (rows.length !== 1 || !Number.isSafeInteger(rows[0].revokedCount) || rows[0].revokedCount < 0) {
    throw new Error("AUTHENTICATED_SESSION_CAPABILITY_REVOKE_FAILED");
  }
  return rows[0].revokedCount;
};
