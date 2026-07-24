import { Prisma } from "@prisma/client";
import { AuthenticatedSessionClaims } from "../../types";
import { issueSessionForUser } from "./authService";
import { confirmAdminMfaSetup } from "./mfaService";
import { withDatabaseAuthenticatedSession } from "../../rls-waves/session-b/b01/canonicalAuthContext";
import type { CanonicalDbContext } from "../../lib/canonicalDbContext";

export const withAdminMfaClaimsTransaction = <T>(
  claims: AuthenticatedSessionClaims,
  capability: string,
  callback: (tx: Prisma.TransactionClient, context: CanonicalDbContext) => Promise<T>,
  context?: { requestId: string; purpose: string }
) => {
  if (!context) throw new Error("B01 MFA transaction requires request attribution");
  return withDatabaseAuthenticatedSession(claims, { ...context, capability }, callback);
};

export const issueAdminMfaSessionFromClaims = (
  claims: AuthenticatedSessionClaims,
  input: {
    ipHash: string | null;
    userAgent: string | null;
    now: Date;
    requestId: string;
    databaseCapability: string;
    requestedLicenseeId?: string | null;
    requestedScopeVersion?: string | null;
  }
) => withAdminMfaClaimsTransaction(claims, input.databaseCapability, (tx) => issueSessionForUser({
    userId: claims.userId,
    ...input,
    authAssurance: "ADMIN_MFA",
    authenticatedAt: input.now,
    mfaVerifiedAt: input.now,
    requestId: input.requestId,
    purpose: "manufacturer-bootstrap",
    requestedLicenseeId: input.requestedLicenseeId ?? claims.licenseeId,
    requestedScopeVersion: input.requestedScopeVersion ?? claims.scopeVersion,
  }, tx), { requestId: input.requestId, purpose: "admin-mfa-session-issue" }
);

export const confirmAdminMfaEnrollmentAndIssueSessionFromClaims = (
  claims: AuthenticatedSessionClaims,
  input: {
    code: string;
    ipHash: string | null;
    userAgent: string | null;
    now: Date;
    requestId: string;
    databaseCapability: string;
    requestedLicenseeId?: string | null;
    requestedScopeVersion?: string | null;
  }
) => withAdminMfaClaimsTransaction(claims, input.databaseCapability, async (tx) => {
  await confirmAdminMfaSetup({
    userId: claims.userId,
    code: input.code,
    mode: "FIRST_ENROLLMENT",
    audit: { ipHash: input.ipHash, userAgent: input.userAgent },
  }, tx);
  const session = await issueSessionForUser({
    userId: claims.userId,
    ipHash: input.ipHash,
    userAgent: input.userAgent,
    authAssurance: "ADMIN_MFA",
    authenticatedAt: input.now,
    mfaVerifiedAt: input.now,
    now: input.now,
    requestId: input.requestId,
    purpose: "manufacturer-bootstrap",
    requestedLicenseeId: input.requestedLicenseeId,
    requestedScopeVersion: input.requestedScopeVersion,
  }, tx);
  return session;
}, { requestId: input.requestId, purpose: "admin-mfa-enrollment-complete" });

export const confirmAdminMfaReplacementFromClaims = (
  claims: AuthenticatedSessionClaims,
  input: { code: string; ipHash: string | null; userAgent: string | null; requestId: string; databaseCapability: string }
) => withAdminMfaClaimsTransaction(claims, input.databaseCapability, async (tx) => {
  return confirmAdminMfaSetup({
    userId: claims.userId,
    code: input.code,
    mode: "REPLACEMENT",
    audit: { ipHash: input.ipHash, userAgent: input.userAgent },
  }, tx);
}, { requestId: input.requestId, purpose: "admin-mfa-replacement-complete" });
