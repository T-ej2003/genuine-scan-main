import prisma from "../../config/database";
import { Prisma } from "@prisma/client";
// rls-prototype-approved-import: verified signed MFA claims establish session context.
import { withRlsPrototypeTransaction } from "../../lib/rlsTransactionContextPrototype";
import { AuthenticatedSessionClaims } from "../../types";
import {
  isManufacturerRole,
  isPlatformSuperAdminRole,
  issueSessionForUser,
} from "./authService";
import { confirmAdminMfaSetup } from "./mfaService";

export const withAdminMfaClaimsTransaction = <T>(
  claims: AuthenticatedSessionClaims,
  callback: (tx: Prisma.TransactionClient) => Promise<T>
) => withRlsPrototypeTransaction(
  prisma,
  {
    userId: claims.userId,
    role: claims.role,
    licenseeId: claims.licenseeId,
    manufacturerId: isManufacturerRole(claims.role) ? claims.userId : null,
    organizationId: claims.orgId,
    isPlatformAdmin: isPlatformSuperAdminRole(claims.role),
  },
  callback
);

export const issueAdminMfaSessionFromClaims = (
  claims: AuthenticatedSessionClaims,
  input: {
    ipHash: string | null;
    userAgent: string | null;
    now: Date;
    requestId: string;
    requestedLicenseeId?: string | null;
    requestedScopeVersion?: string | null;
  }
) => withAdminMfaClaimsTransaction(claims, (tx) => issueSessionForUser({
    userId: claims.userId,
    ...input,
    authAssurance: "ADMIN_MFA",
    authenticatedAt: input.now,
    mfaVerifiedAt: input.now,
    requestId: input.requestId,
    purpose: "manufacturer-bootstrap",
    requestedLicenseeId: input.requestedLicenseeId ?? claims.licenseeId,
    requestedScopeVersion: input.requestedScopeVersion ?? claims.scopeVersion,
  }, tx)
);

export const confirmAdminMfaEnrollmentAndIssueSessionFromClaims = (
  claims: AuthenticatedSessionClaims,
  input: {
    code: string;
    ipHash: string | null;
    userAgent: string | null;
    now: Date;
    requestId: string;
    requestedLicenseeId?: string | null;
    requestedScopeVersion?: string | null;
  }
) => withAdminMfaClaimsTransaction(claims, async (tx) => {
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
});

export const confirmAdminMfaReplacementFromClaims = (
  claims: AuthenticatedSessionClaims,
  input: { code: string; ipHash: string | null; userAgent: string | null }
) => withAdminMfaClaimsTransaction(claims, async (tx) => {
  return confirmAdminMfaSetup({
    userId: claims.userId,
    code: input.code,
    mode: "REPLACEMENT",
    audit: { ipHash: input.ipHash, userAgent: input.userAgent },
  }, tx);
});
