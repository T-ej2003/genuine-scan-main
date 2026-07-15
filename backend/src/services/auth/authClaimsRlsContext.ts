import prisma from "../../config/database";
// rls-prototype-approved-import: verified signed MFA claims establish session context.
import { withRlsPrototypeTransaction } from "../../lib/rlsTransactionContextPrototype";
import { AuthenticatedSessionClaims } from "../../types";
import { isManufacturerRole, isPlatformSuperAdminRole, issueSessionForUser } from "./authService";

export const issueAdminMfaSessionFromClaims = (
  claims: AuthenticatedSessionClaims,
  input: { ipHash: string | null; userAgent: string | null; now: Date }
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
  (tx) => issueSessionForUser({
    userId: claims.userId,
    ...input,
    authAssurance: "ADMIN_MFA",
    authenticatedAt: input.now,
    mfaVerifiedAt: input.now,
  }, tx)
);
