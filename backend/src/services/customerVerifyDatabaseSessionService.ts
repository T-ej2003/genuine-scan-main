import { randomUUID } from "crypto";

import { getB01PreAuthPrisma } from "../rls-waves/session-b/b01/runtimeClients";
import {
  issueCustomerAuthSession,
  readCustomerAuthSession,
  revokeCustomerAuthSession,
} from "../rls-waves/session-b/b02/publicBoundaryRepository";
import {
  CustomerVerifyIdentity,
  getCustomerVerifySessionExpiry,
} from "./customerVerifyAuthService";

export const registerCustomerVerifyDatabaseSession = async (
  capability: string,
  identity: CustomerVerifyIdentity,
  requestId = randomUUID()
) => {
  const issuedAt = new Date();
  const row = await issueCustomerAuthSession(getB01PreAuthPrisma(), {
    capability,
    customerUserId: identity.userId,
    customerEmail: identity.email,
    authStrength: identity.authStrength || "EMAIL_OTP",
    authProvider: identity.authProvider || "EMAIL_OTP",
    issuedAt,
    expiresAt: getCustomerVerifySessionExpiry(issuedAt),
    requestId,
  });
  if (!row?.accepted) throw new Error("Customer database session was not issued");
};

export const revokeCustomerVerifyDatabaseSession = async (
  capability: string,
  requestId = randomUUID()
) => {
  const row = await revokeCustomerAuthSession(getB01PreAuthPrisma(), {
    capability,
    revokedAt: new Date(),
    requestId,
  });
  if (!row?.revoked) throw new Error("Customer database session was not revoked");
};

export const readCustomerVerifyDatabaseSession = (
  capability: string,
  requestId = randomUUID()
) => readCustomerAuthSession(getB01PreAuthPrisma(), {
  capability,
  checkedAt: new Date(),
  requestId,
});
