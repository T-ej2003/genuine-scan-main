import { randomUUID } from "crypto";
import { CustomerVerificationEntryMethod } from "@prisma/client";

import { getB01PreAuthPrisma } from "../rls-waves/session-b/b01/runtimeClients";
import {
  readVerificationSession,
  startVerificationSession,
  writeVerificationSession,
} from "../rls-waves/session-b/b02/publicBoundaryRepository";
import { hashToken } from "../utils/security";

type CustomerIdentity = { userId?: string | null; email?: string | null };
type TrustIntakeInput = {
  purchaseChannel: string;
  sourceCategory?: string | null;
  platformName?: string | null;
  sellerName?: string | null;
  listingUrl?: string | null;
  orderReference?: string | null;
  storeName?: string | null;
  purchaseCity?: string | null;
  purchaseCountry?: string | null;
  purchaseDate?: Date | string | null;
  packagingState?: string | null;
  packagingConcern?: string | null;
  scanReason: string;
  ownershipIntent: string;
  notes?: string | null;
  answers?: Record<string, unknown> | null;
};

const required = (value: unknown, label: string) => {
  const normalized = String(value || "").trim();
  if (!normalized) throw new Error(`${label} required`);
  return normalized;
};

const summary = (row: Awaited<ReturnType<typeof readVerificationSession>> | Awaited<ReturnType<typeof startVerificationSession>>) => {
  if (!row) return null;
  const started = row.startedAt.toISOString();
  return {
    ...row,
    startedAt: started,
    revealAt: "revealed" in row && row.revealed ? new Date().toISOString() : null,
    intakeCompleted: "intakeCompleted" in row ? row.intakeCompleted : false,
    revealed: "revealed" in row ? row.revealed : false,
    verificationLocked: true,
    proofBindingRequired: true,
    proofBindingExpiresAt: row.proofBindingExpiresAt.toISOString(),
    verification: "verification" in row ? row.verification : null,
  };
};

export const createCustomerVerificationSession = async (input: {
  sessionStartToken: string;
  entryMethod: CustomerVerificationEntryMethod;
  customerCapability?: string | null;
}) => {
  const raw = required(input.sessionStartToken, "Verification session token");
  const row = await startVerificationSession(getB01PreAuthPrisma(), {
    sessionStartTokenHash: hashToken(raw),
    entryMethod: input.entryMethod,
    checkedAt: new Date(),
    requestId: randomUUID(),
    customerCapability: input.customerCapability || null,
  });
  if (!row) throw new Error("Verification session token is invalid or expired");
  return summary(row)!;
};

export const getCustomerVerificationSession = async (input: {
  sessionId: string;
  customerCapability?: string | null;
  proofToken?: string | null;
}) => {
  const proofToken = required(input.proofToken, "Verification session continuity check");
  const row = await readVerificationSession(getB01PreAuthPrisma(), {
    sessionId: input.sessionId,
    sessionProofHash: hashToken(proofToken),
    checkedAt: new Date(),
    requestId: randomUUID(),
    customerCapability: input.customerCapability || null,
  });
  return summary(row);
};

export const saveCustomerTrustIntake = async (input: {
  sessionId: string;
  intake: TrustIntakeInput;
  customer: CustomerIdentity;
  customerCapability: string;
  proofToken?: string | null;
}) => {
  const result = await writeVerificationSession(getB01PreAuthPrisma(), {
    sessionId: input.sessionId,
    sessionProofHash: hashToken(required(input.proofToken, "Verification session continuity check")),
    customerCapability: required(input.customerCapability, "Customer session capability"),
    operation: "INTAKE",
    payload: input.intake as Record<string, unknown>,
    checkedAt: new Date(),
    requestId: randomUUID(),
  });
  return { ...input.intake, ...result };
};

export const revealCustomerVerificationSession = async (input: {
  sessionId: string;
  customer: CustomerIdentity;
  customerCapability: string;
  proofToken?: string | null;
}) => {
  const proofToken = required(input.proofToken, "Verification session continuity check");
  await writeVerificationSession(getB01PreAuthPrisma(), {
    sessionId: input.sessionId,
    sessionProofHash: hashToken(proofToken),
    customerCapability: required(input.customerCapability, "Customer session capability"),
    operation: "REVEAL",
    payload: {},
    checkedAt: new Date(),
    requestId: randomUUID(),
  });
  const session = await getCustomerVerificationSession({
    sessionId: input.sessionId,
    customerCapability: input.customerCapability,
    proofToken,
  });
  if (!session) throw new Error("Verification session not found");
  return session;
};
