import { createHash, createPublicKey, randomBytes, randomUUID } from "crypto";
import { z } from "zod";
import { signPrinterAgentPayload, verifyPrinterAgentPayloadSignature } from "./printerAgentSigningService";

const purpose = "mscqr-connector-upgrade-device-proof-v1";
export const upgradeChallengeSchema = z.object({
  purpose: z.literal(purpose),
  attemptId: z.string().uuid(),
  nonce: z.string().regex(/^[A-Za-z0-9_-]{43}$/),
  agentId: z.string().min(3).max(180),
  deviceFingerprint: z.string().min(8).max(256),
  manufacturerId: z.string().min(1).max(180),
  tenantId: z.string().min(1).max(180).nullable(),
  printerId: z.string().uuid(),
  registrationId: z.string().uuid(),
  sourceVersion: z.string().regex(/^\d+\.\d+\.\d+(?:\.\d+)?$/),
  targetVersion: z.string().regex(/^\d+\.\d+\.\d+(?:\.\d+)?$/),
  expiresAt: z.string().datetime(),
}).strict();
export type UpgradeDeviceChallenge = z.infer<typeof upgradeChallengeSchema>;

export const createUpgradeDeviceChallenge = (binding: Omit<UpgradeDeviceChallenge, "purpose" | "attemptId" | "nonce" | "expiresAt">, now = Date.now()): UpgradeDeviceChallenge =>
  upgradeChallengeSchema.parse({ ...binding, purpose, attemptId: randomUUID(), nonce: randomBytes(32).toString("base64url"),
    expiresAt: new Date(now + 120_000).toISOString() });

export const canonicalUpgradeDeviceChallenge = (input: UpgradeDeviceChallenge) => {
  const c = upgradeChallengeSchema.parse(input);
  return JSON.stringify([c.purpose, c.attemptId, c.nonce, c.agentId, c.deviceFingerprint,
    c.manufacturerId, c.tenantId, c.printerId, c.registrationId, c.sourceVersion, c.targetVersion, c.expiresAt]);
};

export const signUpgradeDeviceChallenge = (privateKeyPem: string, input: UpgradeDeviceChallenge) =>
  signPrinterAgentPayload(privateKeyPem, canonicalUpgradeDeviceChallenge(input));

export const verifyUpgradeDeviceChallenge = (input: {
  challenge: UpgradeDeviceChallenge;
  signature: string;
  publicKeyPem: string;
  binding: Omit<UpgradeDeviceChallenge, "purpose" | "attemptId" | "nonce" | "expiresAt">;
  now?: number;
}) => {
  const c = upgradeChallengeSchema.parse(input.challenge);
  if (Date.parse(c.expiresAt) <= (input.now ?? Date.now()) || Date.parse(c.expiresAt) > (input.now ?? Date.now()) + 120_000 ||
      Object.entries(input.binding).some(([key, value]) => c[key as keyof UpgradeDeviceChallenge] !== value) ||
      !/^[A-Za-z0-9_-]{86}$/.test(input.signature) ||
      createPublicKey(input.publicKeyPem).asymmetricKeyType !== "ed25519" ||
      !verifyPrinterAgentPayloadSignature({ publicKeyPem: input.publicKeyPem,
        payload: canonicalUpgradeDeviceChallenge(c), signature: input.signature })) {
    throw new Error("CONNECTOR_UPGRADE_DEVICE_PROOF_INVALID");
  }
  return { attemptId: c.attemptId, proofSha256: createHash("sha256").update(`${canonicalUpgradeDeviceChallenge(c)}|${input.signature}`).digest("hex") };
};
