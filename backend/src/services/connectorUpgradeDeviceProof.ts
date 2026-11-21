import { createHash, createPublicKey, randomBytes, randomUUID } from "crypto";
import { z } from "zod";
import { signPrinterAgentPayload, verifyPrinterAgentPayloadSignature } from "./printerAgentSigningService";

const purpose = "mscqr-connector-upgrade-device-proof-v1";
export const upgradeChallengeSchema = z.object({
  purpose: z.literal(purpose),
  attemptId: z.string().uuid(),
  challengeId: z.string().uuid(),
  nonce: z.string().regex(/^[A-Za-z0-9_-]{43}$/),
  agentId: z.string().min(3).max(180),
  deviceFingerprint: z.string().min(8).max(256),
  manufacturerId: z.string().min(1).max(180),
  tenantId: z.string().min(1).max(180).nullable(),
  printerId: z.string().uuid(),
  registrationId: z.string().uuid(),
  sourceVersion: z.string().regex(/^\d+\.\d+\.\d+(?:\.\d+)?$/),
  currentVersion: z.string().regex(/^\d+\.\d+\.\d+(?:\.\d+)?$/),
  targetVersion: z.string().regex(/^\d+\.\d+\.\d+(?:\.\d+)?$/),
  expiresAt: z.string().datetime(),
}).strict();
export type UpgradeDeviceChallenge = z.infer<typeof upgradeChallengeSchema>;
export const upgradeAttemptKey = (id: string) => `connector-upgrade:attempt:${id}`;
export const upgradeProofKey = (id: string) => `connector-upgrade:proof:${id}`;
export const upgradeHandoffKey = (tokenHash: string) => `connector-upgrade:handoff:${tokenHash}`;
export const upgradeAuthorizationKey = (evidenceSha256: string) => `connector-upgrade:authorization:${evidenceSha256}`;
export const upgradePairingKey = (id: string) => `connector-upgrade:pairing:${id}`;
export const upgradePairingResultKey = (id: string) => `connector-upgrade:pairing-result:${id}`;

export const createUpgradeDeviceChallenge = (binding: Omit<UpgradeDeviceChallenge, "purpose" | "challengeId" | "nonce" | "expiresAt">, now = Date.now()): UpgradeDeviceChallenge =>
  upgradeChallengeSchema.parse({ ...binding, purpose, challengeId: randomUUID(), nonce: randomBytes(32).toString("base64url"),
    expiresAt: new Date(now + 120_000).toISOString() });

export const canonicalUpgradeDeviceChallenge = (input: UpgradeDeviceChallenge) => {
  const c = upgradeChallengeSchema.parse(input);
  return JSON.stringify([c.purpose, c.attemptId, c.challengeId, c.nonce, c.agentId, c.deviceFingerprint,
    c.manufacturerId, c.tenantId, c.printerId, c.registrationId, c.sourceVersion, c.currentVersion, c.targetVersion, c.expiresAt]);
};

export const signUpgradeDeviceChallenge = (privateKeyPem: string, input: UpgradeDeviceChallenge) =>
  signPrinterAgentPayload(privateKeyPem, canonicalUpgradeDeviceChallenge(input));

export const verifyUpgradeDeviceChallenge = (input: {
  challenge: UpgradeDeviceChallenge;
  signature: string;
  publicKeyPem: string;
  binding: Omit<UpgradeDeviceChallenge, "purpose" | "challengeId" | "nonce" | "expiresAt">;
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

const journalEntry = z.object({ name: z.string().regex(/^[a-f0-9]{64}(\.gateway-attempt)?\.json$/),
  sha256: z.string().regex(/^[a-f0-9]{64}$/), printJobId: z.string().min(1).max(180), printItemId: z.string().min(1).max(180),
  attemptId: z.string().max(180).nullable(), state: z.enum(["ATTEMPT_RESERVED", "PREPARING", "PRE_DISPATCH_FAILURE", "PRE_DISPATCH_REPORTED"]),
  gatewayId: z.string().min(1).max(180).optional() }).strict();
export const MAX_MAINTENANCE_CHECKPOINT_CHARS = 8_000_000;
export const maintenanceCheckpointStatementSchema = z.object({
  purpose: z.literal("mscqr-connector-maintenance-checkpoint-v1"), challenge: upgradeChallengeSchema,
  observedAt: z.string().datetime(),
  fence: z.object({ fenced: z.literal(true), active: z.literal(0), idle: z.literal(true), socketClosed: z.literal(true) }).strict(),
  journal: z.object({ count: z.number().int().min(0).max(10_000), sha256: z.string().regex(/^[a-f0-9]{64}$/),
    entries: z.array(journalEntry).max(10_000) }).strict(),
  physicalOutcomes: z.literal("UNVERIFIED"),
}).strict();

export const signMaintenanceCheckpoint = (privateKeyPem: string, statement: unknown) => {
  const canonical = JSON.stringify(maintenanceCheckpointStatementSchema.parse(statement));
  return { statement: canonical, signature: signPrinterAgentPayload(privateKeyPem, canonical) };
};

export const verifyMaintenanceCheckpoint = (envelope: { statement: string; signature: string },
  challenge: UpgradeDeviceChallenge, publicKeyPem: string, now = Date.now()) => {
  if (typeof envelope?.statement !== "string" || envelope.statement.length > MAX_MAINTENANCE_CHECKPOINT_CHARS ||
      typeof envelope.signature !== "string" || !/^[A-Za-z0-9_-]{86}$/.test(envelope.signature))
    throw new Error("CONNECTOR_MAINTENANCE_CHECKPOINT_INVALID");
  const statement = maintenanceCheckpointStatementSchema.parse(JSON.parse(envelope.statement));
  const expected = upgradeChallengeSchema.parse(challenge);
  if (JSON.stringify(statement) !== envelope.statement ||
      canonicalUpgradeDeviceChallenge(statement.challenge) !== canonicalUpgradeDeviceChallenge(expected) ||
      Date.parse(expected.expiresAt) <= now || now - Date.parse(statement.observedAt) > 180_000 ||
      Date.parse(statement.observedAt) - now > 300_000 ||
      statement.journal.count !== statement.journal.entries.length ||
      statement.journal.sha256 !== createHash("sha256").update(JSON.stringify(statement.journal.entries.map(({ name, sha256 }) => [name, sha256]))).digest("hex") ||
      !verifyPrinterAgentPayloadSignature({ publicKeyPem, payload: envelope.statement, signature: envelope.signature }))
    throw new Error("CONNECTOR_MAINTENANCE_CHECKPOINT_INVALID");
  return statement;
};

export const postInstallStatementSchema = z.object({
  purpose: z.literal("mscqr-connector-upgrade-postinstall-v1"), attemptId: z.string().uuid(),
  observedAt: z.string().datetime(), version: z.string(), sha256: z.string().regex(/^[a-f0-9]{64}$/),
  agentId: z.string(), deviceFingerprint: z.string(), registrationId: z.string().uuid(),
  selectedPrinterId: z.string(), sessionId: z.string(), journalSha256: z.string().regex(/^[a-f0-9]{64}$/),
  fenced: z.literal(true),
}).strict();

export const verifyPostInstallStatement = (envelope: { statement: string; signature: string }, publicKeyPem: string) => {
  if (typeof envelope?.statement !== "string" || envelope.statement.length > 4096 ||
      typeof envelope?.signature !== "string" || !/^[A-Za-z0-9_-]{86}$/.test(envelope.signature))
    throw new Error("CONNECTOR_UPGRADE_POSTINSTALL_INVALID");
  const statement = postInstallStatementSchema.parse(JSON.parse(envelope.statement));
  if (JSON.stringify(statement) !== envelope.statement ||
      Math.abs(Date.now() - Date.parse(statement.observedAt)) > 120_000 ||
      !verifyPrinterAgentPayloadSignature({ publicKeyPem, payload: envelope.statement, signature: envelope.signature }))
    throw new Error("CONNECTOR_UPGRADE_POSTINSTALL_INVALID");
  return statement;
};
