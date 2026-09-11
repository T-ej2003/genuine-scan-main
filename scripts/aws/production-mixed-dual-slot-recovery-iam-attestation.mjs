import {
  MIXED_DUAL_SLOT_RECOVERY_EXECUTION_ROLE_ARN,
  MIXED_DUAL_SLOT_RECOVERY_IAM_ACTION,
  MIXED_DUAL_SLOT_RECOVERY_IAM_RESOURCES,
  MIXED_DUAL_SLOT_RECOVERY_MAX_AGE_MS,
  MIXED_DUAL_SLOT_RECOVERY_OPERATION,
  assertMixedDualSlotRecoveryIamPreflight,
  mixedDualSlotRecoverySha256,
} from "./production-mixed-dual-slot-recovery-contract.mjs";
import { ROOT_ATTESTATION_KEY_ALIAS_ARN, ROOT_ATTESTATION_SIGNING_ALGORITHM } from "./production-root-attestation-key.mjs";

export const MIXED_DUAL_SLOT_RECOVERY_IAM_ATTESTATION_KIND = "PRODUCTION_MIXED_DUAL_SLOT_TOPOLOGY_RECOVERY_IAM_ATTESTATION";
const SHA256 = /^[a-f0-9]{64}$/;
const fields = ["schemaVersion", "kind", "operation", "sourceSha", "principalArn", "action", "resources", "preflightSha256", "observedAt", "signingKeyArn", "signingAlgorithm", "signatureBase64", "attestationSha256"];
const exact = (value) => value && typeof value === "object" && !Array.isArray(value) && JSON.stringify(Object.keys(value).sort()) === JSON.stringify([...fields].sort());

export function createMixedDualSlotRecoveryIamAttestation({ preflight, sign, now = new Date() } = {}) {
  const checked = assertMixedDualSlotRecoveryIamPreflight(preflight, { sourceSha: preflight?.sourceSha, now, requireFresh: true });
  if (typeof sign !== "function") throw new Error("Mixed recovery IAM attestation requires the root signer.");
  const body = { schemaVersion: 1, kind: MIXED_DUAL_SLOT_RECOVERY_IAM_ATTESTATION_KIND, operation: MIXED_DUAL_SLOT_RECOVERY_OPERATION, sourceSha: checked.sourceSha, principalArn: checked.principalArn, action: checked.action, resources: checked.resources, preflightSha256: checked.preflightSha256, observedAt: checked.observedAt, signingKeyArn: ROOT_ATTESTATION_KEY_ALIAS_ARN, signingAlgorithm: ROOT_ATTESTATION_SIGNING_ALGORITHM };
  const attestationSha256 = mixedDualSlotRecoverySha256(body);
  const signatureBase64 = sign({ digest: Buffer.from(attestationSha256, "hex"), keyArn: body.signingKeyArn, signingAlgorithm: body.signingAlgorithm });
  if (typeof signatureBase64 !== "string" || !signatureBase64) throw new Error("Mixed recovery IAM attestation signature is invalid.");
  return Object.freeze({ ...body, signatureBase64, attestationSha256 });
}

export function assertMixedDualSlotRecoveryIamAttestation(value, { preflight, sourceSha, now = new Date(), verify } = {}) {
  if (!exact(value)) throw new Error("Mixed recovery IAM attestation schema is invalid.");
  const checked = assertMixedDualSlotRecoveryIamPreflight(preflight, { sourceSha, now, requireFresh: true });
  const { signatureBase64, attestationSha256, ...body } = value;
  const signature = Buffer.from(signatureBase64 || "", "base64");
  const observedAt = Date.parse(value.observedAt); const age = now.getTime() - observedAt;
  if (value.schemaVersion !== 1 || value.kind !== MIXED_DUAL_SLOT_RECOVERY_IAM_ATTESTATION_KIND || value.operation !== MIXED_DUAL_SLOT_RECOVERY_OPERATION || value.sourceSha !== sourceSha || value.principalArn !== MIXED_DUAL_SLOT_RECOVERY_EXECUTION_ROLE_ARN || value.action !== MIXED_DUAL_SLOT_RECOVERY_IAM_ACTION || JSON.stringify(value.resources) !== JSON.stringify(MIXED_DUAL_SLOT_RECOVERY_IAM_RESOURCES) || value.preflightSha256 !== checked.preflightSha256 || value.observedAt !== checked.observedAt || !Number.isFinite(observedAt) || age < 0 || age > MIXED_DUAL_SLOT_RECOVERY_MAX_AGE_MS || value.signingKeyArn !== ROOT_ATTESTATION_KEY_ALIAS_ARN || value.signingAlgorithm !== ROOT_ATTESTATION_SIGNING_ALGORITHM || !SHA256.test(attestationSha256 || "") || mixedDualSlotRecoverySha256(body) !== attestationSha256 || signature.length === 0 || typeof verify !== "function" || verify({ keyArn: value.signingKeyArn, signingAlgorithm: value.signingAlgorithm, digest: Buffer.from(attestationSha256, "hex"), signature }) !== true) throw new Error("Mixed recovery IAM attestation is not an authenticated exact capability proof.");
  return value;
}
