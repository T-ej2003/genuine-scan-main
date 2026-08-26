import { createHash } from "node:crypto";

export const PRODUCTION_INITIAL_MIGRATION_SOURCE_ADVANCE_KIND = "PRODUCTION_INITIAL_MIGRATION_SOURCE_ADVANCE";
export const PRODUCTION_SUPERSESSION_SLOTS = Object.freeze([
  "jwtPending", "qrPrivatePending", "qrPublicPending", "jwtPrevious",
  "qrPublicPrevious", "qrCurrentVersion", "qrPreviousVersion",
]);

const SHA40 = /^[a-f0-9]{40}$/;
const SHA256 = /^[a-f0-9]{64}$/;
const ROTATION_ID = /^[A-Za-z0-9._-]{8,128}$/;
const sha256 = (value) => createHash("sha256").update(value).digest("hex");

export const productionSupersessionVersionId = (sourceSha, rotationId, slot) =>
  sha256(`${sourceSha}:${rotationId}:${slot}`);

export const productionSupersessionEvidenceIdentity = ({ sourceSha, staleSourceSha, rotationId, staleRotationId, resources }) =>
  sha256(JSON.stringify({ schemaVersion: 1, transition: "SUPERSEDE_STALE_PENDING", sourceSha, staleSourceSha, rotationId, staleRotationId, resources }));

export function assertProductionSupersessionEvidence(evidence) {
  const keys = ["schemaVersion", "transition", "sourceSha", "staleSourceSha", "rotationId", "staleRotationId", "generatedAt", "resources", "evidenceIdentitySha256"];
  if (!evidence || Object.keys(evidence).sort().join(",") !== keys.sort().join(",") || evidence.schemaVersion !== 1 || evidence.transition !== "SUPERSEDE_STALE_PENDING") throw new Error("Rotation supersession evidence schema is invalid.");
  if (!SHA40.test(evidence.sourceSha) || !SHA40.test(evidence.staleSourceSha) || evidence.sourceSha === evidence.staleSourceSha || !ROTATION_ID.test(evidence.rotationId) || !ROTATION_ID.test(evidence.staleRotationId) || evidence.rotationId === evidence.staleRotationId || !Number.isFinite(Date.parse(evidence.generatedAt))) throw new Error("Rotation supersession evidence identity is invalid.");
  if (!evidence.resources || Object.keys(evidence.resources).sort().join(",") !== [...PRODUCTION_SUPERSESSION_SLOTS].sort().join(",")) throw new Error("Rotation supersession evidence resources are invalid.");
  for (const slot of PRODUCTION_SUPERSESSION_SLOTS) {
    const resource = evidence.resources[slot];
    if (!resource || Object.keys(resource).sort().join(",") !== "arn,stages,versionId" || typeof resource.arn !== "string" || !resource.arn || resource.versionId !== productionSupersessionVersionId(evidence.sourceSha, evidence.rotationId, slot) || JSON.stringify(resource.stages) !== '["AWSCURRENT"]') throw new Error(`Rotation supersession evidence ${slot} binding is invalid.`);
  }
  if (!SHA256.test(evidence.evidenceIdentitySha256) || evidence.evidenceIdentitySha256 !== productionSupersessionEvidenceIdentity(evidence)) throw new Error("Rotation supersession evidence identity hash is invalid.");
  return evidence;
}

export function assertProductionInitialMigrationSourceAdvance(bridge) {
  const keys = ["schemaVersion", "kind", "currentSourceSha", "supersessionEvidence", "supersessionEvidenceSha256", "bindingEvidenceSha256"];
  if (!bridge || Object.keys(bridge).sort().join(",") !== keys.sort().join(",") || bridge.schemaVersion !== 1 || bridge.kind !== PRODUCTION_INITIAL_MIGRATION_SOURCE_ADVANCE_KIND || !SHA40.test(bridge.currentSourceSha) || !SHA256.test(bridge.supersessionEvidenceSha256) || !SHA256.test(bridge.bindingEvidenceSha256)) throw new Error("Initial-migration source-advance binding is invalid.");
  const evidence = assertProductionSupersessionEvidence(bridge.supersessionEvidence);
  if (sha256(`${JSON.stringify(evidence, null, 2)}\n`) !== bridge.supersessionEvidenceSha256 || evidence.sourceSha === bridge.currentSourceSha) throw new Error("Initial-migration source-advance evidence is invalid.");
  return bridge;
}
