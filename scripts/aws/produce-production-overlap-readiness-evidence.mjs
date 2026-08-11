import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { READY_FOR_OVERLAP_DEPLOYMENT_STAGES, assertReadyForOverlapDeployment } from "./production-overlap-readiness-contract.mjs";

const SHA40 = /^[a-f0-9]{40}$/;
const SHA256 = /^[a-f0-9]{64}$/;
const identityBindings = (value, fallbackSourceSha) => {
  const candidate = value?.identityBindings && typeof value.identityBindings === "object" && !Array.isArray(value.identityBindings)
    ? value.identityBindings
    : Object.fromEntries(["sourceSha", "callerArn", "roleArn", "taskDefinitionArn", "taskArn", "imageDigest", "rotationId"].filter((key) => typeof value?.[key] === "string" && value[key].trim()).map((key) => [key, value[key]]));
  if (!candidate.sourceSha && fallbackSourceSha) candidate.sourceSha = fallbackSourceSha;
  return candidate;
};
const exactStage = (value, name) => {
  if (!value || typeof value !== "object" || Array.isArray(value)
    || Object.keys(value).sort().join(",") !== "evidenceRef,evidenceSha256,identityBindings,valid"
    || value.valid !== true || typeof value.evidenceRef !== "string" || !value.evidenceRef.trim()
    || !SHA256.test(value.evidenceSha256 || "") || Object.keys(identityBindings(value)).length === 0) throw new Error(`${name} stage evidence is invalid.`);
  return { valid: true, evidenceRef: value.evidenceRef, evidenceSha256: value.evidenceSha256, identityBindings: identityBindings(value) };
};

export function buildOverlapReadinessEvidence({ sourceSha, rotationId, rotationStateSha256, stages, generatedAt = new Date().toISOString() } = {}) {
  if (!SHA40.test(sourceSha || "") || typeof rotationId !== "string" || !rotationId.trim() || !SHA256.test(rotationStateSha256 || "")) {
    throw new Error("Overlap readiness identity bindings are invalid.");
  }
  if (!stages || typeof stages !== "object" || Array.isArray(stages)
    || Object.keys(stages).sort().join(",") !== [...READY_FOR_OVERLAP_DEPLOYMENT_STAGES].sort().join(",")) throw new Error("Overlap readiness stages are incomplete.");
  const evidence = {
    evidenceVersion: 1,
    sourceSha,
    rotationId,
    rotationStateSha256,
    generatedAt,
    ...Object.fromEntries(READY_FOR_OVERLAP_DEPLOYMENT_STAGES.map((name) => [name, exactStage({ ...stages[name], identityBindings: identityBindings(stages[name], sourceSha) }, name)])),
    rotationPrepared: true,
    ecsUpdateServiceCount: 0,
  };
  assertReadyForOverlapDeployment(evidence, { sourceSha, rotationId, rotationStateSha256, now: Date.parse(generatedAt) });
  return evidence;
}

export function writeOverlapReadinessEvidence({ outputPath, ...input } = {}) {
  if (typeof outputPath !== "string" || !path.isAbsolute(outputPath)) throw new Error("Overlap readiness output path must be absolute.");
  const evidence = buildOverlapReadinessEvidence(input);
  const bytes = Buffer.from(`${JSON.stringify(evidence, null, 2)}\n`);
  fs.mkdirSync(path.dirname(outputPath), { recursive: true, mode: 0o700 });
  fs.writeFileSync(outputPath, bytes, { mode: 0o600, flag: "wx" });
  fs.chmodSync(outputPath, 0o600);
  return { evidence, evidenceSha256: createHash("sha256").update(bytes).digest("hex"), outputPath };
}

export function persistOverlapReadinessEvidence({ outputPath, evidence } = {}) {
  if (typeof outputPath !== "string" || !path.isAbsolute(outputPath) || !evidence || typeof evidence !== "object") throw new Error("Overlap readiness persistence inputs are invalid.");
  assertReadyForOverlapDeployment(evidence, { sourceSha: evidence.sourceSha, rotationId: evidence.rotationId, rotationStateSha256: evidence.rotationStateSha256, now: Date.parse(evidence.generatedAt) });
  const bytes = Buffer.from(`${JSON.stringify(evidence, null, 2)}\n`);
  fs.mkdirSync(path.dirname(outputPath), { recursive: true, mode: 0o700 });
  fs.writeFileSync(outputPath, bytes, { mode: 0o600, flag: "wx" });
  fs.chmodSync(outputPath, 0o600);
  return { evidenceSha256: createHash("sha256").update(bytes).digest("hex"), outputPath };
}
