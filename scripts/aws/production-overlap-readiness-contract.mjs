import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";

export const READY_FOR_OVERLAP_DEPLOYMENT_STAGES = Object.freeze([
  "imageAuthorization",
  "iamPreflight",
  "rootDrop",
  "releaseIdentity",
  "verifierIdentity",
  "stageA",
  "artifactSigning",
  "overlapTaskDefinition",
  "inventory",
  "rotationPrepare",
]);

const SHA256 = /^[a-f0-9]{64}$/;
const SHA40 = /^[a-f0-9]{40}$/;
const REQUIRED_EVIDENCE_FIELDS = Object.freeze([
  "evidenceVersion",
  "sourceSha",
  "rotationId",
  "rotationStateSha256",
  "generatedAt",
  ...READY_FOR_OVERLAP_DEPLOYMENT_STAGES,
  "rotationPrepared",
  "ecsUpdateServiceCount",
]);

const fail = (message) => { throw new Error(message); };
const exactKeys = (value, expected, label) => {
  const actual = Object.keys(value || {}).sort();
  const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) fail(`${label} fields are not canonical.`);
};

function assertStageEvidence(stage, value) {
  exactKeys(value, ["valid", "evidenceRef", "evidenceSha256", "identityBindings"], `${stage} evidence`);
  if (value.valid !== true) fail(`${stage} evidence is not valid.`);
  if (typeof value.evidenceRef !== "string" || value.evidenceRef.trim() === "" || /[<>\0]/.test(value.evidenceRef)) fail(`${stage} evidence reference is invalid.`);
  if (!SHA256.test(value.evidenceSha256)) fail(`${stage} evidence SHA-256 is invalid.`);
  if (!value.identityBindings || typeof value.identityBindings !== "object" || Array.isArray(value.identityBindings)
    || Object.keys(value.identityBindings).length === 0
    || Object.entries(value.identityBindings).some(([key, entry]) => !/^[A-Za-z][A-Za-z0-9_]*$/.test(key) || typeof entry !== "string" || entry.trim() === "" || /[<>\0]/.test(entry))) {
    fail(`${stage} identity bindings are invalid.`);
  }
}

export function assertReadyForOverlapDeployment(evidence, expected = {}) {
  exactKeys(evidence, REQUIRED_EVIDENCE_FIELDS, "overlap readiness evidence");
  if (evidence.evidenceVersion !== 1) fail("READY_FOR_OVERLAP_DEPLOYMENT evidenceVersion must be 1");
  if (!SHA40.test(evidence.sourceSha)) fail("READY_FOR_OVERLAP_DEPLOYMENT sourceSha is invalid");
  if (expected.sourceSha !== undefined && evidence.sourceSha !== expected.sourceSha) fail("READY_FOR_OVERLAP_DEPLOYMENT sourceSha does not match the release target");
  if (typeof evidence.rotationId !== "string" || evidence.rotationId.trim() === "") fail("READY_FOR_OVERLAP_DEPLOYMENT rotationId is invalid");
  if (expected.rotationId !== undefined && evidence.rotationId !== expected.rotationId) fail("READY_FOR_OVERLAP_DEPLOYMENT rotationId does not match the release input");
  if (!SHA256.test(evidence.rotationStateSha256)) fail("READY_FOR_OVERLAP_DEPLOYMENT rotationStateSha256 is invalid");
  if (expected.rotationStateSha256 !== undefined && evidence.rotationStateSha256 !== expected.rotationStateSha256) fail("READY_FOR_OVERLAP_DEPLOYMENT rotationStateSha256 does not match the persisted rotation state");
  const generatedAt = Date.parse(evidence.generatedAt);
  if (!Number.isFinite(generatedAt) || generatedAt > (expected.now ?? Date.now())) fail("READY_FOR_OVERLAP_DEPLOYMENT generatedAt is invalid");
  for (const stage of READY_FOR_OVERLAP_DEPLOYMENT_STAGES) {
    assertStageEvidence(stage, evidence[stage]);
    if (evidence[stage].identityBindings.sourceSha !== evidence.sourceSha) fail(`${stage} source SHA binding does not match readiness source SHA.`);
    if (evidence[stage].identityBindings.rotationId !== undefined && evidence[stage].identityBindings.rotationId !== evidence.rotationId) fail(`${stage} rotation ID binding does not match readiness rotation ID.`);
  }
  if (evidence.rotationPrepared !== true) fail("READY_FOR_OVERLAP_DEPLOYMENT requires rotationPrepared=true");
  if (evidence.ecsUpdateServiceCount !== 0) fail("READY_FOR_OVERLAP_DEPLOYMENT must be evaluated before ECS UpdateService");
  return { readyForOverlapDeployment: true, stages: [...READY_FOR_OVERLAP_DEPLOYMENT_STAGES] };
}

export function readAndAssertReadyForOverlapDeployment({ filePath, evidenceSha256, sourceSha, rotationId, rotationStateSha256, now = Date.now() } = {}) {
  if (typeof filePath !== "string" || filePath.trim() === "") fail("READY_FOR_OVERLAP_DEPLOYMENT evidence file is required");
  if (!SHA256.test(evidenceSha256)) fail("READY_FOR_OVERLAP_DEPLOYMENT evidence SHA-256 is invalid");
  const raw = readFileSync(filePath);
  if (createHash("sha256").update(raw).digest("hex") !== evidenceSha256) fail("READY_FOR_OVERLAP_DEPLOYMENT evidence SHA-256 does not match the evidence file");
  const evidence = JSON.parse(raw);
  const result = assertReadyForOverlapDeployment(evidence, { sourceSha, rotationId, rotationStateSha256, now });
  return { ...result, evidenceSha256 };
}

function argument(name, argv) {
  const index = argv.indexOf(name);
  if (index < 0 || !argv[index + 1]) fail(`${name} is required`);
  return argv[index + 1];
}

if (process.argv[1] && import.meta.url.endsWith(process.argv[1])) {
  try {
    const argv = process.argv.slice(2);
    if (argument("--mode", argv) !== "rotation-overlap") fail("readiness validator only authorizes rotation-overlap");
    console.log(JSON.stringify(readAndAssertReadyForOverlapDeployment({
      filePath: argument("--evidence-file", argv),
      evidenceSha256: argument("--evidence-sha256", argv),
      sourceSha: argument("--source-sha", argv),
      rotationId: argument("--rotation-id", argv),
      rotationStateSha256: argument("--rotation-state-sha256", argv),
    })));
  } catch (error) {
    console.error(`Production overlap readiness validation failed: ${error.message || error}`);
    process.exit(1);
  }
}
