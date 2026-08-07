import crypto from "node:crypto";
import { canonicalJson } from "./production-green-stage-b-contract.mjs";

export const STAGE_B_APPLY_FAILURE_SCHEMA_VERSION = 1;
export const STAGE_B_APPLY_FAILURE_EVIDENCE_KIND = "STAGE_B_APPLY_FAILURE";

const sha256 = (value) => crypto.createHash("sha256").update(value).digest("hex");
const digest = (value, label) => { if (!/^[a-f0-9]{64}$/.test(value || "")) throw new Error(`${label} must be a SHA256.`); return value; };

export function createStageBApplyFailureArtifact({ generatedAt = new Date().toISOString(), producerCallerArn, protectedSourceSha, plan, lineage, preApplySerial, mutation, stdoutBytes, stderrBytes } = {}) {
  if (!producerCallerArn || !/^[a-f0-9]{40}$/.test(protectedSourceSha || "") || !/^[0-9a-f-]{36}$/i.test(lineage || "") || !Number.isInteger(preApplySerial) || preApplySerial < 0) throw new Error("Stage B apply failure identity is incomplete.");
  if (!mutation?.terraformAddress || !mutation.operation || !mutation.result || !mutation.failureClass) throw new Error("Stage B apply failure mutation identity is incomplete.");
  if (!Buffer.isBuffer(stdoutBytes) || !Buffer.isBuffer(stderrBytes)) throw new Error("Stage B apply failure stdout/stderr bytes are required.");
  return { schemaVersion: STAGE_B_APPLY_FAILURE_SCHEMA_VERSION, evidenceKind: STAGE_B_APPLY_FAILURE_EVIDENCE_KIND, generatedAt, producerCallerArn, protectedSourceSha, terraform: { lineage, preApplySerial }, plan: { savedPlanSha256: digest(plan?.savedPlanSha256, "saved plan"), planJsonSha256: digest(plan?.planJsonSha256, "plan JSON"), logicalCanonicalPlanSha256: digest(plan?.logicalCanonicalPlanSha256, "logical plan") }, mutation, providerFailure: { stdoutSha256: sha256(stdoutBytes), stderrSha256: sha256(stderrBytes) } };
}

export function assertStageBApplyFailureArtifact(report) {
  if (report?.schemaVersion !== STAGE_B_APPLY_FAILURE_SCHEMA_VERSION || report.evidenceKind !== STAGE_B_APPLY_FAILURE_EVIDENCE_KIND || !report.providerFailure?.stdoutSha256 || !report.providerFailure?.stderrSha256) throw new Error("Stage B apply failure artifact is malformed.");
  if (!/^[a-f0-9]{40}$/.test(report.protectedSourceSha || "") || !/^[0-9a-f-]{36}$/i.test(report.terraform?.lineage || "") || !Number.isInteger(report.terraform?.preApplySerial) || report.terraform.preApplySerial < 0 || !report.mutation?.terraformAddress || !report.mutation.operation || report.mutation.result !== "FAILED" || !report.mutation.failureClass) throw new Error("Stage B apply failure identity is incomplete.");
  for (const [name, value] of Object.entries(report.plan || {})) if (!/^[a-f0-9]{64}$/.test(value || "")) throw new Error(`Stage B apply failure ${name} is malformed.`);
  for (const name of ["stdoutSha256", "stderrSha256"]) if (!/^[a-f0-9]{64}$/.test(report.providerFailure[name])) throw new Error(`Stage B apply failure ${name} is malformed.`);
  return true;
}

export const stageBApplyFailureCanonicalSha256 = (report) => sha256(Buffer.from(canonicalJson(report)));
