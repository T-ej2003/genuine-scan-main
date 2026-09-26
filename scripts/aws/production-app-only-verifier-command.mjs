import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { deflateSync } from "node:zlib";
import { canonicalSha256 } from "./production-green-stage-b-contract.mjs";
import { APP_ONLY, assertAppOnlyEvidenceIdentity } from "./production-app-only-contract.mjs";
import { APP_ONLY_VERIFIER, appOnlyVerifierLauncherPolicy } from "./production-app-only-policy.mjs";
import { STAGE_B } from "./production-green-stage-b-contract.mjs";
import { assertEcsTaskDefinitionReadback } from "../../infra/aws/terraform/lambda/production-rls-approval-broker/ecs-task-definition-readback.mjs";
import { assertAppOnlyRequirements, compactAppOnlyRequirements } from "./production-app-only-requirements.mjs";

// The secret ARN is an authenticated Stage-A readback, never a dispatch input.
// Reuse the source-managed read-only boundary, not the write-capable executor.
export function buildAppOnlyVerifierDefinition({ requirements, identity, repositoryRoot, databaseSecretArn }) {
  assert.match(databaseSecretArn || "", new RegExp(`^arn:aws:secretsmanager:${APP_ONLY.region}:${APP_ONLY.account}:secret:mscqr/production/rls-green/phase4/read-only-canary-database-url-[A-Za-z0-9]{6}$`));
  const fixed = buildAppOnlyVerifierCommand({ requirements, identity, repositoryRoot });
  const template = fs.readFileSync(path.join(repositoryRoot, "infra/aws/terraform/production-green-stage-b/task-definitions/green-read-only-rls-canary.json"), "utf8");
  const definition = JSON.parse(template.replaceAll("{{READ_ONLY_CANARY_IMAGE}}", `${APP_ONLY.backendRepository}@${identity.verifierImageDigest}`)
    .replaceAll("{{READ_ONLY_CANARY_DATABASE_SECRET_ARN}}", databaseSecretArn)
    .replaceAll("{{READ_ONLY_CANARY_LOG_GROUP}}", APP_ONLY_VERIFIER.logGroup));
  definition.family = APP_ONLY_VERIFIER.family;
  definition.taskRoleArn = APP_ONLY_VERIFIER.taskRoleArn;
  definition.executionRoleArn = APP_ONLY_VERIFIER.executionRoleArn;
  definition.runtimePlatform = structuredClone(STAGE_B.taskRuntimePlatform);
  assert.equal(definition.containerDefinitions.length, 1);
  const container = definition.containerDefinitions[0];
  container.entryPoint = fixed.entryPoint; container.command = fixed.command;
  container.logConfiguration.options["awslogs-stream-prefix"] = "app-only";
  return { definition, verificationContractSha256: fixed.verificationContractSha256 };
}

export function assertRegisteredAppOnlyVerifier({ definition, taskDefinitionArn, requirements, identity, repositoryRoot, databaseSecretArn }) {
  appOnlyVerifierLauncherPolicy(taskDefinitionArn); // Exact account/region/family/revision.
  const expected = buildAppOnlyVerifierDefinition({ requirements, identity, repositoryRoot, databaseSecretArn });
  assertEcsTaskDefinitionReadback({ definition, taskDefinitionArn, expected: expected.definition, label: "Read-only app compatibility verifier" });
  assert.deepEqual(definition.tags || [], [], "Unreviewed verifier tags");
  return expected;
}

// Called AFTER requirements artifact, image and live predecessor provenance are
// authenticated. This fixes the entire task command at registration; RunTask
// accepts neither command nor environment overrides.
export function buildAppOnlyVerifierCommand({ requirements, identity, repositoryRoot }) {
  assertAppOnlyRequirements(requirements, { repositoryRoot, sourceSha: identity.sourceSha, candidateSourceSha: identity.candidateSourceSha });
  const validation = { identity, generatedAt: new Date().toISOString() };
  assertAppOnlyEvidenceIdentity({ ...validation, evidenceSha256: canonicalSha256(validation) }, identity);
  assert.match(identity.databaseHostname || "", /^[a-z0-9.-]+$/);
  assert.match(identity.verifierImageDigest || "", /^sha256:[a-f0-9]{64}$/);
  const verificationContractSha256 = canonicalSha256({ version: "app-only-database-verifier-v1",
    sourceSha: identity.sourceSha, candidateSourceSha: identity.candidateSourceSha,
    requirementsSha256: requirements.requirementsSha256 });
  const packed = compactAppOnlyRequirements(requirements);
  const payload = deflateSync(Buffer.from(JSON.stringify({ requirements: packed, packedRequirementsSha256: canonicalSha256(packed), identity, verificationContractSha256 }))).toString("base64");
  assert.ok(Buffer.byteLength(payload) <= 48000, "Verifier payload exceeds fixed task-definition budget");
  return { entryPoint: ["node"], command: ["scripts/aws/production-app-only-verifier-runtime.mjs", "--payload", payload], verificationContractSha256 };
}

export function authenticateAppOnlyVerifierResult({ message, identity, requirementsSha256, verificationContractSha256, now = Date.now() }) {
  assert.ok(typeof message === "string" && Buffer.byteLength(message) <= 16384, "Verifier output is oversized");
  const result = JSON.parse(message);
  assert.deepEqual(Object.keys(result).sort(), ["schemaVersion", "kind", "identity", "generatedAt", "verificationContractSha256", "requirementsSha256", "domains", "evidenceSha256"].sort());
  assert.equal(result.schemaVersion, 1); assert.equal(result.kind, "APP_ONLY_DATABASE_COMPATIBILITY");
  assertAppOnlyEvidenceIdentity(result, identity, now);
  assert.equal(result.requirementsSha256, requirementsSha256);
  assert.equal(result.verificationContractSha256, verificationContractSha256);
  assert.deepEqual(Object.keys(result.domains).sort(), ["DATABASE_SCHEMA", "RLS_FUNCTIONS", "RLS_POLICIES", "RLS_GRANTS", "RLS_FORCE_STATUS", "GENERATED_RLS_CONTRACT"].sort());
  assert.ok(Object.values(result.domains).every((value) => value === "COMPATIBLE"), "Database compatibility is incompatible or unproven");
  return result;
}
