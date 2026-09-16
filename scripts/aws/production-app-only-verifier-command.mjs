import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { deflateSync } from "node:zlib";
import { canonicalJson, canonicalSha256 } from "./production-green-stage-b-contract.mjs";
import { APP_ONLY, assertAppOnlyEvidenceIdentity } from "./production-app-only-contract.mjs";
import { APP_ONLY_VERIFIER, appOnlyVerifierLauncherPolicy } from "./production-app-only-policy.mjs";
import { STAGE_B } from "./production-green-stage-b-contract.mjs";
import { assertEcsTaskDefinitionReadback } from "../../infra/aws/terraform/lambda/production-rls-approval-broker/ecs-task-definition-readback.mjs";
import { collectAppOnlyDatabaseCatalogue } from "./production-app-only-database-verifier.mjs";
import { appOnlyRequirementIdentity, assertAppOnlyRequirements, compactAppOnlyRequirements, compareCompactAppOnlyRequirements } from "./production-app-only-requirements.mjs";

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
  const functions = [collectAppOnlyDatabaseCatalogue, appOnlyRequirementIdentity, compareCompactAppOnlyRequirements].map((fn) => fn.toString()).join("\n");
  const verificationContractSha256 = canonicalSha256({ functions, requirementsSha256: requirements.requirementsSha256 });
  const packed = compactAppOnlyRequirements(requirements);
  const payload = deflateSync(Buffer.from(JSON.stringify({ requirements: packed, identity, verificationContractSha256 }))).toString("base64");
  const command = `"use strict";
const assert=require("node:assert/strict"),crypto=require("node:crypto");
const {PrismaClient}=require("@prisma/client");
const canonicalJson=${canonicalJson.toString()};
const canonicalSha256=value=>crypto.createHash("sha256").update(canonicalJson(value)).digest("hex");
${functions}
const input=JSON.parse(require("node:zlib").inflateSync(Buffer.from(${JSON.stringify(payload)},"base64"),{maxOutputLength:1048576}));
let phase="CONFIGURATION";
(async()=>{
  const {requirementsSha256}=input.requirements;
  assert.equal(canonicalSha256(input.requirements),${JSON.stringify(canonicalSha256(packed))});
  const {validateConfiguration}=await import("./scripts/production-green-read-only-rls-canary.mjs");
  const url=validateConfiguration({env:process.env,argv:[]});
  assert.equal(new URL(url).hostname,input.identity.databaseHostname);
  const client=new PrismaClient({datasources:{db:{url}}});
  try {
    phase="CATALOGUE";
    const catalogue=await collectAppOnlyDatabaseCatalogue(client);
    phase="COMPARISON";
    const domains=compareCompactAppOnlyRequirements(catalogue,input.requirements);
    const evidence={schemaVersion:1,kind:"APP_ONLY_DATABASE_COMPATIBILITY",identity:input.identity,
      generatedAt:new Date().toISOString(),verificationContractSha256:input.verificationContractSha256,
      requirementsSha256,domains};
    console.log(JSON.stringify({...evidence,evidenceSha256:canonicalSha256(evidence)}));
    if(!Object.values(domains).every(value=>value==="COMPATIBLE"))process.exitCode=1;
  } finally { await client.$disconnect(); }
})().catch(()=>{console.error(JSON.stringify({status:"APP_ONLY_DATABASE_VERIFICATION_FAILED",phase}));process.exitCode=1;});`;
  assert.ok(Buffer.byteLength(command) <= 48000, "Verifier command exceeds fixed task-definition budget");
  return { entryPoint: ["node"], command: ["-e", command], verificationContractSha256 };
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
