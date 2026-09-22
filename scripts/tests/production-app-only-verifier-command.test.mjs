import test from "node:test";
import assert from "node:assert/strict";
import { APP_ONLY } from "../aws/production-app-only-contract.mjs";
import { canonicalSha256 } from "../aws/production-green-stage-b-contract.mjs";
import { authenticateAppOnlyVerifierResult, buildAppOnlyVerifierDefinition, assertRegisteredAppOnlyVerifier } from "../aws/production-app-only-verifier-command.mjs";
import { createAppOnlyRequirements } from "../aws/production-app-only-requirements.mjs";
import { APP_ONLY_VERIFIER } from "../aws/production-app-only-policy.mjs";

const identity = { sourceSha: "a".repeat(40), candidateSourceSha: "b".repeat(40), account: APP_ONLY.account, region: APP_ONLY.region,
  clusterArn: APP_ONLY.clusterArn, serviceArn: APP_ONLY.serviceArn,
  predecessorTaskDefinition: `arn:aws:ecs:${APP_ONLY.region}:${APP_ONLY.account}:task-definition/${APP_ONLY.family}:14`,
  predecessorBackendDigest: `sha256:${"1".repeat(64)}`, candidateDigest: `sha256:${"2".repeat(64)}`,
  verifierImageDigest: `sha256:${"3".repeat(64)}`, databaseHostname: "reviewed.eu-west-2.rds.amazonaws.com" };
const now = Date.now();
const body = () => ({ schemaVersion: 1, kind: "APP_ONLY_DATABASE_COMPATIBILITY", identity: structuredClone(identity),
  generatedAt: new Date(now).toISOString(), requirementsSha256: "c".repeat(64), verificationContractSha256: "d".repeat(64),
  domains: Object.fromEntries(["DATABASE_SCHEMA", "RLS_FUNCTIONS", "RLS_POLICIES", "RLS_GRANTS", "RLS_FORCE_STATUS", "GENERATED_RLS_CONTRACT"].map((key) => [key, "COMPATIBLE"])) });
const check = (value, overrides = {}) => authenticateAppOnlyVerifierResult({ message: JSON.stringify({ ...value, evidenceSha256: canonicalSha256(value) }),
  identity, requirementsSha256: "c".repeat(64), verificationContractSha256: "d".repeat(64), now, ...overrides });
test("verifier result binds all domain results and exact execution context", () => {
  assert.equal(check(body()).kind, "APP_ONLY_DATABASE_COMPATIBILITY");
  for (const field of Object.keys(identity)) {
    const value = body(); value.identity[field] = "substituted";
    assert.throws(() => check(value));
  }
  for (const domain of Object.keys(body().domains)) {
    for (const status of ["INCOMPATIBLE", "UNPROVEN", true]) {
      const value = body(); value.domains[domain] = status; assert.throws(() => check(value));
    }
    const value = body(); delete value.domains[domain]; assert.throws(() => check(value));
  }
});
test("verifier stale/future evidence, substituted contracts and extra fields fail closed", () => {
  assert.throws(() => check(body(), { now: now + APP_ONLY.maxEvidenceAgeMs + 1 }));
  assert.throws(() => check(body(), { now: now - 1 }));
  for (const field of ["requirementsSha256", "verificationContractSha256"]) assert.throws(() => check(body(), { [field]: "e".repeat(64) }));
  assert.throws(() => check({ ...body(), fullDatabaseDump: "unexpected" }));
  assert.throws(() => authenticateAppOnlyVerifierResult({ message: "x".repeat(16385) }));
});

test("verifier registration is the exact source-owned read-only boundary with fixed command", () => {
  const repositoryRoot = process.cwd();
  const catalogue = { routines: [{ schema: "app_auth", name: "fixed", arguments: "" }], tables: [{ name: "Example" }],
    policies: [{ table: "Example", name: "isolation" }], schemas: [{ name: "app_auth" }], roles: [{ name: "mscqr_prod_rls_canary_read" }] };
  const requirements = createAppOnlyRequirements({ repositoryRoot, ...identity, catalogue, packageChecksums: { fixture: true } });
  const databaseSecretArn = `arn:aws:secretsmanager:${APP_ONLY.region}:${APP_ONLY.account}:secret:mscqr/production/rls-green/phase4/read-only-canary-database-url-ABC123`;
  const input = { requirements, identity, repositoryRoot, databaseSecretArn };
  const { definition } = buildAppOnlyVerifierDefinition(input);
  assert.doesNotThrow(() => new Function(definition.containerDefinitions[0].command[1]));
  assert.match(definition.containerDefinitions[0].command[1], /async function collectAppOnlyDatabaseCatalogueRows/);
  const taskDefinitionArn = `arn:aws:ecs:${APP_ONLY.region}:${APP_ONLY.account}:task-definition/${APP_ONLY_VERIFIER.family}:17`;
  const observed = { ...structuredClone(definition), taskDefinitionArn, status: "ACTIVE", revision: 17, volumes: [], placementConstraints: [], enableFaultInjection: false };
  observed.containerDefinitions[0].cpu = 0;
  observed.containerDefinitions[0].environment = [];
  assertRegisteredAppOnlyVerifier({ ...input, definition: observed, taskDefinitionArn });
  assert.equal(definition.containerDefinitions[0].readonlyRootFilesystem, true);
  assert.equal(definition.containerDefinitions[0].secrets[0].name, "RLS_CANARY_DATABASE_URL");
  for (const mutate of [
    (d) => { d.taskRoleArn += "other"; }, (d) => { d.executionRoleArn += "other"; },
    (d) => { d.family += "other"; }, (d) => { d.tags = [{ key: "privilege", value: "other" }]; },
    (d) => { d.containerDefinitions[0].command = ["-e", "malicious()"]; },
    (d) => { d.containerDefinitions[0].image = "mutable:latest"; },
    (d) => { d.containerDefinitions[0].environment = [{ name: "DATABASE_URL", value: "substituted" }]; },
    (d) => { d.containerDefinitions[0].secrets[0].valueFrom += "other"; },
    (d) => { d.containerDefinitions[0].readonlyRootFilesystem = false; },
    (d) => { d.containerDefinitions.push(structuredClone(d.containerDefinitions[0])); },
  ]) {
    const bad = structuredClone(observed); mutate(bad);
    assert.throws(() => assertRegisteredAppOnlyVerifier({ ...input, definition: bad, taskDefinitionArn }));
  }
  assert.throws(() => buildAppOnlyVerifierDefinition({ ...input, databaseSecretArn: databaseSecretArn.replace("read-only-canary", "executor") }));
});
