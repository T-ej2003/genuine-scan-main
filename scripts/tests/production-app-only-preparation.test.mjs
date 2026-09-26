import test from "node:test";
import assert from "node:assert/strict";
import { prepareAppOnlyDeployment, prepareAppOnlyVerifier, authenticateAppOnlyVerifierInputs, authenticateAppOnlyDeploymentInputs } from "../aws/production-app-only-preparation.mjs";
import { APP_ONLY } from "../aws/production-app-only-contract.mjs";
import { canonicalSha256 } from "../aws/production-green-stage-b-contract.mjs";
import { createAppOnlyRequirements } from "../aws/production-app-only-requirements.mjs";
import { buildAppOnlyVerifierCommand, buildAppOnlyVerifierDefinition } from "../aws/production-app-only-verifier-command.mjs";
import { appOnlyVerifierNetwork } from "../aws/production-app-only-policy.mjs";
import { APP_ONLY_SESSION_RISK_CONTRACT } from "../aws/production-app-only-images.mjs";

const signed = (body) => ({ ...body, evidenceSha256: canonicalSha256(body) });
function fixture(deploymentId = "ecs-svc/100") {
  const sourceSha = "fbc47fd83699403b8708f87d757e552d5bc02dd8", candidateSourceSha = "bcec05a421bff28eb2216f399d0a9e7cd2389d5e";
  const predecessorSourceSha = "7e93853e6c48ad3020915f551ef89155825ae403", now = Date.now(), generatedAt = new Date(now).toISOString();
  const arn = `arn:aws:ecs:${APP_ONLY.region}:${APP_ONLY.account}:task-definition/${APP_ONLY.family}:14`;
  const predecessorBackendDigest = `sha256:${"1".repeat(64)}`, candidateDigest = `sha256:${"2".repeat(64)}`;
  const identity = { sourceSha, candidateSourceSha, candidateDigest, account: APP_ONLY.account, region: APP_ONLY.region,
    clusterArn: APP_ONLY.clusterArn, serviceArn: APP_ONLY.serviceArn, predecessorTaskDefinition: arn, predecessorBackendDigest };
  const definition = { taskDefinitionArn: arn, family: APP_ONLY.family, status: "ACTIVE", taskRoleArn: APP_ONLY.taskRoleArn,
    executionRoleArn: APP_ONLY.executionRoleArn, networkMode: "awsvpc", runtimePlatform: { cpuArchitecture: "X86_64", operatingSystemFamily: "LINUX" },
    containerDefinitions: [{ name: "backend", image: `${APP_ONLY.backendRepository}@${predecessorBackendDigest}` }] };
  const service = { clusterArn: APP_ONLY.clusterArn, serviceArn: APP_ONLY.serviceArn, serviceName: APP_ONLY.service,
    status: "ACTIVE", taskDefinition: arn, desiredCount: 2, runningCount: 2, pendingCount: 0,
    deployments: [{ id: deploymentId, taskDefinition: arn, status: "PRIMARY", rolloutState: "COMPLETED" }] };
  const tasks = ["one", "two"].map((taskArn) => ({ taskArn, taskDefinitionArn: arn, clusterArn: APP_ONLY.clusterArn,
    group: `service:${APP_ONLY.service}`, lastStatus: "RUNNING", healthStatus: "HEALTHY", startedBy: deploymentId,
    containers: [{ name: "backend", imageDigest: predecessorBackendDigest }] }));
  const requirements = createAppOnlyRequirements({ repositoryRoot: process.cwd(), sourceSha, candidateSourceSha,
    packageChecksums: { fixture: true }, catalogue: { routines: [{ schema: "app_auth", name: "fixed", arguments: "" }],
      tables: [{ name: "Example" }], policies: [{ table: "Example", name: "isolation" }], schemas: [{ name: "app_auth" }], roles: [{ name: "app" }] } });
  const verifierImage = { sourceSha, digest: `sha256:${"4".repeat(64)}`, tag: `${sourceSha}-backend-only` };
  const verifierIdentity = { ...identity, verifierImageDigest: verifierImage.digest, databaseHostname: "reviewed.eu-west-2.rds.amazonaws.com" };
  const { verificationContractSha256 } = buildAppOnlyVerifierCommand({ requirements, identity: verifierIdentity, repositoryRoot: process.cwd() });
  return { sourceSha, predecessorSourceSha, now, repositoryRoot: process.cwd(), live: { definition, service, tasks }, requirements,
    images: signed({ schemaVersion: 1, kind: "APP_ONLY_AUTHENTICATED_IMAGES", sourceSha, candidateSourceSha, candidateDigest, generatedAt, sessionRisk: APP_ONLY_SESSION_RISK_CONTRACT }), verifierImage,
    iam: signed({ schemaVersion: 1, kind: "APP_ONLY_LIVE_IAM_COMPATIBILITY", identity, generatedAt,
      status: "ALREADY_APPLIED_COMPATIBLE", sourceToLiveIamSemanticDifferences: 0, scope: "BACKEND_RUNTIME_ROLES" }),
    verifierIam: signed({ schemaVersion: 1, kind: "APP_ONLY_LIVE_IAM_COMPATIBILITY", identity, generatedAt,
      databaseSecretArn: `arn:aws:secretsmanager:${APP_ONLY.region}:${APP_ONLY.account}:secret:mscqr/production/rls-green/phase4/read-only-canary-database-url-ABC123`,
      status: "ALREADY_APPLIED_COMPATIBLE", sourceToLiveIamSemanticDifferences: 0, scope: "READ_ONLY_VERIFIER_ROLES" }),
    runtime: signed({ schemaVersion: 1, kind: "APP_ONLY_RUNTIME_COMPATIBILITY", identity, generatedAt,
      status: "ALREADY_APPLIED_COMPATIBLE", networkDatabase: { databaseHostname: verifierIdentity.databaseHostname } }),
    database: signed({ schemaVersion: 1, kind: "APP_ONLY_DATABASE_COMPATIBILITY", identity: verifierIdentity, generatedAt,
      requirementsSha256: requirements.requirementsSha256, verificationContractSha256,
      domains: Object.fromEntries(["DATABASE_SCHEMA", "RLS_FUNCTIONS", "RLS_POLICIES", "RLS_GRANTS", "RLS_FORCE_STATUS", "GENERATED_RLS_CONTRACT"].map((name) => [name, "COMPATIBLE"])) }) };
}

test("preparation transitively binds fresh live domain, image, requirements and predecessor identities", () => {
  const input = fixture(), result = prepareAppOnlyDeployment(input);
  assert.equal(result.eligible, true);
  assert.ok(Object.values(result.domains).every((value) => value === "ALREADY_APPLIED_COMPATIBLE"));
  assert.equal(result.evidence.images, input.images.evidenceSha256); assert.equal(result.evidence.iam, input.iam.evidenceSha256);
  assert.equal(result.evidence.runtime, input.runtime.evidenceSha256); assert.equal(result.evidence.database, input.database.evidenceSha256);
  assert.equal(result.predecessor.backendDigest, input.iam.identity.predecessorBackendDigest);
  assert.equal(result.candidateDigest, input.images.candidateDigest);
});

test("verifier preparation binds exact task/network requirements without claiming database compatibility", () => {
  const input = fixture(); delete input.database;
  input.databaseSecretArn = `arn:aws:secretsmanager:${APP_ONLY.region}:${APP_ONLY.account}:secret:mscqr/production/rls-green/phase4/read-only-canary-database-url-ABC123`;
  const result = prepareAppOnlyVerifier(input);
  assert.equal(result.eligible, false); assert.equal(result.kind, "APP_ONLY_VERIFIER_PREPARATION");
  assert.equal(result.evidence.requirements, input.requirements.requirementsSha256);
  assert.equal(result.evidence.verifierIam, input.verifierIam.evidenceSha256);
  assert.equal(result.evidence.verifierImage, canonicalSha256(input.verifierImage));
  assert.throws(() => prepareAppOnlyVerifier({ ...input, verifierIam: input.iam }));
  assert.throws(() => prepareAppOnlyVerifier({ ...input, verifierIam: undefined }));
  assert.equal(result.networkSha256, canonicalSha256(appOnlyVerifierNetwork()));
  assert.equal(result.identity.candidateDigest, input.images.candidateDigest);
  assert.equal(result.identity.verifierImageDigest, input.verifierImage.digest);
  assert.notEqual(result.identity.verifierImageDigest, result.identity.candidateDigest, "Verifier code is pinned to protected main, not the older candidate image");
  const { definition } = buildAppOnlyVerifierDefinition({ requirements: input.requirements, identity: result.identity,
    repositoryRoot: input.repositoryRoot, databaseSecretArn: input.databaseSecretArn });
  assert.equal(definition.containerDefinitions[0].image,
    `${APP_ONLY.backendRepository}@${input.verifierImage.digest}`, "The verifier task must execute the protected-main runtime image");
  assert.equal(result.predecessor.taskDefinitionArn, input.live.definition.taskDefinitionArn);
  assert.throws(() => prepareAppOnlyDeployment(input), "A verifier request is not deployment eligibility");
  assert.throws(() => prepareAppOnlyVerifier({ ...input, databaseSecretArn: input.databaseSecretArn.replace("read-only-canary", "admin") }));
  assert.throws(() => prepareAppOnlyVerifier({ ...input, verifierImage: { ...input.verifierImage, sourceSha: input.images.candidateSourceSha } }));
  assert.throws(() => prepareAppOnlyVerifier({ ...input, verifierImage: { ...input.verifierImage, tag: `${input.images.candidateSourceSha}-backend-only` } }));
  assert.throws(() => prepareAppOnlyVerifier({ ...input, verifierImage: { ...input.verifierImage, unexpected: true } }));
  assert.throws(() => prepareAppOnlyVerifier({ ...input, now: input.now + APP_ONLY.maxEvidenceAgeMs + 1 }));
});

test("consumer recomputes the full verifier closure and rejects altered proof or current ECS", () => {
  const input = fixture(); input.databaseSecretArn = input.verifierIam.databaseSecretArn;
  const inputs = { schemaVersion: 1, kind: "APP_ONLY_VERIFIER_INPUTS", preparation: prepareAppOnlyVerifier(input),
    images: input.images, verifierImage: input.verifierImage, iam: input.iam, verifierIam: input.verifierIam, runtime: input.runtime, requirements: input.requirements, requirementsReference: {} };
  const context = { inputs, sourceSha: input.sourceSha, live: input.live, repositoryRoot: input.repositoryRoot, now: input.now + 1000 };
  assert.equal(authenticateAppOnlyVerifierInputs(context).databaseSecretArn, input.databaseSecretArn);
  for (const name of ["images", "verifierImage", "iam", "verifierIam", "runtime", "requirements"]) {
    const changed = structuredClone(inputs); changed[name] = {};
    assert.throws(() => authenticateAppOnlyVerifierInputs({ ...context, inputs: changed }), name);
  }
  const live = structuredClone(input.live); live.service.desiredCount = 3;
  assert.throws(() => authenticateAppOnlyVerifierInputs({ ...context, live }));
  assert.throws(() => authenticateAppOnlyVerifierInputs({ ...context, sourceSha: "f".repeat(40) }));
  assert.throws(() => authenticateAppOnlyVerifierInputs({ ...context, now: input.now + APP_ONLY.maxEvidenceAgeMs + 1 }));
});

test("preparation rejects stale, substituted or unproven live reports even with recomputed content hashes", () => {
  for (const [name, mutate] of [
    ["iam", (r) => { r.sourceToLiveIamSemanticDifferences = 1; }],
    ["iam", (r) => { r.scope = "UNRELATED_ROLE"; }],
    ["runtime", (r) => { r.status = "UNPROVEN"; }],
    ["runtime", (r) => { r.networkDatabase.databaseHostname = "wrong.eu-west-2.rds.amazonaws.com"; }],
    ["database", (r) => { r.domains.RLS_POLICIES = "UNPROVEN"; }],
    ["database", (r) => { r.requirementsSha256 = "f".repeat(64); }],
    ["database", (r) => { r.identity.verifierImageDigest = `sha256:${"f".repeat(64)}`; }],
    ["images", (r) => { r.sourceSha = "f".repeat(40); }],
  ]) {
    const input = fixture(); const { evidenceSha256: ignored, ...body } = input[name]; void ignored;
    mutate(body); input[name] = signed(body); assert.throws(() => prepareAppOnlyDeployment(input));
  }
  for (const name of ["iam", "runtime", "database", "images"]) {
    const input = fixture(); const { evidenceSha256: ignored, ...body } = input[name]; void ignored;
    body.generatedAt = new Date(input.now - APP_ONLY.maxEvidenceAgeMs - 1).toISOString(); input[name] = signed(body);
    assert.throws(() => prepareAppOnlyDeployment(input));
  }
});

for (const deploymentId of ["ecs-svc/0559890711032160707", "ecs-svc/1234567890123456789"]) {
test(`deployment consumer preserves opaque ID and rejects substituted proof and CAS: ${deploymentId}`, () => {
  const input = fixture(deploymentId); input.databaseSecretArn = input.verifierIam.databaseSecretArn;
  const verifierInputs = { schemaVersion: 1, kind: "APP_ONLY_VERIFIER_INPUTS", preparation: prepareAppOnlyVerifier(input),
    images: input.images, iam: input.iam, verifierIam: input.verifierIam, runtime: input.runtime,
    verifierImage: input.verifierImage, requirements: input.requirements, requirementsReference: {} };
  const inputs = { schemaVersion: 1, kind: "APP_ONLY_DEPLOYMENT_INPUTS", preparation: prepareAppOnlyDeployment(input),
    inputs: verifierInputs, database: input.database, compatibilityReference: {}, verifierTaskArn: "fixture", verifierTaskDefinitionArn: "fixture" };
  const context = { inputs, sourceSha: input.sourceSha, live: input.live, repositoryRoot: input.repositoryRoot, now: input.now + 1000 };
  assert.deepEqual(authenticateAppOnlyDeploymentInputs(context), inputs.preparation);
  assert.equal(authenticateAppOnlyDeploymentInputs({ ...context, inputs: JSON.parse(JSON.stringify(inputs)) }).predecessor.deploymentId, deploymentId);
  for (const mutate of [
    (p) => { p.eligible = false; }, (p) => { p.domains.RLS = "UNCHANGED"; },
    (p) => { p.candidateDigest = `sha256:${"f".repeat(64)}`; },
    (p) => { p.evidence.database = "f".repeat(64); },
  ]) {
    const changed = structuredClone(inputs), { preparationSha256: ignored, ...body } = changed.preparation; void ignored;
    mutate(body); changed.preparation = { ...body, preparationSha256: canonicalSha256(body) };
    assert.throws(() => authenticateAppOnlyDeploymentInputs({ ...context, inputs: changed }));
  }
  const changed = structuredClone(inputs); changed.database = undefined;
  assert.throws(() => authenticateAppOnlyDeploymentInputs({ ...context, inputs: changed }));
  const live = structuredClone(input.live); live.service.deployments[0].id = "concurrent";
  assert.throws(() => authenticateAppOnlyDeploymentInputs({ ...context, live }));
  assert.throws(() => authenticateAppOnlyDeploymentInputs({ ...context, now: input.now + APP_ONLY.maxEvidenceAgeMs + 1 }));
});
}
