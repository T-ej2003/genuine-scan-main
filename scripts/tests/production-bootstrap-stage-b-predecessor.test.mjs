import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { APP_ONLY } from "../aws/production-app-only-contract.mjs";
import { assertBootstrapStageBLivePredecessor, bootstrapStageBSourceRange, COMPONENT_STATE_BOOTSTRAP_WORKFLOW } from "../aws/production-bootstrap-stage-b-predecessor-contract.mjs";
import { WEB_RELEASE } from "../aws/production-web-release-contract.mjs";
import { advanceProductionComponentDeploymentState, componentDeploymentProvenance } from "../aws/production-component-deployment-state.mjs";

const sha = (letter) => letter.repeat(40), image = (letter) => `sha256:${letter.repeat(64)}`;
const serviceArn = (name) => `arn:aws:ecs:eu-west-2:368992683803:service/mscqr-prod-euw2-main/${name}`;
const taskArn = (family, revision) => `arn:aws:ecs:eu-west-2:368992683803:task-definition/${family}:${revision}`;
const clusterArn = "arn:aws:ecs:eu-west-2:368992683803:cluster/mscqr-prod-euw2-main";

function fixture() {
  const source = { backend: sha("a"), frontend: sha("b") }, toolingSha = sha("c");
  const components = {
    backend: { sourceSha: source.backend, establishedThroughSha: source.backend, imageDigest: image("1"), taskDefinitionArn: taskArn(APP_ONLY.family, 24), desiredCount: 2 },
    frontend: { sourceSha: source.frontend, establishedThroughSha: source.frontend, imageDigest: image("2"), taskDefinitionArn: taskArn(WEB_RELEASE.family, 22), desiredCount: 2 },
    database: null, security: null,
  };
  const updatedAt = "2026-10-02T09:00:00.000Z";
  const provenance = { lane: "BOOTSTRAP", workflow: COMPONENT_STATE_BOOTSTRAP_WORKFLOW, githubRunId: "123456789", generation: 1, updatedAt };
  const componentState = { schemaVersion: 2, environment: "production", repository: "T-ej2003/genuine-scan-main", generation: 1, updatedAt, updatedByLane: "BOOTSTRAP", updatedByWorkflow: COMPONENT_STATE_BOOTSTRAP_WORKFLOW, githubRunId: "123456789", components, componentProvenance: { backend: { ...provenance }, frontend: { ...provenance } } };
  const live = (name, contract, revision) => ({
    service: { clusterArn, serviceArn: serviceArn(contract.service), serviceName: contract.service, status: "ACTIVE", desiredCount: 2, runningCount: 2, pendingCount: 0, taskDefinition: components[name].taskDefinitionArn, deployments: [{ status: "PRIMARY", rolloutState: "COMPLETED", taskDefinition: components[name].taskDefinitionArn }] },
    taskDefinition: { taskDefinitionArn: components[name].taskDefinitionArn, family: contract.family, revision, status: "ACTIVE", ...(name === "backend" ? { networkMode: "awsvpc", taskRoleArn: APP_ONLY.taskRoleArn, executionRoleArn: APP_ONLY.executionRoleArn, runtimePlatform: { operatingSystemFamily: "LINUX", cpuArchitecture: "X86_64" } } : {}), containerDefinitions: [{ name: contract.container, image: `${contract.repository}@${components[name].imageDigest}`, ...(name === "backend" ? { environment: [{ name: "RELEASE_GIT_SHA", value: source[name] }] } : {}) }] },
  });
  const backend = live("backend", { service: APP_ONLY.service, family: APP_ONLY.family, container: APP_ONLY.container, repository: APP_ONLY.backendRepository }, 24);
  const frontend = live("frontend", { service: WEB_RELEASE.serviceName, family: WEB_RELEASE.family, container: WEB_RELEASE.container, repository: `${WEB_RELEASE.account}.dkr.ecr.${WEB_RELEASE.region}.amazonaws.com/${WEB_RELEASE.repository}` }, 22);
  const sourceRanges = {
    backend: bootstrapStageBSourceRange({ component: "backend", fromSha: source.backend, toSha: toolingSha, files: ["scripts/plan-production-green-stage-b.mjs"] }),
    frontend: bootstrapStageBSourceRange({ component: "frontend", fromSha: source.frontend, toSha: toolingSha, files: ["backend/src/services/auditLogOutboxService.ts", "scripts/plan-production-green-stage-b.mjs"] }),
  };
  return { componentState, toolingSha, backend, frontend, sourceRanges };
}

test("complete bootstrapped live set and independent stronger-lane ranges authenticate", () => {
  const result = assertBootstrapStageBLivePredecessor(fixture());
  assert.equal(result.components.backend.sourceSha, sha("a")); assert.equal(result.components.frontend.sourceSha, sha("b"));
  assert.equal(result.classifications.backend.releaseClass, "EMERGENCY_RECOVERY"); assert.equal(result.classifications.frontend.releaseClass, "EMERGENCY_RECOVERY");
});

test("state machine advances BOOTSTRAP only through a truthful stronger-lane terminal", () => {
  const f = fixture(); assertBootstrapStageBLivePredecessor(f);
  const deployed = Object.fromEntries(["backend", "frontend"].map((name) => [name, { ...f.componentState.components[name], sourceSha: f.toolingSha, establishedThroughSha: f.toolingSha, imageDigest: image(name === "backend" ? "7" : "8"), taskDefinitionArn: taskArn(name === "backend" ? APP_ONLY.family : WEB_RELEASE.family, name === "backend" ? 25 : 23) }]));
  const next = advanceProductionComponentDeploymentState({ current: f.componentState, expectedGeneration: 1, lane: "SECURITY_INFRASTRUCTURE", changes: { ...deployed, database: { sourceSha: f.toolingSha, releaseIdentity: "database-receipt" }, security: { sourceSha: f.toolingSha, releaseIdentity: "a".repeat(64) } }, isAncestor: () => true, updatedByWorkflow: "T-ej2003/genuine-scan-main/.github/workflows/release-gate.yml@refs/heads/main", githubRunId: "987654321" });
  assert.equal(next.generation, 2); assert.equal(next.normalDeploymentReceipt, undefined);
  for (const name of ["backend", "frontend", "database", "security"]) assert.equal(componentDeploymentProvenance(next, name).lane, "SECURITY_INFRASTRUCTURE");
});

test("mutation boundary revalidates the bootstrap predecessor before reserving or applying", () => {
  const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
  const source = fs.readFileSync(path.join(root, "scripts/apply-production-green-stage-b.mjs"), "utf8");
  const revalidate = source.indexOf("effectiveDeps.revalidateBootstrapReference(");
  assert.ok(revalidate > source.indexOf("const executableAuditSha256"));
  assert.ok(revalidate < source.indexOf("const applyAttemptPath", revalidate));
  assert.ok(revalidate < source.indexOf("reserveSharedApplyAttempt(", revalidate));
  assert.ok(revalidate < source.indexOf("effectiveDeps.apply(", revalidate));
});

const attacks = [
  ["schema downgrade", (f) => { f.componentState.schemaVersion = 1; delete f.componentState.componentProvenance; }],
  ["generation substitution", (f) => { f.componentState.generation = 2; }],
  ["aggregate lane substitution", (f) => { f.componentState.updatedByLane = "NORMAL_APPLICATION"; }],
  ["aggregate workflow substitution", (f) => { f.componentState.updatedByWorkflow = "other/workflow"; }],
  ["non-run bootstrap identity", (f) => { f.componentState.githubRunId = "bootstrap"; }],
  ["backend provenance lane substitution", (f) => { f.componentState.componentProvenance.backend.lane = "NORMAL_APPLICATION"; }],
  ["frontend provenance workflow substitution", (f) => { f.componentState.componentProvenance.frontend.workflow = "other/workflow"; }],
  ["backend provenance generation substitution", (f) => { f.componentState.componentProvenance.backend.generation = 2; }],
  ["pending normal receipt", (f) => { f.componentState.normalDeploymentReceipt = {}; }],
  ["database authority asserted", (f) => { f.componentState.components.database = { sourceSha: sha("a"), releaseIdentity: "db" }; f.componentState.componentProvenance.database = { ...f.componentState.componentProvenance.backend }; }],
  ["security authority asserted", (f) => { f.componentState.components.security = { sourceSha: sha("a"), releaseIdentity: "security" }; f.componentState.componentProvenance.security = { ...f.componentState.componentProvenance.backend }; }],
  ["backend established baseline substitution", (f) => { f.componentState.components.backend.establishedThroughSha = sha("d"); }],
  ["frontend established baseline substitution", (f) => { f.componentState.components.frontend.establishedThroughSha = sha("d"); }],
  ["backend service ARN substitution", (f) => { f.backend.service.serviceArn = serviceArn("other"); }],
  ["frontend service substitution", (f) => { f.frontend.service.serviceName = "other"; }],
  ["wrong cluster", (f) => { f.backend.service.clusterArn = clusterArn.replace("main", "other"); }],
  ["backend task ARN substitution", (f) => { f.backend.service.taskDefinition = taskArn(APP_ONLY.family, 25); }],
  ["frontend task ARN substitution", (f) => { f.frontend.taskDefinition.taskDefinitionArn = taskArn(WEB_RELEASE.family, 23); }],
  ["backend family substitution", (f) => { f.backend.taskDefinition.family = "other"; }],
  ["frontend family substitution", (f) => { f.frontend.taskDefinition.family = APP_ONLY.family; }],
  ["backend image substitution", (f) => { f.backend.taskDefinition.containerDefinitions[0].image = `${APP_ONLY.backendRepository}@${image("9")}`; }],
  ["frontend image substitution", (f) => { f.frontend.taskDefinition.containerDefinitions[0].image = f.frontend.taskDefinition.containerDefinitions[0].image.replace(image("2"), image("9")); }],
  ["backend source env substitution", (f) => { f.backend.taskDefinition.containerDefinitions[0].environment[0].value = sha("d"); }],
  ["backend container removal", (f) => { f.backend.taskDefinition.containerDefinitions = []; }],
  ["frontend container removal", (f) => { f.frontend.taskDefinition.containerDefinitions = []; }],
  ["backend task inactive", (f) => { f.backend.taskDefinition.status = "INACTIVE"; }],
  ["frontend task inactive", (f) => { f.frontend.taskDefinition.status = "INACTIVE"; }],
  ["backend deployment pending", (f) => { f.backend.service.pendingCount = 1; }],
  ["frontend running count short", (f) => { f.frontend.service.runningCount = 1; }],
  ["multiple backend deployments", (f) => { f.backend.service.deployments.push({ ...f.backend.service.deployments[0] }); }],
  ["missing frontend component", (f) => { f.componentState.components.frontend = null; delete f.componentState.componentProvenance.frontend; }],
  ["missing frontend range", (f) => { delete f.sourceRanges.frontend; }],
  ["cross-component range start", (f) => { f.sourceRanges.backend = { ...f.sourceRanges.backend, fromSha: f.componentState.components.frontend.sourceSha }; }],
  ["range target substitution", (f) => { f.sourceRanges.backend = { ...f.sourceRanges.backend, toSha: sha("d") }; }],
  ["range file hash substitution", (f) => { f.sourceRanges.backend = { ...f.sourceRanges.backend, filesSha256: "0".repeat(64) }; }],
  ["range classification substitution", (f) => { f.sourceRanges.backend = { ...f.sourceRanges.backend, releaseClass: "NORMAL_APPLICATION" }; }],
  ["normal-only bridge range", (f) => { f.sourceRanges.backend = bootstrapStageBSourceRange({ component: "backend", fromSha: f.componentState.components.backend.sourceSha, toSha: f.toolingSha, files: ["backend/src/services/batchService.ts"] }); f.sourceRanges.frontend = bootstrapStageBSourceRange({ component: "frontend", fromSha: f.componentState.components.frontend.sourceSha, toSha: f.toolingSha, files: ["src/App.tsx"] }); }],
  ["unclassified bridge path", (f) => { f.sourceRanges.backend = { ...f.sourceRanges.backend, files: ["unknown/runtime"], filesSha256: "0".repeat(64) }; }],
];

for (const [name, mutate] of attacks) test(`bootstrap Stage B predecessor rejects ${name}`, () => {
  const value = fixture(); mutate(value); assert.throws(() => assertBootstrapStageBLivePredecessor(value));
});
