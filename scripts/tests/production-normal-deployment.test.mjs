import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";
import { PRODUCTION_RELEASE_CLASS, classifyProductionChanges } from "../aws/production-deployment-classification.mjs";
import { buildNormalReleasePlan, executeNormalFrontendActivation, executeNormalRelease, NORMAL_RELEASE } from "../aws/production-normal-release.mjs";
import { assertNormalImageIdentity } from "../aws/production-normal-image-contract.mjs";
import { WEB_RELEASE, buildNormalFrontendCandidate, captureFrontendPredecessor } from "../aws/production-web-release-contract.mjs";

const sourceSha = "a".repeat(40);
const backendImage = NORMAL_RELEASE.account + ".dkr.ecr." + NORMAL_RELEASE.region + ".amazonaws.com/mscqr-backend@sha256:" + "b".repeat(64);
const frontendImage = NORMAL_RELEASE.account + ".dkr.ecr." + NORMAL_RELEASE.region + ".amazonaws.com/mscqr-web@sha256:" + "c".repeat(64);
const imageRepository = (name) => ({ repositoryName: name, registryId: NORMAL_RELEASE.account, repositoryUri: NORMAL_RELEASE.account + ".dkr.ecr." + NORMAL_RELEASE.region + ".amazonaws.com/" + name, imageTagMutability: "IMMUTABLE", imageTagMutabilityExclusionFilters: [] });
const imageLabels = (title) => ({ "org.opencontainers.image.revision": sourceSha, "org.opencontainers.image.title": title });

test("release classification is deterministic and sensitive lanes fail closed", () => {
  assert.equal(classifyProductionChanges([]).releaseClass, PRODUCTION_RELEASE_CLASS.NORMAL_APPLICATION);
  assert.deepEqual(classifyProductionChanges(["backend/src/services/batchService.ts"]), {
    releaseClass: PRODUCTION_RELEASE_CLASS.NORMAL_APPLICATION, files: ["backend/src/services/batchService.ts"],
    backend: true, frontend: false, worker: false, database: false,
  });
  assert.equal(classifyProductionChanges(["src/App.tsx"]).frontend, true);
  assert.equal(classifyProductionChanges(["backend/src/auth/loginService.ts"]).releaseClass, PRODUCTION_RELEASE_CLASS.SECURITY_INFRASTRUCTURE);
  assert.equal(classifyProductionChanges(["src/features/auth/login.tsx"]).releaseClass, PRODUCTION_RELEASE_CLASS.SECURITY_INFRASTRUCTURE);
  assert.equal(classifyProductionChanges(["backend/prisma/schema.prisma"]).releaseClass, PRODUCTION_RELEASE_CLASS.SECURITY_INFRASTRUCTURE);
  assert.equal(classifyProductionChanges(["infra/aws/terraform/production-web-release/main.tf"]).releaseClass, PRODUCTION_RELEASE_CLASS.SECURITY_INFRASTRUCTURE);
  assert.equal(classifyProductionChanges(["scripts/aws/recover-production-backend-health.mjs"]).releaseClass, PRODUCTION_RELEASE_CLASS.EMERGENCY_RECOVERY);
  assert.equal(classifyProductionChanges(["backend/src/workers/consume.ts"]).releaseClass, PRODUCTION_RELEASE_CLASS.SECURITY_INFRASTRUCTURE);
  assert.throws(() => classifyProductionChanges(["unknown/build-input"]), /Ambiguous/);
});

test("normal plans require only immutable affected images", () => {
  const backendPlan = buildNormalReleasePlan({ sourceSha, changedFiles: ["backend/src/services/batchService.ts"], images: { backend: backendImage } });
  assert.equal(backendPlan.classification.backend, true);
  const frontendPlan = buildNormalReleasePlan({ sourceSha, changedFiles: ["src/App.tsx"], images: { frontend: frontendImage } });
  assert.equal(frontendPlan.classification.frontend, true);
  const bothPlan = buildNormalReleasePlan({ sourceSha, changedFiles: ["backend/src/services/batchService.ts", "src/App.tsx"], images: { backend: backendImage, frontend: frontendImage } });
  assert.equal(bothPlan.classification.backend && bothPlan.classification.frontend, true);
  assert.doesNotThrow(() => buildNormalReleasePlan({ sourceSha, changedFiles: ["README.md"] }));
  assert.throws(() => buildNormalReleasePlan({ sourceSha, changedFiles: ["src/App.tsx"], images: { frontend: "latest" } }), /immutable/);
  assert.throws(() => buildNormalReleasePlan({ sourceSha, changedFiles: ["backend/src/workers/consume.ts"], images: { backend: backendImage } }), /Sensitive/);
  assert.throws(() => buildNormalReleasePlan({ sourceSha: "z".repeat(40), changedFiles: [] }), /40/);
});

test("normal image publication binds the exact source, repository, digest, and platform", () => {
  const digest = "sha256:" + "c".repeat(64);
  const image = { repositoryName: "mscqr-web", registryId: NORMAL_RELEASE.account, imageTags: [sourceSha], imageDigest: digest };
  assert.equal(assertNormalImageIdentity({ service: "frontend", sourceSha, repository: imageRepository("mscqr-web"), image, labels: imageLabels("mscqr-frontend"), platforms: ["linux/amd64"] }), imageRepository("mscqr-web").repositoryUri + "@" + digest);
  assert.throws(() => assertNormalImageIdentity({ service: "frontend", sourceSha, repository: imageRepository("mscqr-web"), image: { ...image, imageTags: ["latest"] }, labels: imageLabels("mscqr-frontend"), platforms: ["linux/amd64"] }));
  assert.throws(() => assertNormalImageIdentity({ service: "frontend", sourceSha, repository: imageRepository("other"), image, labels: imageLabels("mscqr-frontend"), platforms: ["linux/amd64"] }));
  assert.throws(() => assertNormalImageIdentity({ service: "frontend", sourceSha, repository: imageRepository("mscqr-web"), image, labels: imageLabels("mscqr-frontend"), platforms: ["linux/arm64"] }));
  assert.throws(() => assertNormalImageIdentity({ service: "frontend", sourceSha, repository: imageRepository("mscqr-web"), image, labels: { ...imageLabels("mscqr-frontend"), "org.opencontainers.image.revision": "b".repeat(40) }, platforms: ["linux/amd64"] }));
});

const taskArn = "arn:aws:ecs:" + WEB_RELEASE.region + ":" + WEB_RELEASE.account + ":task-definition/mscqr-frontend:20";
const task = {
  taskDefinitionArn: taskArn, family: "mscqr-frontend", revision: 20, status: "ACTIVE", networkMode: "awsvpc",
  requiresCompatibilities: ["FARGATE"], cpu: "256", memory: "512",
  executionRoleArn: "arn:aws:iam::" + WEB_RELEASE.account + ":role/mscqr-ecs-execution-role",
  taskRoleArn: "arn:aws:iam::" + WEB_RELEASE.account + ":role/mscqr-ecs-task-role",
  tags: [{ key: "Environment", value: "production" }],
  containerDefinitions: [{ name: "frontend", image: frontendImage, essential: true, cpu: 0, readonlyRootFilesystem: true, privileged: false, interactive: false, pseudoTerminal: false }],
};
const service = {
  serviceArn: "arn:aws:ecs:" + WEB_RELEASE.region + ":" + WEB_RELEASE.account + ":service/" + WEB_RELEASE.cluster + "/" + WEB_RELEASE.serviceName,
  clusterArn: "arn:aws:ecs:" + WEB_RELEASE.region + ":" + WEB_RELEASE.account + ":cluster/" + WEB_RELEASE.cluster,
  serviceName: WEB_RELEASE.serviceName, status: "ACTIVE", desiredCount: 2, runningCount: 2, pendingCount: 0,
  taskDefinition: taskArn, deployments: [{ id: "ecs-svc/opaque", status: "PRIMARY", taskDefinition: taskArn, rolloutState: "COMPLETED" }],
};

test("normal frontend activation uses the exact active predecessor and rolls it back on health failure", async () => {
  let active = taskArn;
  const candidateArn = taskArn.replace(":20", ":21");
  const predecessor = captureFrontendPredecessor(service, task);
  const candidate = buildNormalFrontendCandidate({ predecessor, imageRef: frontendImage });
  const updates = [];
  const readService = async () => ({ ...service, taskDefinition: active, deployments: [{ ...service.deployments[0], id: active === taskArn ? "ecs-svc/opaque" : "ecs-svc/candidate", taskDefinition: active }] });
  const describe = async (arn) => arn === taskArn ? task : { ...candidate, taskDefinitionArn: candidateArn, revision: 21, status: "ACTIVE" };
  const adapters = {
    readService, describeTaskDefinition: describe,
    registerTaskDefinition: async (value) => { assert.deepEqual(value, candidate); return { taskDefinitionArn: candidateArn }; },
    updateService: async ({ taskDefinition }) => { updates.push(taskDefinition); active = taskDefinition; },
    waitStable: async ({ expectedTaskDefinitionArn }) => assert.equal(active, expectedTaskDefinitionArn),
    verifyHealth: async () => ({ ready: false, loginStatus: 500 }),
  };
  await assert.rejects(() => executeNormalFrontendActivation({ sourceSha, imageRef: frontendImage, adapters }), /health/);
  assert.deepEqual(updates, [candidateArn, taskArn]);
  assert.equal(active, taskArn);
});

test("normal release orchestrator covers no-op and failure rollback without caller-selected targets", async () => {
  const calls = [];
  const plan = buildNormalReleasePlan({ sourceSha, changedFiles: ["backend/src/services/batchService.ts", "src/App.tsx"], images: { backend: backendImage, frontend: frontendImage } });
  const backend = { deploy: async (image) => { calls.push(["backend-deploy", image]); return { predecessor: "backend:20", candidate: "backend:21" }; }, rollback: async (result) => calls.push(["backend-rollback", result]) };
  const frontend = { deploy: async (image) => { calls.push(["frontend-deploy", image]); return { predecessor: "frontend:20", candidate: "frontend:21" }; }, rollback: async (result) => calls.push(["frontend-rollback", result]) };
  await assert.rejects(() => executeNormalRelease({ plan, sourceSha, backend, frontend, smoke: async () => { throw new Error("smoke failed"); } }), /smoke failed/);
  assert.deepEqual(calls.map(([name]) => name), ["backend-deploy", "frontend-deploy", "frontend-rollback", "backend-rollback"]);
  const noOp = buildNormalReleasePlan({ sourceSha, changedFiles: ["README.md"] });
  assert.deepEqual(await executeNormalRelease({ plan: noOp, sourceSha, backend, frontend }), { sourceSha, database: "UNCHANGED", backend: "UNCHANGED", frontend: "UNCHANGED" });
  await assert.rejects(() => executeNormalRelease({ plan: { ...noOp, sourceSha: "b".repeat(40) }, sourceSha, backend, frontend }), /source identity/);
});

test("normal production workflow is fixed, OIDC-only, gated by main, and smoke-tested", () => {
  const workflow = fs.readFileSync(".github/workflows/production-deploy.yml", "utf8");
  assert.match(workflow, /name: Normal Production Deployment/);
  assert.match(workflow, /branches: \[main\]/);
  assert.match(workflow, /configure-aws-credentials@v6/);
  assert.match(workflow, /MSCQR_AWS_CREDENTIAL_SOURCE: github-oidc-release-deployer/);
  assert.match(workflow, /SMOKE_AUTHENTICATED_REQUIRED: "true"/);
  assert.match(workflow, /production-normal-release\.mjs/);
  assert.doesNotMatch(workflow, /run: npm run smoke:release/);
  assert.doesNotMatch(workflow, /AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|terraform apply|PutSecretValue|KMS_SIGN/);
  assert.doesNotMatch(workflow, /role-to-assume:\s*\$\{\{/);
});
