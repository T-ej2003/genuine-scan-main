import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import test from "node:test";
import { PRODUCTION_RELEASE_CLASS, classifyProductionChanges } from "../aws/production-deployment-classification.mjs";
import { buildNormalReleasePlan, buildNormalBackendPreparation, executeNormalFrontendActivation, executeNormalRelease, NORMAL_RELEASE, parseNormalReleaseArgs } from "../aws/production-normal-release.mjs";
import { APP_ONLY } from "../aws/production-app-only-contract.mjs";
import { assertNormalImageIdentity } from "../aws/production-normal-image-contract.mjs";
import { WEB_RELEASE, buildNormalFrontendCandidate, captureFrontendPredecessor } from "../aws/production-web-release-contract.mjs";
import { resolveNormalDeploymentBaseline } from "../aws/production-deployment-baseline.mjs";

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
  for (const file of ["backend/src/middleware/rbac.ts", "backend/src/services/accessControlService.ts", "backend/src/middleware/csrf.ts", "backend/src/middleware/tenantIsolation.ts", "backend/src/utils/clientIp.ts", "scripts/aws/production-normal-release.mjs", ".github/workflows/production-deploy.yml"])
    assert.equal(classifyProductionChanges([file]).releaseClass, PRODUCTION_RELEASE_CLASS.SECURITY_INFRASTRUCTURE, file);
  assert.equal(classifyProductionChanges(["src/features/auth/login.tsx"]).releaseClass, PRODUCTION_RELEASE_CLASS.SECURITY_INFRASTRUCTURE);
  assert.equal(classifyProductionChanges(["backend/prisma/schema.prisma"]).releaseClass, PRODUCTION_RELEASE_CLASS.SECURITY_INFRASTRUCTURE);
  assert.equal(classifyProductionChanges(["infra/aws/terraform/production-web-release/main.tf"]).releaseClass, PRODUCTION_RELEASE_CLASS.SECURITY_INFRASTRUCTURE);
  assert.equal(classifyProductionChanges(["scripts/aws/recover-production-backend-health.mjs"]).releaseClass, PRODUCTION_RELEASE_CLASS.EMERGENCY_RECOVERY);
  assert.equal(classifyProductionChanges(["backend/src/workers/consume.ts"]).releaseClass, PRODUCTION_RELEASE_CLASS.SECURITY_INFRASTRUCTURE);
  assert.throws(() => classifyProductionChanges(["unknown/build-input"]), /Ambiguous/);
});

test("successful GitHub workflow history supplies the complete undeployed range baseline", () => {
  const a = "a".repeat(40), b = "b".repeat(40), c = "c".repeat(40);
  const ancestor = (left, right) => [[a, b], [a, c], [b, c]].some(([x, y]) => left === x && right === y);
  assert.deepEqual(resolveNormalDeploymentBaseline({ candidateSha: c, successfulSourceShas: [a], isAncestor: ancestor }), { candidateSha: c, baselineSha: a, bootstrap: false });
  assert.deepEqual(resolveNormalDeploymentBaseline({ candidateSha: c, successfulSourceShas: [b, a], isAncestor: ancestor }), { candidateSha: c, baselineSha: b, bootstrap: false });
  assert.deepEqual(resolveNormalDeploymentBaseline({ candidateSha: c, successfulSourceShas: [], isAncestor: ancestor }), { candidateSha: c, baselineSha: null, bootstrap: true });
  assert.deepEqual(resolveNormalDeploymentBaseline({ candidateSha: c, successfulSourceShas: ["d".repeat(40)], isAncestor: ancestor }), { candidateSha: c, baselineSha: null, bootstrap: true });
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

test("service selection admits each affected service in a combined release and rejects false selections", () => {
  const parse = (serviceName, files, images) => {
    const original = process.env.GITHUB_SHA; process.env.GITHUB_SHA = sourceSha;
    try {
      return parseNormalReleaseArgs([`--service=${serviceName}`, `--source-sha=${sourceSha}`, `--changed-files=${JSON.stringify(files)}`,
        ...Object.entries(images).map(([name, image]) => `--${name}-image=${image}`)]);
    } finally { if (original === undefined) delete process.env.GITHUB_SHA; else process.env.GITHUB_SHA = original; }
  };
  assert.equal(parse("backend", ["backend/src/services/batchService.ts"], { backend: backendImage }).classification.backend, true);
  assert.equal(parse("frontend", ["src/App.tsx"], { frontend: frontendImage }).classification.frontend, true);
  const files = ["backend/src/services/batchService.ts", "src/App.tsx"], images = { backend: backendImage, frontend: frontendImage };
  assert.equal(parse("backend", files, images).sourceSha, sourceSha);
  assert.equal(parse("frontend", files, images).sourceSha, sourceSha);
  assert.equal(parse("none", ["README.md"], {}).classification.backend, false);
  assert.throws(() => parse("backend", ["src/App.tsx"], { frontend: frontendImage }));
  assert.throws(() => parse("frontend", ["backend/src/services/batchService.ts"], { backend: backendImage }));
  assert.throws(() => parse("none", files, images));
});

test("backend preparation binds an independently authenticated predecessor source", () => {
  const digest = `sha256:${"1".repeat(64)}`, priorArn = `arn:aws:ecs:${APP_ONLY.region}:${APP_ONLY.account}:task-definition/${APP_ONLY.family}:14`;
  const definition = { taskDefinitionArn: priorArn, revision: 14, status: "ACTIVE", family: APP_ONLY.family, taskRoleArn: APP_ONLY.taskRoleArn,
    executionRoleArn: APP_ONLY.executionRoleArn, networkMode: "awsvpc", runtimePlatform: { cpuArchitecture: "X86_64", operatingSystemFamily: "LINUX" }, cpu: "1024", memory: "2048",
    containerDefinitions: [{ name: "backend", image: `${APP_ONLY.backendRepository}@${digest}`, environment: [], secrets: [], portMappings: [{ containerPort: 4000 }], logConfiguration: { logDriver: "awslogs" } }], tags: [{ key: "Environment", value: "production" }] };
  const live = { definition, service: { clusterArn: APP_ONLY.clusterArn, serviceArn: APP_ONLY.serviceArn, serviceName: APP_ONLY.service, status: "ACTIVE", taskDefinition: priorArn, desiredCount: 2, runningCount: 2, pendingCount: 0, deployments: [{ id: "ecs-svc/100", status: "PRIMARY", rolloutState: "COMPLETED", taskDefinition: priorArn }] }, tasks: ["a", "b"].map((taskArn) => ({ taskArn, clusterArn: APP_ONLY.clusterArn, group: `service:${APP_ONLY.service}`, taskDefinitionArn: priorArn, lastStatus: "RUNNING", healthStatus: "HEALTHY", startedBy: "ecs-svc/100", containers: [{ name: "backend", imageDigest: digest }] })) };
  const preparation = buildNormalBackendPreparation({ sourceSha, predecessorSourceSha: "b".repeat(40), live, candidateDigest: `sha256:${"c".repeat(64)}` });
  assert.equal(preparation.candidateSourceSha, sourceSha); assert.equal(preparation.predecessorSourceSha, "b".repeat(40));
  assert.throws(() => buildNormalBackendPreparation({ sourceSha, live, candidateDigest: `sha256:${"c".repeat(64)}` }));
  assert.throws(() => buildNormalBackendPreparation({ sourceSha, predecessorSourceSha: "unknown", live, candidateDigest: `sha256:${"c".repeat(64)}` }));
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

test("normal release plans cannot smuggle database or forged classification work into the normal lane", async () => {
  const dbFiles = ["backend/prisma/migrations/001_init/migration.sql"];
  assert.equal(classifyProductionChanges(dbFiles).releaseClass, PRODUCTION_RELEASE_CLASS.SECURITY_INFRASTRUCTURE);
  assert.throws(() => buildNormalReleasePlan({ sourceSha, changedFiles: dbFiles, images: { backend: backendImage } }), /Sensitive/);
  const normal = buildNormalReleasePlan({ sourceSha, changedFiles: ["backend/src/services/batchService.ts"], images: { backend: backendImage } });
  const forged = { ...normal, classification: { ...normal.classification, database: true } };
  forged.planSha256 = crypto.createHash("sha256").update(JSON.stringify({ sourceSha, classification: forged.classification, images: forged.images })).digest("hex");
  await assert.rejects(() => executeNormalRelease({ plan: forged, sourceSha, database: { applyAndVerify: async () => { throw new Error("must not run"); } }, backend: {}, frontend: {} }), /derived from its protected source paths/);
});

test("normal production workflow is fixed, OIDC-only, gated by main, and smoke-tested", () => {
  const workflow = fs.readFileSync(".github/workflows/production-deploy.yml", "utf8");
  assert.match(workflow, /name: Normal Production Deployment/);
  assert.match(workflow, /branches: \[main\]/);
  assert.match(workflow, /configure-aws-credentials@v6/);
  assert.match(workflow, /MSCQR_AWS_CREDENTIAL_SOURCE: github-oidc-release-deployer/);
  assert.match(workflow, /SMOKE_AUTHENTICATED_REQUIRED: "true"/);
  assert.match(workflow, /production-normal-release\.mjs/);
  assert.match(workflow, /listWorkflowRuns/);
  assert.match(workflow, /git merge-base --is-ancestor/);
  assert.match(workflow, /Preserve normal-release mutation journal[\s\S]*if: always\(\)/);
  assert.match(workflow, /publish-backend:[\s\S]*?environment: production-stage-b-image-publish/);
  assert.match(workflow, /publish-frontend:[\s\S]*?environment: production-web-image-publish/);
  const webTrust = JSON.parse(fs.readFileSync("infra/aws/terraform/production-web-release/publisher-trust-policy.json", "utf8"));
  assert.equal(webTrust.Statement[0].Condition.StringEquals["token.actions.githubusercontent.com:sub"], "repo:T-ej2003/genuine-scan-main:environment:production-web-image-publish");
  const webEnvironmentUsers = fs.readdirSync(".github/workflows").filter((file) => file.endsWith(".yml") && fs.readFileSync(`.github/workflows/${file}`, "utf8").match(/environment:\s*production-web-image-publish/));
  assert.deepEqual(webEnvironmentUsers.sort(), ["production-deploy.yml", "production-web-image.yml"]);
  assert.doesNotMatch(workflow, /run: npm run smoke:release/);
  assert.doesNotMatch(workflow, /AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|terraform apply|PutSecretValue|KMS_SIGN/);
  assert.doesNotMatch(workflow, /role-to-assume:\s*\$\{\{/);
});
