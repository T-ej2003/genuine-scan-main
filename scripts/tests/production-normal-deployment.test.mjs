import assert from "node:assert/strict";
import crypto from "node:crypto";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import test from "node:test";
import { PRODUCTION_RELEASE_CLASS, classifyProductionChanges, classifyProductionComponentRanges } from "../aws/production-deployment-classification.mjs";
import { classifyLaneAComponentRanges } from "../aws/classify-production-lane-a.mjs";
import { buildNormalReleasePlan, buildNormalBackendPreparation, assertNormalBackendExactCandidate, classifyNormalLiveComponentState, executeNormalFrontendActivation, executeNormalRelease, executeNormalComponentTransaction, NORMAL_RELEASE, parseNormalReleaseArgs } from "../aws/production-normal-release.mjs";
import { APP_ONLY } from "../aws/production-app-only-contract.mjs";
import { assertNormalImageIdentity } from "../aws/production-normal-image-contract.mjs";
import { WEB_RELEASE, buildNormalFrontendCandidate, captureFrontendPredecessor } from "../aws/production-web-release-contract.mjs";
import { createProductionComponentDeploymentState } from "../aws/production-component-deployment-state.mjs";
import { assertRevalidatedProductionNormalDeploymentPlan, buildProductionNormalDeploymentPlan } from "../aws/prepare-production-normal-deployment.mjs";
import { classifyStageBImageReusePath } from "../aws/validate-stage-b-image-reuse.mjs";

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
  assert.equal(classifyProductionChanges([".dockerignore"]).backend, true);
  assert.equal(classifyProductionChanges([".dockerignore"]).frontend, true);
  assert.equal(classifyProductionChanges(["shared/ui/button.tsx"]).backend, true);
  assert.equal(classifyProductionChanges(["shared/ui/button.tsx"]).frontend, true);
  for (const file of ["package.json", "package-lock.json", "Dockerfile.ecs-frontend", "tailwind.config.ts", "postcss.config.js", "vite.config.ts", "docker/nginx-entrypoint.sh"])
    assert.equal(classifyProductionChanges([file]).frontend, true, file);
  for (const file of ["src/lib/api/internal-client-core.ts", "src/lib/api/internal-client-auth.ts", "src/components/auth/StepUpRecoveryDialog.tsx", "src/features/account-settings/AdminMfaCard.tsx", "src/features/auth/login.tsx"])
    assert.equal(classifyProductionChanges([file]).releaseClass, PRODUCTION_RELEASE_CLASS.NORMAL_APPLICATION, file);
  for (const file of ["backend/src/app.ts", "backend/src/index.ts", "backend/src/auth/loginService.ts", "backend/src/routes/index.ts", "backend/src/routes/modules/authRoutes.ts", "backend/src/controllers/authController.ts", "backend/src/controllers/authControllerShared.ts", "backend/src/controllers/authSessionController.ts", "backend/src/controllers/authAdminSecurityController.ts", "backend/src/services/auth/tokenService.ts", "backend/src/services/sessionService.ts", "backend/src/middleware/auth.ts", "backend/src/middleware/incidentUpload.ts", "backend/src/middleware/rbac.ts", "backend/src/services/accessControlService.ts", "backend/src/middleware/csrf.ts", "backend/src/middleware/tenantIsolation.ts", "backend/src/utils/clientIp.ts", "backend/src/rls-waves/session-c/policy.sql", "backend/src/workers/consume.ts", "src/lib/webauthn.ts", "scripts/aws/production-normal-release.mjs", ".github/workflows/production-deploy.yml"])
    assert.equal(classifyProductionChanges([file]).releaseClass, PRODUCTION_RELEASE_CLASS.SECURITY_INFRASTRUCTURE, file);
  assert.equal(classifyProductionChanges(["backend/prisma/schema.prisma"]).releaseClass, PRODUCTION_RELEASE_CLASS.SECURITY_INFRASTRUCTURE);
  assert.equal(classifyProductionChanges(["infra/aws/terraform/production-web-release/main.tf"]).releaseClass, PRODUCTION_RELEASE_CLASS.SECURITY_INFRASTRUCTURE);
  assert.equal(classifyProductionChanges(["scripts/aws/recover-production-backend-health.mjs"]).releaseClass, PRODUCTION_RELEASE_CLASS.EMERGENCY_RECOVERY);
  assert.throws(() => classifyProductionChanges(["unknown/build-input"]), /Ambiguous/);
});

test("shared root-context image inputs include every required service owner", () => {
  const files = execFileSync("git", ["ls-files", "-z"], { encoding: "utf8" }).split("\0").filter(Boolean);
  const missingRequiredOwners = [];
  for (const file of files) {
    const impact = classifyStageBImageReusePath(file);
    if (!impact.imageAffecting) continue;
    try {
      const classification = classifyProductionChanges([file]);
      const required = file === ".dockerignore" || /^shared\/(?:ui|formatting|validation)\//.test(file) ? ["backend", "frontend"] : [];
      for (const owner of required) if (!classification[owner]) missingRequiredOwners.push(`${file}:${owner}`);
    } catch (error) {
      if (!/Image-affecting production input has no service owner|Ambiguous production change paths/.test(error.message)) throw error;
    }
  }
  assert.deepEqual(missingRequiredOwners, []);
});

test("component deployment state, never workflow history, supplies component-specific undeployed ranges", () => {
  const a = "a".repeat(40), b = "b".repeat(40), c = "c".repeat(40), d = "d".repeat(40);
  const component = (name, source) => ({ sourceSha: source, establishedThroughSha: source, imageDigest: `sha256:${(name === "backend" ? "1" : "2").repeat(64)}`, taskDefinitionArn: `arn:aws:ecs:eu-west-2:368992683803:task-definition/${name}:1`, desiredCount: 2 });
  const state = createProductionComponentDeploymentState({ components: { backend: component("backend", b), frontend: component("frontend", a), database: { sourceSha: a, releaseIdentity: "db-release" }, security: { sourceSha: a, releaseIdentity: "security-release" } } });
  const ranges = new Map([[`${b}..${d}`, ["backend/src/services/batchService.ts"]], [`${a}..${d}`, ["src/App.tsx"]]]);
  const plan = buildProductionNormalDeploymentPlan({ sourceSha: d, state, isAncestor: (left, right) => [a, b, c, d].indexOf(left) <= [a, b, c, d].indexOf(right), readRange: (left, right) => ranges.get(`${left}..${right}`) || [] });
  assert.equal(plan.classification.backend, true); assert.equal(plan.classification.frontend, true); assert.equal(plan.componentBaselines.backend, b); assert.equal(plan.componentBaselines.frontend, a);
  assert.throws(() => buildProductionNormalDeploymentPlan({ sourceSha: d, state: { ...state, components: { ...state.components, backend: null } }, isAncestor: () => true, readRange: () => [] }), /bootstrapped/);
  assert.throws(() => buildProductionNormalDeploymentPlan({ sourceSha: d, state, isAncestor: () => false, readRange: () => [] }), /ancestor/);
  assert.equal(typeof classifyProductionComponentRanges, "function");
});

test("revalidation tolerates only unrelated component-state advancement", () => {
  const initial = { kind: "NORMAL_COMPONENT_DEPLOYMENT_PREPARATION", sourceSha, componentBaselines: { backend: "b".repeat(40), frontend: "c".repeat(40) }, classification: { backend: true, frontend: false } };
  const unrelated = { ...initial, stateGeneration: 2, componentBaselines: { ...initial.componentBaselines }, stateSha256: "d".repeat(64) };
  assert.equal(assertRevalidatedProductionNormalDeploymentPlan(initial, unrelated), unrelated);
  assert.throws(() => assertRevalidatedProductionNormalDeploymentPlan(initial, { ...unrelated, componentBaselines: { ...unrelated.componentBaselines, backend: "e".repeat(40) } }), /backend predecessor/);
  assert.throws(() => assertRevalidatedProductionNormalDeploymentPlan(initial, { ...unrelated, classification: { backend: false, frontend: true } }), /classification/);
});

test("recorded security work does not deadlock an unrelated frontend release, but unrecorded security does", () => {
  const a = "a".repeat(40), b = "b".repeat(40), c = "c".repeat(40);
  const state = createProductionComponentDeploymentState({ components: {
    backend: { sourceSha: a, establishedThroughSha: a, imageDigest: `sha256:${"1".repeat(64)}`, taskDefinitionArn: `arn:aws:ecs:eu-west-2:368992683803:task-definition/${APP_ONLY.family}:1`, desiredCount: 2 },
    frontend: { sourceSha: a, establishedThroughSha: a, imageDigest: `sha256:${"2".repeat(64)}`, taskDefinitionArn: taskArn, desiredCount: 2 },
    database: null, security: { sourceSha: b, releaseIdentity: "security" },
  } });
  const ranges = new Map([[`${a}..${b}`, ["backend/src/middleware/rbac.ts"]], [`${a}..${c}`, ["backend/src/middleware/rbac.ts", "src/App.tsx"]], [`${b}..${c}`, ["src/App.tsx"]]]);
  const plan = buildProductionNormalDeploymentPlan({ sourceSha: c, state, isAncestor: (left, right) => [a, b, c].indexOf(left) <= [a, b, c].indexOf(right), readRange: (left, right) => ranges.get(`${left}..${right}`) || [] });
  assert.equal(plan.classification.frontend, true); assert.equal(plan.classification.backend, false);
  assert.throws(() => buildProductionNormalDeploymentPlan({ sourceSha: c, state: { ...state, components: { ...state.components, security: null } }, isAncestor: () => true, readRange: (left, right) => ranges.get(`${left}..${right}`) || [] }), /Sensitive|stronger-lane/);
});

test("completed recovery uses its reconciliation source while preserving the historical live image source", () => {
  const h = "0".repeat(40), a = "a".repeat(40), r = "b".repeat(40), c = "c".repeat(40);
  const backend = { sourceSha: h, establishedThroughSha: r, imageDigest: `sha256:${"1".repeat(64)}`, taskDefinitionArn: `arn:aws:ecs:eu-west-2:368992683803:task-definition/${APP_ONLY.family}:1`, desiredCount: 2 };
  const frontend = { sourceSha: a, establishedThroughSha: a, imageDigest: `sha256:${"2".repeat(64)}`, taskDefinitionArn: taskArn, desiredCount: 2 };
  const state = createProductionComponentDeploymentState({ components: { backend, frontend, database: null, security: null } });
  const calls = [], ranges = new Map([[`${r}..${c}`, ["backend/src/services/batchService.ts"]], [`${a}..${c}`, ["src/App.tsx"]]]);
  const options = { sourceSha: c, state, isAncestor: (left, right) => [h, a, r, c].indexOf(left) <= [h, a, r, c].indexOf(right), readRange: (left, right) => { calls.push(`${left}..${right}`); return ranges.get(`${left}..${right}`) || []; } };
  const plan = buildProductionNormalDeploymentPlan(options);
  assert.equal(plan.classification.backend, true); assert.equal(plan.classification.frontend, true); assert.equal(plan.componentBaselines.backend, r); assert.ok(calls.includes(`${r}..${c}`)); assert.equal(calls.includes(`${h}..${c}`), false);
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
  const candidate = structuredClone(live.definition); candidate.taskDefinitionArn = priorArn.replace(":14", ":15"); candidate.revision = 15; candidate.containerDefinitions[0].image = `${APP_ONLY.backendRepository}@sha256:${"c".repeat(64)}`;
  assert.doesNotThrow(() => assertNormalBackendExactCandidate(live.definition, candidate, `sha256:${"c".repeat(64)}`));
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

test("normal frontend rollback failure remains journal-visible and fail-closed", async () => {
  let active = taskArn;
  const candidateArn = taskArn.replace(":20", ":21");
  const predecessor = captureFrontendPredecessor(service, task);
  const candidate = buildNormalFrontendCandidate({ predecessor, imageRef: frontendImage });
  const adapters = {
    readService: async () => ({ ...service, taskDefinition: active, deployments: [{ ...service.deployments[0], taskDefinition: active }] }),
    describeTaskDefinition: async (arn) => arn === taskArn ? task : { ...candidate, taskDefinitionArn: candidateArn, revision: 21, status: "ACTIVE" },
    registerTaskDefinition: async () => ({ taskDefinitionArn: candidateArn }),
    updateService: async ({ taskDefinition }) => { if (taskDefinition === taskArn) throw new Error("rollback update denied"); active = taskDefinition; },
    waitStable: async ({ expectedTaskDefinitionArn }) => assert.equal(active, expectedTaskDefinitionArn),
    verifyHealth: async () => ({ ready: false, loginStatus: 500 }),
  };
  await assert.rejects(() => executeNormalFrontendActivation({ sourceSha, imageRef: frontendImage, adapters }), (error) => {
    assert.match(error.message, /rollback failed/); assert.deepEqual(error.frontendRollback, { attempted: true, verified: false, error: "rollback update denied" }); return true;
  });
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

test("combined release attempts backend rollback even when frontend rollback fails", async () => {
  const events = [];
  const plan = buildNormalReleasePlan({ sourceSha, changedFiles: ["backend/src/services/batchService.ts", "src/App.tsx"], images: { backend: backendImage, frontend: frontendImage } });
  const backend = { deploy: async () => ({ candidate: "backend:21" }), rollback: async () => events.push("backend-rollback") };
  const frontend = { deploy: async () => ({ candidate: "frontend:21" }), rollback: async () => { events.push("frontend-rollback"); throw new Error("frontend rollback denied"); } };
  await assert.rejects(() => executeNormalRelease({ plan, sourceSha, backend, frontend, smoke: async () => { throw new Error("smoke failed"); } }), (error) => {
    assert.match(error.message, /rollback failed after: smoke failed/); assert.deepEqual(error.rollbackErrors, [{ component: "FRONTEND", error: "frontend rollback denied" }]); return true;
  });
  assert.deepEqual(events, ["frontend-rollback", "backend-rollback"]);
});

test("journal failure never prevents rollback of an already-mutated service", async () => {
  const events = [];
  const plan = buildNormalReleasePlan({ sourceSha, changedFiles: ["backend/src/services/batchService.ts", "src/App.tsx"], images: { backend: backendImage, frontend: frontendImage } });
  const backend = { deploy: async () => ({ candidate: "backend:21" }), rollback: async () => events.push("backend-rollback") };
  const frontend = { deploy: async () => { throw new Error("frontend failed"); }, rollback: async () => events.push("frontend-rollback") };
  await assert.rejects(() => executeNormalRelease({ plan, sourceSha, backend, frontend, writeJournal: async ({ status }) => { if (status === "FAILURE") throw new Error("journal unavailable"); } }), /rollback failed after: frontend failed/);
  assert.deepEqual(events, ["backend-rollback"]);
});

test("combined component transaction rolls every mutated service back before state commit and commits both only after smoke", async () => {
  const candidate = "d".repeat(40), prior = "b".repeat(40);
  const state = createProductionComponentDeploymentState({ components: {
    backend: { sourceSha: prior, establishedThroughSha: prior, imageDigest: `sha256:${"1".repeat(64)}`, taskDefinitionArn: `arn:aws:ecs:eu-west-2:368992683803:task-definition/${APP_ONLY.family}:14`, desiredCount: 2 },
    frontend: { sourceSha: prior, establishedThroughSha: prior, imageDigest: `sha256:${"2".repeat(64)}`, taskDefinitionArn: taskArn, desiredCount: 2 },
    database: { sourceSha: prior, releaseIdentity: "db" }, security: { sourceSha: prior, releaseIdentity: "security" },
  } });
  const plan = buildNormalReleasePlan({ sourceSha: candidate, componentFiles: { backendFiles: ["backend/src/services/batchService.ts"], frontendFiles: ["src/App.tsx"], securityFiles: [], databaseFiles: [] }, images: { backend: backendImage, frontend: frontendImage } });
  const events = [], backend = { deploy: async (_, { recordCandidate }) => {
    const candidateTaskDefinition = `arn:aws:ecs:eu-west-2:368992683803:task-definition/${APP_ONLY.family}:15`;
    await recordCandidate(candidateTaskDefinition);
    return { result: { candidateTaskDefinition, candidateDeploymentId: "ecs-svc/15", deployedBackendDigest: backendImage.split("@")[1] }, rollback: async () => events.push("backend-rollback") };
  }, rollback: async (value) => value.rollback() };
  const frontendFailure = { deploy: async () => { throw new Error("frontend failed"); }, rollback: async () => events.push("frontend-rollback") };
  let committed = false;
  let stored = structuredClone(state);
  const stateClient = { read: () => structuredClone(stored), advance: (_, next) => { stored = structuredClone(next); committed = next.components.backend.sourceSha === candidate; } };
  const context = { stateClient, verifyCandidates: async () => {}, writerContext: { updatedByWorkflow: "T-ej2003/genuine-scan-main/.github/workflows/production-deploy.yml@refs/heads/main", githubRunId: "123" } };
  await assert.rejects(() => executeNormalComponentTransaction({ plan, sourceSha: candidate, state, ...context, backend, frontend: frontendFailure, smoke: async () => true, isAncestor: () => true }), /frontend failed/);
  assert.deepEqual(events, ["backend-rollback"]); assert.equal(committed, false);
  stored = structuredClone(state);
  const frontend = { deploy: async (_, { recordCandidate }) => { const candidateTaskDefinitionArn = taskArn.replace(":20", ":21"); await recordCandidate(candidateTaskDefinitionArn); return { result: { candidateTaskDefinitionArn, imageRef: frontendImage }, rollback: async () => events.push("frontend-rollback") }; }, rollback: async (value) => value.rollback() };
  const complete = await executeNormalComponentTransaction({ plan, sourceSha: candidate, state, ...context, backend, frontend, smoke: async () => true, isAncestor: () => true });
  assert.equal(committed, true); assert.equal(complete.componentState.components.backend.sourceSha, candidate); assert.equal(complete.componentState.components.backend.establishedThroughSha, candidate); assert.equal(complete.componentState.components.frontend.sourceSha, candidate); assert.equal(complete.componentState.components.frontend.establishedThroughSha, candidate);
});

test("live source equality without a durable receipt never authorizes reconciliation", () => {
  const predecessor = { sourceSha: "a".repeat(40), imageDigest: `sha256:${"1".repeat(64)}`, taskDefinitionArn: "task:1", desiredCount: 2 };
  const candidate = { sourceSha: "b".repeat(40), imageDigest: `sha256:${"2".repeat(64)}` };
  assert.equal(classifyNormalLiveComponentState({ live: predecessor, predecessor, candidate }), "LIVE_IS_PREDECESSOR");
  assert.equal(classifyNormalLiveComponentState({ live: { ...candidate, taskDefinitionArn: "task:2", desiredCount: 2 }, predecessor, candidate }), "LIVE_IS_UNKNOWN");
  assert.equal(classifyNormalLiveComponentState({ live: { ...candidate, taskDefinitionArn: "task:1" }, predecessor, candidate }), "LIVE_IS_UNKNOWN");
  assert.equal(classifyNormalLiveComponentState({ live: { ...candidate, sourceSha: "c".repeat(40), taskDefinitionArn: "task:3" }, predecessor, candidate }), "LIVE_IS_UNKNOWN");
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

test("Lane A accepts application changes and rejects infrastructure, RLS, schema, and worker changes", () => {
  assert.deepEqual(classifyLaneAComponentRanges({ backendFiles: ["backend/src/services/batchService.ts"], frontendFiles: ["src/App.tsx"] }), { releaseClass: "NORMAL_APPLICATION", backend: true, frontend: true, worker: false });
  for (const file of ["infra/aws/main.tf", "backend/prisma/schema.prisma", "backend/src/migrations/backfill.ts", "backend/src/security/tenant.ts", "backend/src/workers/jobs.ts", "scripts/rls/generated.sql"])
    assert.throws(() => classifyLaneAComponentRanges({ backendFiles: [file], frontendFiles: [] }), /Lane B|stronger lane|Ambiguous/i);
});

test("normal production workflow is fixed, OIDC-only, gated by main, and smoke-tested", () => {
  const workflow = fs.readFileSync(".github/workflows/production-deploy.yml", "utf8");
  assert.match(workflow, /name: Normal Production Deployment/);
  assert.match(workflow, /branches: \[main\]/);
  assert.match(workflow, /configure-aws-credentials@v6/);
  assert.match(workflow, /MSCQR_AWS_CREDENTIAL_SOURCE: github-oidc-release-deployer/);
  assert.match(workflow, /SMOKE_AUTHENTICATED_REQUIRED: "true"/);
  assert.match(workflow, /classify-production-lane-a\.mjs/);
  assert.match(workflow, /publish-ecs-images\.sh/);
  assert.match(workflow, /deploy-ecs-service\.sh/);
  assert.match(workflow, /rollback-ecs-service\.sh/);
  assert.match(workflow, /docker save "\$image" -o "\$RUNNER_TEMP\/\$\{component\}\.tar"/);
  assert.match(workflow, /trivy:0\.69\.3 image --input "\/workspace\/\$\{component\}\.tar"/);
  assert.doesNotMatch(workflow, /\/var\/run\/docker\.sock/);
  assert.doesNotMatch(workflow, /production-normal-release|prepare-production-normal-deployment|normal-component-deployment-plan|DynamoDB/i);
  assert.match(workflow, /mscqr-production-normal-deployer/);
  assert.match(workflow, /environment: production-normal-deploy/);
  const normalEnvironmentUsers = fs.readdirSync(".github/workflows").filter((file) => file.endsWith(".yml") && fs.readFileSync(`.github/workflows/${file}`, "utf8").match(/environment:\s*production-normal-deploy/));
  assert.deepEqual(normalEnvironmentUsers, ["production-deploy.yml"]);
  assert.equal((workflow.match(/environment: production-normal-deploy/g) || []).length, 1);
  assert.match(workflow, /Roll back exact predecessors after failure[\s\S]*if: failure\(\)/);
  assert.match(workflow, /rollback_failed=0[\s\S]*if ! CLUSTER_NAME=[\s\S]*rollback_failed=1[\s\S]*exit "\$rollback_failed"/);
  assert.match(fs.readFileSync("scripts/aws/publish-ecs-images.sh", "utf8"), /await import\(process\.env\.NORMAL_IMAGE_CONTRACT\)/);
  assert.match(workflow, /node scripts\/smoke-release\.mjs/);
  assert.doesNotMatch(workflow, /AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|terraform apply|PutSecretValue|KMS_SIGN/);
  assert.doesNotMatch(workflow, /role-to-assume:\s*\$\{\{/);
});
