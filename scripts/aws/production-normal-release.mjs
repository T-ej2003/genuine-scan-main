#!/usr/bin/env node
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import crypto from "node:crypto";
import { fileURLToPath, pathToFileURL } from "node:url";
import path from "node:path";
import { classifyProductionChanges, assertNormalApplicationRelease } from "./production-deployment-classification.mjs";
import { APP_ONLY, captureAppOnlyPredecessor } from "./production-app-only-contract.mjs";
import { createAppOnlyEcsReaders, createAppOnlyActivationAdapters } from "./production-app-only-adapters.mjs";
import { executeAppOnlyActivation } from "./production-app-only-activation.mjs";
import { createAppOnlyEvidenceWriter } from "./production-app-only-artifacts.mjs";
import { buildNormalFrontendCandidate, captureFrontendPredecessor, assertFrontendCandidateReadback, assertFrontendPredecessorCas, buildFrontendUpdate, buildFrontendRollback, WEB_RELEASE } from "./production-web-release-contract.mjs";
import { assertGithubOidcReleaseDeployerEnvironment, createProductionAwsCommandRunner, PRODUCTION_AWS_CREDENTIAL_SOURCE } from "./production-credential-source-contract.mjs";
import { assertProductionBackendReadiness } from "./production-backend-readiness-contract.mjs";
import { CANONICAL_PRODUCTION_ORIGIN, CANONICAL_PRODUCTION_READINESS_URL } from "./production-backend-readiness-contract.mjs";

export const NORMAL_RELEASE = Object.freeze({
  account: "368992683803", region: "eu-west-2", cluster: "mscqr-prod-euw2-main",
  backendService: "mscqr-backend-servi-euw2", frontendService: "mscqr-frontend-servi-euw2",
  backendRole: "mscqr-production-app-only-deployer", frontendRole: "mscqr-production-release-deployer",
});
const SHA = /^[a-f0-9]{40}$/;
const IMAGE = /^368992683803\.dkr\.ecr\.eu-west-2\.amazonaws\.com\/(mscqr-backend|mscqr-web)@sha256:[a-f0-9]{64}$/;
const taskArn = (family) => new RegExp(`^arn:aws:ecs:${NORMAL_RELEASE.region}:${NORMAL_RELEASE.account}:task-definition/${family}:[1-9][0-9]*$`);
const sha256 = (value) => crypto.createHash("sha256").update(value).digest("hex");

function runNormalSmoke(repositoryRoot) {
  const result = spawnSync(process.execPath, [path.join(repositoryRoot, "scripts/smoke-release.mjs")], { stdio: "inherit", env: process.env });
  if (result.error) throw result.error;
  assert.equal(result.status, 0, "Authenticated application smoke failed.");
}

export function buildNormalReleasePlan({ sourceSha, changedFiles, images = {} } = {}) {
  assert.match(sourceSha || "", SHA);
  const classification = assertNormalApplicationRelease(classifyProductionChanges(changedFiles));
  for (const [name, required] of Object.entries({ backend: classification.backend, frontend: classification.frontend })) {
    if (required) assert.match(images[name] || "", IMAGE, `Missing immutable ${name} image`);
    if (!required && images[name] !== undefined) throw new Error(`Unneeded ${name} image was supplied.`);
  }
  if (classification.worker) throw new Error("Production has no worker service; worker-impacting changes require the reviewed infrastructure lane.");
  return Object.freeze({ schemaVersion: 1, kind: "NORMAL_APPLICATION_RELEASE", sourceSha, classification, images,
    imageReleaseSha: sourceSha, planSha256: sha256(JSON.stringify({ sourceSha, classification, images })) });
}

export function assertNormalReleasePlan(plan, sourceSha) {
  assert.equal(plan?.schemaVersion, 1); assert.equal(plan.kind, "NORMAL_APPLICATION_RELEASE"); assert.equal(plan.sourceSha, sourceSha, "Normal release plan source identity mismatch");
  assert.equal(plan.imageReleaseSha, sourceSha); assert.equal(plan.planSha256, sha256(JSON.stringify({ sourceSha, classification: plan.classification, images: plan.images })));
  assertNormalApplicationRelease(plan.classification);
  for (const name of ["backend", "frontend"]) if (plan.classification[name]) assert.match(plan.images?.[name] || "", IMAGE);
  return true;
}

export function buildNormalBackendPreparation({ sourceSha, live, candidateDigest } = {}) {
  assert.match(sourceSha || "", SHA); assert.match(candidateDigest || "", /^sha256:[a-f0-9]{64}$/);
  const predecessor = captureAppOnlyPredecessor(live);
  const body = { schemaVersion: 1, kind: "NORMAL_APPLICATION_BACKEND_PREPARATION", candidateSourceSha: sourceSha,
    predecessorSourceSha: sourceSha, candidateDigest, predecessor };
  return Object.freeze({ ...body, preparationSha256: sha256(JSON.stringify(body)) });
}

export async function executeNormalFrontendActivation({ sourceSha, imageRef, adapters } = {}) {
  assert.match(sourceSha || "", SHA); assert.match(imageRef || "", /^368992683803\.dkr\.ecr\.eu-west-2\.amazonaws\.com\/mscqr-web@sha256:[a-f0-9]{64}$/);
  for (const name of ["readService", "describeTaskDefinition", "registerTaskDefinition", "updateService", "waitStable", "verifyHealth"]) assert.equal(typeof adapters?.[name], "function", `Missing frontend adapter: ${name}`);
  const initialService = await adapters.readService();
  const initialDefinition = await adapters.describeTaskDefinition(initialService.taskDefinition);
  const predecessor = captureFrontendPredecessor(initialService, initialDefinition);
  const candidate = buildNormalFrontendCandidate({ predecessor, imageRef });
  const registered = await adapters.registerTaskDefinition(candidate);
  const candidateArn = registered?.taskDefinition?.taskDefinitionArn || registered?.taskDefinitionArn;
  assert.match(candidateArn || "", taskArn(WEB_RELEASE.family));
  const readback = await adapters.describeTaskDefinition(candidateArn);
  assertFrontendCandidateReadback({ definition: readback, taskDefinitionArn: candidateArn, candidate });
  const casService = await adapters.readService();
  const casDefinition = await adapters.describeTaskDefinition(casService.taskDefinition);
  assertFrontendPredecessorCas({ predecessor, currentService: casService, currentTaskDefinition: casDefinition });
  let updateAttempted = false;
  try {
    updateAttempted = true; await adapters.updateService(buildFrontendUpdate({ predecessor, candidateTaskDefinitionArn: candidateArn }));
    await adapters.waitStable({ expectedTaskDefinitionArn: candidateArn });
    const health = await adapters.verifyHealth({ expectedTaskDefinitionArn: candidateArn, expectedImageRef: imageRef });
    assert.equal(health?.ready, true, "Frontend health failed"); assert.equal(health?.loginStatus, 200, "Frontend login health failed");
    return Object.freeze({ sourceSha, predecessorTaskDefinitionArn: predecessor.taskDefinitionArn, candidateTaskDefinitionArn: candidateArn, imageRef, rollbackCount: 0, health });
  } catch (error) {
    if (updateAttempted) {
      const current = await adapters.readService();
      if (current.taskDefinition === candidateArn) {
        await adapters.updateService(buildFrontendRollback({ predecessor, failedCandidateTaskDefinitionArn: candidateArn }));
        await adapters.waitStable({ expectedTaskDefinitionArn: predecessor.taskDefinitionArn });
        const restored = await adapters.readService();
        assert.equal(restored.taskDefinition, predecessor.taskDefinitionArn); assert.equal(restored.desiredCount, predecessor.desiredCount);
      }
    }
    throw error;
  }
}

const json = (run, args) => JSON.parse(run([...args, "--output", "json", "--no-cli-pager"]));
export function createNormalFrontendAdapters({ run, fetchImpl = fetch, wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms)) } = {}) {
  const serviceArn = `arn:aws:ecs:${NORMAL_RELEASE.region}:${NORMAL_RELEASE.account}:service/${NORMAL_RELEASE.cluster}/${NORMAL_RELEASE.frontendService}`;
  const clusterArn = `arn:aws:ecs:${NORMAL_RELEASE.region}:${NORMAL_RELEASE.account}:cluster/${NORMAL_RELEASE.cluster}`;
  const readService = () => {
    const response = json(run, ["ecs", "describe-services", "--cluster", clusterArn, "--services", serviceArn]);
    assert.equal(response.failures?.length, 0); assert.equal(response.services?.length, 1);
    const service = response.services[0]; assert.equal(service.serviceArn, serviceArn); assert.equal(service.clusterArn, clusterArn); return service;
  };
  const describeTaskDefinition = (arn) => {
    assert.match(arn || "", taskArn(WEB_RELEASE.family));
    const response = json(run, ["ecs", "describe-task-definition", "--task-definition", arn, "--include", "TAGS"]);
    assert.equal(response.taskDefinition?.taskDefinitionArn, arn); return { ...response.taskDefinition, tags: response.tags || [] };
  };
  const registerTaskDefinition = (definition) => {
    assert.equal(definition.family, WEB_RELEASE.family);
    return json(run, ["ecs", "register-task-definition", "--cli-input-json", JSON.stringify(definition)]);
  };
  const updateService = ({ cluster, service, taskDefinition }) => {
    assert.equal(cluster, NORMAL_RELEASE.cluster); assert.equal(service, NORMAL_RELEASE.frontendService); assert.match(taskDefinition || "", taskArn(WEB_RELEASE.family));
    return json(run, ["ecs", "update-service", "--cluster", clusterArn, "--service", serviceArn, "--task-definition", taskDefinition]).service;
  };
  const waitStable = async ({ expectedTaskDefinitionArn }) => {
    assert.match(expectedTaskDefinitionArn || "", taskArn(WEB_RELEASE.family));
    run(["ecs", "wait", "services-stable", "--cluster", clusterArn, "--services", serviceArn]);
    const service = readService(); assert.equal(service.taskDefinition, expectedTaskDefinitionArn); assert.equal(service.desiredCount, service.runningCount); assert.equal(service.pendingCount, 0); return service;
  };
  const verifyHealth = async () => {
    const login = await fetchImpl(`${CANONICAL_PRODUCTION_ORIGIN}/login`, { redirect: "error" });
    const readyResponse = await fetchImpl(CANONICAL_PRODUCTION_READINESS_URL, { redirect: "error" });
    assert.equal(login.status, 200); const body = await readyResponse.json(); assertProductionBackendReadiness(body);
    return { ready: true, loginStatus: login.status };
  };
  return { readService, describeTaskDefinition, registerTaskDefinition, updateService, waitStable, verifyHealth };
}

function assertCaller(caller, role) {
  assert.equal(String(caller?.Account), NORMAL_RELEASE.account);
  assert.match(caller?.Arn || "", new RegExp(`^arn:aws:sts::${NORMAL_RELEASE.account}:assumed-role/${role}/[^/]+$`));
}

async function executeBackendCli({ sourceSha, imageRef, run, repositoryRoot }) {
  assert.match(imageRef || "", /^368992683803\.dkr\.ecr\.eu-west-2\.amazonaws\.com\/mscqr-backend@sha256:[a-f0-9]{64}$/);
  const readers = createAppOnlyEcsReaders(run), live = readers.readLive();
  const digest = imageRef.split("@")[1];
  const preparation = buildNormalBackendPreparation({ sourceSha, live, candidateDigest: digest });
  const authenticate = async () => { assertCaller(json(run, ["sts", "get-caller-identity"]), NORMAL_RELEASE.backendRole); };
  const journal = createAppOnlyEvidenceWriter({ repositoryRoot, sourceSha, preparationSha256: preparation.preparationSha256 });
  const adapters = createAppOnlyActivationAdapters({ run, preparation, authenticate, writeEvidence: journal.writeEvidence });
  return executeAppOnlyActivation(preparation, { ...adapters, readHealth: async () => { const health = await adapters.readHealth(); runNormalSmoke(repositoryRoot); return health; } });
}

async function executeFrontendCli({ sourceSha, imageRef, run, repositoryRoot }) {
  assert.match(imageRef || "", /^368992683803\.dkr\.ecr\.eu-west-2\.amazonaws\.com\/mscqr-web@sha256:[a-f0-9]{64}$/);
  assertCaller(json(run, ["sts", "get-caller-identity"]), NORMAL_RELEASE.frontendRole);
  const repo = json(run, ["ecr", "describe-repositories", "--repository-names", WEB_RELEASE.repository]).repositories?.[0];
  assert.equal(repo?.repositoryName, WEB_RELEASE.repository); assert.equal(String(repo.registryId), NORMAL_RELEASE.account); assert.equal(repo.imageTagMutability, "IMMUTABLE");
  const digest = imageRef.split("@")[1]; const image = json(run, ["ecr", "describe-images", "--repository-name", WEB_RELEASE.repository, "--image-ids", `imageDigest=${digest}`]).imageDetails;
  assert.equal(image?.length, 1); assert.equal(image[0].imageDigest, digest); assert.ok(image[0].imageTags?.includes(sourceSha));
  const adapters = createNormalFrontendAdapters({ run });
  return executeNormalFrontendActivation({ sourceSha, imageRef, adapters: { ...adapters, verifyHealth: async (value) => { const health = await adapters.verifyHealth(value); runNormalSmoke(repositoryRoot); return health; } } });
}

export async function executeNormalRelease({ plan, sourceSha, backend, frontend, database = {}, smoke = async () => true } = {}) {
  assert.match(sourceSha || "", SHA, "Normal release source identity is required");
  assertNormalReleasePlan(plan, sourceSha);
  if (plan.classification.database) await database.applyAndVerify();
  const result = { sourceSha: plan.sourceSha, database: plan.classification.database ? "APPLIED" : "UNCHANGED", backend: "UNCHANGED", frontend: "UNCHANGED" };
  try {
    if (plan.classification.backend) result.backend = await backend.deploy(plan.images.backend);
    if (plan.classification.frontend) result.frontend = await frontend.deploy(plan.images.frontend);
    await smoke({ sourceSha: plan.sourceSha, result });
  }
  catch (error) {
    if (plan.classification.frontend && result.frontend !== "UNCHANGED") await frontend.rollback(result.frontend);
    if (plan.classification.backend && result.backend !== "UNCHANGED") await backend.rollback(result.backend);
    throw error;
  }
  return Object.freeze(result);
}

// The CLI is intentionally fixed to the checked-out commit and workflow
// credential source. It accepts only image refs emitted by the preceding
// publisher jobs; resource names, roles, region, and account are constants.
export function parseNormalReleaseArgs(argv) {
  const values = Object.fromEntries(argv.map((value) => value.split("=", 2)).filter(([key, value]) => key && value).map(([key, value]) => [key.replace(/^--/, ""), value]));
  assert.deepEqual(Object.keys(values).sort(), ["backend-image", "changed-files", "frontend-image", "service", "source-sha"].filter((key) => values[key] !== undefined).sort());
  assert.match(values["source-sha"] || "", SHA); assert.equal(values["source-sha"], process.env.GITHUB_SHA); assert.ok(["backend", "frontend", "none"].includes(values.service));
  const files = JSON.parse(values["changed-files"]); assert.ok(Array.isArray(files));
  const plan = buildNormalReleasePlan({ sourceSha: values["source-sha"], changedFiles: files, images: Object.fromEntries(["backend", "frontend"].filter((name) => values[`${name}-image`] !== undefined).map((name) => [name, values[`${name}-image`]])) });
  assert.equal(values.service === "backend", plan.classification.backend); assert.equal(values.service === "frontend", plan.classification.frontend); assert.equal(values.service === "none", !plan.classification.backend && !plan.classification.frontend);
  return plan;
}

async function main() {
  const repositoryRoot = fileURLToPath(new URL("../../", import.meta.url));
  const plan = parseNormalReleaseArgs(process.argv.slice(2));
  if (!plan.classification.backend && !plan.classification.frontend) { process.stdout.write(`${JSON.stringify(plan)}\n`); return; }
  assertGithubOidcReleaseDeployerEnvironment();
  const run = createProductionAwsCommandRunner({ credentialSource: PRODUCTION_AWS_CREDENTIAL_SOURCE.GITHUB_OIDC_RELEASE_DEPLOYER, region: NORMAL_RELEASE.region });
  const service = process.argv.find((value) => value.startsWith("--service="))?.split("=", 2)[1];
  const image = service === "backend" ? plan.images.backend : plan.images.frontend;
  const result = service === "backend" ? await executeBackendCli({ sourceSha: plan.sourceSha, imageRef: image, run, repositoryRoot }) : await executeFrontendCli({ sourceSha: plan.sourceSha, imageRef: image, run, repositoryRoot });
  process.stdout.write(`${JSON.stringify({ plan, result })}\n`);
}

if (process.argv[1] && pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url) main().catch((error) => { process.stderr.write(`${error.message}\n`); process.exitCode = 1; });
