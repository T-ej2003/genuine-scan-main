#!/usr/bin/env node
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { bootstrapProductionComponentDeploymentState, createProductionComponentDeploymentStateClient, PRODUCTION_COMPONENT_STATE } from "./production-component-deployment-state.mjs";
import { APP_ONLY } from "./production-app-only-contract.mjs";
import { WEB_RELEASE } from "./production-web-release-contract.mjs";
import { assertGithubOidcReleaseDeployerEnvironment, createProductionAwsCommandRunner, PRODUCTION_AWS_CREDENTIAL_SOURCE } from "./production-credential-source-contract.mjs";

const SHA = /^[a-f0-9]{40}$/;
const DIGEST = /^sha256:[a-f0-9]{64}$/;
const json = (run, args) => JSON.parse(run([...args, "--output", "json", "--no-cli-pager"]));

function imageSource(run, repository, digest) {
  assert.match(digest || "", DIGEST);
  const response = json(run, ["ecr", "describe-images", "--repository-name", repository, "--image-ids", `imageDigest=${digest}`]);
  assert.equal(response.imageDetails?.length, 1, "Live image identity is unavailable");
  const image = response.imageDetails[0];
  assert.equal(image.repositoryName, repository); assert.equal(String(image.registryId), PRODUCTION_COMPONENT_STATE.account); assert.equal(image.imageDigest, digest);
  const sources = (image.imageTags || []).filter((tag) => SHA.test(tag));
  assert.equal(sources.length, 1, "Live image source identity is ambiguous");
  return sources[0];
}

export function serviceDefinition(run, cluster, service, family, container, repository) {
  const response = json(run, ["ecs", "describe-services", "--cluster", cluster, "--services", service]);
  assert.equal(response.failures?.length, 0); assert.equal(response.services?.length, 1);
  const live = response.services[0];
  assert.equal(live.clusterArn, `arn:aws:ecs:${PRODUCTION_COMPONENT_STATE.region}:${PRODUCTION_COMPONENT_STATE.account}:cluster/${cluster}`);
  assert.equal(live.serviceName, service); assert.equal(live.status, "ACTIVE"); assert.ok(Number.isSafeInteger(live.desiredCount) && live.desiredCount > 0); assert.equal(live.desiredCount, live.runningCount); assert.equal(live.pendingCount, 0); assert.equal(live.taskDefinition, live.deployments?.find((deployment) => deployment.status === "PRIMARY" && deployment.rolloutState === "COMPLETED")?.taskDefinition);
  const definition = json(run, ["ecs", "describe-task-definition", "--task-definition", live.taskDefinition]).taskDefinition;
  assert.equal(definition?.taskDefinitionArn, live.taskDefinition); assert.equal(definition.family, family); assert.equal(definition.status, "ACTIVE");
  const matched = definition.containerDefinitions?.filter((value) => value.name === container);
  assert.equal(matched?.length, 1); const image = matched[0].image;
  assert.match(image || "", new RegExp(`^${repository.replace(/[.*+?^${}()|[\\]\\]/g, "\\$&")}@`));
  const digest = image.split("@")[1]; assert.match(digest, DIGEST);
  return { sourceSha: imageSource(run, repository.split("/").at(-1), digest), imageDigest: digest, taskDefinitionArn: definition.taskDefinitionArn, desiredCount: live.desiredCount };
}

export function bootstrapProductionComponentStateFromLive({ run, isProtectedMainAncestor = () => true, now, updatedByWorkflow, githubRunId } = {}) {
  assert.equal(typeof run, "function"); assert.equal(typeof isProtectedMainAncestor, "function");
  const caller = json(run, ["sts", "get-caller-identity"]);
  assert.equal(String(caller.Account), PRODUCTION_COMPONENT_STATE.account);
  assert.match(caller.Arn || "", /^arn:aws:sts::368992683803:assumed-role\/mscqr-production-component-state-bootstrap\/[^/]+$/);
  const backend = serviceDefinition(run, APP_ONLY.cluster, APP_ONLY.service, APP_ONLY.family, APP_ONLY.container, APP_ONLY.backendRepository);
  const frontend = serviceDefinition(run, WEB_RELEASE.cluster, WEB_RELEASE.serviceName, WEB_RELEASE.family, WEB_RELEASE.container, `368992683803.dkr.ecr.eu-west-2.amazonaws.com/${WEB_RELEASE.repository}`);
  for (const value of [backend, frontend]) assert.equal(isProtectedMainAncestor(value.sourceSha), true, "Live component source is not protected-main history");
  return bootstrapProductionComponentDeploymentState({ components: { backend: { ...backend, establishedThroughSha: backend.sourceSha }, frontend: { ...frontend, establishedThroughSha: frontend.sourceSha }, database: null, security: null }, now, updatedByWorkflow, githubRunId });
}

function main() {
  assert.deepEqual(process.argv.slice(2), []);
  assertGithubOidcReleaseDeployerEnvironment();
  assert.match(process.env.GITHUB_WORKFLOW_REF || "", /^T-ej2003\/genuine-scan-main\/.github\/workflows\/bootstrap-production-component-deployment-state\.yml@refs\/heads\/main$/);
  assert.match(process.env.GITHUB_RUN_ID || "", /^[1-9][0-9]*$/);
  const run = createProductionAwsCommandRunner({ credentialSource: PRODUCTION_AWS_CREDENTIAL_SOURCE.GITHUB_OIDC_RELEASE_DEPLOYER, region: PRODUCTION_COMPONENT_STATE.region });
  const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
  const state = bootstrapProductionComponentStateFromLive({ run, updatedByWorkflow: process.env.GITHUB_WORKFLOW_REF, githubRunId: process.env.GITHUB_RUN_ID, isProtectedMainAncestor: (sourceSha) => {
    try { execFileSync("git", ["merge-base", "--is-ancestor", sourceSha, "refs/remotes/origin/main"], { cwd: root, stdio: "ignore" }); return true; } catch { return false; }
  } });
  const client = createProductionComponentDeploymentStateClient({ run });
  assert.equal(client.read(), null, "Component deployment state was already bootstrapped.");
  client.initialize(state);
  process.stdout.write(`${JSON.stringify({ environment: state.environment, generation: state.generation, components: Object.fromEntries(Object.entries(state.components).map(([name, value]) => [name, value && { sourceSha: value.sourceSha, establishedThroughSha: value.establishedThroughSha, imageDigest: value.imageDigest, taskDefinitionArn: value.taskDefinitionArn }])) })}\n`);
}

if (process.argv[1] && pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url) main();
