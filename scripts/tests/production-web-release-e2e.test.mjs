import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";
import { canonicalSha256 } from "../aws/production-green-stage-b-contract.mjs";
import { WEB_RELEASE, assertCoordinatedImageAuthorization, buildWebImageAuthorization, buildWebImageEvidence, buildWebPublicationIdentity, captureFrontendPredecessor, runGovernedFrontendActivation, signWebImageEvidence } from "../aws/production-web-release-contract.mjs";
import { produceGovernedWebEvidence } from "../aws/produce-production-web-image-evidence.mjs";

const sourceSha = "a".repeat(40);
const otherSha = "c".repeat(40);
const now = "2026-09-17T12:00:00.000Z";
const digest = `sha256:${"b".repeat(64)}`;
const imageRef = `${WEB_RELEASE.account}.dkr.ecr.${WEB_RELEASE.region}.amazonaws.com/${WEB_RELEASE.repository}@${digest}`;
const hash = (value) => crypto.createHash("sha256").update(value).digest("hex");
const impact = (webPublicationRequired = true) => Object.freeze({ schemaVersion: 1, toolingSha: sourceSha, webPublicationRequired, classifiedFiles: webPublicationRequired ? ["src/App.tsx"] : ["backend/src/app.ts"] });
const stageB = (webPublicationRequired = true) => Object.freeze({ sourceSha, authorizationSha256: "d".repeat(64), imageReuseEvidence: impact(webPublicationRequired) });

function publication() {
  const sbomBytes = Buffer.from('{"spdxVersion":"SPDX-2.3"}');
  const provenanceBytes = Buffer.from(JSON.stringify({ releaseSha: sourceSha, workflowDefinitionSha: sourceSha, workflowRunId: "12", repository: WEB_RELEASE.repository, platform: WEB_RELEASE.platform, dockerfile: WEB_RELEASE.dockerfile, buildContext: WEB_RELEASE.buildContext }));
  const artifactBytes = Buffer.from(`${JSON.stringify({ service: "frontend", repository: WEB_RELEASE.repository, image_uri: `${WEB_RELEASE.account}.dkr.ecr.${WEB_RELEASE.region}.amazonaws.com/${WEB_RELEASE.repository}:${sourceSha}`, image_tag: sourceSha, image_digest: digest, image_ref: imageRef, platform: WEB_RELEASE.platform, dockerfile: WEB_RELEASE.dockerfile, build_context: WEB_RELEASE.buildContext, critical_scan: "pass", sbom_sha256: hash(sbomBytes), provenance_sha256: hash(provenanceBytes), cosign_signature_verified: true, sbom_attestation_verified: true, provenance_attestation_verified: true })}\n`);
  return Object.freeze({ observed: Object.freeze({ workflowRunId: "12", workflowDatabaseId: "34", workflowFile: WEB_RELEASE.workflowFile, workflowName: WEB_RELEASE.workflowName, event: "workflow_dispatch", workflowDefinitionSha: sourceSha, headBranch: "main", conclusion: "success", artifactId: "56", artifactName: WEB_RELEASE.artifactName, artifactExpired: false, reviewer: WEB_RELEASE.reviewer }), artifactBytes, sbomBytes, provenanceBytes });
}

const run = (args) => {
  if (args[0] === "sts") return JSON.stringify({ Arn: "arn:aws:iam::368992683803:root", Account: WEB_RELEASE.account });
  if (args[1] === "describe-repositories") return JSON.stringify({ repositories: [{ repositoryArn: `arn:aws:ecr:${WEB_RELEASE.region}:${WEB_RELEASE.account}:repository/${WEB_RELEASE.repository}`, repositoryName: WEB_RELEASE.repository, registryId: WEB_RELEASE.account, imageTagMutability: "IMMUTABLE", imageTagMutabilityExclusionFilters: [] }] });
  if (args[1] === "describe-images") return JSON.stringify({ imageDetails: [{ imageDigest: digest, imagePushedAt: now }] });
  throw new Error(`Unexpected mocked AWS command: ${args.join(" ")}`);
};

function authorization() {
  return produceGovernedWebEvidence({ sourceSha, stageBAuthorization: stageB(), publication: publication(), run, now, verifyStageBAuthorization: () => true, verifyArtifacts: (value) => value === imageRef, sign: () => "AQ==", verifyWebEvidence: () => true }).authorization;
}

const taskArn = `arn:aws:ecs:${WEB_RELEASE.region}:${WEB_RELEASE.account}:task-definition/${WEB_RELEASE.family}:21`;
const task = { taskDefinitionArn: taskArn, family: WEB_RELEASE.family, revision: 21, status: "ACTIVE", networkMode: "awsvpc", requiresCompatibilities: ["FARGATE"], cpu: "256", memory: "512", executionRoleArn: `arn:aws:iam::${WEB_RELEASE.account}:role/mscqr-ecs-execution-role`, taskRoleArn: `arn:aws:iam::${WEB_RELEASE.account}:role/mscqr-ecs-task-role`, containerDefinitions: [{ name: WEB_RELEASE.container, image: `${WEB_RELEASE.account}.dkr.ecr.${WEB_RELEASE.region}.amazonaws.com/${WEB_RELEASE.repository}@sha256:${"1".repeat(64)}`, essential: true, cpu: 0, readonlyRootFilesystem: true, privileged: false, interactive: false, pseudoTerminal: false }], tags: [] };
const service = { serviceArn: `arn:aws:ecs:${WEB_RELEASE.region}:${WEB_RELEASE.account}:service/${WEB_RELEASE.cluster}/${WEB_RELEASE.serviceName}`, clusterArn: `arn:aws:ecs:${WEB_RELEASE.region}:${WEB_RELEASE.account}:cluster/${WEB_RELEASE.cluster}`, serviceName: WEB_RELEASE.serviceName, status: "ACTIVE", desiredCount: 2, runningCount: 2, pendingCount: 0, taskDefinition: taskArn, deployments: [{ id: "ecs-svc/predecessor", status: "PRIMARY", taskDefinition: taskArn, rolloutState: "COMPLETED" }] };

test("mocked end-to-end release accepts web-required evidence and exact active predecessor", async () => {
  const web = authorization();
  assert.equal(assertCoordinatedImageAuthorization({ sourceSha, stageBAuthorization: stageB(), webAuthorization: web, webPublicationRequired: true, verifyWeb: () => true, now }).webRequired, true);
  let active = taskArn; const updates = []; const candidateArn = taskArn.replace(":21", ":22");
  const result = await runGovernedFrontendActivation({ sourceSha, webAuthorization: web, verifyWebAuthorization: () => true, now,
    readService: async () => ({ ...service, taskDefinition: active, deployments: [{ ...service.deployments[0], taskDefinition: active, id: active === taskArn ? "ecs-svc/predecessor" : "ecs-svc/candidate" }] }),
    describeTaskDefinition: async (arn) => arn === taskArn ? task : { ...task, taskDefinitionArn: candidateArn, revision: 22, containerDefinitions: [{ ...task.containerDefinitions[0], image: imageRef }] },
    registerTaskDefinition: async () => ({ taskDefinitionArn: candidateArn }), updateService: async ({ taskDefinition }) => { updates.push(taskDefinition); active = taskDefinition; }, waitStable: async () => {}, verifyHealth: async () => ({ ready: true, loginStatus: 200 }),
  });
  assert.deepEqual(updates, [candidateArn]); assert.equal(result.predecessorTaskDefinitionArn, taskArn);
});

test("mocked end-to-end release rejects every incompatible authorization transition before activation", () => {
  const web = authorization();
  const reject = (options, expression = /authorization|impact|invalid|forbidden|source/i) => assert.throws(() => assertCoordinatedImageAuthorization(options), expression);
  // Scenario 2: a backend-only impact preserves the authenticated current frontend and has no web artifacts.
  assert.equal(assertCoordinatedImageAuthorization({ sourceSha, stageBAuthorization: stageB(false), webPublicationRequired: false }).webRequired, false);
  // Scenarios 3-6 and 15: supplied web auth, missing auth, mixed source, and stale/tampered impact all fail closed.
  reject({ sourceSha, stageBAuthorization: stageB(false), webAuthorization: web, webPublicationRequired: false });
  reject({ sourceSha, stageBAuthorization: stageB(), webPublicationRequired: true, verifyWeb: () => true, now });
  reject({ sourceSha: otherSha, stageBAuthorization: stageB(), webAuthorization: web, webPublicationRequired: true, verifyWeb: () => true, now });
  reject({ sourceSha, stageBAuthorization: { ...stageB(), imageReuseEvidence: { ...impact(), webPublicationRequired: false } }, webAuthorization: web, webPublicationRequired: true, verifyWeb: () => true, now });
  // Scenarios 7-11: workflow, artifact, ECR, binding, and signature drift fail before authorization.
  for (const mutate of [
    (value) => ({ ...value, evidence: { ...value.evidence, workflowRunId: "13" } }),
    (value) => ({ ...value, evidence: { ...value.evidence, publicationArtifactSha256: "e".repeat(64) } }),
    (value) => ({ ...value, evidence: { ...value.evidence, imageDigest: `sha256:${"e".repeat(64)}` } }),
    (value) => ({ ...value, evidence: { ...value.evidence, repository: "other" } }),
    (value) => ({ ...value, signature: { ...value.signature, signatureBase64: "%%%" } }),
  ]) reject({ sourceSha, stageBAuthorization: stageB(), webAuthorization: mutate(web), webPublicationRequired: true, verifyWeb: () => true, now });
});

test("mocked failure path rolls back only the captured active predecessor", async () => {
  const web = authorization(); const candidateArn = taskArn.replace(":21", ":22"); let active = taskArn; const updates = [];
  await assert.rejects(() => runGovernedFrontendActivation({ sourceSha, webAuthorization: web, verifyWebAuthorization: () => true, now,
    readService: async () => ({ ...service, taskDefinition: active, deployments: [{ ...service.deployments[0], taskDefinition: active, id: active === taskArn ? "ecs-svc/predecessor" : "ecs-svc/candidate" }] }),
    describeTaskDefinition: async (arn) => arn === taskArn ? task : { ...task, taskDefinitionArn: candidateArn, revision: 22, containerDefinitions: [{ ...task.containerDefinitions[0], image: imageRef }] },
    registerTaskDefinition: async () => ({ taskDefinitionArn: candidateArn }), updateService: async ({ taskDefinition }) => { updates.push(taskDefinition); active = taskDefinition; }, waitStable: async () => {}, verifyHealth: async () => ({ ready: false, loginStatus: 500 }),
  }), /health/);
  assert.deepEqual(updates, [candidateArn, taskArn]);
  assert.throws(() => captureFrontendPredecessor(service, { ...task, status: "INACTIVE" }), /stable production/);
});

test("web authorization builder cannot be used to substitute the authenticated Stage-B impact", () => {
  const published = publication(); const identity = buildWebPublicationIdentity({ sourceSha, observed: published.observed, artifactBytes: published.artifactBytes, observedAt: now });
  const evidence = buildWebImageEvidence({ publicationIdentity: identity, repositoryEvidence: { repositoryArn: `arn:aws:ecr:${WEB_RELEASE.region}:${WEB_RELEASE.account}:repository/${WEB_RELEASE.repository}`, repositoryName: WEB_RELEASE.repository, registryId: WEB_RELEASE.account, imageTagMutability: "IMMUTABLE", imageTagMutabilityExclusionFilters: [] }, imageReadback: { digest, imagePushedAt: now }, imageImpactSha256: canonicalSha256(impact()), createdAt: now, expiresAt: "2026-09-18T12:00:00.000Z" });
  const signature = signWebImageEvidence(evidence, { signedAt: now, sign: () => "AQ==" });
  assert.throws(() => buildWebImageAuthorization({ sourceSha, evidence, signature, imageImpact: impact(false), reviewer: WEB_RELEASE.reviewer, now, verify: () => true }), /binding/);
});
