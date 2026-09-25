import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";
import yaml from "js-yaml";
import { canonicalSha256 } from "../aws/production-green-stage-b-contract.mjs";
import {
  WEB_RELEASE, WEB_RELEASE_DOWNSTREAM_RESERVE_MS, parseWebPublicationArtifact, buildWebPublicationIdentity, buildWebImageEvidence, signWebImageEvidence,
  assertWebImageEvidence, buildWebImageAuthorization, assertWebImageAuthorization, assertCoordinatedImageAuthorization, authenticateWebImageAuthorization,
  captureFrontendPredecessor, buildFrontendCandidate, assertFrontendCandidateReadback, assertFrontendPredecessorCas,
  buildFrontendUpdate, buildFrontendRollback,
  runGovernedFrontendActivation,
} from "../aws/production-web-release-contract.mjs";
import { activateAuthenticatedWebRelease, createWebActivationAwsRunner, assertBackendActivationLiveReadback, assertFrontendActivationAuthorized } from "../aws/run-production-web-activation.mjs";
import { NORMAL_ACTIVATION } from "../aws/production-normal-backend-activation.mjs";

const sourceSha = "a".repeat(40); const digest = `sha256:${"b".repeat(64)}`; const createdAt = "2026-09-16T12:00:00.000Z"; const expiresAt = "2026-09-17T12:00:00.000Z";
const imageRef = `${WEB_RELEASE.account}.dkr.ecr.${WEB_RELEASE.region}.amazonaws.com/${WEB_RELEASE.repository}@${digest}`;
const artifact = (changes = {}) => Buffer.from(`${JSON.stringify({ service: "frontend", repository: "mscqr-web", image_uri: `${WEB_RELEASE.account}.dkr.ecr.${WEB_RELEASE.region}.amazonaws.com/mscqr-web:${sourceSha}`, image_tag: sourceSha, image_digest: digest, image_ref: imageRef, platform: "linux/amd64", dockerfile: "Dockerfile.ecs-frontend", build_context: ".", critical_scan: "pass", sbom_sha256: "1".repeat(64), provenance_sha256: "2".repeat(64), cosign_signature_verified: true, sbom_attestation_verified: true, provenance_attestation_verified: true, ...changes })}\n`);
const impact = Object.freeze({ schemaVersion: 1, toolingSha: sourceSha, webPublicationRequired: true, classifiedFiles: ["src/App.tsx"] });

test("web publisher requires review, permits operator self-review, and stays protected-main-only", () => {
  const contract = JSON.parse(fs.readFileSync("infra/aws/terraform/production-web-release/github-environment-contract.json", "utf8"));
  assert.equal(WEB_RELEASE.reviewer, "T-ej2003");
  assert.deepEqual(contract, {
    name: "production-web-image-publish",
    deploymentBranches: "protected-main-only",
    requiredReviewers: true,
    preventSelfReview: false,
    forbidUnprotectedBranchesAndTags: true,
    variables: ["PRODUCTION_WEB_IMAGE_PUBLISH_ROLE"],
    forbiddenSecrets: ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"],
    requiresEnvironmentSecrets: false,
    activation: "operator-configured; not managed by Terraform",
  });
});

function fixture() {
  const artifactBytes = artifact();
  const identity = buildWebPublicationIdentity({ sourceSha, artifactBytes, observedAt: createdAt, observed: { workflowRunId: "12", workflowDatabaseId: "34", workflowFile: WEB_RELEASE.workflowFile, workflowName: WEB_RELEASE.workflowName, event: "workflow_dispatch", workflowDefinitionSha: sourceSha, headBranch: "main", conclusion: "success", artifactId: "56", artifactName: WEB_RELEASE.artifactName, artifactExpired: false, reviewer: "reviewer-one" } });
  const evidence = buildWebImageEvidence({ publicationIdentity: identity, repositoryEvidence: { repositoryArn: `arn:aws:ecr:${WEB_RELEASE.region}:${WEB_RELEASE.account}:repository/mscqr-web`, repositoryName: "mscqr-web", registryId: WEB_RELEASE.account, imageTagMutability: "IMMUTABLE", imageTagMutabilityExclusionFilters: [] }, imageReadback: { digest, imagePushedAt: createdAt }, imageImpactSha256: canonicalSha256(impact), createdAt, expiresAt });
  const signature = signWebImageEvidence(evidence, { signedAt: createdAt, sign: () => "AQ==" });
  const authorization = buildWebImageAuthorization({ sourceSha, evidence, signature, imageImpact: impact, reviewer: "reviewer-one", now: createdAt, verify: () => true });
  return { artifactBytes, identity, evidence, signature, authorization };
}

test("web publication accepts only its exact immutable source contract", () => {
  assert.equal(parseWebPublicationArtifact(artifact(), sourceSha).image_ref, imageRef);
  for (const changes of [{ repository: "other" }, { dockerfile: "Dockerfile" }, { platform: "linux/arm64" }, { image_tag: "c".repeat(40) }, { image_ref: `${WEB_RELEASE.account}.dkr.ecr.${WEB_RELEASE.region}.amazonaws.com/mscqr-web:latest` }]) assert.throws(() => parseWebPublicationArtifact(artifact(changes), sourceSha), /canonical contract/);
});

test("web evidence and authorization reject source, repository, digest, expiry, reviewer and signature drift", () => {
  const { evidence, signature, authorization } = fixture();
  assert.equal(assertWebImageAuthorization(authorization, { sourceSha, now: createdAt, verify: () => true }), true);
  assert.throws(() => assertWebImageAuthorization({ ...authorization, sourceSha: "c".repeat(40) }, { sourceSha, now: createdAt, verify: () => true }), /invalid/);
  assert.throws(() => assertWebImageEvidence({ ...evidence, repository: "other" }, { now: createdAt }), /invalid/);
  assert.throws(() => assertWebImageEvidence({ ...evidence, imageDigest: `sha256:${"d".repeat(64)}` }, { now: createdAt }), /invalid/);
  assert.throws(() => assertWebImageEvidence(evidence, { signature: { ...signature, signatureBase64: "%%%" }, now: createdAt, verify: () => true }), /signature/);
  assert.throws(() => assertWebImageEvidence(evidence, { now: "2026-09-17T12:00:00.001Z" }), /expired/);
  assert.throws(() => buildWebImageAuthorization({ sourceSha, evidence, signature, imageImpact: impact, reviewer: "other", now: createdAt, verify: () => true }), /reviewer/);
});

test("web authorization lifetime is bound to the signed evidence lifetime", () => {
  const { authorization } = fixture();
  const forged = { ...authorization, expiresAt: "2026-09-18T12:00:00.000Z" };
  const { authorizationSha256: _authorizationSha256, ...payload } = forged;
  forged.authorizationSha256 = canonicalSha256(payload);
  assert.throws(() => assertWebImageAuthorization(forged, { sourceSha, now: createdAt, verify: () => true, minimumRemainingMs: WEB_RELEASE_DOWNSTREAM_RESERVE_MS }), /invalid/);
});

test("web authorization cannot wrap valid evidence from another source", () => {
  const { authorization } = fixture(); const staleEvidence = structuredClone(authorization.evidence); const staleSource = "c".repeat(40);
  staleEvidence.sourceSha = staleSource; staleEvidence.publicationIdentity.sourceSha = staleSource; staleEvidence.publicationIdentity.workflowDefinitionSha = staleSource;
  staleEvidence.publicationIdentitySha256 = canonicalSha256(staleEvidence.publicationIdentity); const { evidenceSha256: _evidenceSha256, ...staleEvidencePayload } = staleEvidence; staleEvidence.evidenceSha256 = canonicalSha256(staleEvidencePayload);
  const staleSignature = { ...authorization.signature, sourceSha: staleSource, evidenceSha256: staleEvidence.evidenceSha256 }; const forged = { ...authorization, evidence: staleEvidence, signature: staleSignature, evidenceSha256: staleEvidence.evidenceSha256, signatureSha256: canonicalSha256(staleSignature) }; const { authorizationSha256: _authorizationSha256, ...forgedPayload } = forged; forged.authorizationSha256 = canonicalSha256(forgedPayload);
  assert.throws(() => assertWebImageAuthorization(forged, { sourceSha, now: createdAt, verify: () => true }), /invalid/);
});

test("coordinated release requires matching web authorization only when web publication is required", () => {
  const { authorization } = fixture(); const stageB = { sourceSha, authorizationSha256: "d".repeat(64), imageReuseEvidence: impact };
  assert.equal(assertCoordinatedImageAuthorization({ sourceSha, stageBAuthorization: stageB, webAuthorization: authorization, webPublicationRequired: true, verifyWeb: () => true, now: createdAt }).webRequired, true);
  assert.throws(() => assertCoordinatedImageAuthorization({ sourceSha, stageBAuthorization: stageB, webAuthorization: { ...authorization, sourceSha: "e".repeat(40) }, webPublicationRequired: true, verifyWeb: () => true, now: createdAt }), /invalid/);
  assert.throws(() => assertCoordinatedImageAuthorization({ sourceSha, stageBAuthorization: { ...stageB, imageReuseEvidence: { ...impact, classifiedFiles: ["src/other.tsx"] } }, webAuthorization: authorization, webPublicationRequired: true, verifyWeb: () => true, now: createdAt }), /image impact/);
  assert.equal(assertCoordinatedImageAuthorization({ sourceSha, stageBAuthorization: stageB, webPublicationRequired: false }).webRequired, false);
  assert.throws(() => assertCoordinatedImageAuthorization({ sourceSha, stageBAuthorization: stageB, webAuthorization: authorization, webPublicationRequired: false }), /forbidden/);
});

test("coordinated web authorization reserves the complete downstream release window", () => {
  const { authorization } = fixture();
  const nearlyExpired = new Date(Date.parse(authorization.expiresAt) - WEB_RELEASE_DOWNSTREAM_RESERVE_MS + 1).toISOString();
  const enoughLifetime = new Date(Date.parse(authorization.expiresAt) - WEB_RELEASE_DOWNSTREAM_RESERVE_MS - 1).toISOString();
  const stageB = { sourceSha, authorizationSha256: "d".repeat(64), imageReuseEvidence: impact };
  assert.throws(() => assertCoordinatedImageAuthorization({ sourceSha, stageBAuthorization: stageB, webAuthorization: authorization, webPublicationRequired: true, verifyWeb: () => true, now: nearlyExpired, minimumWebAuthorizationRemainingMs: WEB_RELEASE_DOWNSTREAM_RESERVE_MS }), /remaining lifetime/);
  assert.equal(assertCoordinatedImageAuthorization({ sourceSha, stageBAuthorization: stageB, webAuthorization: authorization, webPublicationRequired: true, verifyWeb: () => true, now: enoughLifetime, minimumWebAuthorizationRemainingMs: WEB_RELEASE_DOWNSTREAM_RESERVE_MS }).webRequired, true);
  assert.throws(() => assertCoordinatedImageAuthorization({ sourceSha, stageBAuthorization: stageB, webAuthorization: authorization, webPublicationRequired: true, verifyWeb: () => true, now: createdAt, minimumWebAuthorizationRemainingMs: -1 }), /remaining lifetime/);
});

test("frontend activation consumes the authenticated Stage-B web decision before AWS adapters", async () => {
  assert.equal(assertFrontendActivationAuthorized({ webRequired: true }), true);
  assert.throws(() => assertFrontendActivationAuthorized({ webRequired: false }), /forbidden/);
  assert.throws(() => assertFrontendActivationAuthorized(undefined), /forbidden/);
  let adapters = 0;
  await assert.rejects(() => activateAuthenticatedWebRelease({ sourceSha, stageBAuthorization: {}, webAuthorization: {}, verifyWeb: () => true, verifyCoordinated: async () => ({ webRequired: false }), createAdapters: () => { adapters += 1; throw new Error("must not construct adapters"); } }), /forbidden/);
  assert.equal(adapters, 0);
});

test("web activation requires completed same-source backend activation evidence", async () => {
  const backend = { schemaVersion: 1, operation: "PRODUCTION_NORMAL_BACKEND_ACTIVATION", sourceSha, stageBAuthorizationSha256: "stage-auth", workflowRunId: "12", releaseTrainRunId: "34", sourceArn: "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-backend:20", targetArn: "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-production-rls-green-backend-candidate:21", newTaskDefinitionArn: "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-production-rls-green-backend-candidate:21", observedTaskDefinitionArn: "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-production-rls-green-backend-candidate:21", imageRef: `368992683803.dkr.ecr.eu-west-2.amazonaws.com/mscqr-backend@sha256:${"b".repeat(64)}`, imageDigest: `sha256:${"b".repeat(64)}`, clusterArn: NORMAL_ACTIVATION.clusterArn, serviceArn: NORMAL_ACTIVATION.serviceArn, serviceStable: true, desiredCount: 2, runningCount: 2, pendingCount: 0 };
  const stageBAuthorization = { sourceSha, authorizationSha256: "stage-auth", imageReuseEvidence: { webPublicationRequired: false } };
  await assert.rejects(() => activateAuthenticatedWebRelease({ sourceSha, stageBAuthorization, webAuthorization: undefined, backendActivationEvidence: backend, verifyCoordinated: async () => ({ webRequired: false }), createAdapters: () => assert.fail("web=false must stop before adapters") }), /forbidden/);
  await assert.rejects(() => activateAuthenticatedWebRelease({ sourceSha, stageBAuthorization: { ...stageBAuthorization, imageReuseEvidence: { webPublicationRequired: true } }, webAuthorization: {}, backendActivationEvidence: { ...backend, sourceSha: "c".repeat(40) }, verifyCoordinated: async () => ({ webRequired: true }), createAdapters: () => assert.fail("invalid backend evidence must stop before adapters") }), /backend activation evidence/);
  assert.throws(() => assertBackendActivationLiveReadback({ sourceSha, expectedDigest: backend.imageDigest, backendActivationEvidence: backend, service: { serviceArn: NORMAL_ACTIVATION.serviceArn, clusterArn: NORMAL_ACTIVATION.clusterArn, status: "ACTIVE", desiredCount: 2, runningCount: 2, pendingCount: 0, taskDefinition: backend.targetArn, deployments: [{ status: "PRIMARY", taskDefinition: backend.targetArn, rolloutState: "COMPLETED" }] }, tasks: [], healthStatus: 200, healthBody: { status: "ready", release: { gitSha: sourceSha } } }), /stable source-bound/);
  assert.equal(typeof backend.operation, "string");
});

const taskArn = `arn:aws:ecs:${WEB_RELEASE.region}:${WEB_RELEASE.account}:task-definition/mscqr-frontend:20`;
const task = { taskDefinitionArn: taskArn, family: "mscqr-frontend", revision: 20, status: "ACTIVE", networkMode: "awsvpc", requiresCompatibilities: ["FARGATE"], cpu: "256", memory: "512", executionRoleArn: `arn:aws:iam::${WEB_RELEASE.account}:role/mscqr-ecs-execution-role`, taskRoleArn: `arn:aws:iam::${WEB_RELEASE.account}:role/mscqr-ecs-task-role`, tags: [{ key: "Environment", value: "production" }], containerDefinitions: [{ name: "frontend", image: `${WEB_RELEASE.account}.dkr.ecr.${WEB_RELEASE.region}.amazonaws.com/mscqr-web@sha256:${"1".repeat(64)}`, essential: true, cpu: 0, readonlyRootFilesystem: true, privileged: false, interactive: false, pseudoTerminal: false }] };
const service = { serviceArn: `arn:aws:ecs:${WEB_RELEASE.region}:${WEB_RELEASE.account}:service/${WEB_RELEASE.cluster}/${WEB_RELEASE.serviceName}`, clusterArn: `arn:aws:ecs:${WEB_RELEASE.region}:${WEB_RELEASE.account}:cluster/${WEB_RELEASE.cluster}`, serviceName: WEB_RELEASE.serviceName, status: "ACTIVE", desiredCount: 2, runningCount: 2, pendingCount: 0, taskDefinition: taskArn, deployments: [{ id: "ecs-svc/opaque", status: "PRIMARY", taskDefinition: taskArn, rolloutState: "COMPLETED" }] };

test("frontend candidate is image-only, read back exactly, and uses predecessor CAS", () => {
  const { authorization } = fixture(); const authenticatedWebAuthorization = authenticateWebImageAuthorization({ sourceSha, webAuthorization: authorization, verify: () => true, now: createdAt }); const predecessor = captureFrontendPredecessor(service, task); const candidate = buildFrontendCandidate({ predecessor, authenticatedWebAuthorization }); const candidateArn = taskArn.replace(":20", ":21");
  assert.equal(candidate.containerDefinitions[0].image, imageRef);
  assert.equal(assertFrontendCandidateReadback({ definition: { ...candidate, taskDefinitionArn: candidateArn, revision: 21, status: "ACTIVE" }, taskDefinitionArn: candidateArn, candidate }), true);
  assert.throws(() => assertFrontendCandidateReadback({ definition: { ...candidate, tags: [], taskDefinitionArn: candidateArn, revision: 21, status: "ACTIVE" }, taskDefinitionArn: candidateArn, candidate }), /tags drifted/);
  assert.equal(assertFrontendPredecessorCas({ predecessor, currentService: service, currentTaskDefinition: task }), true);
  assert.throws(() => assertFrontendPredecessorCas({ predecessor, currentService: { ...service, deployments: [{ ...service.deployments[0], id: "ecs-svc/changed" }] }, currentTaskDefinition: task }), /CAS/);
  assert.deepEqual(buildFrontendUpdate({ predecessor, candidateTaskDefinitionArn: candidateArn }), { cluster: WEB_RELEASE.cluster, service: WEB_RELEASE.serviceName, taskDefinition: candidateArn });
  assert.equal(buildFrontendRollback({ predecessor, failedCandidateTaskDefinitionArn: candidateArn }).taskDefinition, taskArn);
  assert.throws(() => buildFrontendRollback({ predecessor, failedCandidateTaskDefinitionArn: taskArn }), /invalid/);
  assert.throws(() => buildFrontendCandidate({ predecessor, authenticatedWebAuthorization: { sourceSha, imageRef, authorizationSha256: authorization.authorizationSha256 } }), /Authenticated/);
});

test("frontend preservation authenticates stable governed revisions after bootstrap", () => {
  for (const revision of [20, 21, 22, 107]) {
    const arn = taskArn.replace(":20", `:${revision}`);
    const currentTask = { ...task, taskDefinitionArn: arn, revision };
    const currentService = { ...service, taskDefinition: arn, deployments: [{ ...service.deployments[0], taskDefinition: arn }] };
    assert.equal(captureFrontendPredecessor(currentService, currentTask).taskDefinitionArn, arn);
    assert.throws(() => captureFrontendPredecessor(currentService, { ...currentTask, status: "INACTIVE" }), /stable production service/);
  }
  for (const status of [undefined, "DELETE_IN_PROGRESS", "unexpected"]) assert.throws(() => captureFrontendPredecessor(service, { ...task, status }), /stable production service/);
  assert.throws(() => captureFrontendPredecessor({ ...service, deployments: [...service.deployments, { ...service.deployments[0], id: "ecs-svc/old", status: "ACTIVE" }] }, task), /stable production service/);
  assert.throws(() => captureFrontendPredecessor(service, { ...task, containerDefinitions: [...task.containerDefinitions, { name: "sidecar", image: task.containerDefinitions[0].image }] }), /stable production service/);
});

test("inactive frontend predecessor fails before candidate registration or service mutation", async () => {
  const { authorization } = fixture(); let registrations = 0; let updates = 0;
  await assert.rejects(() => runGovernedFrontendActivation({
    sourceSha, webAuthorization: authorization, verifyWebAuthorization: () => true, now: createdAt,
    readService: async () => service,
    describeTaskDefinition: async () => ({ ...task, status: "INACTIVE" }),
    registerTaskDefinition: async () => { registrations += 1; },
    updateService: async () => { updates += 1; },
    waitStable: async () => {}, verifyHealth: async () => ({ ready: true, loginStatus: 200 }),
  }), /stable production service/);
  assert.equal(registrations, 0); assert.equal(updates, 0);
});

test("frontend activation updates once and rollback can only restore its captured predecessor", async () => {
  const { authorization } = fixture(); const authenticatedWebAuthorization = authenticateWebImageAuthorization({ sourceSha, webAuthorization: authorization, verify: () => true, now: createdAt }); const candidateArn = taskArn.replace(":20", ":21"); let active = taskArn; const updates = [];
  const currentService = () => ({ ...service, taskDefinition: active, deployments: [{ id: active === taskArn ? "ecs-svc/opaque" : "ecs-svc/candidate", status: "PRIMARY", taskDefinition: active, rolloutState: "COMPLETED" }] });
  const describe = async (arn) => arn === taskArn ? task : { ...buildFrontendCandidate({ predecessor: captureFrontendPredecessor(service, task), authenticatedWebAuthorization }), taskDefinitionArn: candidateArn, revision: 21, status: "ACTIVE" };
  const success = await runGovernedFrontendActivation({ sourceSha, webAuthorization: authorization, verifyWebAuthorization: () => true, now: createdAt, readService: async () => currentService(), describeTaskDefinition: describe, registerTaskDefinition: async () => ({ taskDefinitionArn: candidateArn }), updateService: async ({ taskDefinition }) => { updates.push(taskDefinition); active = taskDefinition; }, waitStable: async () => {}, verifyHealth: async () => ({ ready: true, loginStatus: 200 }) });
  assert.equal(success.updateCount, 1); assert.deepEqual(updates, [candidateArn]);

  active = taskArn; updates.length = 0;
  await assert.rejects(() => runGovernedFrontendActivation({ sourceSha, webAuthorization: authorization, verifyWebAuthorization: () => true, now: createdAt, readService: async () => currentService(), describeTaskDefinition: describe, registerTaskDefinition: async () => ({ taskDefinitionArn: candidateArn }), updateService: async ({ taskDefinition }) => { updates.push(taskDefinition); active = taskDefinition; }, waitStable: async () => {}, verifyHealth: async () => ({ ready: false, loginStatus: 500 }) }), /health/);
  assert.deepEqual(updates, [candidateArn, taskArn]);

  active = taskArn; updates.length = 0;
  await assert.rejects(() => runGovernedFrontendActivation({ sourceSha, webAuthorization: authorization, verifyWebAuthorization: () => true, now: createdAt, readService: async () => currentService(), describeTaskDefinition: describe, registerTaskDefinition: async () => ({ taskDefinitionArn: candidateArn }), updateService: async ({ taskDefinition }) => { updates.push(taskDefinition); active = taskDefinition; if (taskDefinition === candidateArn) throw new Error("uncertain response"); }, waitStable: async () => {}, verifyHealth: async () => ({ ready: true, loginStatus: 200 }) }), /uncertain response/);
  assert.deepEqual(updates, [candidateArn, taskArn]);
});

test("web workflow and IAM are fixed, OIDC-only, and isolated from Stage-B four-image authority", () => {
  const workflow = yaml.load(fs.readFileSync(".github/workflows/production-web-image.yml", "utf8")); const job = workflow.jobs.publish;
  assert.deepEqual(Object.keys(workflow.on.workflow_dispatch.inputs), ["release_sha"]); assert.equal(job.environment, WEB_RELEASE.environment); assert.equal(job.permissions["id-token"], "write");
  const serialized = JSON.stringify(workflow); for (const forbidden of ["inputs.repository", "inputs.dockerfile", "inputs.platform", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"]) assert.doesNotMatch(serialized, new RegExp(forbidden));
  for (const required of ["mscqr-web", "Dockerfile.ecs-frontend", "linux/amd64", "368992683803", "eu-west-2", "PRODUCTION_WEB_IMAGE_PUBLISH_ROLE"]) assert.match(serialized, new RegExp(required.replaceAll(".", "\\.")));
  const build = job.steps.find(({ name }) => name === "Publish exact immutable web image").run;
  assert.match(build, /--build-arg "GIT_SHA=\$IMAGE_TAG"/);
  assert.match(build, /--build-arg "RELEASE_GIT_SHA=\$IMAGE_TAG"/);
  const signing = job.steps.find(({ name }) => name === "Sign and attest immutable web image");
  assert.match(signing.env.COSIGN_CERT_IDENTITY_REGEXP, /production-web-image/);
  assert.equal(signing.env.COSIGN_CERT_OIDC_ISSUER, "https://token.actions.githubusercontent.com");
  assert.match(fs.readFileSync("scripts/aws/cosign-idempotent-sign-and-attest.sh", "utf8"), /production-web-provenance\/v1/);
  const binding = job.steps.find(({ name }) => name === "Bind protected workflow and release source");
  assert.match(binding.run, /git merge-base --is-ancestor "\$IMAGE_TAG" "\$protected_main_sha"/);
  assert.match(binding.run, /git cat-file -e "\$IMAGE_TAG\^\{commit\}"/);
  assert.match(binding.run, /\[\[ "\$IMAGE_TAG" =~ \^\[0-9a-f\]\{40\}\$ \]\]/);
  assert.match(binding.run, /\[\[ "\$WORKFLOW_DEFINITION_SHA" =~ \^\[0-9a-f\]\{40\}\$ \]\]/);
  assert.equal(job.steps.find(({ uses, with: options }) => uses === "actions/checkout@v6" && options?.path === "release-source").with.ref, "${{ inputs.release_sha }}");
  assert.equal(job.env.WORKFLOW_DEFINITION_SHA, "${{ github.sha }}");
  const publisher = JSON.parse(fs.readFileSync("infra/aws/terraform/production-web-release/publisher-permissions-policy.json")); const allowedResources = publisher.Statement.filter(({ Effect }) => Effect === "Allow").flatMap(({ Resource }) => Array.isArray(Resource) ? Resource : [Resource]); assert.equal(allowedResources.some((resource) => String(resource).includes("mscqr-backend") || String(resource).includes("mscqr-worker")), false);
  const activation = JSON.parse(fs.readFileSync("infra/aws/terraform/production-web-release/frontend-activation-policy.json"));
  const register = activation.Statement.find(({ Action }) => Action === "ecs:RegisterTaskDefinition"); assert.equal(register.Resource, "*"); assert.deepEqual(register.Condition, { StringEquals: { "aws:RequestedRegion": "eu-west-2" } });
  const tag = activation.Statement.find(({ Action }) => Action === "ecs:TagResource"); assert.equal(tag.Resource, `arn:aws:ecs:${WEB_RELEASE.region}:${WEB_RELEASE.account}:task-definition/${WEB_RELEASE.family}:*`); assert.deepEqual(tag.Condition, { StringEquals: { "aws:RequestedRegion": WEB_RELEASE.region, "ecs:CreateAction": "RegisterTaskDefinition" } });
  const passRole = activation.Statement.find(({ Action }) => Action === "iam:PassRole"); assert.deepEqual(passRole.Resource, [`arn:aws:iam::${WEB_RELEASE.account}:role/mscqr-ecs-execution-role`, `arn:aws:iam::${WEB_RELEASE.account}:role/mscqr-ecs-task-role`]); assert.equal(passRole.Condition.StringEquals["iam:PassedToService"], "ecs-tasks.amazonaws.com");
  const runtimeRead = activation.Statement.find(({ Sid }) => Sid === "ReadExactFrontendRuntime"); assert.equal(runtimeRead.Action, "ecs:DescribeTasks"); assert.equal(runtimeRead.Resource, `arn:aws:ecs:${WEB_RELEASE.region}:${WEB_RELEASE.account}:task/${WEB_RELEASE.cluster}/*`); assert.equal(runtimeRead.Condition.ArnEquals["ecs:cluster"], `arn:aws:ecs:${WEB_RELEASE.region}:${WEB_RELEASE.account}:cluster/${WEB_RELEASE.cluster}`);
  const runtimeList = activation.Statement.find(({ Sid }) => Sid === "ListExactFrontendRuntime"); assert.equal(runtimeList.Action, "ecs:ListTasks"); assert.equal(runtimeList.Condition.ArnEquals["ecs:cluster"], `arn:aws:ecs:${WEB_RELEASE.region}:${WEB_RELEASE.account}:cluster/${WEB_RELEASE.cluster}`);
  assert.equal(JSON.stringify(activation).includes("ecs:ExecuteCommand"), false);
  const activationWorkflow = yaml.load(fs.readFileSync(".github/workflows/production-web-activation.yml", "utf8")); const serializedActivation = JSON.stringify(activationWorkflow); for (const fixed of ["verify-production-web-release-authorization.mjs", "run-production-web-activation.mjs"]) assert.match(serializedActivation, new RegExp(fixed.replaceAll(".", "\\.")));
  assert.equal(activationWorkflow.concurrency.group, yaml.load(fs.readFileSync(".github/workflows/release-gate.yml", "utf8")).concurrency.group); assert.equal(activationWorkflow.concurrency["cancel-in-progress"], false);
  for (const input of ["backend_activation_evidence_json", "backend_activation_evidence_sha256"]) assert.ok(activationWorkflow.on.workflow_dispatch.inputs[input]);
  assert.match(serializedActivation, /MSCQR_AWS_CREDENTIAL_SOURCE.*github-oidc-release-deployer/);
  for (const forbidden of ["inputs.service", "inputs.task_definition", "inputs.image", "inputs.rollback", "execute-command"]) assert.doesNotMatch(serializedActivation, new RegExp(forbidden));
  const fourImage = fs.readFileSync("scripts/aws/production-green-stage-b-image-evidence.mjs", "utf8"); assert.match(fourImage, /exactly four image records|all four Stage B images/);
});

test("web activation uses only the sanitized GitHub OIDC release-deployer session", () => {
  const hostile = {
    AWS_PROFILE: "arbitrary", AWS_DEFAULT_PROFILE: "arbitrary-default",
    AWS_CONFIG_FILE: "/hostile/config", AWS_SHARED_CREDENTIALS_FILE: "/hostile/credentials",
    AWS_ROLE_ARN: "arn:aws:iam::111111111111:role/hostile", AWS_WEB_IDENTITY_TOKEN_FILE: "/hostile/token",
    AWS_CONTAINER_CREDENTIALS_FULL_URI: "https://hostile.invalid", AWS_CONTAINER_CREDENTIALS_RELATIVE_URI: "/hostile",
    AWS_EC2_METADATA_SERVICE_ENDPOINT: "https://hostile.invalid", AWS_ENDPOINT_URL: "https://hostile.invalid",
  };
  const session = { MSCQR_AWS_CREDENTIAL_SOURCE: "github-oidc-release-deployer", AWS_ACCESS_KEY_ID: "fixture-access", AWS_SECRET_ACCESS_KEY: "fixture-secret", AWS_SESSION_TOKEN: "fixture-session", PATH: process.env.PATH };
  const calls = [];
  const run = createWebActivationAwsRunner({ env: { ...session, ...hostile }, exec: (file, args, options) => { calls.push({ file, args, options }); return "{}"; } });
  run(["ecs", "describe-services"]);
  assert.equal(calls.length, 1); assert.equal(calls[0].file, "aws");
  assert.deepEqual(calls[0].args.slice(-5), ["--output", "json", "--no-cli-pager", "--region", "eu-west-2"]);
  assert.equal(calls[0].options.env.AWS_EC2_METADATA_DISABLED, "true");
  for (const key of Object.keys(hostile)) assert.equal(calls[0].options.env[key], undefined, key);
  for (const key of ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"]) assert.equal(calls[0].options.env[key], session[key]);

  const never = () => assert.fail("invalid credentials must fail before AWS execution");
  for (const env of [
    { AWS_PROFILE: "arbitrary" }, { AWS_DEFAULT_PROFILE: "arbitrary" },
    { AWS_ACCESS_KEY_ID: "key", AWS_SECRET_ACCESS_KEY: "secret" },
    { AWS_ACCESS_KEY_ID: "key", AWS_SECRET_ACCESS_KEY: "secret", AWS_SESSION_TOKEN: "token" },
    { AWS_ROLE_ARN: hostile.AWS_ROLE_ARN, AWS_WEB_IDENTITY_TOKEN_FILE: hostile.AWS_WEB_IDENTITY_TOKEN_FILE },
    { AWS_EC2_METADATA_SERVICE_ENDPOINT: hostile.AWS_EC2_METADATA_SERVICE_ENDPOINT },
    { AWS_CONTAINER_CREDENTIALS_RELATIVE_URI: hostile.AWS_CONTAINER_CREDENTIALS_RELATIVE_URI },
    { ...session, MSCQR_AWS_CREDENTIAL_SOURCE: "unknown" },
  ]) assert.throws(() => createWebActivationAwsRunner({ env, exec: never }), /GitHub OIDC release-deployer|AWS_/);
});

test("both governed activation callers establish the canonical credential source", () => {
  const releaseGate = yaml.load(fs.readFileSync(".github/workflows/release-gate.yml", "utf8"));
  const activation = releaseGate.jobs["deploy-production-ecs"].steps.find(({ name }) => name === "Activate authenticated frontend image");
  assert.equal(activation.env.MSCQR_AWS_CREDENTIAL_SOURCE, "github-oidc-release-deployer");
  const standalone = yaml.load(fs.readFileSync(".github/workflows/production-web-activation.yml", "utf8"));
  assert.match(JSON.stringify(standalone), /MSCQR_AWS_CREDENTIAL_SOURCE.*github-oidc-release-deployer/);
});

test("standalone activation accepts an authenticated retained target under current protected tooling", () => {
  const workflow = fs.readFileSync(".github/workflows/production-web-activation.yml", "utf8");
  assert.match(workflow, /WORKFLOW_DEFINITION_SHA: '\$\{\{ github\.sha \}\}'/);
  assert.match(workflow, /test "\$GITHUB_SHA" = "\$WORKFLOW_DEFINITION_SHA"/);
  assert.doesNotMatch(workflow, /test "\$GITHUB_SHA" = "\$TARGET_SHA"/);
  assert.match(workflow, /git cat-file -e "\$TARGET_SHA\^\{commit\}"/);
  assert.match(workflow, /git merge-base --is-ancestor "\$TARGET_SHA" "\$protected_main_sha"/);
  assert.match(workflow, /git merge-base --is-ancestor "\$WORKFLOW_DEFINITION_SHA" "\$protected_main_sha"/);
});

test("release gate reserves web authorization before the database mutation boundary", () => {
  const workflow = yaml.load(fs.readFileSync(".github/workflows/release-gate.yml", "utf8"));
  const steps = workflow.jobs["deploy-production-ecs"].steps;
  const database = steps.findIndex(({ name }) => name === "Apply and verify checksum-bound production RLS package");
  const step = steps[database];
  assert.match(step.run, /--reserve-downstream-lifetime/);
  assert.match(step.run, /verify-production-web-release-authorization\.mjs/);
  assert.match(step.run, /steps\.images\.outputs\.web_required/);
  assert.ok(database > -1);
});

test("web publication resumes immutable tags through the reviewed digest-bound preflight", () => {
  const workflow = yaml.load(fs.readFileSync(".github/workflows/production-web-image.yml", "utf8"));
  const publish = workflow.jobs.publish.steps.find(({ name }) => name === "Publish exact immutable web image").run;
  assert.match(publish, /describe-images/);
  assert.match(publish, /ImageNotFoundException/);
  assert.match(publish, /resolveWebImagePublication/);
  assert.match(publish, /image_ref=.*@\$digest/);
  assert.match(publish, /if \[\[ "\$image_state" == absent \]\]; then\n\s+docker buildx build[\s\S]*?--push/);
  assert.match(publish, /verify-image-manifest\.sh"? "\$image_ref"/);
});
