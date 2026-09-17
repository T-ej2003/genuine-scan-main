import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";
import { WEB_RELEASE } from "../aws/production-web-release-contract.mjs";
import { buildGovernedWebImageAuthorization } from "../aws/production-web-image-authorization.mjs";
import { produceGovernedWebEvidence, readGovernedWebPublication } from "../aws/produce-production-web-image-evidence.mjs";

const sourceSha = "a".repeat(40); const digest = `sha256:${"b".repeat(64)}`; const now = "2026-09-17T12:00:00.000Z";
const hash = (value) => crypto.createHash("sha256").update(value).digest("hex");
const imageRef = `${WEB_RELEASE.account}.dkr.ecr.${WEB_RELEASE.region}.amazonaws.com/${WEB_RELEASE.repository}@${digest}`;
const sbom = Buffer.from('{"spdxVersion":"SPDX-2.3"}');
const provenance = Buffer.from(JSON.stringify({ releaseSha: sourceSha, workflowDefinitionSha: sourceSha, workflowRunId: "12", repository: "mscqr-web", platform: "linux/amd64", dockerfile: "Dockerfile.ecs-frontend", buildContext: "." }));
const artifactBytes = Buffer.from(`${JSON.stringify({ service: "frontend", repository: "mscqr-web", image_uri: `${WEB_RELEASE.account}.dkr.ecr.${WEB_RELEASE.region}.amazonaws.com/mscqr-web:${sourceSha}`, image_tag: sourceSha, image_digest: digest, image_ref: imageRef, platform: "linux/amd64", dockerfile: "Dockerfile.ecs-frontend", build_context: ".", critical_scan: "pass", sbom_sha256: hash(sbom), provenance_sha256: hash(provenance), cosign_signature_verified: true, sbom_attestation_verified: true, provenance_attestation_verified: true })}\n`);
const publication = Object.freeze({ observed: Object.freeze({ workflowRunId: "12", workflowDatabaseId: "34", workflowFile: WEB_RELEASE.workflowFile, workflowName: WEB_RELEASE.workflowName, event: "workflow_dispatch", workflowDefinitionSha: sourceSha, headBranch: "main", conclusion: "success", artifactId: "56", artifactName: WEB_RELEASE.artifactName, artifactExpired: false, reviewer: WEB_RELEASE.reviewer }), artifactBytes, sbomBytes: sbom, provenanceBytes: provenance });
const stageBAuthorization = Object.freeze({ imageReuseEvidence: Object.freeze({ schemaVersion: 1, toolingSha: sourceSha, webPublicationRequired: true, classifiedFiles: ["src/App.tsx"] }) });
const run = (args) => {
  if (args[0] === "sts") return JSON.stringify({ Arn: "arn:aws:iam::368992683803:root", Account: "368992683803" });
  if (args[0] === "ecr" && args[1] === "describe-repositories") return JSON.stringify({ repositories: [{ repositoryArn: `arn:aws:ecr:${WEB_RELEASE.region}:${WEB_RELEASE.account}:repository/${WEB_RELEASE.repository}`, repositoryName: WEB_RELEASE.repository, registryId: WEB_RELEASE.account, imageTagMutability: "IMMUTABLE", imageTagMutabilityExclusionFilters: [] }] });
  if (args[0] === "ecr" && args[1] === "describe-images") return JSON.stringify({ imageDetails: [{ imageDigest: digest, imagePushedAt: now }] });
  throw new Error(`unexpected AWS call ${args.join(" ")}`);
};
const verifyStageB = ({ authorization, sourceSha: actual }) => { assert.equal(authorization, stageBAuthorization); assert.equal(actual, sourceSha); return true; };

test("governed web publication authenticates one exact workflow artifact", () => {
  const archive = Buffer.from("fixed archive"); const github = (args, options = {}) => options.binary ? archive : JSON.stringify(args.at(-1).endsWith("/artifacts") ? { artifacts: [{ id: 56, name: WEB_RELEASE.artifactName, expired: false, digest: `sha256:${hash(archive)}` }] } : { id: 12, workflow_id: 34, path: WEB_RELEASE.workflowFile, name: WEB_RELEASE.workflowName, event: "workflow_dispatch", head_sha: sourceSha, head_branch: "main", conclusion: "success", actor: { login: WEB_RELEASE.reviewer } });
  const observed = readGovernedWebPublication({ sourceSha, workflowRunId: "12", github, extract: () => ({ artifactBytes, sbomBytes: sbom, provenanceBytes: provenance }) });
  assert.equal(observed.observed.artifactId, "56");
  assert.throws(() => readGovernedWebPublication({ sourceSha, workflowRunId: "12", github: (args, options) => options?.binary ? archive : JSON.stringify({ id: 12, workflow_id: 34, path: WEB_RELEASE.workflowFile, name: WEB_RELEASE.workflowName, event: "workflow_dispatch", head_sha: "c".repeat(40), head_branch: "main", conclusion: "success", actor: { login: WEB_RELEASE.reviewer }, artifacts: [] }), extract: () => ({ artifactBytes, sbomBytes: sbom, provenanceBytes: provenance }) }), /identity|artifacts/);
});

test("governed web evidence signs exactly once after authenticated publication and rejects drift before signing", () => {
  let signatures = 0;
  const result = produceGovernedWebEvidence({ sourceSha, stageBAuthorization, publication, run, now, verifyStageBAuthorization: verifyStageB, verifyArtifacts: (ref) => ref === imageRef, sign: () => { signatures += 1; return "AQ=="; }, verifyWebEvidence: () => true });
  assert.equal(signatures, 1); assert.equal(result.authorization.sourceSha, sourceSha); assert.equal(result.authorization.imageRef, imageRef);
  assert.throws(() => produceGovernedWebEvidence({ sourceSha, stageBAuthorization: { ...stageBAuthorization, imageReuseEvidence: { ...stageBAuthorization.imageReuseEvidence, webPublicationRequired: false } }, publication, run, now, verifyStageBAuthorization: () => true, verifyArtifacts: () => true, sign: () => { signatures += 1; return "AQ=="; }, verifyWebEvidence: () => true }), /web-required/);
  assert.equal(signatures, 1);
  assert.throws(() => produceGovernedWebEvidence({ sourceSha, stageBAuthorization, publication: { ...publication, provenanceBytes: Buffer.from("{}") }, run, now, verifyStageBAuthorization: verifyStageB, verifyArtifacts: () => true, sign: () => "AQ==", verifyWebEvidence: () => true }), /hashes|provenance/);
});

test("web authorization handoff accepts only the authenticated web-required Stage-B impact", () => {
  const result = produceGovernedWebEvidence({ sourceSha, stageBAuthorization, publication, run, now, verifyStageBAuthorization: verifyStageB, verifyArtifacts: () => true, sign: () => "AQ==", verifyWebEvidence: () => true });
  assert.equal(buildGovernedWebImageAuthorization({ sourceSha, evidence: result.evidence, signature: result.signature, stageBAuthorization, now, verify: () => true }).authorizationSha256, result.authorization.authorizationSha256);
  assert.throws(() => buildGovernedWebImageAuthorization({ sourceSha, evidence: result.evidence, signature: result.signature, stageBAuthorization: { ...stageBAuthorization, imageReuseEvidence: { ...stageBAuthorization.imageReuseEvidence, webPublicationRequired: false } }, now, verify: () => true }), /web-required/);
  assert.throws(() => buildGovernedWebImageAuthorization({ sourceSha, evidence: { ...result.evidence, reviewer: "other" }, signature: result.signature, stageBAuthorization, now, verify: () => true }), /web-required/);
});
