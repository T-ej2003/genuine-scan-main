import assert from "node:assert/strict";
import crypto from "node:crypto";
import { b03ApprovalMessage, b03TaskDefinitionSha256, authenticateB03BrokerRequest, B03_BROKER } from "../../infra/aws/terraform/lambda/production-rls-approval-broker/b03-approval.mjs";
import { canonicalSha256, STAGE_B } from "./production-green-stage-b-contract.mjs";
import { assertProtectedCheckout } from "./prepare-production-initial-activation-reconciler-installation.mjs";
import { authenticateCanonicalProductionRequirements } from "./probe-production-rls-catalogue.mjs";
import { downloadAppOnlyArtifact } from "./production-app-only-artifacts.mjs";
import { buildB03DeltaPackage } from "./production-b03-delta-package.mjs";
import { verifyProductionReleaseImageAuthorization } from "./verify-production-release-image-authorization.mjs";
import { verifyImageEvidenceSignature } from "./production-green-stage-b-image-evidence.mjs";
import { createProductionGithubCommandRunner } from "./production-credential-source-contract.mjs";
import { fileURLToPath } from "node:url";

// The issuer authenticates requirements, image provenance and task readback before
// invoking this signing boundary; the broker independently rechecks the fixed task.
export async function prepareB03Approval(input,
  { authenticateSourceAndPackage, caller, describeTaskDefinition, now = new Date(), nonce = crypto.randomUUID() } = {}) {
  const { sourceSha, backendImage, pkg, databaseHostname, taskDefinitionArn, ticketId } = input;
  assert.ok(Object.keys(input).every(key => ["operation", "sourceSha", "backendImage", "pkg", "databaseHostname", "taskDefinitionArn", "ticketId", "predecessorRequirementsReference", "successorRequirementsReference"].includes(key)), "B03 unknown approval input");
  assert.ok([authenticateSourceAndPackage, caller, describeTaskDefinition].every(fn => typeof fn === "function"));
  await authenticateSourceAndPackage({ sourceSha, backendImage, pkg });
  const checkerIdentity = (await caller()).Arn;
  const observed = await describeTaskDefinition(taskDefinitionArn);
  const approval = { schemaVersion: 1, operation: "PRODUCTION_B03_BROKER_APPROVAL", account: STAGE_B.account,
    region: STAGE_B.region, clusterArn: STAGE_B.clusterArn, approvalId: `APR-B03-${sourceSha}-${nonce}`,
    sourceSha, backendImage, taskDefinitionArn, taskDefinitionSha256: b03TaskDefinitionSha256(observed.taskDefinition),
    packageSha256: pkg.packageSha256, database: B03_BROKER.database, databaseHostname,
    predecessorCatalogue: pkg.predecessorCatalogue, successorCatalogue: pkg.successorCatalogue,
    ticketId, checkerIdentity, issuedAt: now.toISOString(), expiresAt: new Date(now.getTime() + 30 * 60_000).toISOString(),
    nonce, signatureBase64: "" };
  const request = { operation: B03_BROKER.mode, approval, package: pkg };
  // Validate all identity and task constraints before the one privileged Sign call.
  await authenticateB03BrokerRequest(request, { now, describeTaskDefinition: async () => observed, verifySignature: async () => true });
  return request;
}

export async function signB03Approval(input, deps) {
  assert.ok([deps.sign, deps.verifySignature].every(fn => typeof fn === "function"));
  const request = await prepareB03Approval(input, deps);
  await deps.authenticateSourceAndPackage(input);
  request.approval.signatureBase64 = await deps.sign({ keyId: STAGE_B.approvalKmsKeyArn, message: b03ApprovalMessage(request.approval) });
  await authenticateB03BrokerRequest(request, deps);
  return request;
}

export function createB03SourceAuthenticator({ input, imageAuthorization, runAws, repositoryRoot = fileURLToPath(new URL("../../", import.meta.url)), githubRun = createProductionGithubCommandRunner() }) {
  let authenticated;
  return async ({ sourceSha, backendImage, pkg }) => {
    assertProtectedCheckout({ sourceSha, repositoryRoot });
    const branch = JSON.parse(githubRun("gh", ["api", "repos/T-ej2003/genuine-scan-main/branches/main"]));
    assert.equal(branch.commit?.sha, sourceSha); assert.equal(branch.protected, true);
    const fingerprint = canonicalSha256({ sourceSha, backendImage, pkg, databaseHostname: input.databaseHostname,
      predecessor: input.predecessorRequirementsReference, successor: input.successorRequirementsReference });
    if (authenticated) { assert.equal(authenticated, fingerprint); return; }
    const successor = authenticateCanonicalProductionRequirements({ sourceSha, requirementsReference: input.successorRequirementsReference, repositoryRoot, githubRun }).requirements;
    const ref = input.predecessorRequirementsReference;
    assert.equal(ref?.sourceSha, "d785aa7f1e154f37c0dc621082e3f6c46d5d5aec");
    const predecessor = JSON.parse(downloadAppOnlyArtifact({ kind: "requirements", reference: ref, repositoryRoot, githubRun }).bytes);
    assert.equal(predecessor.sourceSha, ref.sourceSha); assert.equal(predecessor.candidateSourceSha, ref.sourceSha);
    assert.equal(canonicalSha256(pkg), canonicalSha256(buildB03DeltaPackage({ predecessor, successor, repositoryRoot })));
    const images = verifyProductionReleaseImageAuthorization({ authorization: imageAuthorization, sourceSha, minimumRemainingMs: 30 * 60_000,
      verifyImageEvidence: options => verifyImageEvidenceSignature({ ...options, run: runAws }) });
    assert.equal(images.backend, backendImage);
    const database = JSON.parse(runAws(["rds", "describe-db-instances", "--db-instance-identifier", "mscqr-production-rls-green-phase2", "--output", "json"])).DBInstances?.[0];
    assert.equal(database?.DBName, B03_BROKER.database); assert.equal(database?.DBInstanceStatus, "available");
    assert.equal(database?.Endpoint?.Address, input.databaseHostname);
    authenticated = fingerprint;
  };
}
