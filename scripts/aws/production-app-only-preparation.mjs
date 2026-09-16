import assert from "node:assert/strict";
import { APP_ONLY, APP_ONLY_DOMAINS, assertAppOnlyEvidenceIdentity, captureAppOnlyPredecessor, assertAppOnlyCas,
  buildAppOnlyCandidate, appOnlyDefinitionSha256, assertAppOnlySessionRiskConfiguration } from "./production-app-only-contract.mjs";
import { canonicalSha256 } from "./production-green-stage-b-contract.mjs";
import { deriveAppOnlyImpact } from "./production-app-only-impact.mjs";
import { assertAppOnlyRequirements } from "./production-app-only-requirements.mjs";
import { buildAppOnlyVerifierCommand, buildAppOnlyVerifierDefinition, authenticateAppOnlyVerifierResult } from "./production-app-only-verifier-command.mjs";
import { APP_ONLY_VERIFIER, appOnlyVerifierNetwork } from "./production-app-only-policy.mjs";
import { createAppOnlyEcsReaders, readAppOnlyVerifierResult } from "./production-app-only-adapters.mjs";
import { authenticateAppOnlyImages, APP_ONLY_SESSION_RISK_CONTRACT } from "./production-app-only-images.mjs";
import { collectAppOnlyLiveIamCompatibility, collectAppOnlyVerifierIamCompatibility } from "./production-app-only-iam-source.mjs";
import { collectAppOnlyRuntimeCompatibility } from "./production-app-only-runtime.mjs";
import { downloadAppOnlyArtifact } from "./production-app-only-artifacts.mjs";
import { createProductionGithubCommandRunner } from "./production-credential-source-contract.mjs";
import { assertProtectedCheckout } from "./prepare-production-initial-activation-reconciler-installation.mjs";

// Read-only composition: expectation files and compatibility reports are never
// accepted from the caller. Only compact authenticated artifact references enter;
// IAM/runtime observations are collected afresh under the preparation identity.
export async function collectAppOnlyVerifierPreparation({ sourceSha, candidateDigest, publicationReference,
  authorizationReference, requirementsReference, repositoryRoot, run, githubRun = createProductionGithubCommandRunner() }) {
  assert.equal(typeof run, "function"); assert.match(sourceSha || "", /^[a-f0-9]{40}$/);
  assert.equal(requirementsReference.sourceSha, sourceSha);
  const source = () => {
    assertProtectedCheckout({ sourceSha, repositoryRoot });
    const main = JSON.parse(githubRun("gh", ["api", "repos/T-ej2003/genuine-scan-main/branches/main"]));
    assert.equal(main.name, "main"); assert.equal(main.protected, true); assert.equal(main.commit?.sha, sourceSha);
  };
  source();
  const aws = (args) => {
    const value = run([...args, "--output", "json", "--no-cli-pager"]);
    return typeof value === "string" ? JSON.parse(value) : value;
  };
  const readers = createAppOnlyEcsReaders(run);
  const live = readers.readLive(), predecessor = captureAppOnlyPredecessor(live);
  const images = authenticateAppOnlyImages({ sourceSha, candidateDigest, publicationReference, authorizationReference, repositoryRoot, run, githubRun });
  const requirementArtifact = downloadAppOnlyArtifact({ kind: "requirements", reference: requirementsReference, repositoryRoot, githubRun });
  const requirements = assertAppOnlyRequirements(JSON.parse(requirementArtifact.bytes), { sourceSha, candidateSourceSha: images.candidateSourceSha, repositoryRoot });
  const identity = { sourceSha, candidateSourceSha: images.candidateSourceSha, candidateDigest,
    account: APP_ONLY.account, region: APP_ONLY.region, clusterArn: APP_ONLY.clusterArn, serviceArn: APP_ONLY.serviceArn,
    predecessorTaskDefinition: predecessor.taskDefinitionArn, predecessorBackendDigest: predecessor.backendDigest };
  const iam = collectAppOnlyLiveIamCompatibility({ repositoryRoot, identity, run });
  const candidate = buildAppOnlyCandidate(live.definition, candidateDigest);
  const runtime = await collectAppOnlyRuntimeCompatibility({ identity, candidate, predecessor, readLive: readers.readLive, aws, repositoryRoot });
  const secret = aws(["secretsmanager", "describe-secret", "--secret-id", APP_ONLY_VERIFIER.databaseSecretName]);
  assert.equal(secret.Name, APP_ONLY_VERIFIER.databaseSecretName); assert.equal(secret.DeletedDate, undefined);
  assert.match(secret.ARN || "", new RegExp(`^arn:aws:secretsmanager:${APP_ONLY.region}:${APP_ONLY.account}:secret:${APP_ONLY_VERIFIER.databaseSecretName}-[A-Za-z0-9]{6}$`));
  const verifierIam = collectAppOnlyVerifierIamCompatibility({ repositoryRoot, identity, databaseSecretArn: secret.ARN, run });
  assertAppOnlyCas(predecessor, captureAppOnlyPredecessor(readers.readLive())); source();
  const preparation = prepareAppOnlyVerifier({ sourceSha, live, images, iam, verifierIam, runtime, requirements, repositoryRoot, databaseSecretArn: secret.ARN });
  return { schemaVersion: 1, kind: "APP_ONLY_VERIFIER_INPUTS", preparation,
    images, iam, verifierIam, runtime, requirements, requirementsReference: structuredClone(requirementsReference) };
}

export async function collectAppOnlyDeploymentPreparation({ sourceSha, compatibilityReference, repositoryRoot, run, githubRun = createProductionGithubCommandRunner() }) {
  assert.equal(compatibilityReference.sourceSha, sourceSha);
  const artifact = downloadAppOnlyArtifact({ kind: "compatibility", reference: compatibilityReference, repositoryRoot, githubRun });
  const compatibility = JSON.parse(artifact.bytes);
  const { resultSha256, ...body } = compatibility;
  assert.equal(resultSha256, canonicalSha256(body));
  assert.equal(body.schemaVersion, 1); assert.equal(body.kind, "APP_ONLY_VERIFIED_COMPATIBILITY"); assert.equal(body.sourceSha, sourceSha);
  const readers = createAppOnlyEcsReaders(run), live = readers.readLive();
  const verifier = authenticateAppOnlyVerifierInputs({ inputs: body.inputs, sourceSha, live, repositoryRoot });
  const age = Date.now() - Date.parse(body.generatedAt);
  assert.ok(Number.isFinite(age) && age >= 0 && age <= APP_ONLY.maxEvidenceAgeMs, "Stale verifier execution artifact");
  assert.equal(body.registration.taskDefinitionArn, body.taskDefinitionArn);
  assert.equal(body.registration.preparationSha256, body.inputs.preparation.preparationSha256);
  assert.match(body.taskArn || "", new RegExp(`^arn:aws:ecs:${APP_ONLY.region}:${APP_ONLY.account}:task/${APP_ONLY.cluster}/[a-f0-9]{32}$`));
  const taskResponse = JSON.parse(run(["ecs", "describe-tasks", "--cluster", APP_ONLY.clusterArn, "--tasks", body.taskArn, "--output", "json", "--no-cli-pager"]));
  assert.equal((taskResponse.failures || []).length, 0); assert.equal(taskResponse.tasks?.length, 1);
  const task = taskResponse.tasks[0]; assert.equal(task.taskArn, body.taskArn); assert.equal(task.taskDefinitionArn, body.taskDefinitionArn);
  const database = await readAppOnlyVerifierResult({ run, verifier, execution: { task, verificationContractSha256: body.inputs.preparation.verificationContractSha256 } });
  assert.deepEqual(database, body.database, "Verifier artifact no longer matches the exact observed task output");
  const fresh = await collectAppOnlyVerifierPreparation({ sourceSha, candidateDigest: body.inputs.images.candidateDigest,
    publicationReference: body.inputs.images.publicationReference, authorizationReference: body.inputs.images.authorizationReference,
    requirementsReference: body.inputs.requirementsReference, repositoryRoot, run, githubRun });
  assertAppOnlyCas(body.inputs.preparation.predecessor, fresh.preparation.predecessor);
  const current = readers.readLive(); assertAppOnlyCas(fresh.preparation.predecessor, captureAppOnlyPredecessor(current));
  const releaseMetadata = current.definition.containerDefinitions.find(({ name }) => name === APP_ONLY.container).environment?.filter(({ name }) => name === "RELEASE_GIT_SHA");
  assert.equal(releaseMetadata?.length, 1, "Historical release metadata is unavailable for impact enumeration");
  const predecessorSourceSha = releaseMetadata[0].value; assert.match(predecessorSourceSha || "", /^[a-f0-9]{40}$/);
  // Retained metadata can over-enumerate historical changes after image-only
  // deployments. It is never image provenance or an unchanged-domain waiver:
  // prepareAppOnlyDeployment requires positive CURRENT proof for all domains.
  const preparation = prepareAppOnlyDeployment({ ...fresh, sourceSha, predecessorSourceSha, live: current, database, repositoryRoot });
  return { schemaVersion: 1, kind: "APP_ONLY_DEPLOYMENT_INPUTS", preparation, inputs: fresh, database,
    compatibilityReference, verifierTaskArn: body.taskArn, verifierTaskDefinitionArn: body.taskDefinitionArn };
}

// Internal producer closure, not a public JSON approval API. Every report must
// first come from its canonical collector or authenticated workflow artifact.
// The deployer consumes only the exact preparation producer's immutable artifact.
function authenticatePreparationInputs({ sourceSha, live, images, iam, runtime,
  requirements, repositoryRoot, now = Date.now() }) {
  const predecessor = captureAppOnlyPredecessor(live);
  const { evidenceSha256: imageHash, ...imageBody } = images;
  assert.equal(imageHash, canonicalSha256(imageBody));
  assert.equal(images.kind, "APP_ONLY_AUTHENTICATED_IMAGES"); assert.equal(images.schemaVersion, 1);
  assert.equal(images.sourceSha, sourceSha);
  assert.deepEqual(images.sessionRisk, APP_ONLY_SESSION_RISK_CONTRACT, "Session-risk source proof is missing");
  const identity = { sourceSha, candidateSourceSha: images.candidateSourceSha, candidateDigest: images.candidateDigest,
    account: APP_ONLY.account, region: APP_ONLY.region, clusterArn: APP_ONLY.clusterArn, serviceArn: APP_ONLY.serviceArn,
    predecessorTaskDefinition: predecessor.taskDefinitionArn, predecessorBackendDigest: predecessor.backendDigest };
  const age = now - Date.parse(images.generatedAt);
  assert.ok(Number.isFinite(age) && age >= 0 && age <= APP_ONLY.maxEvidenceAgeMs, "Stale image readback");
  for (const report of [iam, runtime]) {
    assertAppOnlyEvidenceIdentity(report, identity, now);
    assert.equal(report.status, "ALREADY_APPLIED_COMPATIBLE");
  }
  assert.equal(iam.kind, "APP_ONLY_LIVE_IAM_COMPATIBILITY"); assert.equal(iam.sourceToLiveIamSemanticDifferences, 0);
  assert.equal(iam.scope, "BACKEND_RUNTIME_ROLES"); assert.equal(runtime.kind, "APP_ONLY_RUNTIME_COMPATIBILITY");
  assertAppOnlyRequirements(requirements, { sourceSha, candidateSourceSha: images.candidateSourceSha, repositoryRoot });
  const verifierIdentity = { ...identity, verifierImageDigest: images.candidateDigest,
    databaseHostname: runtime.networkDatabase.databaseHostname };
  const { verificationContractSha256 } = buildAppOnlyVerifierCommand({ requirements, identity: verifierIdentity, repositoryRoot });
  return { predecessor, identity, verifierIdentity, verificationContractSha256, imageHash };
}

// This is a request to verify, never compatibility proof or deployment approval.
// Registration/launch re-derive the task from these authenticated inputs; no
// dispatch input can replace its JSON, networking or command.
export function prepareAppOnlyVerifier(input) {
  const { sourceSha, live, images, iam, runtime, requirements, repositoryRoot, databaseSecretArn, now = Date.now() } = input;
  const { predecessor, identity, verifierIdentity, imageHash } = authenticatePreparationInputs(input);
  assertAppOnlyEvidenceIdentity(input.verifierIam, identity, now);
  assert.equal(input.verifierIam.kind, "APP_ONLY_LIVE_IAM_COMPATIBILITY");
  assert.equal(input.verifierIam.scope, "READ_ONLY_VERIFIER_ROLES");
  assert.equal(input.verifierIam.status, "ALREADY_APPLIED_COMPATIBLE");
  assert.equal(input.verifierIam.sourceToLiveIamSemanticDifferences, 0);
  assert.equal(input.verifierIam.databaseSecretArn, databaseSecretArn);
  const { definition, verificationContractSha256 } = buildAppOnlyVerifierDefinition({ requirements, identity: verifierIdentity, repositoryRoot, databaseSecretArn });
  const body = { schemaVersion: 1, kind: "APP_ONLY_VERIFIER_PREPARATION", sourceSha,
    generatedAt: new Date(now).toISOString(), identity: verifierIdentity, predecessor,
    definitionSha256: canonicalSha256(definition), networkSha256: canonicalSha256(appOnlyVerifierNetwork()),
    databaseSecretArn, verificationContractSha256,
    evidence: { images: imageHash, iam: iam.evidenceSha256, verifierIam: input.verifierIam.evidenceSha256, runtime: runtime.evidenceSha256, requirements: requirements.requirementsSha256 },
    eligible: false };
  // Also reject an unusable backend candidate before requesting production work.
  buildAppOnlyCandidate(live.definition, images.candidateDigest);
  return { ...body, preparationSha256: canonicalSha256(body) };
}

// Recompute the semantic closure from an authenticated producer envelope and
// CURRENT ECS observations. No caller-provided task JSON becomes registration
// authority. A content hash alone is not sufficient: the caller must use the
// exact workflow/artifact downloader before entering this function.
export function authenticateAppOnlyVerifierInputs({ inputs, sourceSha, live, repositoryRoot, now = Date.now() }) {
  assert.deepEqual(Object.keys(inputs).sort(), ["schemaVersion", "kind", "preparation", "images", "iam", "verifierIam", "runtime", "requirements", "requirementsReference"].sort());
  assert.equal(inputs.schemaVersion, 1); assert.equal(inputs.kind, "APP_ONLY_VERIFIER_INPUTS");
  const { preparationSha256, ...approved } = inputs.preparation;
  assert.equal(preparationSha256, canonicalSha256(approved));
  assert.equal(approved.sourceSha, sourceSha);
  const age = now - Date.parse(approved.generatedAt);
  assert.ok(Number.isFinite(age) && age >= 0 && age <= APP_ONLY.maxEvidenceAgeMs, "Stale verifier producer artifact");
  assertAppOnlyCas(approved.predecessor, captureAppOnlyPredecessor(live));
  const actual = prepareAppOnlyVerifier({ ...inputs, sourceSha, live, repositoryRoot, databaseSecretArn: approved.databaseSecretArn, now });
  const { preparationSha256: recomputed, ...body } = actual; void recomputed;
  body.generatedAt = approved.generatedAt;
  assert.deepEqual(body, approved, "Verifier producer closure was substituted");
  return { requirements: inputs.requirements, identity: approved.identity, repositoryRoot, databaseSecretArn: approved.databaseSecretArn };
}

export function prepareAppOnlyDeployment(input) {
  const { sourceSha, predecessorSourceSha, live, images, iam, runtime, database, requirements, repositoryRoot, now = Date.now() } = input;
  const { predecessor, identity, verifierIdentity, verificationContractSha256, imageHash } = authenticatePreparationInputs(input);
  authenticateAppOnlyVerifierResult({ message: JSON.stringify(database), identity: verifierIdentity,
    requirementsSha256: requirements.requirementsSha256, verificationContractSha256, now });
  const impact = deriveAppOnlyImpact({ repositoryRoot, liveSourceSha: predecessorSourceSha,
    candidateSourceSha: images.candidateSourceSha, protectedSourceSha: sourceSha });
  assert.ok(impact.liveToCandidate.sourceClassificationComplete && impact.candidateToProtected.sourceClassificationComplete,
    "Unclassified source changes cannot authorize application-only deployment");
  // Require all live domains even when a source delta appears unchanged. This
  // avoids treating retained task release-metadata variables as image provenance.
  // It is deliberately stricter than using historical source equality alone.
  const domains = Object.fromEntries(APP_ONLY_DOMAINS.map((name) => [name, "ALREADY_APPLIED_COMPATIBLE"]));
  const candidate = buildAppOnlyCandidate(live.definition, images.candidateDigest);
  const body = { schemaVersion: 1, kind: "APP_ONLY_DEPLOYMENT_PREPARATION", sourceSha,
    generatedAt: new Date(now).toISOString(), candidateSourceSha: images.candidateSourceSha, predecessorSourceSha,
    predecessorSourceProvenance: "RETAINED_TASK_RELEASE_METADATA_NOT_IMAGE_PROOF",
    candidateDigest: images.candidateDigest, predecessor, candidateDefinitionSha256: appOnlyDefinitionSha256(candidate),
    identity, impact, domains, eligible: true, sessionRisk: assertAppOnlySessionRiskConfiguration(live.definition),
    evidence: { images: imageHash, iam: iam.evidenceSha256, runtime: runtime.evidenceSha256,
      database: database.evidenceSha256, requirements: requirements.requirementsSha256, verificationContractSha256 } };
  return { ...body, preparationSha256: canonicalSha256(body) };
}

// Called only after exact producer provenance has been authenticated. Rebuild
// the approved semantic closure rather than trusting its eligible boolean.
export function authenticateAppOnlyDeploymentInputs({ inputs, sourceSha, live, repositoryRoot, now = Date.now() }) {
  assert.deepEqual(Object.keys(inputs).sort(), ["schemaVersion", "kind", "preparation", "inputs", "database",
    "compatibilityReference", "verifierTaskArn", "verifierTaskDefinitionArn"].sort());
  assert.equal(inputs.schemaVersion, 1); assert.equal(inputs.kind, "APP_ONLY_DEPLOYMENT_INPUTS");
  const { preparationSha256, ...approved } = inputs.preparation;
  assert.equal(preparationSha256, canonicalSha256(approved));
  assert.equal(approved.sourceSha, sourceSha);
  const age = now - Date.parse(approved.generatedAt);
  assert.ok(Number.isFinite(age) && age >= 0 && age <= APP_ONLY.maxEvidenceAgeMs, "Stale deployment preparation");
  authenticateAppOnlyVerifierInputs({ inputs: inputs.inputs, sourceSha, live, repositoryRoot, now });
  assertAppOnlyCas(approved.predecessor, captureAppOnlyPredecessor(live));
  const actual = prepareAppOnlyDeployment({ ...inputs.inputs, sourceSha, live, database: inputs.database,
    predecessorSourceSha: approved.predecessorSourceSha, repositoryRoot, now });
  const { preparationSha256: recomputed, ...body } = actual; void recomputed;
  body.generatedAt = approved.generatedAt;
  assert.deepEqual(body, approved, "Deployment producer closure was substituted");
  return inputs.preparation;
}
