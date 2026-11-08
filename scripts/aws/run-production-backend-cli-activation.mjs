#!/usr/bin/env node
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { parseArgs } from "node:util";
import { fileURLToPath, pathToFileURL } from "node:url";
import { APP_ONLY, APP_ONLY_DOMAINS, buildAppOnlyCandidate, captureAppOnlyPredecessor } from "./production-app-only-contract.mjs";
import { createAppOnlyEcsReaders, createAppOnlyActivationAdapters } from "./production-app-only-adapters.mjs";
import { executeAppOnlyActivation } from "./production-app-only-activation.mjs";
import { createAppOnlyEvidenceWriter, downloadAppOnlyArtifact, parseAppOnlyArtifactReference } from "./production-app-only-artifacts.mjs";
import { authenticateAppOnlyImages } from "./production-app-only-images.mjs";
import { deriveAppOnlyImpact } from "./production-app-only-impact.mjs";
import { assertAppOnlyRequirements } from "./production-app-only-requirements.mjs";
import { assertBackendCliActivationAuthorization } from "./production-backend-cli-authorization.mjs";
import { createProductionAwsCommandRunner, createProductionGithubCommandRunner, PRODUCTION_AWS_CREDENTIAL_SOURCE } from "./production-credential-source-contract.mjs";
import { createProductionEnvironmentApprovalEvidence, PRODUCTION_ENVIRONMENT_APPROVAL } from "./production-github-environment-approval.mjs";
import { canonicalSha256, PRODUCTION_ACTIVATION_LIFECYCLE } from "./production-green-stage-b-contract.mjs";
import { assertProtectedCheckout } from "./prepare-production-initial-activation-reconciler-installation.mjs";

const root = fileURLToPath(new URL("../../", import.meta.url));
const repository = PRODUCTION_ENVIRONMENT_APPROVAL.repository;
const readJson = (value) => JSON.parse(value);
const reviewedCandidate = "cbbb353bbae5f5a642871e90a79e76a4eb12aa82";
const reviewedPredecessorTag = "187326f3c85aecc55a7affd26e09c1850d9a0a33-connector-2026.11.6.2";
const reviewedUnknownPaths = new Set([
  "scripts/release/generate-rf7-contract-inventory.mjs", "src/contexts/AuthContext.tsx",
  "src/features/dashboard/hooks.ts", "src/features/dashboard/realtime-cache.ts", "src/lib/api/internal-client-core.ts",
  "src/lib/printer-user-facing.ts", "src/pages/Dashboard.tsx",
  "src/test/auth-bootstrap-reload.test.tsx", "src/test/auth-scope-refresh.test.tsx",
  "src/test/batch-allocation-cache.test.tsx", "src/test/dashboard-independent-stats.test.tsx",
  "src/test/dashboard-manufacturer-scope.test.tsx", "src/test/dashboard-rate-limit.test.tsx",
  "src/test/internal-client-core.test.ts", "src/test/printer-user-facing.test.ts",
]);
export const createBackendCliAwsRunner = (exec = execFileSync) => createProductionAwsCommandRunner({
  credentialSource: PRODUCTION_AWS_CREDENTIAL_SOURCE.NAMED_PROFILE, profile: "mscqr-ops-admin",
  exec: (file, args, options) => exec(file, args, { ...options,
    env: { ...options.env, AWS_MAX_ATTEMPTS: "1", AWS_RETRY_MODE: "standard" } }),
});

export function assertBackendCliSourceImpact(impact) {
  assert.equal(impact.candidateSourceSha, reviewedCandidate, "CLI route is limited to the reviewed backend candidate");
  assert.ok(impact.liveToCandidate.unknown.every((file) => reviewedUnknownPaths.has(file)), "Unreviewed live-to-candidate source path");
  assert.equal(impact.candidateToProtected.sourceClassificationComplete, true, "Unclassified candidate-to-tooling source path");
  for (const range of [impact.liveToCandidate, impact.candidateToProtected]) {
    assert.deepEqual(Object.keys(range.changed).sort(), [...APP_ONLY_DOMAINS].sort(), "Incomplete source impact domains");
    assert.ok(Object.values(range.changed).every((changed) => changed === false), "Infrastructure, SQL or RLS change requires its separate release route");
  }
  return impact;
}

export function readBackendCliPredecessorSource(run, digest) {
  assert.match(digest || "", /^sha256:[a-f0-9]{64}$/);
  const response = readJson(run(["ecr", "describe-images", "--repository-name", "mscqr-backend",
    "--image-ids", `imageDigest=${digest}`, "--output", "json", "--no-cli-pager"]));
  assert.equal(response.imageDetails?.length, 1);
  const image = response.imageDetails[0];
  assert.equal(image.repositoryName, "mscqr-backend"); assert.equal(String(image.registryId), APP_ONLY.account);
  assert.equal(image.imageDigest, digest);
  assert.deepEqual(image.imageTags, [reviewedPredecessorTag], "Live predecessor source tag changed");
  return reviewedPredecessorTag.slice(0, 40);
}

export function assertBackendCliProbe(result, authorization) {
  assert.deepEqual(Object.keys(result || {}).sort(), ["status", "sourceSha", "candidateSourceSha", "probeImageDigest",
    "applicationImageDigest", "taskDefinitionArn", "taskArn", "classification", "deltaObjects", "requirementsSha256"].sort());
  assert.equal(result.status, "PRODUCTION_RLS_CATALOGUE_PROBED");
  assert.equal(result.sourceSha, authorization.sourceSha);
  assert.equal(result.candidateSourceSha, authorization.candidateSourceSha);
  assert.equal(result.applicationImageDigest, authorization.candidateDigest);
  assert.equal(result.requirementsSha256, authorization.requirementsSha256);
  assert.equal(result.classification, "MATCH"); assert.deepEqual(result.deltaObjects, []);
  assert.match(result.taskArn, /^arn:aws:ecs:eu-west-2:368992683803:task\/mscqr-prod-euw2-main\/[a-f0-9]{32}$/);
  assert.match(result.taskDefinitionArn, /^arn:aws:ecs:eu-west-2:368992683803:task-definition\/mscqr-production-app-only-compatibility-verifier:[1-9][0-9]*$/);
  return result;
}

export function assertBackendCliApprovalReadback(authorization, { run, environment, approvals, now = Date.now() }) {
  assertBackendCliActivationAuthorization(authorization, { run, now });
  assert.equal(run.run_attempt, 1, "Approval workflow rerun is not authorized");
  const approved = (Array.isArray(approvals) ? approvals : []).flatMap((event) =>
    event?.state === "approved" && (event.environments || []).some((item) => item?.id === environment?.id && item?.name === "production")
      ? [{ state: "approved", environmentId: environment.id, environmentName: "production", userId: event.user?.id, userLogin: event.user?.login }]
      : []);
  assert.equal(approved.length, 1, "Exactly one authenticated production review is required");
  const approval = authorization.approval;
  const observed = createProductionEnvironmentApprovalEvidence({ environmentConfig: environment,
    repository, environment: "production", sourceSha: authorization.sourceSha,
    workflowRef: PRODUCTION_ENVIRONMENT_APPROVAL.backendCliActivationWorkflowRef,
    eventName: "workflow_dispatch", workflowRunId: run.id, workflowRunAttempt: run.run_attempt,
    executionActor: run.actor.login, observedAt: approval.observedAt, actualApproval: approved[0] });
  assert.deepEqual(observed, approval, "Production review or environment configuration changed");
  return authorization;
}

const reviewReadback = (githubRun, authorization, run) => {
  const api = (endpoint) => readJson(githubRun("gh", ["api", `repos/${repository}/${endpoint}`]));
  return assertBackendCliApprovalReadback(authorization, { run,
    environment: api("environments/production"), approvals: api(`actions/runs/${run.id}/approvals`) });
};

export const reserveAuthorization = (run, authorization) => {
  const key = `production-backend-cli-activation/${authorization.authorizationSha256}/claim.json`;
  const body = { schemaVersion: 1, kind: "BACKEND_CLI_ACTIVATION_CLAIM", sourceSha: authorization.sourceSha,
    candidateSourceSha: authorization.candidateSourceSha, candidateDigest: authorization.candidateDigest,
    predecessorTaskDefinitionArn: authorization.predecessorTaskDefinitionArn,
    authorizationSha256: authorization.authorizationSha256 };
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-backend-cli-claim-"));
  try {
    fs.chmodSync(directory, 0o700);
    const file = path.join(directory, "claim.json");
    const bytes = Buffer.from(`${JSON.stringify(body)}\n`);
    fs.writeFileSync(file, bytes, { flag: "wx", mode: 0o600 });
    // Conditional create is the one-use distributed claim. An ambiguous result stops; never retry.
    run(["s3api", "put-object", "--bucket", PRODUCTION_ACTIVATION_LIFECYCLE.bucket,
      "--key", key, "--body", file, "--if-none-match", "*", "--server-side-encryption", "AES256", "--output", "json", "--no-cli-pager"]);
    const readback = path.join(directory, "readback.json");
    run(["s3api", "get-object", "--bucket", PRODUCTION_ACTIVATION_LIFECYCLE.bucket,
      "--key", key, readback, "--output", "json", "--no-cli-pager"]);
    assert.deepEqual(fs.readFileSync(readback), bytes, "Activation claim readback changed");
    return { key, sha256: canonicalSha256(body) };
  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
};

export async function runBackendCliActivation({ reference, profile = "mscqr-ops-admin", probeProfile = "default", journalDir,
  awsRun, githubRun = createProductionGithubCommandRunner(), probe = execFileSync, now = Date.now } = {}) {
  assert.equal(profile, "mscqr-ops-admin", "Root and alternate deployment profiles are forbidden");
  assert.equal(probeProfile, "default", "The bounded catalogue probe requires the approved root profile");
  assert.ok(path.isAbsolute(journalDir || ""), "A private external journal directory is required");
  const journalStat = fs.lstatSync(journalDir);
  const journalPath = fs.realpathSync(journalDir), checkoutPath = fs.realpathSync(root);
  assert.ok(journalStat.isDirectory() && !journalStat.isSymbolicLink() && (journalStat.mode & 0o077) === 0
    && journalPath !== checkoutPath && !journalPath.startsWith(checkoutPath + path.sep),
  "A private external journal directory is required");
  const run = awsRun || createBackendCliAwsRunner();
  const downloaded = downloadAppOnlyArtifact({ kind: "backendCliAuthorization", reference, repositoryRoot: root, githubRun });
  const authorization = readJson(downloaded.bytes.toString("utf8"));
  const assertFresh = () => {
    assertProtectedCheckout({ sourceSha: authorization.sourceSha, repositoryRoot: root });
    const main = readJson(githubRun("gh", ["api", `repos/${repository}/branches/main`]));
    assert.equal(main.protected, true); assert.equal(main.commit?.sha, authorization.sourceSha);
    reviewReadback(githubRun, authorization, downloaded.run);
  };
  assertFresh();
  const caller = readJson(run(["sts", "get-caller-identity", "--output", "json", "--no-cli-pager"]));
  assert.equal(caller.Account, APP_ONLY.account);
  assert.equal(caller.Arn, `arn:aws:iam::${APP_ONLY.account}:user/mscqr-ops-admin`);
  const readers = createAppOnlyEcsReaders(run);
  const live = readers.readLive();
  const predecessor = captureAppOnlyPredecessor(live);
  assert.equal(predecessor.taskDefinitionArn, authorization.predecessorTaskDefinitionArn);
  const predecessorSourceSha = readBackendCliPredecessorSource(run, predecessor.backendDigest);
  const impact = assertBackendCliSourceImpact(deriveAppOnlyImpact({ repositoryRoot: root, liveSourceSha: predecessorSourceSha,
    candidateSourceSha: authorization.candidateSourceSha, protectedSourceSha: authorization.sourceSha }));
  const authenticateImages = () => authenticateAppOnlyImages({ sourceSha: authorization.sourceSha,
    candidateDigest: authorization.candidateDigest, publicationReference: authorization.publicationReference,
    authorizationReference: authorization.imageAuthorizationReference, repositoryRoot: root, githubRun,
    run: (args) => run(args) });
  const images = authenticateImages();
  assert.equal(images.candidateSourceSha, authorization.candidateSourceSha);
  const requirementsBytes = downloadAppOnlyArtifact({ kind: "requirements", reference: authorization.requirementsReference,
    repositoryRoot: root, githubRun }).bytes;
  const requirements = readJson(requirementsBytes.toString("utf8"));
  assertAppOnlyRequirements(requirements, { sourceSha: authorization.sourceSha,
    candidateSourceSha: authorization.candidateSourceSha, repositoryRoot: root });
  assert.equal(requirements.requirementsSha256, authorization.requirementsSha256);
  const args = ["scripts/aws/probe-production-rls-catalogue.mjs", "--source-sha", authorization.sourceSha,
    "--candidate-source-sha", authorization.candidateSourceSha, "--candidate-digest", authorization.candidateDigest,
    "--publication-reference", JSON.stringify(authorization.publicationReference),
    "--image-authorization-reference", JSON.stringify(authorization.imageAuthorizationReference),
    "--requirements-reference", JSON.stringify(authorization.requirementsReference), "--aws-profile", probeProfile];
  assertFresh();
  const claim = reserveAuthorization(run, authorization);
  const probeResult = assertBackendCliProbe(readJson(probe(process.execPath, args, { cwd: root, encoding: "utf8", timeout: 15 * 60 * 1000, maxBuffer: 65536 })), authorization);
  const probeVerifiedAt = now();
  const body = { schemaVersion: 1, kind: "BACKEND_CLI_ACTIVATION_PREPARATION", sourceSha: authorization.sourceSha,
    candidateSourceSha: authorization.candidateSourceSha, predecessorSourceSha, candidateDigest: authorization.candidateDigest,
    predecessor, generatedAt: new Date(probeVerifiedAt).toISOString(),
    evidence: { authorization: authorization.authorizationSha256, images: images.evidenceSha256,
      requirements: requirements.requirementsSha256, probe: canonicalSha256(probeResult), impact: impact.impactSha256 },
    candidateDefinitionSha256: canonicalSha256(buildAppOnlyCandidate(live.definition, authorization.candidateDigest)) };
  const preparation = { ...body, preparationSha256: canonicalSha256(body) };
  const journal = createAppOnlyEvidenceWriter({ repositoryRoot: root, sourceSha: authorization.sourceSha,
    preparationSha256: preparation.preparationSha256, directory: journalDir });
  const writeEvidence = async (event) => {
    const local = journal.writeEvidence(event);
    const key = `production-backend-cli-activation/${authorization.authorizationSha256}/journal/${path.basename(local.path)}`;
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-backend-cli-readback-"));
    try {
      fs.chmodSync(directory, 0o700);
      run(["s3api", "put-object", "--bucket", PRODUCTION_ACTIVATION_LIFECYCLE.bucket,
        "--key", key, "--body", local.path, "--if-none-match", "*", "--server-side-encryption", "AES256", "--output", "json", "--no-cli-pager"]);
      const readback = path.join(directory, "journal.json");
      run(["s3api", "get-object", "--bucket", PRODUCTION_ACTIVATION_LIFECYCLE.bucket,
        "--key", key, readback, "--output", "json", "--no-cli-pager"]);
      assert.deepEqual(fs.readFileSync(readback), fs.readFileSync(local.path), "Deployment journal readback changed");
    } finally { fs.rmSync(directory, { recursive: true, force: true }); }
  };
  const authenticate = async () => {
    assertFresh();
    assert.ok(now() - probeVerifiedAt <= APP_ONLY.maxEvidenceAgeMs, "Database compatibility evidence expired");
    authenticateImages();
  };
  await authenticate();
  await writeEvidence({ status: "CLAIM_INTENT", sourceSha: authorization.sourceSha,
    preparationSha256: preparation.preparationSha256, authorizationSha256: authorization.authorizationSha256 });
  await writeEvidence({ status: "CLAIMED", claim });
  return executeAppOnlyActivation(preparation, createAppOnlyActivationAdapters({ run, preparation,
    authenticate, writeEvidence }));
}

if (process.argv[1] && pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url) {
  try {
    const { values } = parseArgs({ options: { "authorization-reference": { type: "string" }, "aws-profile": { type: "string" },
      "probe-aws-profile": { type: "string" }, "journal-dir": { type: "string" } }, strict: true });
    const result = await runBackendCliActivation({ reference: parseAppOnlyArtifactReference(values["authorization-reference"]),
      profile: values["aws-profile"], probeProfile: values["probe-aws-profile"], journalDir: values["journal-dir"] });
    process.stdout.write(`${JSON.stringify({ status: result.status, candidateTaskDefinition: result.candidateTaskDefinition,
      deployedBackendDigest: result.deployedBackendDigest, journalDir: values["journal-dir"] })}\n`);
  } catch {
    process.stderr.write("Backend CLI activation stopped. Preserve the journal; do not retry an ambiguous mutation.\n");
    process.exitCode = 1;
  }
}
