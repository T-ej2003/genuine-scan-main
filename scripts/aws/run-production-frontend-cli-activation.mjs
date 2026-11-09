#!/usr/bin/env node
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { parseArgs } from "node:util";
import { fileURLToPath, pathToFileURL } from "node:url";
import { APP_ONLY } from "./production-app-only-contract.mjs";
import { downloadAppOnlyArtifact, parseAppOnlyArtifactReference } from "./production-app-only-artifacts.mjs";
import { deriveAppOnlyImpact } from "./production-app-only-impact.mjs";
import { assertAppOnlyRequirements } from "./production-app-only-requirements.mjs";
import { assertBackendCliProbe } from "./run-production-backend-cli-activation.mjs";
import { createProductionAwsCommandRunner, createProductionGithubCommandRunner,
  PRODUCTION_AWS_CREDENTIAL_SOURCE } from "./production-credential-source-contract.mjs";
import { PRODUCTION_ENVIRONMENT_APPROVAL, createProductionEnvironmentApprovalEvidence } from "./production-github-environment-approval.mjs";
import { canonicalSha256, PRODUCTION_ACTIVATION_LIFECYCLE } from "./production-green-stage-b-contract.mjs";
import { assertProtectedCheckout } from "./prepare-production-initial-activation-reconciler-installation.mjs";
import { assertFrontendCliAuthorization } from "./production-frontend-cli-authorization.mjs";
import { WEB_RELEASE, assertWebImageAuthorization, runGovernedFrontendActivation,
  captureFrontendPredecessor } from "./production-web-release-contract.mjs";
import { createAwsFrontendActivationAdapters } from "./run-production-web-activation.mjs";
import { readGovernedWebPublication } from "./produce-production-web-image-evidence.mjs";
import { createPinnedRootAttestationVerifier } from "./production-root-attestation-key.mjs";
import { verifyProductionReleaseImageAuthorization } from "./verify-production-release-image-authorization.mjs";
import { verifyImageEvidenceSignature } from "./production-green-stage-b-image-evidence.mjs";
import { authenticateCompleteRlsProbeObservation, classifyProductionRlsCatalogue }
  from "./probe-production-rls-catalogue.mjs";

const root = fileURLToPath(new URL("../../", import.meta.url));
const repository = PRODUCTION_ENVIRONMENT_APPROVAL.repository;
const frontendTargetGroup = "arn:aws:elasticloadbalancing:eu-west-2:368992683803:targetgroup/mscqr-frontend-ecs-tg-euw2/ddafd2fc00ed732e";
const json = (value) => JSON.parse(value);
const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");

export function assertFrontendCliSourceImpact({ candidateSourceSha, sourceSha, repositoryRoot = root,
  derive = deriveAppOnlyImpact } = {}) {
  const impact = derive({ repositoryRoot, liveSourceSha: candidateSourceSha,
    candidateSourceSha, protectedSourceSha: sourceSha });
  const range = impact.candidateToProtected;
  assert.equal(range.sourceClassificationComplete, true, "Unclassified source path forbids frontend image reuse");
  assert.deepEqual(range.unknown, []);
  assert.deepEqual(range.application, [], "Frontend application changed after image publication");
  assert.ok(Object.values(range.changed).every((value) => value === false),
    "Security, database or infrastructure source change forbids frontend image reuse");
  return impact;
}

export function assertFrontendCliApprovalReadback(authorization, { run, environment, approvals, now = Date.now() }) {
  assertFrontendCliAuthorization(authorization, { run, now });
  assert.equal(run.run_attempt, 1, "Approval workflow rerun is not authorized");
  const approved = (Array.isArray(approvals) ? approvals : []).flatMap((event) =>
    event?.state === "approved" && (event.environments || []).some((item) => item?.id === environment?.id && item?.name === "production")
      ? [{ state: "approved", environmentId: environment.id, environmentName: "production",
        userId: event.user?.id, userLogin: event.user?.login }]
      : []);
  assert.equal(approved.length, 1, "Exactly one authenticated production review is required");
  const approval = authorization.approval;
  const observed = createProductionEnvironmentApprovalEvidence({ environmentConfig: environment,
    repository, environment: "production", sourceSha: authorization.sourceSha,
    workflowRef: PRODUCTION_ENVIRONMENT_APPROVAL.frontendCliActivationWorkflowRef,
    eventName: "workflow_dispatch", workflowRunId: run.id, workflowRunAttempt: run.run_attempt,
    executionActor: run.actor.login, observedAt: approval.observedAt, actualApproval: approved[0] });
  assert.deepEqual(observed, approval, "Production review or environment configuration changed");
  return authorization;
}

export function createFrontendCliAwsRunner(exec = execFileSync) {
  return createProductionAwsCommandRunner({ credentialSource: PRODUCTION_AWS_CREDENTIAL_SOURCE.NAMED_PROFILE,
    profile: "mscqr-ops-admin", exec: (file, args, options) => exec(file, args, { ...options,
      env: { ...options.env, AWS_MAX_ATTEMPTS: "1", AWS_RETRY_MODE: "standard" } }) });
}

export function createFrontendCliJournal({ run, authorizationSha256, directory }) {
  assert.match(authorizationSha256, /^[a-f0-9]{64}$/);
  const rootPath = fs.realpathSync(root), journalPath = fs.realpathSync(directory);
  const stat = fs.lstatSync(directory);
  assert.ok(stat.isDirectory() && !stat.isSymbolicLink() && (stat.mode & 0o077) === 0
    && journalPath !== rootPath && !journalPath.startsWith(rootPath + path.sep), "Private external journal required");
  const prefix = `production-frontend-cli-activation/${authorizationSha256}`;
  const key = (operationId, phase) => {
    assert.match(operationId, /^[a-f0-9]{64}$/);
    assert.match(phase, /^FRONTEND:[A-Z:]+$/);
    return `${prefix}/${operationId}/${phase}.json`;
  };
  const read = (operationId, phase) => {
    const file = path.join(directory, `read-${process.pid}-${Date.now()}-${Math.random().toString(16).slice(2)}.json`);
    try {
      run(["s3api", "get-object", "--bucket", PRODUCTION_ACTIVATION_LIFECYCLE.bucket,
        "--expected-bucket-owner", WEB_RELEASE.account,
        "--key", key(operationId, phase), file, "--output", "json", "--no-cli-pager"]);
      const record = json(fs.readFileSync(file, "utf8"));
      assert.deepEqual(Object.keys(record).sort(), ["operationId", "phase", "value"].sort());
      assert.equal(record.operationId, operationId); assert.equal(record.phase, phase);
      return record.value;
    } catch (error) {
      if (/NoSuchKey|404|Not Found/.test(String(error?.stderr || ""))) return null;
      throw error;
    } finally { fs.rmSync(file, { force: true }); }
  };
  const write = (operationId, phase, value, claim = false) => {
    const filename = path.join(directory, `${operationId}-${phase.replaceAll(":", "-")}.json`);
    const bytes = Buffer.from(`${JSON.stringify({ operationId, phase, value })}\n`);
    fs.writeFileSync(filename, bytes, { flag: "wx", mode: 0o600 });
    try {
      run(["s3api", "put-object", "--bucket", PRODUCTION_ACTIVATION_LIFECYCLE.bucket,
        "--key", key(operationId, phase), "--body", filename, "--if-none-match", "*",
        "--expected-bucket-owner", WEB_RELEASE.account,
        "--server-side-encryption", "AES256", "--output", "json", "--no-cli-pager"]);
    } catch (error) {
      if (claim || JSON.stringify(read(operationId, phase)) !== JSON.stringify(value)) throw error;
    }
    assert.deepEqual(read(operationId, phase), value, "Durable frontend journal readback changed");
    return true;
  };
  return { readOperation: read, writeOperation: (id, phase, value) => write(id, phase, value),
    claimOperation: (id, phase, value) => write(id, phase, value, true) };
}

export async function runFrontendCliActivation({ reference, webAuthorizationFile, webAuthorizationFileSha256,
  databaseProbeFile, databaseProbeFileSha256, requirementsReference, journalDir, profile = "mscqr-ops-admin",
  awsRun, githubRun = createProductionGithubCommandRunner(), verifyWeb = createPinnedRootAttestationVerifier(),
  verifyArtifacts, readPublication = readGovernedWebPublication, now = Date.now,
  adapters: injectedAdapters, fetchImpl = fetch } = {}) {
  assert.equal(profile, "mscqr-ops-admin", "Root and alternate deployment profiles are forbidden");
  const run = awsRun || createFrontendCliAwsRunner();
  const downloaded = downloadAppOnlyArtifact({ kind: "frontendCliAuthorization", reference,
    repositoryRoot: root, githubRun });
  const authorization = json(downloaded.bytes.toString("utf8"));
  const githubApi = (endpoint) => json(githubRun("gh", ["api", `repos/${repository}/${endpoint}`]));
  const assertFresh = () => {
    assertProtectedCheckout({ sourceSha: authorization.sourceSha, repositoryRoot: root });
    const main = githubApi("branches/main");
    assert.equal(main.protected, true); assert.equal(main.commit?.sha, authorization.sourceSha);
    assertFrontendCliApprovalReadback(authorization, { run: downloaded.run,
      environment: githubApi("environments/production"),
      approvals: githubApi(`actions/runs/${downloaded.run.id}/approvals`), now: now() });
  };
  assertFresh();
  const impact = assertFrontendCliSourceImpact(authorization);
  const caller = json(run(["sts", "get-caller-identity", "--output", "json", "--no-cli-pager"]));
  assert.equal(caller.Account, WEB_RELEASE.account);
  assert.equal(caller.Arn, `arn:aws:iam::${WEB_RELEASE.account}:user/mscqr-ops-admin`);
  const readBound = (file, hash) => {
    assert.match(hash, /^[a-f0-9]{64}$/);
    const bytes = fs.readFileSync(file);
    assert.equal(sha256(bytes), hash, "Evidence file SHA-256 differs from approval");
    return json(bytes.toString("utf8"));
  };
  const web = readBound(webAuthorizationFile, webAuthorizationFileSha256);
  const probe = readBound(databaseProbeFile, databaseProbeFileSha256);
  assert.equal(webAuthorizationFileSha256, authorization.webAuthorizationSha256);
  assert.equal(databaseProbeFileSha256, authorization.databaseProbeSha256);
  const imageAuthorization = json(downloadAppOnlyArtifact({ kind: "imageAuthorization",
    reference: authorization.imageAuthorizationReference, repositoryRoot: root, githubRun }).bytes.toString("utf8"));
  const verifyImageEvidence = (options) => verifyImageEvidenceSignature({ ...options, verify: verifyWeb });
  verifyProductionReleaseImageAuthorization({ authorization: imageAuthorization,
    sourceSha: authorization.sourceSha, verifyImageEvidence });
  if (authorization.candidateSourceSha !== authorization.sourceSha)
    assert.equal(imageAuthorization.imageReuseEvidence.webPublicationRequired, false,
      "Current-source image authorization requires a new frontend image");
  assert.equal(impact.candidateToProtected.sourceClassificationComplete, true);
  assertWebImageAuthorization(web, { sourceSha: authorization.candidateSourceSha, verify: verifyWeb });
  assert.equal(web.imageDigest, authorization.candidateDigest);
  assertBackendCliProbe(probe, { sourceSha: authorization.candidateSourceSha,
    candidateSourceSha: authorization.backendSourceSha, candidateDigest: authorization.backendDigest,
    requirementsSha256: probe.requirementsSha256 });
  const requirements = json(downloadAppOnlyArtifact({ kind: "requirements", reference: requirementsReference,
    repositoryRoot: root, githubRun }).bytes.toString("utf8"));
  assertAppOnlyRequirements(requirements, { sourceSha: authorization.candidateSourceSha,
    candidateSourceSha: authorization.backendSourceSha, repositoryRoot: root });
  assert.equal(requirements.requirementsSha256, probe.requirementsSha256);
  const probeTask = json(run(["ecs", "describe-tasks", "--cluster", WEB_RELEASE.cluster,
    "--tasks", probe.taskArn, "--output", "json", "--no-cli-pager"])).tasks?.[0];
  assert.equal(probeTask?.lastStatus, "STOPPED");
  assert.equal(probeTask.taskDefinitionArn, probe.taskDefinitionArn);
  assert.equal(probeTask?.containers?.[0]?.exitCode, 0);
  assert.equal(probeTask.containers[0].imageDigest, probe.probeImageDigest);
  assert.ok(now() - Date.parse(probeTask.stoppedAt) >= 0
    && now() - Date.parse(probeTask.stoppedAt) <= 24 * 60 * 60 * 1000, "Database probe is stale");
  const probeDefinition = json(run(["ecs", "describe-task-definition", "--task-definition",
    probe.taskDefinitionArn, "--output", "json", "--no-cli-pager"])).taskDefinition;
  const probeContainer = probeDefinition?.containerDefinitions?.[0];
  assert.equal(probeContainer?.name, "production-green-read-only-rls-canary");
  assert.equal(probeContainer.logConfiguration?.options?.["awslogs-group"],
    "/ecs/mscqr-production/rls-green-read-only-canary");
  const stream = `${probeContainer.logConfiguration.options["awslogs-stream-prefix"]}/${probeContainer.name}/${probe.taskArn.split("/").at(-1)}`;
  const events = json(run(["logs", "get-log-events", "--log-group-name",
    "/ecs/mscqr-production/rls-green-read-only-canary", "--log-stream-name", stream,
    "--start-from-head", "--limit", "101", "--output", "json", "--no-cli-pager"])).events;
  assert.ok(Array.isArray(events) && events.length <= 100, "Database probe log is unbounded");
  const observed = authenticateCompleteRlsProbeObservation(events.map(({ message }) => message), {
    sourceSha: probe.sourceSha, candidateSourceSha: probe.candidateSourceSha,
    probeImageDigest: probe.probeImageDigest, applicationImageDigest: probe.applicationImageDigest,
    requirementsSha256: probe.requirementsSha256, securityMode: false });
  assert.ok(observed, "Database probe terminal evidence is missing");
  assert.deepEqual(classifyProductionRlsCatalogue(observed.evidence.catalogue, requirements),
    { classification: "MATCH", deltaObjects: [] }, "Live database catalogue differs from canonical requirements");
  const verifyImage = verifyArtifacts || ((ref) => {
    execFileSync("scripts/aws/verify-release-artifacts.sh", [ref], { cwd: root, stdio: "ignore",
      env: { ...process.env,
        COSIGN_CERT_IDENTITY_REGEXP: `^https://github.com/${repository}/${WEB_RELEASE.workflowFile}@.*$`,
        COSIGN_CERT_OIDC_ISSUER: "https://token.actions.githubusercontent.com",
        PROVENANCE_ATTESTATION_TYPE: "https://mscqr.com/attestations/production-web-provenance/v1" } });
  });
  const authenticateImage = () => {
    verifyProductionReleaseImageAuthorization({ authorization: imageAuthorization,
      sourceSha: authorization.sourceSha, verifyImageEvidence, now: new Date(now()).toISOString() });
    assertWebImageAuthorization(web, { sourceSha: authorization.candidateSourceSha,
      verify: verifyWeb, now: new Date(now()).toISOString() });
    const publication = readPublication({ sourceSha: authorization.candidateSourceSha,
      workflowRunId: web.evidence.workflowRunId });
    assert.equal(publication.observed.workflowRunId, web.evidence.workflowRunId);
    assert.equal(json(publication.artifactBytes.toString("utf8").trim()).image_digest, authorization.candidateDigest);
    const ecr = json(run(["ecr", "describe-images", "--repository-name", WEB_RELEASE.repository,
      "--image-ids", `imageTag=${authorization.candidateSourceSha}`, "--output", "json", "--no-cli-pager"]));
    assert.equal(ecr.imageDetails?.length, 1);
    assert.equal(ecr.imageDetails[0].imageDigest, authorization.candidateDigest);
    assert.equal(String(ecr.imageDetails[0].registryId), WEB_RELEASE.account);
    verifyImage(web.imageRef);
  };
  authenticateImage();
  const execute = (args) => run([...args, "--output", "json", "--no-cli-pager"]);
  const adapters = injectedAdapters || createAwsFrontendActivationAdapters({ execute, fetchImpl });
  const readBackend = async () => {
    const service = json(execute(["ecs", "describe-services", "--cluster", APP_ONLY.cluster,
      "--services", APP_ONLY.service])).services?.[0];
    assert.equal(service?.serviceArn, APP_ONLY.serviceArn);
    assert.equal(service?.taskDefinition, authorization.backendTaskDefinitionArn);
    assert.equal(service.desiredCount, 2); assert.equal(service.runningCount, 2); assert.equal(service.pendingCount, 0);
    assert.equal(service.deployments?.length, 1);
    assert.equal(service.deployments[0].rolloutState, "COMPLETED");
    const arns = json(execute(["ecs", "list-tasks", "--cluster", APP_ONLY.cluster,
      "--service-name", APP_ONLY.service, "--desired-status", "RUNNING"])).taskArns;
    assert.equal(arns?.length, 2);
    const tasks = json(execute(["ecs", "describe-tasks", "--cluster", APP_ONLY.cluster,
      "--tasks", ...arns])).tasks;
    assert.equal(tasks?.length, 2);
    assert.ok(tasks.every((task) => task.lastStatus === "RUNNING"
      && task.taskDefinitionArn === authorization.backendTaskDefinitionArn
      && task.containers?.find(({ name }) => name === APP_ONLY.container)?.imageDigest === authorization.backendDigest));
    const health = await fetchImpl("https://www.mscqr.com/api/health/ready");
    const body = health.ok ? await health.json() : null;
    assert.equal(health.status, 200);
    assert.equal(body?.status, "ready");
    assert.equal(body?.release?.gitSha, authorization.backendSourceSha);
  };
  await readBackend();
  const service = await adapters.readService();
  assert.equal(service?.loadBalancers?.length, 1);
  assert.equal(service.loadBalancers[0].targetGroupArn, frontendTargetGroup);
  const predecessor = captureFrontendPredecessor(service, await adapters.describeTaskDefinition(service.taskDefinition));
  assert.equal(predecessor.taskDefinitionArn, authorization.predecessorTaskDefinitionArn);
  const journal = createFrontendCliJournal({ run, authorizationSha256: authorization.authorizationSha256,
    directory: journalDir });
  const operationId = canonicalSha256({ kind: "FRONTEND_CLI_ACTIVATION", authorizationSha256: authorization.authorizationSha256 });
  const beforeWrite = async () => {
    assertFresh(); authenticateImage(); await readBackend();
    const current = await adapters.readService();
    assert.equal(current?.loadBalancers?.[0]?.targetGroupArn, frontendTargetGroup);
    const observed = captureFrontendPredecessor(current, await adapters.describeTaskDefinition(current.taskDefinition));
    assert.equal(observed.taskDefinitionArn, authorization.predecessorTaskDefinitionArn);
    assert.equal(observed.deploymentId, predecessor.deploymentId);
  };
  await beforeWrite();
  journal.claimOperation(operationId, "FRONTEND:AUTHORIZATION:CLAIM", { sourceSha: authorization.sourceSha,
    candidateSourceSha: authorization.candidateSourceSha, candidateDigest: authorization.candidateDigest,
    predecessorTaskDefinitionArn: predecessor.taskDefinitionArn, authorizationSha256: authorization.authorizationSha256 });
  const verifiedAdapters = { ...adapters,
    registerTaskDefinition: async (candidate) => { await beforeWrite(); return adapters.registerTaskDefinition(candidate); },
    updateService: async (update) => { await beforeWrite(); return adapters.updateService(update); },
    verifyHealth: async (expected) => {
      const health = await adapters.verifyHealth(expected);
      const service = await adapters.readService();
      assert.equal(service?.loadBalancers?.[0]?.targetGroupArn, frontendTargetGroup);
      const targets = json(execute(["elbv2", "describe-target-health", "--target-group-arn", frontendTargetGroup]))
        .TargetHealthDescriptions;
      assert.ok(Array.isArray(targets) && targets.length >= 2 && targets.length <= 4);
      assert.equal(targets.filter((target) => target.TargetHealth?.State === "healthy").length, 2);
      assert.ok(targets.every((target) => ["healthy", "draining"].includes(target.TargetHealth?.State)));
      await readBackend();
      return health;
    } };
  const result = await runGovernedFrontendActivation({ sourceSha: authorization.candidateSourceSha,
    webAuthorization: web, verifyWebAuthorization: verifyWeb,
    now: new Date(now()).toISOString(), ...verifiedAdapters, journal, operationId });
  return { ...result, authorizationSha256: authorization.authorizationSha256 };
}

if (process.argv[1] && pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url) {
  try {
    const { values } = parseArgs({ options: Object.fromEntries(["authorization-reference", "web-authorization",
      "web-authorization-sha256", "database-probe", "database-probe-sha256", "requirements-reference",
      "journal-dir", "aws-profile"]
      .map((name) => [name, { type: "string" }])) });
    const result = await runFrontendCliActivation({ reference: parseAppOnlyArtifactReference(values["authorization-reference"]),
      webAuthorizationFile: values["web-authorization"], webAuthorizationFileSha256: values["web-authorization-sha256"],
      databaseProbeFile: values["database-probe"], databaseProbeFileSha256: values["database-probe-sha256"],
      requirementsReference: parseAppOnlyArtifactReference(values["requirements-reference"]),
      journalDir: values["journal-dir"], profile: values["aws-profile"] });
    process.stdout.write(`${JSON.stringify(result)}\n`);
  } catch {
    process.stderr.write("Frontend CLI activation stopped. Preserve the journal; do not retry an ambiguous mutation.\n");
    process.exitCode = 1;
  }
}
