import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import {
  buildInitialActivationClaim,
  buildInitialActivationCompletion,
  createInitialActivationClaim,
  createInitialActivationCompletion,
  assertInitialActivationCompletionAbsent,
  assertOpaqueS3VersionId,
  readInitialActivationClaim,
  readInitialActivationCompletion,
} from "../aws/production-initial-activation-lifecycle.mjs";
import { PRODUCTION_ACTIVATION_LIFECYCLE } from "../aws/production-green-stage-b-contract.mjs";
import { runCli } from "../aws/manage-production-initial-activation-lifecycle.mjs";
import { stageBApprovalIdForReleaseSha } from "../aws/production-green-stage-b-contract.mjs";
import { buildStageAProductionArtifactsBucketPolicy, buildStageAProductionArtifactsBucketPolicyWithInitialActivationReservation } from "../aws/production-stage-a-control-plane.mjs";
import { produceOnboardingEvidence } from "../security/produce-production-onboarding-evidence.mjs";

const sourceSha = "a".repeat(40);
const identity = {
  sourceSha,
  rotationId: "rotation-initial-activation-1",
  overlapDeploymentSha: "b".repeat(40),
  taskDefinitionArn: "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-production-rls-green-backend-candidate:51",
  activationTaskDefinitionArn: "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-production-rls-green-backend-candidate:52",
  imageDigest: `sha256:${"c".repeat(64)}`,
  overlapRuntimeProofSha256: "d".repeat(64),
};
const claim = (overrides = {}) => buildInitialActivationClaim({ ...identity, createdAt: "2026-08-26T12:00:00.000Z", ...overrides });
const terraformFiles = (directory) => readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
  const target = path.join(directory, entry.name);
  return entry.isDirectory() ? terraformFiles(target) : entry.name.endsWith(".tf") ? [target] : [];
});
const asArray = (value) => Array.isArray(value) ? value : [value];
const policyDecision = (policy, { action, resource, principalArn, ifNoneMatch } = {}) => {
  const matches = (statement) => asArray(statement.Action).includes(action)
    && asArray(statement.Resource).some((candidate) => candidate === resource || candidate.endsWith("*") && resource.startsWith(candidate.slice(0, -1)))
    && (statement.Principal === "*" || asArray(statement.Principal?.AWS).includes(principalArn))
    && (statement.Condition?.StringEquals?.["s3:if-none-match"] === undefined || statement.Condition.StringEquals["s3:if-none-match"] === ifNoneMatch)
    && (statement.Condition?.StringNotEquals?.["s3:if-none-match"] === undefined || statement.Condition.StringNotEquals["s3:if-none-match"] !== ifNoneMatch)
    && (statement.Condition?.StringNotEquals?.["aws:PrincipalArn"] === undefined || statement.Condition.StringNotEquals["aws:PrincipalArn"] !== principalArn);
  if (policy.Statement.some((statement) => statement.Effect === "Deny" && matches(statement))) return "explicitDeny";
  return policy.Statement.some((statement) => statement.Effect === "Allow" && matches(statement)) ? "allowed" : "implicitDeny";
};

const memoryS3 = ({ versionIds = {} } = {}) => {
  const objects = new Map();
  let writes = 0;
  const aws = (args) => {
    const operation = args[1];
    const key = args[args.indexOf("--key") + 1];
    if (operation === "put-object") {
      assert.equal(args[args.indexOf("--if-none-match") + 1], "*");
      if (objects.has(key)) return { ok: false, conflict: "PRECONDITION_FAILED" };
      objects.set(key, readFileSync(args[args.indexOf("--body") + 1]));
      writes += 1;
      return { ok: true, value: { VersionId: `v${writes}` } };
    }
    if (operation === "get-object") {
      if (!objects.has(key)) return { ok: false, missing: true };
      writeFileSync(args.at(-1), objects.get(key));
      return { ok: true, value: { VersionId: versionIds[key] ?? (key.endsWith("claim.json") ? "v1" : "v2") } };
    }
    throw new Error(`unexpected ${operation}`);
  };
  return { aws, objects, get writes() { return writes; } };
};

test("S3 VersionId bindings remain opaque and exact", () => {
  for (const value of ["opaque+/=", "null", "é".repeat(512)]) assert.equal(assertOpaqueS3VersionId(value), value);
  for (const value of ["", null, 7, [], "é".repeat(513), "\ud800"]) assert.throws(() => assertOpaqueS3VersionId(value));

  const s3 = memoryS3({ versionIds: { [PRODUCTION_ACTIVATION_LIFECYCLE.claimKey]: "claim+/=", [PRODUCTION_ACTIVATION_LIFECYCLE.completionKey]: "completion+/=" } });
  const createdClaim = createInitialActivationClaim({ claim: claim(), aws: s3.aws });
  assert.equal(createdClaim.versionId, "claim+/=");
  assert.equal(readInitialActivationClaim({ expected: claim(), aws: s3.aws }).versionId, "claim+/=");
  const completion = buildInitialActivationCompletion({ claim: createdClaim.value, claimSha256: createdClaim.sha256, claimVersionId: createdClaim.versionId, rlsReceiptSha256: "1".repeat(64), onboardingEvidenceSha256: "2".repeat(64), completedAt: "2026-08-26T13:00:00.000Z" });
  const createdCompletion = createInitialActivationCompletion({ completion, claim: createdClaim.value, claimSha256: createdClaim.sha256, claimVersionId: createdClaim.versionId, aws: s3.aws });
  assert.equal(createdCompletion.versionId, "completion+/=");
  assert.equal(readInitialActivationCompletion({ claim: createdClaim.value, claimSha256: createdClaim.sha256, claimVersionId: "claim+/=", aws: s3.aws }).versionId, "completion+/=");
  assert.equal(createInitialActivationCompletion({ completion, claim: createdClaim.value, claimSha256: createdClaim.sha256, claimVersionId: createdClaim.versionId, aws: s3.aws }).status, "ALREADY_EXISTS_MATCHING");
  assert.throws(() => readInitialActivationCompletion({ claim: createdClaim.value, claimSha256: createdClaim.sha256, claimVersionId: "claim=/=", aws: s3.aws }), /claim version/);
});

test("lifecycle readers remain injection-only", () => {
  assert.throws(() => readInitialActivationClaim({ expected: claim() }), /Production initial activation AWS client must be injected/);
  assert.throws(() => assertInitialActivationCompletionAbsent(), /Production initial activation AWS client must be injected/);
});

test("atomic fixed-key claim has one creator and matching retry", () => {
  const s3 = memoryS3();
  const first = createInitialActivationClaim({ claim: claim(), aws: s3.aws });
  const second = createInitialActivationClaim({ claim: claim(), aws: s3.aws });
  assert.equal(first.status, "CREATED");
  assert.equal(second.status, "ALREADY_EXISTS_MATCHING");
  assert.equal(s3.writes, 1);
  assert.equal(readInitialActivationClaim({ expected: claim(), aws: s3.aws }).sha256, first.sha256);
  for (const different of [
    { sourceSha: "e".repeat(40) }, { rotationId: "rotation-different" }, { overlapDeploymentSha: "f".repeat(40) },
    { taskDefinitionArn: identity.taskDefinitionArn.replace(/:51$/, ":53") },
    { activationTaskDefinitionArn: identity.activationTaskDefinitionArn.replace(/:52$/, ":53") }, { imageDigest: `sha256:${"e".repeat(64)}` },
  ]) assert.throws(() => createInitialActivationClaim({ claim: claim(different), aws: s3.aws }), /conflicts/);
});

test("completion is conditional, immutable, and claim-bound", () => {
  const s3 = memoryS3();
  const createdClaim = createInitialActivationClaim({ claim: claim(), aws: s3.aws });
  const completion = buildInitialActivationCompletion({ claim: createdClaim.value, claimSha256: createdClaim.sha256, claimVersionId: createdClaim.versionId, rlsReceiptSha256: "1".repeat(64), onboardingEvidenceSha256: "2".repeat(64), completedAt: "2026-08-26T13:00:00.000Z" });
  assert.equal(createInitialActivationCompletion({ completion, claim: createdClaim.value, claimSha256: createdClaim.sha256, claimVersionId: createdClaim.versionId, aws: s3.aws }).status, "CREATED");
  assert.equal(createInitialActivationCompletion({ completion, claim: createdClaim.value, claimSha256: createdClaim.sha256, claimVersionId: createdClaim.versionId, aws: s3.aws }).status, "ALREADY_EXISTS_MATCHING");
  assert.equal(createInitialActivationCompletion({ completion: { ...completion, completedAt: "2026-08-26T13:00:01.000Z" }, claim: createdClaim.value, claimSha256: createdClaim.sha256, claimVersionId: createdClaim.versionId, aws: s3.aws }).status, "ALREADY_EXISTS_MATCHING");
  assert.throws(() => createInitialActivationCompletion({ completion: { ...completion, onboardingEvidenceSha256: "3".repeat(64) }, claim: createdClaim.value, claimSha256: createdClaim.sha256, claimVersionId: createdClaim.versionId, aws: s3.aws }), /conflicts/);
});

test("completion publication requires authenticated RLS and strict onboarding evidence", async () => {
  const directory = mkdtempSync(path.join(tmpdir(), "mscqr-activation-completion-"));
  try {
    const s3 = memoryS3();
    const created = createInitialActivationClaim({ claim: claim(), aws: s3.aws });
    const claimFile = path.join(directory, "claim.json");
    const receiptFile = path.join(directory, "receipt.json");
    const onboardingFile = path.join(directory, "onboarding.json");
    const stateFile = path.join(directory, "rotation-state.json");
    writeFileSync(stateFile, "{}\n");
    const stateSha256 = createHash("sha256").update("{}\n").digest("hex");
    writeFileSync(claimFile, `${JSON.stringify(created.value, Object.keys(created.value).sort())}\n`);
    const receipt = {
      schemaVersion: 2,
      environment: "production",
      releaseSha: sourceSha,
      sourceContractSha256: "1".repeat(64),
      migrationSetDigest: "2".repeat(64),
      packageChecksumSha256: "3".repeat(64),
      approvalId: stageBApprovalIdForReleaseSha(sourceSha),
      approvalContractSha256: "4".repeat(64),
      applicationCanary: "passed",
      images: {
        executor: `368992683803.dkr.ecr.eu-west-2.amazonaws.com/mscqr-backend@sha256:${"5".repeat(64)}`,
        backend: `368992683803.dkr.ecr.eu-west-2.amazonaws.com/mscqr-backend@${identity.imageDigest}`,
        worker: `368992683803.dkr.ecr.eu-west-2.amazonaws.com/mscqr-worker@sha256:${"6".repeat(64)}`,
        canary: `368992683803.dkr.ecr.eu-west-2.amazonaws.com/mscqr-backend@sha256:${"7".repeat(64)}`,
        frontendTaskDefinition: "mscqr-frontend:20",
      },
      receipts: [],
    };
    receipt.receiptBundleSha256 = createHash("sha256").update(`${JSON.stringify(receipt)}\n`).digest("hex");
    writeFileSync(receiptFile, JSON.stringify(receipt));
    const runtime = Object.fromEntries(["jwtCurrentRuntimeVerify", "jwtPreviousRuntimeVerify", "jwtInvalidRuntimeRejected", "qrCurrentRuntimeVerify", "qrPreviousRuntimeVerify", "qrTamperMatchingKeyTest", "qrUnknownKeyRejected", "cookieCurrentSealOnly", "cookiePreviousOpenDuringOverlap", "artifactCurrentRuntimeVerify", "artifactHistoricalRuntimeVerify"].map((name) => [name, true]));
    const acceptance = Object.fromEntries(["superAdminLogin", "mfa", "authMe", "refresh", "dashboardStats", "qrStats", "tenantIsolation", "rbac", "auditPath", "printerTrust", "antiCloning", "dbReady", "redisReady", "objectStorageReady", "stageANetworkingReady"].map((name) => [name, true]));
    const onboarding = { valid: true, evidenceRef: "onboarding:test", evidenceSha256: "7".repeat(64), sourceSha, imageDigest: identity.imageDigest, taskDefinitionArn: identity.activationTaskDefinitionArn, taskArn: "arn:aws:ecs:eu-west-2:368992683803:task/mscqr-prod-euw2-main/0123456789abcdef0123456789abcdef", rotationId: identity.rotationId, rotationStateSha256: stateSha256, taskMarker: true, ecsExecProof: true, serviceStable: true, targetTaskDefinitionMatch: true, targetImageDigestMatch: true, health: { serviceHealthy: true, healthReleaseGitSha: sourceSha }, rotationPhase: "verified", runtime, acceptance };
    const onboardingBundle = await produceOnboardingEvidence({
      runStrictProbes: async () => onboarding,
      expectedSourceSha: sourceSha,
      expectedImageDigest: identity.imageDigest,
      expectedTaskDefinitionArn: identity.activationTaskDefinitionArn,
      expectedTaskArn: onboarding.taskArn,
      expectedRotationId: identity.rotationId,
      expectedRotationStateSha256: onboarding.rotationStateSha256,
      expectedRotationFixtureSha256: "9".repeat(64),
    });
    writeFileSync(onboardingFile, JSON.stringify(onboardingBundle));
    const argv = ["--mode", "complete", "--claim-file", claimFile, "--claim-sha256", created.sha256, "--state-file", stateFile, "--state-sha256", stateSha256, "--rls-receipt", receiptFile, "--onboarding-evidence", onboardingFile];
    const validateOverlap = () => ({ taskArn: onboarding.taskArn });
    assert.equal((await runCli(argv, { aws: s3.aws, validateOverlap, now: () => "2026-08-26T13:00:00.000Z" })).status, "CREATED");
    const invalidEvidence = { ...onboarding, acceptance: { ...acceptance, tenantIsolation: false } };
    writeFileSync(onboardingFile, JSON.stringify({ ...onboardingBundle, evidenceSha256: createHash("sha256").update(JSON.stringify(invalidEvidence)).digest("hex"), evidence: invalidEvidence }));
    await assert.rejects(runCli(argv, { aws: s3.aws, validateOverlap }), /tenantIsolation/);
    writeFileSync(onboardingFile, JSON.stringify({ ...onboardingBundle, evidence: { ...onboarding, sourceSha: "e".repeat(40) } }));
    await assert.rejects(runCli(argv, { aws: s3.aws, validateOverlap }), /bundle|claim/);
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test("source policy and bucket policy enforce only exact conditional lifecycle objects", () => {
  const policy = JSON.parse(readFileSync("documents/ops/iam/MSCQRProductionInitialActivationLifecycle-v1.json", "utf8"));
  const terraform = readFileSync("infra/aws/terraform/production-green-stage-a/main.tf", "utf8");
  const bucketPolicy = terraform.slice(terraform.indexOf('resource "aws_s3_bucket_policy" "production_artifacts"'), terraform.indexOf("# Stage A owns only new"));
  const expected = [PRODUCTION_ACTIVATION_LIFECYCLE.claimArn, PRODUCTION_ACTIVATION_LIFECYCLE.completionArn];
  const lifecycle = policy.Statement.filter(({ Sid }) => ["ReadExactActivationLifecycle", "CreateExactActivationLifecycleConditionally", "DenyNonConditionalActivationLifecycleWrites", "DenyActivationLifecycleDeletion"].includes(Sid));
  assert.equal(lifecycle.length, 4);
  for (const statement of lifecycle) assert.deepEqual([statement.Resource].flat(), expected);
  assert.deepEqual(lifecycle.find(({ Sid }) => Sid === "CreateExactActivationLifecycleConditionally").Condition, { StringEquals: { "s3:if-none-match": "*" } });
  assert.deepEqual(lifecycle.find(({ Sid }) => Sid === "DenyNonConditionalActivationLifecycleWrites").Condition, { StringNotEquals: { "s3:if-none-match": "*" } });
  assert.deepEqual(lifecycle.find(({ Sid }) => Sid === "DenyActivationLifecycleDeletion").Action, ["s3:DeleteObject", "s3:DeleteObjectVersion"]);
  assert.doesNotMatch(JSON.stringify(lifecycle), /ListBucket|production-activation-lifecycle\/\*/);
  assert.deepEqual(policy.Statement.filter(({ Sid }) => ["ReadCompleteProductionArtifactsBucketPolicy", "ApplyCompleteProductionArtifactsBucketPolicy"].includes(Sid)), [
    { Sid: "ReadCompleteProductionArtifactsBucketPolicy", Effect: "Allow", Action: "s3:GetBucketPolicy", Resource: `arn:aws:s3:::${PRODUCTION_ACTIVATION_LIFECYCLE.bucket}` },
    { Sid: "ApplyCompleteProductionArtifactsBucketPolicy", Effect: "Allow", Action: "s3:PutBucketPolicy", Resource: `arn:aws:s3:::${PRODUCTION_ACTIVATION_LIFECYCLE.bucket}` },
  ]);
  assert.match(bucketPolicy, /AllowReleaseDeployerReadActivationLifecycle[\s\S]*Principal = \{ AWS = var\.release_role_arn \}[\s\S]*Action = "s3:GetObject"[\s\S]*Resource = local\.activation_lifecycle_object_arns/);
  assert.match(bucketPolicy, /AllowReleaseDeployerConditionalActivationLifecycleCreate[\s\S]*Principal = \{ AWS = var\.release_role_arn \}[\s\S]*Action = "s3:PutObject"[\s\S]*Resource = local\.activation_lifecycle_object_arns/);
  assert.match(terraform, /DenyNonConditionalActivationLifecycleWrites[\s\S]*Principal\s*=\s*"\*"/);
  assert.match(terraform, /DenyOtherPrincipalsActivationLifecycleWrites[\s\S]*aws:PrincipalArn[\s\S]*var\.release_role_arn/);
  assert.match(terraform, /StringEquals\s*=\s*\{\s*"s3:if-none-match"\s*=\s*"\*"\s*\}/);
  assert.match(terraform, /StringNotEquals\s*=\s*\{\s*"s3:if-none-match"\s*=\s*"\*"\s*\}/);
  assert.match(terraform, /DenyActivationLifecycleDeletion[\s\S]*s3:DeleteObjectVersion/);
  assert.deepEqual([...bucketPolicy.matchAll(/Sid = "([^"]+)"/g)].map(([, sid]) => sid), [
    "AllowReleaseDeployerReadActivationLifecycle",
    "AllowReleaseDeployerConditionalActivationLifecycleCreate",
    "DenyNonConditionalActivationLifecycleWrites",
    "DenyOtherPrincipalsActivationLifecycleWrites",
    "DenyActivationLifecycleDeletion",
    "AllowReleaseDeployerReadRebaselineEvidence",
    "AllowReleaseDeployerConditionalRebaselineEvidenceCreate",
    "DenyNonConditionalRebaselineEvidenceWrites",
    "DenyOtherPrincipalsRebaselineEvidenceWrites",
    "DenyRebaselineEvidenceDeletion",
    "AllowReleaseDeployerReadStageAProductionArtifactsReconciliation",
    "AllowReleaseDeployerConditionalStageAProductionArtifactsReconciliationCreate",
    "DenyNonConditionalStageAProductionArtifactsReconciliationWrites",
    "DenyOtherPrincipalsStageAProductionArtifactsReconciliationWrites",
    "DenyStageAProductionArtifactsReconciliationDeletion",
    "AllowRootOperatorReadInitialActivationPolicyReconciliationReservations",
    "AllowRootOperatorConditionalInitialActivationPolicyReconciliationReservationCreate",
    "DenyNonConditionalInitialActivationPolicyReconciliationReservationWrites",
    "DenyOtherPrincipalsInitialActivationPolicyReconciliationReservationWrites",
    "DenyInitialActivationPolicyReconciliationReservationDeletion",
    "DenyProductionArtifactsBucketPolicyMutation",
  ]);
  const evidence = policy.Statement.filter(({ Sid }) => ["ReadExactRebaselineEvidence", "CreateExactRebaselineEvidenceConditionally", "DenyNonConditionalRebaselineEvidenceWrites", "DenyRebaselineEvidenceDeletion"].includes(Sid));
  assert.equal(evidence.length, 4);
  for (const statement of evidence) assert.equal(statement.Resource, PRODUCTION_ACTIVATION_LIFECYCLE.rebaselineEvidenceArn);
  assert.deepEqual(evidence.find(({ Sid }) => Sid === "CreateExactRebaselineEvidenceConditionally").Condition, { StringEquals: { "s3:if-none-match": "*" } });
  assert.deepEqual(evidence.find(({ Sid }) => Sid === "DenyNonConditionalRebaselineEvidenceWrites").Condition, { StringNotEquals: { "s3:if-none-match": "*" } });
  assert.match(bucketPolicy, /DenyProductionArtifactsBucketPolicyMutation[\s\S]*s3:PutBucketPolicy[\s\S]*s3:DeleteBucketPolicy[\s\S]*var\.receipt_bucket_arn/);
  assert.doesNotMatch(bucketPolicy, /rls-(?:broker-)?receipts|ignore_changes|production-activation-lifecycle\/\*/);
});

test("initial-activation policy reconciliation reservation is exact, conditional, root-only, and immutable", () => {
  const current = buildStageAProductionArtifactsBucketPolicy();
  const desired = buildStageAProductionArtifactsBucketPolicyWithInitialActivationReservation();
  const prefixArn = PRODUCTION_ACTIVATION_LIFECYCLE.initialActivationPolicyReconciliationReservationArn;
  const exactObjectArn = prefixArn.replace("*", `${"a".repeat(64)}.json`);
  assert.deepEqual(desired.Statement.slice(0, current.Statement.length), current.Statement);
  assert.equal(desired.Statement.length, current.Statement.length + 5);
  assert.equal(PRODUCTION_ACTIVATION_LIFECYCLE.initialActivationPolicyReconciliationReservationPrefix, "production-initial-activation-lifecycle-policy-reconciliation/reservations/");
  assert.equal(prefixArn, `arn:aws:s3:::${PRODUCTION_ACTIVATION_LIFECYCLE.bucket}/${PRODUCTION_ACTIVATION_LIFECYCLE.initialActivationPolicyReconciliationReservationPrefix}*`);
  assert.equal(policyDecision(desired, { action: "s3:GetObject", resource: exactObjectArn, principalArn: PRODUCTION_ACTIVATION_LIFECYCLE.rootOperatorArn }), "allowed");
  assert.equal(policyDecision(desired, { action: "s3:PutObject", resource: exactObjectArn, principalArn: PRODUCTION_ACTIVATION_LIFECYCLE.rootOperatorArn, ifNoneMatch: "*" }), "allowed");
  assert.equal(policyDecision(desired, { action: "s3:PutObject", resource: exactObjectArn, principalArn: PRODUCTION_ACTIVATION_LIFECYCLE.rootOperatorArn }), "explicitDeny");
  assert.equal(policyDecision(desired, { action: "s3:PutObject", resource: exactObjectArn, principalArn: PRODUCTION_ACTIVATION_LIFECYCLE.releaseRoleArn, ifNoneMatch: "*" }), "explicitDeny");
  for (const action of ["s3:DeleteObject", "s3:DeleteObjectVersion"]) assert.equal(policyDecision(desired, { action, resource: exactObjectArn, principalArn: PRODUCTION_ACTIVATION_LIFECYCLE.rootOperatorArn }), "explicitDeny");
  assert.equal(policyDecision(desired, { action: "s3:PutObject", resource: `arn:aws:s3:::${PRODUCTION_ACTIVATION_LIFECYCLE.bucket}/unrelated/${"a".repeat(64)}.json`, principalArn: PRODUCTION_ACTIVATION_LIFECYCLE.rootOperatorArn, ifNoneMatch: "*" }), "implicitDeny");
  assert.equal(desired.Statement.some(({ Action }) => asArray(Action).includes("s3:ListBucket")), false);
});

test("Stage A is the sole complete production artifacts bucket-policy owner", () => {
  const root = "infra/aws/terraform";
  const files = readdirSync(root, { withFileTypes: true })
    .filter((entry) => entry.isDirectory() && entry.name.startsWith("production-"))
    .flatMap((entry) => terraformFiles(path.join(root, entry.name)));
  const sources = files.map((file) => [file, readFileSync(file, "utf8")]);
  const owners = sources.flatMap(([file, source]) => [...source.matchAll(/resource\s+"aws_s3_bucket_policy"\s+"([^"]+)"/g)]
    .map((match) => ({ file, name: match[1], body: source.slice(match.index, source.indexOf("\nresource ", match.index + 1) < 0 ? source.length : source.indexOf("\nresource ", match.index + 1)) }))
    .filter(({ body }) => /receipt_bucket_arn|mscqr-prod-euw2-artifacts-368992683803-eu-west-2-an/.test(body))
    .map(({ file: ownerFile, name }) => ({ file: ownerFile, name })));
  assert.deepEqual(owners, [{ file: "infra/aws/terraform/production-green-stage-a/main.tf", name: "production_artifacts" }]);
  assert.equal(sources.some(([, source]) => /data\s+"aws_s3_bucket_policy"[\s\S]{0,500}(?:receipt_bucket_arn|mscqr-prod-euw2-artifacts-368992683803-eu-west-2-an)/.test(source)), false);
  const stageA = sources.find(([file]) => file === "infra/aws/terraform/production-green-stage-a/main.tf")[1];
  assert.doesNotMatch(stageA, /(?:ignore_changes|\bimport\s*\{|\bmoved\s*\{)/);
  assert.match(stageA, /resource "aws_s3_bucket_policy" "production_artifacts"[\s\S]*bucket\s*=\s*trimprefix\(var\.receipt_bucket_arn/);
});

test("strict onboarding producer rejects every deployment identity mismatch", async () => {
  const base = {
    sourceSha,
    imageDigest: identity.imageDigest,
    taskDefinitionArn: identity.activationTaskDefinitionArn,
    taskArn: "arn:aws:ecs:eu-west-2:368992683803:task/mscqr-prod-euw2-main/0123456789abcdef0123456789abcdef",
    rotationId: identity.rotationId,
    rotationStateSha256: "8".repeat(64),
  };
  for (const [field, value] of Object.entries({ taskDefinitionArn: `${identity.taskDefinitionArn}0`, taskArn: `${base.taskArn}0`, rotationId: "rotation-other", rotationStateSha256: "9".repeat(64) })) {
    await assert.rejects(produceOnboardingEvidence({
      runStrictProbes: async () => ({ ...base, [field]: value }),
      expectedSourceSha: base.sourceSha,
      expectedImageDigest: base.imageDigest,
      expectedTaskDefinitionArn: base.taskDefinitionArn,
      expectedTaskArn: base.taskArn,
      expectedRotationId: base.rotationId,
      expectedRotationStateSha256: base.rotationStateSha256,
      expectedRotationFixtureSha256: "a".repeat(64),
    }), /identity/);
  }
});

test("Release Gate binds the prepared activation target before the first RLS mutation", () => {
  const workflow = readFileSync(".github/workflows/release-gate.yml", "utf8");
  const prepare = workflow.indexOf("Authorize exact Stage-B backend candidate before database mutation");
  const claim = workflow.indexOf("Atomically claim initial production activation");
  const rls = workflow.indexOf("Apply and verify checksum-bound production RLS package");
  assert(prepare > 0 && prepare < claim && claim < rls);
  assert.match(workflow.slice(claim, rls), /ACTIVATION_BINDING_FILE[\s\S]*targetArn[\s\S]*--activation-task-definition/);
});
