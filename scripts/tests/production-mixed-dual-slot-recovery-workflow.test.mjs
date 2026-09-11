import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { MIXED_DUAL_SLOT_PREDECESSOR, MIXED_DUAL_SLOT_RECOVERY_ARTIFACT, MIXED_DUAL_SLOT_RECOVERY_EXECUTION_ROLE_ARN, MIXED_DUAL_SLOT_RECOVERY_IAM_ACTION, MIXED_DUAL_SLOT_RECOVERY_IAM_CAPABILITIES, MIXED_DUAL_SLOT_RECOVERY_IAM_RESOURCES, assertMixedDualSlotRecoveryAuthorization, buildMixedDualSlotRecoveryIamPreflight, buildMixedDualSlotRecoveryPreparation, createMixedDualSlotRecoveryAuthorization, resolveMixedDualSlotRecoveryAuthorizationArtifact } from "../aws/production-mixed-dual-slot-recovery-contract.mjs";
import { createProductionEnvironmentApprovalEvidence, PRODUCTION_ENVIRONMENT_APPROVAL } from "../aws/production-github-environment-approval.mjs";
import { createMixedDualSlotRecoveryIamAttestation } from "../aws/production-mixed-dual-slot-recovery-iam-attestation.mjs";

const root = path.resolve(new URL(".", import.meta.url).pathname, "../..");
const sourceSha = "a".repeat(40); const observedAt = "2026-09-10T00:00:00.000Z"; const now = new Date("2026-09-10T00:05:00.000Z");
const iamCapabilityPreflight = buildMixedDualSlotRecoveryIamPreflight({ sourceSha, principalArn: MIXED_DUAL_SLOT_RECOVERY_EXECUTION_ROLE_ARN, action: MIXED_DUAL_SLOT_RECOVERY_IAM_ACTION, resources: [...MIXED_DUAL_SLOT_RECOVERY_IAM_RESOURCES], roleTrustPolicySha256: "1".repeat(64), organizationsGuard: { accountId: "368992683803", status: "NOT_IN_ORGANIZATION", evidence: "AWSOrganizationsNotInUseException" }, resourcePolicies: MIXED_DUAL_SLOT_RECOVERY_IAM_RESOURCES.map((resource) => ({ resource, resourcePolicySha256: "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b", resourcePolicyAccess: "NO_RESOURCE_POLICY" })), evaluations: MIXED_DUAL_SLOT_RECOVERY_IAM_CAPABILITIES.flatMap(({ action, resources }) => resources.map((resource) => ({ action, resource, decision: "allowed", missingContextValues: [], organizationsAllowed: true, permissionsBoundaryAllowed: null }))), observedAt });
const preparation = buildMixedDualSlotRecoveryPreparation({ sourceSha, predecessor: structuredClone(MIXED_DUAL_SLOT_PREDECESSOR), iamCapabilityPreflight, preparedAt: observedAt });
const preparationFileSha256 = "d".repeat(64);
const approvalFor = (workflowRef) => createProductionEnvironmentApprovalEvidence({ environmentConfig: { name: "production", id: 17, can_admins_bypass: false, protection_rules: [{ type: "required_reviewers", prevent_self_review: false, reviewers: [{ type: "User", reviewer: { id: 7, login: "checker" } }] }] }, repository: "T-ej2003/genuine-scan-main", environment: "production", sourceSha, workflowRef, eventName: "workflow_dispatch", workflowRunId: "123456", workflowRunAttempt: "1", executionActor: "operator", observedAt, actualApproval: { state: "approved", environmentId: 17, environmentName: "production", userId: 7, userLogin: "checker" } });
const evidence = approvalFor(PRODUCTION_ENVIRONMENT_APPROVAL.mixedDualSlotRecoveryAuthorizationWorkflowRef);
const iamCapabilityAttestation = createMixedDualSlotRecoveryIamAttestation({ preflight: iamCapabilityPreflight, sign: () => "c2ln", now });
const authorization = createMixedDualSlotRecoveryAuthorization({ preparation, preparationFileSha256, iamCapabilityAttestation, iamCapabilityAttestationFileSha256: "e".repeat(64), verifyIamCapabilityAttestation: () => true, protectedEnvironmentApprovalEvidence: evidence, reason: "Exact mixed topology recovery", approverRole: "production-independent-checker", verificationRef: "recovery-1", now });

test("protected workflows expose only canonical artifact coordinates and gate credentials before mutation", () => {
  const authorize = readFileSync(path.join(root, ".github/workflows/authorize-production-mixed-dual-slot-topology-recovery.yml"), "utf8");
  const execute = readFileSync(path.join(root, ".github/workflows/execute-production-mixed-dual-slot-topology-recovery.yml"), "utf8");
  const executionEnvironment = JSON.parse(readFileSync(path.join(root, "infra/aws/terraform/production-initial-activation-policy-reconciler/mixed-recovery-github-environment-contract.json"), "utf8"));
  assert.deepEqual(executionEnvironment, { name: "production-mixed-dual-slot-recovery", deploymentBranches: "protected-main-only", requiredReviewers: false, preventSelfReview: false, forbidUnprotectedBranchesAndTags: true, forbiddenSecrets: ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"], requiresEnvironmentSecrets: false, activation: "operator-configured; not managed by Terraform" });
  assert.match(authorize, /environment: production/);
  assert.match(execute, /environment: production-mixed-dual-slot-recovery/);
  assert.equal(readdirSync(path.join(root, ".github/workflows")).filter((file) => readFileSync(path.join(root, ".github/workflows", file), "utf8").includes("environment: production-mixed-dual-slot-recovery")).length, 1);
  for (const workflow of [authorize, execute]) assert.doesNotMatch(workflow.match(/inputs:[\s\S]*?\npermissions:/)?.[0] || "", /secret_arn|version_id|payload_hash|rotation_id|historical_source|mutation_(?:count|plan|order)|predecessor_manifest/);
  assert.match(authorize, /--require-actual-approval/); assert.doesNotMatch(authorize, /configure-aws-credentials|UpdateSecretVersionStage|PutSecretValue|DeleteSecret/);
  assert.match(authorize, /name: Verify effective recovery IAM capability/);
  assert.match(authorize, /needs: preflight/);
  assert.ok(authorize.indexOf("Verify effective recovery IAM capability") < authorize.indexOf("environment: production"));
  assert.match(authorize, /verify-production-mixed-dual-slot-recovery-iam-attestation\.mjs/);
  assert.match(authorize, /iam_preflight_attestation_base64/);
  for (const workflow of [authorize, execute]) { assert.match(workflow, /source-before\.sha256/); assert.match(workflow, /source-after\.sha256/); assert.match(workflow, /cmp --silent/); assert.match(workflow, /chmod 600 "\$workdir\/preparation\.json"/); }
  assert.ok(execute.indexOf("environment: production-mixed-dual-slot-recovery") < execute.indexOf("configure-aws-credentials") && execute.indexOf("configure-aws-credentials") < execute.indexOf("run-production-mixed-dual-slot-topology-recovery.mjs --execute"));
  assert.match(readFileSync(path.join(root, "infra/aws/terraform/production-initial-activation-policy-reconciler/mixed-recovery-trust-policy.json"), "utf8"), /repo:T-ej2003\/genuine-scan-main:environment:production-mixed-dual-slot-recovery/);
  assert.match(execute, /secretsmanager:UpdateSecretVersionStage/); assert.doesNotMatch(execute, /secretsmanager:(?:PutSecretValue|CreateSecret|DeleteSecret)/);
  assert.match(execute, /role-to-assume: arn:aws:iam::368992683803:role\/mscqr-production-mixed-dual-slot-recovery-executor/);
  assert.doesNotMatch(execute, /role-to-assume: arn:aws:iam::368992683803:role\/mscqr-production-release-deployer/);
  assert.match(execute, /execute-production-mixed-dual-slot-topology-recovery\.yml@refs\/heads\/main/);
  assert.match(execute, /concurrency:\s+group: production-mixed-dual-slot-topology-recovery\s+cancel-in-progress: false/);
  for (const arn of Object.values(MIXED_DUAL_SLOT_PREDECESSOR).map(({ arn }) => arn)) assert.match(execute, new RegExp(arn.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
});

test("production entrypoint has no operator-selectable verification seams", () => {
  const cli = readFileSync(path.join(root, "scripts/aws/run-production-mixed-dual-slot-topology-recovery.mjs"), "utf8");
  const bootstrapCli = readFileSync(path.join(root, "scripts/aws/bootstrap-production-initial-dual-slot.mjs"), "utf8");
  const runtimeCli = readFileSync(path.join(root, "scripts/aws/prepare-production-cutover-runtime.mjs"), "utf8");
  assert.doesNotMatch(cli, /--(?:authorize|assert-predecessor|payload-hash|send|aws-callback)/);
  assert.doesNotMatch(`${bootstrapCli}\n${runtimeCli}`, /retainedHistoryPayloadHash/);
  assert.match(cli, /GITHUB_WORKFLOW_REF !== EXECUTION_WORKFLOW_REF/);
  assert.match(cli, /resolveMixedDualSlotRecoveryAuthorizationArtifact/);
  assert.match(cli, /readStageBProtectedMainCheckout/);
  assert.match(cli, /new SecretsManagerClient/);
  for (const option of ["--authorize", "--assert-predecessor", "--payload-hash", "--send", "--aws-callback"]) assert.throws(() => execFileSync(process.execPath, [path.join(root, "scripts/aws/run-production-mixed-dual-slot-topology-recovery.mjs"), "--execute", option, "true"], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }), /Command failed/);
});

test("authorization rejects other workflows and resolver authenticates exact run, archive and attempt", () => {
  assert.doesNotThrow(() => assertMixedDualSlotRecoveryAuthorization(authorization, { preparation, preparationFileSha256, sourceSha, now }));
  assert.throws(() => createMixedDualSlotRecoveryAuthorization({ preparation, preparationFileSha256, iamCapabilityAttestation, iamCapabilityAttestationFileSha256: "e".repeat(64), verifyIamCapabilityAttestation: () => false, protectedEnvironmentApprovalEvidence: evidence, reason: "x", approverRole: "x", verificationRef: "x", now }), /authenticated exact capability proof/i);
  assert.throws(() => createMixedDualSlotRecoveryAuthorization({ preparation, preparationFileSha256, iamCapabilityAttestation, iamCapabilityAttestationFileSha256: "e".repeat(64), verifyIamCapabilityAttestation: () => true, protectedEnvironmentApprovalEvidence: approvalFor(PRODUCTION_ENVIRONMENT_APPROVAL.dualSlotRebaselineWorkflowRef), reason: "x", approverRole: "x", verificationRef: "x", now }), /dedicated protected workflow identity/i);
  const directory = mkdtempSync(path.join(os.tmpdir(), "mscqr-mixed-auth-test-")); const json = path.join(directory, "authorization.json"); const archive = path.join(directory, "authorization.zip");
  try {
    writeFileSync(json, `${JSON.stringify(authorization)}\n`); execFileSync("zip", ["-q", "-j", archive, json]); const bytes = readFileSync(archive); const digest = `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
    const workflow = { id: 123456, repository: { id: 1, full_name: "T-ej2003/genuine-scan-main" }, head_repository: { full_name: "T-ej2003/genuine-scan-main" }, path: ".github/workflows/authorize-production-mixed-dual-slot-topology-recovery.yml", event: "workflow_dispatch", head_sha: sourceSha, status: "completed", conclusion: "success", run_attempt: 1, actor: { login: "operator" } };
    const artifact = { id: 88, name: MIXED_DUAL_SLOT_RECOVERY_ARTIFACT, expired: false, digest, workflow_run: { id: 123456, head_sha: sourceSha, repository_id: 1 } };
    const run = (command, args, options = {}) => { const joined = args.join(" "); if (command === "gh" && joined.includes("/actions/runs/123456/artifacts")) return JSON.stringify([{ artifacts: [artifact] }]); if (command === "gh" && joined.includes("/actions/runs/123456")) return JSON.stringify(workflow); if (command === "gh") return bytes; return execFileSync(command, args, { encoding: options.encoding === null ? null : "utf8" }); };
    assert.equal(resolveMixedDualSlotRecoveryAuthorizationArtifact({ workflowRunId: "123456", workflowRunAttempt: "1", sourceSha, preparation, preparationFileSha256, now, run }).authorization.authorizationSha256, authorization.authorizationSha256);
    assert.throws(() => resolveMixedDualSlotRecoveryAuthorizationArtifact({ workflowRunId: "123456", workflowRunAttempt: "2", sourceSha, preparation, preparationFileSha256, now, run }), /provenance/);
  } finally { rmSync(directory, { recursive: true, force: true }); }
});
