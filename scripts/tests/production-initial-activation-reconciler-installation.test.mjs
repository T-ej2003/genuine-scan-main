import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { PRODUCTION_ENVIRONMENT_APPROVAL, createProductionEnvironmentApprovalEvidence } from "../aws/production-github-environment-approval.mjs";
import { INSTALLATION, INSTALLATION_BACKEND, assertInstallationAuthorization, assertInstallationInitializedBackendMetadata, assertInstallationPlan, assertInstallationPreparation, assertInstallationStateResources, classifyInstallationStatePullError, createInstallationAuthorization, createInstallationPreparation, resolveInstallationAuthorizationArtifact, stateIdentity } from "../aws/production-initial-activation-reconciler-installation-contract.mjs";
import { executeInstallation, runInstallCli } from "../aws/install-production-initial-activation-reconciler.mjs";
import { discoverInstallationPredecessor } from "../aws/prepare-production-initial-activation-reconciler-installation.mjs";
import { INITIAL_ACTIVATION_RECONCILER } from "../aws/verify-production-initial-activation-policy-reconciler.mjs";

const sourceSha = "a".repeat(40);
const now = new Date("2026-09-05T12:00:00.000Z");
const trust = fs.readFileSync("infra/aws/terraform/production-initial-activation-policy-reconciler/trust-policy.json", "utf8");
const permissions = fs.readFileSync("infra/aws/terraform/production-initial-activation-policy-reconciler/permissions-policy.json", "utf8");
const capability = JSON.parse(fs.readFileSync("documents/ops/iam/MSCQRProductionInitialActivationPolicyReconcilerInstallation-v1.json", "utf8"));
const fixture = (name) => JSON.parse(fs.readFileSync(`scripts/tests/fixtures/production-initial-activation-reconciler-plan-${name}.json`, "utf8"));
const plan = fixture("absent");
const partialPlans = [fixture("partial-role"), fixture("partial-policy"), fixture("partial-unattached")];
const allAddresses = [...INSTALLATION.expectedAddresses].sort();
const planBytes = Buffer.from("exact-saved-plan");
const state = JSON.stringify({ version: 4, terraform_version: "1.15.8", serial: 0, lineage: "first-install-lineage", outputs: {}, resources: [] });
const installedState = JSON.stringify({ version: 4, terraform_version: "1.15.8", serial: 1, lineage: "first-install-lineage", outputs: {}, resources: [
  { mode: "managed", type: "aws_iam_role", name: "reconciler", instances: [{}] },
  { mode: "managed", type: "aws_iam_policy", name: "reconciler", instances: [{}] },
  { mode: "managed", type: "aws_iam_role_policy_attachment", name: "reconciler", instances: [{}] },
] });
const approval = createProductionEnvironmentApprovalEvidence({
  environmentConfig: { id: 7, name: "production", can_admins_bypass: false, protection_rules: [{ type: "required_reviewers", prevent_self_review: true, reviewers: [{ type: "User", reviewer: { id: 3, login: "reviewer" } }] }] },
  repository: INSTALLATION.repository, environment: "production", sourceSha,
  workflowRef: PRODUCTION_ENVIRONMENT_APPROVAL.installationWorkflowRef, eventName: "workflow_dispatch", workflowRunId: "100", workflowRunAttempt: "1", executionActor: "operator", observedAt: now.toISOString(), actualApproval: { state: "approved", environmentId: 7, environmentName: "production", userId: 3, userLogin: "reviewer" },
});
const preparation = createInstallationPreparation({ sourceSha, state: stateIdentity(undefined), livePredecessor: "ABSENT", livePredecessorAddresses: [], planJson: plan, planBytes, preparedAt: now.toISOString() });
const authorization = createInstallationAuthorization({ preparation, preparationArtifactSha256: preparation.preparationArtifactSha256, protectedEnvironmentApprovalEvidence: approval, sourceSha });
const completePlan = fixture("complete");
const completePlanBytes = Buffer.from("exact-saved-noop-plan");
const completePreparation = createInstallationPreparation({ sourceSha, state: stateIdentity(Buffer.from(installedState)), livePredecessor: "EXACT_COMPLETE", livePredecessorAddresses: allAddresses, planJson: completePlan, planBytes: completePlanBytes, preparedAt: now.toISOString() });
const completeAuthorization = createInstallationAuthorization({ preparation: completePreparation, preparationArtifactSha256: completePreparation.preparationArtifactSha256, protectedEnvironmentApprovalEvidence: approval, sourceSha });

const discoveryRun = ({ role = true, policy = true, attached = [{ PolicyArn: INITIAL_ACTIVATION_RECONCILER.policyArn }], inline = [], entities = [{ PolicyRoles: [{ RoleName: INITIAL_ACTIVATION_RECONCILER.roleName }], PolicyUsers: [], PolicyGroups: [], IsTruncated: false }], policyPages } = {}) => (args) => {
  if (args[0] === "sts") return JSON.stringify({ Arn: INSTALLATION.administratorArn });
  if (args[1] === "get-open-id-connect-provider") return JSON.stringify({ Url: "token.actions.githubusercontent.com", ClientIDList: ["sts.amazonaws.com"] });
  if (args[1] === "get-role") { if (!role) throw Object.assign(new Error("NoSuchEntity"), { stderr: "NoSuchEntity" }); return JSON.stringify({ Role: { Arn: INITIAL_ACTIVATION_RECONCILER.roleArn, MaxSessionDuration: 3600, AssumeRolePolicyDocument: JSON.parse(trust) } }); }
  if (args[1] === "get-policy") { if (!policy) throw Object.assign(new Error("NoSuchEntity"), { stderr: "NoSuchEntity" }); return JSON.stringify({ Policy: { Arn: INITIAL_ACTIVATION_RECONCILER.policyArn, PolicyName: INITIAL_ACTIVATION_RECONCILER.policyName, DefaultVersionId: "v1", PermissionsBoundaryUsageCount: 0 } }); }
  if (args[1] === "list-policies") {
    const pages = policyPages || [{ Policies: policy ? [{ Arn: INITIAL_ACTIVATION_RECONCILER.policyArn, PolicyName: INITIAL_ACTIVATION_RECONCILER.policyName }] : [], IsTruncated: false }];
    return JSON.stringify(pages[args.includes("--marker") ? 1 : 0]);
  }
  if (args[1] === "get-policy-version") return JSON.stringify({ PolicyVersion: { Document: JSON.parse(permissions) } });
  if (args[1] === "list-attached-role-policies") return JSON.stringify({ AttachedPolicies: attached });
  if (args[1] === "list-role-policies") return JSON.stringify({ PolicyNames: inline });
  if (args[1] === "list-entities-for-policy") return JSON.stringify(entities[args.includes("--marker") ? 1 : 0]);
  throw new Error(`unexpected discovery call: ${args.join(" ")}`);
};

const githubAuthorizationRunner = ({ artifactBody = authorization, mutateWorkflow, mutateArtifact, environmentConfig, approvals } = {}) => {
  const archive = Buffer.from("fixture-authorization-zip");
  const workflow = mutateWorkflow?.({ id: 100, repository: { id: 1, full_name: INSTALLATION.repository }, head_repository: { full_name: INSTALLATION.repository }, path: INSTALLATION.authorizationWorkflowPath, event: "workflow_dispatch", head_sha: sourceSha, status: "completed", conclusion: "success", run_attempt: 1, actor: { login: "operator" } }) || { id: 100, repository: { id: 1, full_name: INSTALLATION.repository }, head_repository: { full_name: INSTALLATION.repository }, path: INSTALLATION.authorizationWorkflowPath, event: "workflow_dispatch", head_sha: sourceSha, status: "completed", conclusion: "success", run_attempt: 1, actor: { login: "operator" } };
  const artifact = mutateArtifact?.({ id: 9, name: INSTALLATION.authorizationArtifactName, expired: false, workflow_run: { id: 100, head_sha: sourceSha, repository_id: 1 }, digest: `sha256:${crypto.createHash("sha256").update(archive).digest("hex")}` }) || { id: 9, name: INSTALLATION.authorizationArtifactName, expired: false, workflow_run: { id: 100, head_sha: sourceSha, repository_id: 1 }, digest: `sha256:${crypto.createHash("sha256").update(archive).digest("hex")}` };
  const env = environmentConfig || { id: 7, name: "production", can_admins_bypass: false, protection_rules: [{ type: "required_reviewers", prevent_self_review: true, reviewers: [{ type: "User", reviewer: { id: 3, login: "reviewer" } }] }] };
  const approvalEvents = approvals || [{ state: "approved", environments: [{ id: 7, name: "production" }], user: { id: 3, login: "reviewer" } }];
  return (command, args) => {
    if (command === "unzip") {
      if (args[0] === "-Z1") return "authorization.json\n";
      if (args[0] === "-Z") return "-rw-------  authorization.json\n";
      if (args[0] === "-p") return Buffer.from(JSON.stringify(artifactBody));
      throw new Error(`unexpected unzip arguments: ${args.join(" ")}`);
    }
    assert.equal(command, "gh");
    const endpoint = args[1];
    if (endpoint.endsWith("/actions/runs/100")) return JSON.stringify(workflow);
    if (endpoint.endsWith("/artifacts")) return JSON.stringify([{ artifacts: [artifact] }]);
    if (endpoint.endsWith("/environments/production")) return JSON.stringify(env);
    if (endpoint.endsWith("/approvals")) return JSON.stringify(approvalEvents);
    if (endpoint.endsWith("/zip")) return archive;
    throw new Error(`unexpected GitHub endpoint: ${endpoint}`);
  };
};

test("first-install preparation binds absent state and exact plan addresses", () => {
  assert.equal(preparation.predecessorState.stateExists, false);
  assert.equal(preparation.planSemantics.resourceChangeCount, 3);
  assert.equal(preparation.planSemantics.noOpCount, 0);
  assert.doesNotThrow(() => assertInstallationPreparation(preparation, { sourceSha, planBytes }));
  assert.throws(() => assertInstallationPlan({ ...plan, resource_changes: [...plan.resource_changes, { address: "aws_s3_bucket.unrelated", mode: "managed", type: "aws_s3_bucket", change: { actions: ["create"], before: null } }] }), /resource count|unreviewed/);
});

test("real exact-partial plans count only creates across every safe topology", () => {
  for (const partial of partialPlans) {
    const semantics = assertInstallationPlan(partial);
    assert.ok(semantics.createCount === 1 || semantics.createCount === 2);
    assert.equal(semantics.noOpCount, 3 - semantics.createCount);
    const livePredecessorAddresses = assertInstallationPlan(partial).noOpAddresses;
    const partialPreparation = createInstallationPreparation({ sourceSha, state: stateIdentity(Buffer.from(state)), livePredecessor: "EXACT_PARTIAL", livePredecessorAddresses, planJson: partial, planBytes, preparedAt: now.toISOString() });
    assert.doesNotThrow(() => assertInstallationPreparation(partialPreparation, { sourceSha, planBytes }));
    assert.throws(() => createInstallationPreparation({ sourceSha, state: stateIdentity(undefined), livePredecessor: "EXACT_PARTIAL", livePredecessorAddresses, planJson: partial, planBytes, preparedAt: now.toISOString() }), /state predecessor/);
  }
  assert.throws(() => createInstallationPreparation({
    sourceSha,
    state: stateIdentity(Buffer.from(state)),
    livePredecessor: "EXACT_PARTIAL",
    livePredecessorAddresses: ["aws_iam_policy.reconciler", "aws_iam_role.reconciler"],
    planJson: fixture("partial-role"),
    planBytes,
    preparedAt: now.toISOString(),
  }), /authenticated live predecessor/);
});

test("discovery reaches exact-complete only through the canonical verifier topology", () => {
  assert.deepEqual(discoverInstallationPredecessor({ run: discoveryRun() }), { classification: "EXACT_COMPLETE", existingAddresses: allAddresses });
  assert.deepEqual(discoverInstallationPredecessor({ run: discoveryRun({ attached: [], entities: [{ PolicyRoles: [], PolicyUsers: [], PolicyGroups: [], IsTruncated: false }] }) }), { classification: "EXACT_PARTIAL", existingAddresses: ["aws_iam_policy.reconciler", "aws_iam_role.reconciler"] });
  assert.equal(discoverInstallationPredecessor({ run: discoveryRun({ attached: [{ PolicyArn: INITIAL_ACTIVATION_RECONCILER.policyArn }, { PolicyArn: "arn:aws:iam::368992683803:policy/unexpected" }] }) }).classification, "UNEXPECTED");
  assert.equal(discoverInstallationPredecessor({ run: discoveryRun({ entities: [{ PolicyRoles: [{ RoleName: INITIAL_ACTIVATION_RECONCILER.roleName }], PolicyUsers: [{ UserName: "unexpected" }], PolicyGroups: [], IsTruncated: false }] }) }).classification, "UNEXPECTED");
  assert.equal(discoverInstallationPredecessor({ run: discoveryRun({ role: true, policy: false, attached: [{ PolicyArn: "arn:aws:iam::368992683803:policy/unexpected" }] }) }).classification, "UNEXPECTED");
  assert.equal(discoverInstallationPredecessor({ run: discoveryRun({ role: true, policy: false, inline: ["unexpected"] }) }).classification, "UNEXPECTED");
  assert.equal(discoverInstallationPredecessor({ run: discoveryRun({ role: false, policy: false, policyPages: [{ Policies: [{ Arn: "arn:aws:iam::368992683803:policy/other/MSCQRProductionInitialActivationPolicyReconciler", PolicyName: INITIAL_ACTIVATION_RECONCILER.policyName }], IsTruncated: false }] }) }).classification, "UNEXPECTED");
  assert.equal(discoverInstallationPredecessor({ run: discoveryRun({ role: false, policy: false, policyPages: [{ Policies: [], IsTruncated: true, Marker: "next" }, { Policies: [{ Arn: "arn:aws:iam::368992683803:policy/other/MSCQRProductionInitialActivationPolicyReconciler", PolicyName: INITIAL_ACTIVATION_RECONCILER.policyName }], IsTruncated: false }] }) }).classification, "UNEXPECTED");
  assert.throws(() => discoverInstallationPredecessor({ run: discoveryRun({ role: false, policy: false, policyPages: [{ Policies: [], IsTruncated: true }] }) }), /pagination/);
  assert.throws(() => discoverInstallationPredecessor({ run: (args) => {
    if (args[1] === "get-open-id-connect-provider") return JSON.stringify({ Url: "token.actions.githubusercontent.com", ClientIDList: ["sts.amazonaws.com"] });
    if (args[1] === "get-role") throw Object.assign(new Error("endpoint not found"), { stderr: "transport endpoint not found" });
    throw new Error(`unexpected discovery call: ${args.join(" ")}`);
  } }), /endpoint not found/);
});

test("authorization is source, plan, root and environment bound", () => {
  assert.doesNotThrow(() => assertInstallationAuthorization(authorization, { sourceSha, preparation }));
  const prettyFileSha256 = crypto.createHash("sha256").update(`${JSON.stringify(preparation, null, 2)}\n`).digest("hex");
  assert.notEqual(prettyFileSha256, preparation.preparationArtifactSha256);
  assert.throws(() => createInstallationAuthorization({ preparation, preparationArtifactSha256: prettyFileSha256, protectedEnvironmentApprovalEvidence: approval, sourceSha }), /artifact digest/);
  assert.throws(() => assertInstallationAuthorization({ ...authorization, sourceSha: "b".repeat(40) }, { sourceSha, preparation }), /binding|hash/);
  assert.throws(() => assertInstallationAuthorization({ ...authorization, administratorArn: "arn:aws:iam::368992683803:role/other" }, { sourceSha, preparation }), /operation|hash/);
});

test("authorization is accepted only from the authenticated GitHub run artifact", () => {
  const resolved = resolveInstallationAuthorizationArtifact({ workflowRunId: "100", workflowRunAttempt: "1", sourceSha, githubRun: githubAuthorizationRunner(), now });
  assert.equal(resolved.authorizationFileSha256, crypto.createHash("sha256").update(Buffer.from(JSON.stringify(authorization))).digest("hex"));
  assert.doesNotThrow(() => assertInstallationAuthorization(resolved.authorization, { sourceSha, preparation }));
  for (const mutateWorkflow of [
    (workflow) => ({ ...workflow, conclusion: "failure" }),
    (workflow) => ({ ...workflow, repository: { ...workflow.repository, full_name: "other/repository" } }),
    (workflow) => ({ ...workflow, path: ".github/workflows/other.yml" }),
    (workflow) => ({ ...workflow, head_sha: "b".repeat(40) }),
    (workflow) => ({ ...workflow, run_attempt: 2 }),
  ]) assert.throws(() => resolveInstallationAuthorizationArtifact({ workflowRunId: "100", workflowRunAttempt: "1", sourceSha, githubRun: githubAuthorizationRunner({ mutateWorkflow }), now }), /provenance/);
  assert.throws(() => resolveInstallationAuthorizationArtifact({ workflowRunId: "100", workflowRunAttempt: "1", sourceSha, githubRun: githubAuthorizationRunner({ mutateArtifact: (artifact) => ({ ...artifact, workflow_run: { ...artifact.workflow_run, id: 101 } }) }), now }), /artifact identity/);
  assert.throws(() => resolveInstallationAuthorizationArtifact({ workflowRunId: "100", workflowRunAttempt: "1", sourceSha, githubRun: githubAuthorizationRunner({ mutateArtifact: (artifact) => ({ ...artifact, digest: `sha256:${"0".repeat(64)}` }) }), now }), /archive digest/);
  assert.throws(() => resolveInstallationAuthorizationArtifact({ workflowRunId: "100", workflowRunAttempt: "1", sourceSha, githubRun: githubAuthorizationRunner({ approvals: [] }), now }), /approval event/);
});

test("locally self-consistent authorization has no provenance and cannot become authorization", () => {
  const forged = createInstallationAuthorization({ preparation, preparationArtifactSha256: preparation.preparationArtifactSha256, protectedEnvironmentApprovalEvidence: approval, sourceSha });
  assert.doesNotThrow(() => assertInstallationAuthorization(forged, { sourceSha, preparation }));
  assert.throws(() => resolveInstallationAuthorizationArtifact({ workflowRunId: "100", workflowRunAttempt: "1", sourceSha, githubRun: () => { throw new Error("no authenticated GitHub run"); }, now }), /unavailable/);
});

test("executor applies one exact plan and requires canonical verifier", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-install-test-"));
  const resultPath = path.join(directory, "result.json");
  let applies = 0;
  let reads = 0;
  const result = executeInstallation({ sourceSha, preparation, authorization, planBytes, planJson: plan, administratorArn: INSTALLATION.administratorArn, livePredecessor: "ABSENT", livePredecessorAddresses: [], applySavedPlan: ({ planBytes: bytes }) => { applies += 1; assert.deepEqual(bytes, planBytes); }, verifyInstalled: () => true, readState: () => reads++ === 0 ? undefined : Buffer.from(installedState), resultPath, consumptionDirectory: path.join(directory, "consumptions"), now });
  assert.equal(applies, 1);
  assert.equal(result.applyCount, 1);
  assert.equal(result.targetPolicyCreatePolicyVersionCount, 0);
  assert.equal(JSON.parse(fs.readFileSync(resultPath)).verifier, "PASS");
  fs.rmSync(directory, { recursive: true, force: true });
});

test("realistic absent first install reaches only the mocked exact saved-plan apply boundary", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-install-cli-"));
  const terraformDataDir = path.join(directory, "terraform");
  fs.mkdirSync(terraformDataDir, { mode: 0o700 });
  const metadata = JSON.parse(fs.readFileSync("scripts/tests/fixtures/production-green-stage-b-s3-backend-metadata.json", "utf8"));
  metadata.backend.config.key = INSTALLATION.backend.key;
  fs.writeFileSync(path.join(terraformDataDir, "terraform.tfstate"), JSON.stringify(metadata), { mode: 0o600 });
  const planPath = path.join(directory, "installation.tfplan");
  const preparationPath = path.join(directory, "preparation.json");
  const resultPath = path.join(directory, "result.json");
  fs.writeFileSync(planPath, planBytes, { mode: 0o600 });
  const preparationBytes = Buffer.from(`${JSON.stringify(preparation, null, 2)}\n`);
  fs.writeFileSync(preparationPath, preparationBytes, { mode: 0o600 });
  let applies = 0;
  let applied = false;
  let pulls = 0;
  const terraformEnvironments = [];
  const exec = (command, args, options = {}) => {
    if (command === "git") return args[0] === "status" ? "" : sourceSha;
    if (command !== "terraform") throw new Error(`unexpected executable: ${command}`);
    terraformEnvironments.push(options.env);
    if (args.includes("workspace")) return "default\n";
    if (args.includes("show")) return JSON.stringify(plan);
    if (args.includes("state") && args.includes("pull")) {
      pulls += 1;
      if (!applied) { const error = new Error("No state file was found!"); error.stderr = "No state file was found!"; throw error; }
      return installedState;
    }
    if (args.includes("apply")) { applies += 1; applied = true; assert.ok(args.includes("-lock-timeout=60s")); assert.ok(!args.includes("-lock=false")); return ""; }
    throw new Error(`unexpected Terraform command: ${args.join(" ")}`);
  };
  const run = (args) => {
    if (args[0] === "sts") return JSON.stringify({ Arn: INSTALLATION.administratorArn });
    if (args[1] === "get-open-id-connect-provider") return JSON.stringify({ Url: "token.actions.githubusercontent.com", ClientIDList: ["sts.amazonaws.com"] });
    if (!applied && (args[1] === "get-role" || args[1] === "get-policy")) { const error = new Error("NoSuchEntity"); error.stderr = "NoSuchEntity"; throw error; }
    if (!applied && args[1] === "list-policies") return JSON.stringify({ Policies: [], IsTruncated: false });
    return discoveryRun()(args);
  };
  const args = ["--execute", "--source-sha", sourceSha, "--admin-profile", "mscqr-production-root", "--preparation", preparationPath, "--preparation-file-sha256", crypto.createHash("sha256").update(preparationBytes).digest("hex"), "--authorization-workflow-run-id", "100", "--authorization-workflow-run-attempt", "1", "--plan", planPath, "--result", resultPath, "--terraform-data-dir", terraformDataDir];
  assert.throws(() => runInstallCli(args, { exec, run, githubRun: () => { throw new Error("forged local authorization has no GitHub provenance"); }, now }), /unavailable/);
  assert.equal(applies, 0);
  const result = runInstallCli(args, { exec, run, githubRun: githubAuthorizationRunner(), now, env: { HOME: os.homedir(), PATH: process.env.PATH, AWS_ACCESS_KEY_ID: "attacker", AWS_SECRET_ACCESS_KEY: "attacker", AWS_ENDPOINT_URL: "https://attacker.invalid", AWS_PROFILE: "attacker" } });
  assert.equal(applies, 1);
  assert.equal(pulls, 2);
  assert.equal(result.applyCount, 1);
  for (const environment of terraformEnvironments) {
    assert.equal(environment.AWS_PROFILE, "mscqr-production-root");
    assert.equal(environment.AWS_ACCESS_KEY_ID, undefined);
    assert.equal(environment.AWS_SECRET_ACCESS_KEY, undefined);
    assert.equal(environment.AWS_ENDPOINT_URL, undefined);
  }
  fs.rmSync(directory, { recursive: true, force: true });
});

test("real exact-partial plans traverse preparation, authorization, state CAS, and one intercepted apply", () => {
  const allStateResources = JSON.parse(installedState).resources;
  for (const [index, partialPlan] of partialPlans.entries()) {
    const noOpAddresses = partialPlan.resource_changes.filter((entry) => entry.change.actions[0] === "no-op").map((entry) => entry.address);
    const partialState = JSON.stringify({ version: 4, terraform_version: "1.15.8", serial: index + 1, lineage: "partial-lineage", outputs: {}, resources: allStateResources.filter((resource) => noOpAddresses.includes(`${resource.type}.${resource.name}`)) });
    const partialPlanBytes = Buffer.from(`exact-partial-plan-${index}`);
    const partialPreparation = createInstallationPreparation({ sourceSha, state: stateIdentity(Buffer.from(partialState)), livePredecessor: "EXACT_PARTIAL", livePredecessorAddresses: noOpAddresses, planJson: partialPlan, planBytes: partialPlanBytes, preparedAt: now.toISOString() });
    const partialAuthorization = createInstallationAuthorization({ preparation: partialPreparation, preparationArtifactSha256: partialPreparation.preparationArtifactSha256, protectedEnvironmentApprovalEvidence: approval, sourceSha });
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-install-partial-"));
    let applies = 0;
    let reads = 0;
    const result = executeInstallation({ sourceSha, preparation: partialPreparation, authorization: partialAuthorization, planBytes: partialPlanBytes, planJson: partialPlan, administratorArn: INSTALLATION.administratorArn, livePredecessor: "EXACT_PARTIAL", livePredecessorAddresses: noOpAddresses, applySavedPlan: () => { applies += 1; }, verifyInstalled: () => true, readState: () => Buffer.from(reads++ === 0 ? partialState : installedState), resultPath: path.join(directory, "result.json"), consumptionDirectory: path.join(directory, "consumptions"), now });
    assert.equal(applies, 1);
    assert.equal(result.applyCount, 1);
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("exact-complete replay performs zero apply", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-install-replay-"));
  let applies = 0;
  const result = executeInstallation({ sourceSha, preparation: completePreparation, authorization: completeAuthorization, planBytes: completePlanBytes, planJson: completePlan, administratorArn: INSTALLATION.administratorArn, livePredecessor: "EXACT_COMPLETE", livePredecessorAddresses: allAddresses, applySavedPlan: () => { applies += 1; }, verifyInstalled: () => true, readState: () => Buffer.from(installedState), resultPath: path.join(directory, "result.json"), now });
  assert.equal(applies, 0);
  assert.equal(result.applyCount, 0);
  fs.rmSync(directory, { recursive: true, force: true });
});

test("real exact-complete plan traverses the CLI contract and performs zero apply", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-install-complete-cli-"));
  const terraformDataDir = path.join(directory, "terraform");
  fs.mkdirSync(terraformDataDir, { mode: 0o700 });
  const metadata = JSON.parse(fs.readFileSync("scripts/tests/fixtures/production-green-stage-b-s3-backend-metadata.json", "utf8"));
  metadata.backend.config.key = INSTALLATION.backend.key;
  fs.writeFileSync(path.join(terraformDataDir, "terraform.tfstate"), JSON.stringify(metadata), { mode: 0o600 });
  const planPath = path.join(directory, "complete.tfplan");
  const preparationPath = path.join(directory, "preparation.json");
  const resultPath = path.join(directory, "result.json");
  fs.writeFileSync(planPath, completePlanBytes, { mode: 0o600 });
  const preparationBytes = Buffer.from(`${JSON.stringify(completePreparation, null, 2)}\n`);
  fs.writeFileSync(preparationPath, preparationBytes, { mode: 0o600 });
  let applies = 0;
  const exec = (command, args) => {
    if (command === "git") return args[0] === "status" ? "" : sourceSha;
    if (args.includes("workspace")) return "default\n";
    if (args.includes("show")) return JSON.stringify(completePlan);
    if (args.includes("state") && args.includes("pull")) return installedState;
    if (args.includes("apply")) { applies += 1; throw new Error("complete replay must not apply"); }
    throw new Error(`unexpected command: ${command} ${args.join(" ")}`);
  };
  const run = (args) => args[0] === "sts" ? JSON.stringify({ Arn: INSTALLATION.administratorArn }) : discoveryRun()(args);
  const result = runInstallCli(["--execute", "--source-sha", sourceSha, "--admin-profile", "mscqr-production-root", "--preparation", preparationPath, "--preparation-file-sha256", crypto.createHash("sha256").update(preparationBytes).digest("hex"), "--authorization-workflow-run-id", "100", "--authorization-workflow-run-attempt", "1", "--plan", planPath, "--result", resultPath, "--terraform-data-dir", terraformDataDir], { exec, run, githubRun: githubAuthorizationRunner({ artifactBody: completeAuthorization }), now });
  assert.equal(result.applyCount, 0);
  assert.equal(applies, 0);
  fs.rmSync(directory, { recursive: true, force: true });
});

test("exact-complete replay rejects absent state instead of adopting live resources", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-install-replay-state-"));
  assert.throws(() => executeInstallation({ sourceSha, preparation: completePreparation, authorization: completeAuthorization, planBytes: completePlanBytes, planJson: completePlan, administratorArn: INSTALLATION.administratorArn, livePredecessor: "EXACT_COMPLETE", livePredecessorAddresses: allAddresses, applySavedPlan: () => { throw new Error("must not apply"); }, verifyInstalled: () => true, readState: () => undefined, resultPath: path.join(directory, "result.json"), now }), /state/);
  fs.rmSync(directory, { recursive: true, force: true });
});

test("ambiguous apply recovers only through a successful read-only verifier", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-install-ambiguous-"));
  let applies = 0;
  let reads = 0;
  const result = executeInstallation({ sourceSha, preparation, authorization, planBytes, planJson: plan, administratorArn: INSTALLATION.administratorArn, livePredecessor: "ABSENT", livePredecessorAddresses: [], applySavedPlan: () => { applies += 1; throw new Error("transport lost after commit"); }, verifyInstalled: () => true, readState: () => reads++ === 0 ? undefined : Buffer.from(installedState), resultPath: path.join(directory, "result.json"), consumptionDirectory: path.join(directory, "consumptions"), now });
  assert.equal(applies, 1);
  assert.equal(result.recoveredFromAmbiguousApply, true);
  fs.rmSync(directory, { recursive: true, force: true });
});

test("ambiguous apply never retries when read-only verification fails", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-install-ambiguous-fail-"));
  let applies = 0;
  assert.throws(() => executeInstallation({ sourceSha, preparation, authorization, planBytes, planJson: plan, administratorArn: INSTALLATION.administratorArn, livePredecessor: "ABSENT", livePredecessorAddresses: [], applySavedPlan: () => { applies += 1; throw new Error("transport lost"); }, verifyInstalled: () => { throw new Error("not complete"); }, readState: () => undefined, resultPath: path.join(directory, "result.json"), consumptionDirectory: path.join(directory, "consumptions"), now }), /transport lost/);
  assert.equal(applies, 1);
  fs.rmSync(directory, { recursive: true, force: true });
});

test("unsafe state and plan changes fail before apply", () => {
  assert.deepEqual(stateIdentity(undefined), { stateExists: false });
  assert.throws(() => createInstallationPreparation({ sourceSha, state: stateIdentity(undefined), livePredecessor: "UNEXPECTED", livePredecessorAddresses: [], planJson: plan, planBytes }), /Unexpected|classification/);
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-install-fail-"));
  let applies = 0;
  assert.throws(() => executeInstallation({ sourceSha, preparation, authorization, planBytes: Buffer.from("changed"), planJson: plan, administratorArn: INSTALLATION.administratorArn, livePredecessor: "ABSENT", livePredecessorAddresses: [], applySavedPlan: () => { applies += 1; }, verifyInstalled: () => true, resultPath: path.join(directory, "result.json"), now }), /saved plan/);
  assert.equal(applies, 0);
  fs.rmSync(directory, { recursive: true, force: true });
});

test("no installation artifact contains credential-shaped material", () => {
  const serialized = JSON.stringify({ preparation, authorization });
  assert.doesNotMatch(serialized, /AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN|MFA|token/i);
  assert.ok(crypto.createHash("sha256").update(planBytes).digest("hex") === preparation.savedPlanSha256);
  assert.notEqual(preparation.preparationArtifactSha256, crypto.createHash("sha256").update(JSON.stringify(preparation, null, 2)).digest("hex"));
});

test("stale embedded preparation digest fails closed", () => {
  const tampered = { ...preparation, savedPlanByteLength: preparation.savedPlanByteLength + 1 };
  assert.throws(() => assertInstallationPreparation(tampered, { sourceSha, planBytes }), /hash/);
});

test("installation capability is purpose-bound and cannot consume the runtime target", () => {
  assert.equal(capability.sourceOnly, true);
  assert.equal(capability.terraformRoot, INSTALLATION.terraformRoot);
  assert.deepEqual(capability.resources, INSTALLATION.expectedAddresses);
  assert.equal(capability.maxAwsMutations["iam:CreatePolicyVersion"], 0);
  assert.match(capability.postcondition, /canonical-read-only-reconciler-verifier/);
});

test("initialized backend and state-pull contracts fail closed", () => {
  const metadata = JSON.parse(fs.readFileSync("scripts/tests/fixtures/production-green-stage-b-s3-backend-metadata.json", "utf8"));
  metadata.backend.config.key = INSTALLATION_BACKEND.key;
  assert.doesNotThrow(() => assertInstallationInitializedBackendMetadata(metadata.backend));
  assert.doesNotThrow(() => assertInstallationInitializedBackendMetadata({ ...metadata.backend, config: { ...metadata.backend.config, skip_requesting_account_id: null } }));
  for (const [field, value] of [["bucket", "wrong"], ["key", "wrong.tfstate"], ["region", "us-east-1"], ["use_lockfile", false], ["skip_requesting_account_id", true]]) assert.throws(() => assertInstallationInitializedBackendMetadata({ ...metadata.backend, config: { ...metadata.backend.config, [field]: value } }), /backend/);
  assert.throws(() => assertInstallationInitializedBackendMetadata({ type: "local", hash: 1, config: {} }), /backend/);
  assert.throws(() => assertInstallationInitializedBackendMetadata({ ...metadata.backend, config: { ...metadata.backend.config, unreviewed: true } }), /unreviewed/);
  assert.deepEqual(classifyInstallationStatePullError({ stderr: "No state file was found!" }), undefined);
  assert.deepEqual(classifyInstallationStatePullError({ stderr: "No state file was found!\n\nState management commands require a state file. Run this command in a directory where Terraform has been run.\n" }), undefined);
  assert.deepEqual(classifyInstallationStatePullError({ stderr: "\u001b[31m╷\u001b[0m\n\u001b[31m│ Error: No state file was found!\u001b[0m\n\u001b[31m│ State management commands require a state file. Run this command in a directory where Terraform has been run.\u001b[0m\n╵\n" }), undefined);
  assert.throws(() => classifyInstallationStatePullError({ stderr: "Error: No state file was found!\nError: AccessDenied" }), (error) => error.stderr.includes("AccessDenied"));
  assert.throws(() => classifyInstallationStatePullError({ stderr: "AccessDenied" }), (error) => error.stderr === "AccessDenied");
  assert.throws(() => classifyInstallationStatePullError({ stderr: "timeout" }), (error) => error.stderr === "timeout");
  assert.throws(() => classifyInstallationStatePullError({ stderr: "malformed state" }), (error) => error.stderr === "malformed state");
  assertInstallationStateResources(Buffer.from(installedState));
  assert.throws(() => assertInstallationStateResources(Buffer.from(state)), /state/);
});

test("first-install attachment permits only its exact computed policy reference", () => {
  assert.doesNotThrow(() => assertInstallationPlan(plan));
  const withoutReference = structuredClone(plan);
  withoutReference.configuration.root_module.resources[2].expressions.policy_arn = {};
  assert.throws(() => assertInstallationPlan(withoutReference), /resource configuration/);
  const wrongReference = structuredClone(plan);
  wrongReference.configuration.root_module.resources[2].expressions.policy_arn.references = ["aws_iam_policy.other.arn"];
  assert.throws(() => assertInstallationPlan(wrongReference), /resource configuration/);
  const literal = structuredClone(plan);
  literal.resource_changes[2].change.after.policy_arn = INSTALLATION.policyArn;
  delete literal.resource_changes[2].change.after_unknown.policy_arn;
  assert.throws(() => assertInstallationPlan(literal), /attachment contract/);
  assert.doesNotThrow(() => assertInstallationPlan(completePlan));
  const wrongRole = structuredClone(plan);
  wrongRole.resource_changes[2].change.after.role = "other";
  assert.throws(() => assertInstallationPlan(wrongRole), /attachment contract/);
});

test("saved plans bind the exact provider, resource configuration, and no-provisioner boundary", () => {
  for (const canonicalPlan of [plan, ...partialPlans, completePlan]) assert.doesNotThrow(() => assertInstallationPlan(canonicalPlan));
  for (const mutate of [
    (candidate) => { candidate.configuration.provider_config.aws.expressions.allowed_account_ids.constant_value = ["000000000000"]; },
    (candidate) => { candidate.configuration.provider_config.aws.expressions.profile = { constant_value: "other" }; },
    (candidate) => { candidate.configuration.provider_config.aws.expressions.assume_role = { references: ["local.other_role"] }; },
    (candidate) => { candidate.configuration.provider_config.aws.expressions.endpoints = { constant_value: { iam: "https://attacker.invalid" } }; },
    (candidate) => { candidate.configuration.provider_config.other = structuredClone(candidate.configuration.provider_config.aws); },
    (candidate) => { candidate.configuration.root_module.resources[0].provider_config_key = "aws.other"; },
    (candidate) => { candidate.configuration.root_module.resources[0].provisioners = [{ type: "local-exec", expressions: { command: { constant_value: "aws iam create-user --user-name attacker" } } }]; },
    (candidate) => { candidate.configuration.root_module.module_calls = { attacker: { source: "./attacker" } }; },
    (candidate) => { candidate.configuration.root_module.resources[1].expressions.name = { constant_value: "other" }; },
    (candidate) => { candidate.configuration.root_module.outputs.unreviewed = { expression: { constant_value: "other" } }; },
  ]) {
    const changed = structuredClone(plan);
    mutate(changed);
    assert.throws(() => assertInstallationPlan(changed), /configuration boundary|provider configuration|root configuration|resource configuration/);
  }
});

test("real no-op plan authenticates all resources while counting zero mutation", () => {
  const semantics = assertInstallationPlan(completePlan);
  assert.equal(semantics.plannedResourceCount, 3);
  assert.equal(semantics.noOpCount, 3);
  assert.equal(semantics.actionableResourceChangeCount, 0);
  assert.deepEqual(semantics.changedAddresses, []);
  assert.doesNotThrow(() => assertInstallationPreparation(completePreparation, { sourceSha, planBytes: completePlanBytes }));
});

test("IAM paths and every security-relevant desired value are exact for create and no-op", () => {
  for (const canonicalPlan of [plan, ...partialPlans, completePlan]) {
    assert.doesNotThrow(() => assertInstallationPlan(canonicalPlan));
    for (const [address, field, value] of [
      ["aws_iam_role.reconciler", "name", "wrong"],
      ["aws_iam_role.reconciler", "path", "/evil/"],
      ["aws_iam_role.reconciler", "description", "wrong"],
      ["aws_iam_role.reconciler", "force_detach_policies", true],
      ["aws_iam_role.reconciler", "max_session_duration", 7200],
      ["aws_iam_role.reconciler", "permissions_boundary", "arn:aws:iam::368992683803:policy/other"],
      ["aws_iam_role.reconciler", "assume_role_policy", "{}"],
      ["aws_iam_role.reconciler", "tags", {}],
      ["aws_iam_policy.reconciler", "name", "wrong"],
      ["aws_iam_policy.reconciler", "path", "/evil/"],
      ["aws_iam_policy.reconciler", "description", "wrong"],
      ["aws_iam_policy.reconciler", "delay_after_policy_creation_in_ms", 1],
      ["aws_iam_policy.reconciler", "policy", "{}"],
      ["aws_iam_policy.reconciler", "tags", {}],
    ]) {
      const changed = structuredClone(canonicalPlan);
      const resource = changed.resource_changes.find((entry) => entry.address === address);
      resource.change.after[field] = value;
      assert.throws(() => assertInstallationPlan(changed), /predecessor|contract/);
    }
  }
});

test("updates, deletes, replacements, reads, and unexpected no-ops fail closed", () => {
  for (const actions of [["update"], ["delete"], ["delete", "create"], ["create", "delete"], ["read"]]) {
    const changed = structuredClone(completePlan);
    changed.resource_changes[0].change.actions = actions;
    assert.throws(() => assertInstallationPlan(changed), /resource action/);
  }
  const unexpected = structuredClone(completePlan);
  unexpected.resource_changes[0].address = "aws_iam_policy.other";
  assert.throws(() => assertInstallationPlan(unexpected), /unreviewed|missing/);
});

test("production apply uses native Terraform state locking", () => {
  const source = fs.readFileSync("scripts/aws/install-production-initial-activation-reconciler.mjs", "utf8");
  const preparationSource = fs.readFileSync("scripts/aws/prepare-production-initial-activation-reconciler-installation.mjs", "utf8");
  assert.doesNotMatch(source, /"apply",[^\n]*"-lock=false"/);
  assert.match(source, /"apply",[^\n]*"-lock-timeout=60s"/);
  assert.match(preparationSource, /-backend-config=use_lockfile=\$\{INSTALLATION\.backend\.useLockfile\}/);
  assert.doesNotMatch(preparationSource, /"init",[^\n]*"-lock=false"/);
});

test("authorization workflow passes dynamic values through environment variables, never shell interpolation", () => {
  const workflow = fs.readFileSync(".github/workflows/authorize-production-initial-activation-policy-reconciler-installation.yml", "utf8");
  const authorizationStep = workflow.match(/- name: Produce exact installation authorization[\s\S]*?(?=\n      - uses: actions\/upload-artifact@v4)/)?.[0];
  assert.ok(authorizationStep);
  const shell = authorizationStep.split("\n        run: |\n")[1];
  assert.doesNotMatch(shell, /\$\{\{/);
  assert.match(authorizationStep, /PREPARATION_ARTIFACT_BASE64: \$\{\{ inputs\.preparation_artifact_base64 \}\}/);
  assert.match(shell, /printf '%s' "\$PREPARATION_ARTIFACT_BASE64"/);
  assert.match(shell, /--environment-approval-sha256 "\$ENVIRONMENT_APPROVAL_SHA256"/);
});
