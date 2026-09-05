import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { PRODUCTION_ENVIRONMENT_APPROVAL, createProductionEnvironmentApprovalEvidence } from "../aws/production-github-environment-approval.mjs";
import { INSTALLATION, INSTALLATION_BACKEND, assertInstallationAuthorization, assertInstallationInitializedBackendMetadata, assertInstallationPlan, assertInstallationPreparation, assertInstallationStateResources, classifyInstallationStatePullError, createInstallationAuthorization, createInstallationPreparation, stateIdentity } from "../aws/production-initial-activation-reconciler-installation-contract.mjs";
import { executeInstallation, runInstallCli } from "../aws/install-production-initial-activation-reconciler.mjs";
import { discoverInstallationPredecessor, runPrepareCli } from "../aws/prepare-production-initial-activation-reconciler-installation.mjs";
import { INITIAL_ACTIVATION_RECONCILER } from "../aws/verify-production-initial-activation-policy-reconciler.mjs";
import { INSTALLATION_BOOTSTRAP, assertBootstrapAuthorization, createBootstrapAuthorization, discoverBootstrapRole, installBootstrapRole, resolveBootstrapAuthorization, runBootstrapCli } from "../aws/production-initial-activation-reconciler-bootstrap.mjs";

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
  environmentConfig: { id: 7, name: INSTALLATION.environment, can_admins_bypass: false, protection_rules: [{ type: "required_reviewers", prevent_self_review: true, reviewers: [{ type: "User", reviewer: { id: 3, login: "reviewer" } }] }] },
  repository: INSTALLATION.repository, environment: INSTALLATION.environment, sourceSha,
  workflowRef: PRODUCTION_ENVIRONMENT_APPROVAL.installationWorkflowRef, eventName: "workflow_dispatch", workflowRunId: "100", workflowRunAttempt: "1", executionActor: "operator", observedAt: now.toISOString(), actualApproval: { state: "approved", environmentId: 7, environmentName: INSTALLATION.environment, userId: 3, userLogin: "reviewer" },
});
const bootstrapApproval = createProductionEnvironmentApprovalEvidence({
  environmentConfig: { id: 8, name: INSTALLATION_BOOTSTRAP.environment, can_admins_bypass: false, protection_rules: [{ type: "required_reviewers", prevent_self_review: true, reviewers: [{ type: "User", reviewer: { id: 3, login: "reviewer" } }] }] },
  repository: INSTALLATION_BOOTSTRAP.repository, environment: INSTALLATION_BOOTSTRAP.environment, sourceSha,
  workflowRef: INSTALLATION_BOOTSTRAP.workflowRef, eventName: "workflow_dispatch", workflowRunId: "200", workflowRunAttempt: "1", executionActor: "operator", observedAt: now.toISOString(), actualApproval: { state: "approved", environmentId: 8, environmentName: INSTALLATION_BOOTSTRAP.environment, userId: 3, userLogin: "reviewer" },
});
const preparation = createInstallationPreparation({ sourceSha, state: stateIdentity(undefined), livePredecessor: "ABSENT", livePredecessorAddresses: [], planJson: plan, planBytes, preparedAt: now.toISOString() });
const authorization = createInstallationAuthorization({ preparation, preparationArtifactSha256: preparation.preparationArtifactSha256, protectedEnvironmentApprovalEvidence: approval, sourceSha });
const completePlan = fixture("complete");
const completePlanBytes = Buffer.from("exact-saved-noop-plan");
const completePreparation = createInstallationPreparation({ sourceSha, state: stateIdentity(Buffer.from(installedState)), livePredecessor: "EXACT_COMPLETE", livePredecessorAddresses: allAddresses, planJson: completePlan, planBytes: completePlanBytes, preparedAt: now.toISOString() });
const completeAuthorization = createInstallationAuthorization({ preparation: completePreparation, preparationArtifactSha256: completePreparation.preparationArtifactSha256, protectedEnvironmentApprovalEvidence: approval, sourceSha });
const reconcilerTags = Object.entries(INITIAL_ACTIVATION_RECONCILER.tags).map(([Key, Value]) => ({ Key, Value }));

const discoveryRun = ({ role = true, policy = true, attached = [{ PolicyArn: INITIAL_ACTIVATION_RECONCILER.policyArn }], inline = [], entities = [{ PolicyRoles: [{ RoleName: INITIAL_ACTIVATION_RECONCILER.roleName }], PolicyUsers: [], PolicyGroups: [], IsTruncated: false }], policyPages } = {}) => (args) => {
  if (args[0] === "sts") return JSON.stringify({ Arn: "arn:aws:iam::368992683803:root" });
  if (args[1] === "get-open-id-connect-provider") return JSON.stringify({ Url: "token.actions.githubusercontent.com", ClientIDList: ["sts.amazonaws.com"] });
  if (args[1] === "get-role") { if (!role) throw Object.assign(new Error("NoSuchEntity"), { stderr: "NoSuchEntity" }); return JSON.stringify({ Role: { Arn: INITIAL_ACTIVATION_RECONCILER.roleArn, RoleName: INITIAL_ACTIVATION_RECONCILER.roleName, Path: "/", Description: INITIAL_ACTIVATION_RECONCILER.roleDescription, Tags: reconcilerTags, MaxSessionDuration: 3600, AssumeRolePolicyDocument: JSON.parse(trust), ...(typeof role === "object" ? role : {}) } }); }
  if (args[1] === "get-policy") { if (!policy) throw Object.assign(new Error("NoSuchEntity"), { stderr: "NoSuchEntity" }); return JSON.stringify({ Policy: { Arn: INITIAL_ACTIVATION_RECONCILER.policyArn, PolicyName: INITIAL_ACTIVATION_RECONCILER.policyName, Path: "/", Description: INITIAL_ACTIVATION_RECONCILER.policyDescription, Tags: reconcilerTags, DefaultVersionId: "v1", PermissionsBoundaryUsageCount: 0, ...(typeof policy === "object" ? policy : {}) } }); }
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
  assert.equal(discoverInstallationPredecessor({ run: discoveryRun({ role: { Description: "drift" }, policy: false }) }).classification, "UNEXPECTED");
  assert.equal(discoverInstallationPredecessor({ run: discoveryRun({ role: false, policy: { Tags: [] } }) }).classification, "UNEXPECTED");
  assert.equal(discoverInstallationPredecessor({ run: discoveryRun({ role: false, policy: false, policyPages: [{ Policies: [{ Arn: "arn:aws:iam::368992683803:policy/other/MSCQRProductionInitialActivationPolicyReconciler", PolicyName: INITIAL_ACTIVATION_RECONCILER.policyName }], IsTruncated: false }] }) }).classification, "UNEXPECTED");
  assert.equal(discoverInstallationPredecessor({ run: discoveryRun({ role: false, policy: false, policyPages: [{ Policies: [], IsTruncated: true, Marker: "next" }, { Policies: [{ Arn: "arn:aws:iam::368992683803:policy/other/MSCQRProductionInitialActivationPolicyReconciler", PolicyName: INITIAL_ACTIVATION_RECONCILER.policyName }], IsTruncated: false }] }) }).classification, "UNEXPECTED");
  assert.throws(() => discoverInstallationPredecessor({ run: discoveryRun({ role: false, policy: false, policyPages: [{ Policies: [], IsTruncated: true }] }) }), /pagination/);
  assert.throws(() => discoverInstallationPredecessor({ run: (args) => {
    if (args[1] === "get-open-id-connect-provider") return JSON.stringify({ Url: "token.actions.githubusercontent.com", ClientIDList: ["sts.amazonaws.com"] });
    if (args[1] === "get-role") throw Object.assign(new Error("endpoint not found"), { stderr: "transport endpoint not found" });
    throw new Error(`unexpected discovery call: ${args.join(" ")}`);
  } }), /endpoint not found/);
});

test("authorization is source, plan, workflow role and environment bound", () => {
  assert.doesNotThrow(() => assertInstallationAuthorization(authorization, { sourceSha, preparation }));
  const prettyFileSha256 = crypto.createHash("sha256").update(`${JSON.stringify(preparation, null, 2)}\n`).digest("hex");
  assert.notEqual(prettyFileSha256, preparation.preparationArtifactSha256);
  assert.throws(() => createInstallationAuthorization({ preparation, preparationArtifactSha256: prettyFileSha256, protectedEnvironmentApprovalEvidence: approval, sourceSha }), /artifact digest/);
  assert.throws(() => assertInstallationAuthorization({ ...authorization, sourceSha: "b".repeat(40) }, { sourceSha, preparation }), /binding|hash/);
  assert.throws(() => assertInstallationAuthorization({ ...authorization, executionRoleArn: "arn:aws:iam::368992683803:role/other" }, { sourceSha, preparation }), /operation|hash/);
});

test("executor applies one exact plan and requires canonical verifier", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-install-test-"));
  const resultPath = path.join(directory, "result.json");
  let applies = 0;
  let reads = 0;
  const result = executeInstallation({ sourceSha, preparation, authorization, planBytes, planJson: plan, executionRoleArn: INSTALLATION.executionRoleArn, livePredecessor: "ABSENT", livePredecessorAddresses: [], applySavedPlan: ({ planBytes: bytes }) => { applies += 1; assert.deepEqual(bytes, planBytes); }, verifyInstalled: () => true, readState: () => reads++ === 0 ? undefined : Buffer.from(installedState), resultPath, now });
  assert.equal(applies, 1);
  assert.equal(result.applyCount, 1);
  assert.equal(result.targetPolicyCreatePolicyVersionCount, 0);
  assert.equal(JSON.parse(fs.readFileSync(resultPath)).verifier, "PASS");
  fs.rmSync(directory, { recursive: true, force: true });
});

test("executor rejects a saved plan whose action split differs from authorized preparation", () => {
  const preparedPlan = partialPlans[0];
  const renderedPlan = partialPlans[1];
  const preparedAddresses = assertInstallationPlan(preparedPlan).noOpAddresses;
  const partialState = JSON.stringify({ version: 4, terraform_version: "1.15.8", serial: 1, lineage: "semantic-lineage", outputs: {}, resources: JSON.parse(installedState).resources.filter((resource) => preparedAddresses.includes(`${resource.type}.${resource.name}`)) });
  const preparedBytes = Buffer.from("prepared-partial-plan");
  const prepared = createInstallationPreparation({ sourceSha, state: stateIdentity(Buffer.from(partialState)), livePredecessor: "EXACT_PARTIAL", livePredecessorAddresses: preparedAddresses, planJson: preparedPlan, planBytes: preparedBytes, preparedAt: now.toISOString() });
  const authorized = createInstallationAuthorization({ preparation: prepared, preparationArtifactSha256: prepared.preparationArtifactSha256, protectedEnvironmentApprovalEvidence: approval, sourceSha });
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-install-semantic-mismatch-"));
  let applies = 0;
  assert.throws(() => executeInstallation({ sourceSha, preparation: prepared, authorization: authorized, planBytes: preparedBytes, planJson: renderedPlan, executionRoleArn: INSTALLATION.executionRoleArn, livePredecessor: "EXACT_PARTIAL", livePredecessorAddresses: preparedAddresses, applySavedPlan: () => { applies += 1; }, verifyInstalled: () => true, readState: () => Buffer.from(partialState), resultPath: path.join(directory, "result.json"), now }), /semantics differ/);
  assert.equal(applies, 0);
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
  const authorizationPath = path.join(directory, "authorization.json");
  const resultPath = path.join(directory, "result.json");
  fs.writeFileSync(planPath, planBytes, { mode: 0o600 });
  const preparationBytes = Buffer.from(`${JSON.stringify(preparation, null, 2)}\n`);
  fs.writeFileSync(preparationPath, preparationBytes, { mode: 0o600 });
  const authorizationBytes = Buffer.from(`${JSON.stringify(authorization, null, 2)}\n`);
  fs.writeFileSync(authorizationPath, authorizationBytes, { mode: 0o600 });
  let applies = 0;
  let applied = false;
  let failApply = true;
  const appliedPaths = [];
  let pulls = 0;
  const terraformEnvironments = [];
  const exec = (command, args, options = {}) => {
    if (command === "git") return args[0] === "status" ? "" : sourceSha;
    if (command !== "terraform") throw new Error(`unexpected executable: ${command}`);
    terraformEnvironments.push(options.env);
    if (args.includes("init")) return "";
    if (args.includes("workspace")) return "default\n";
    if (args.includes("show")) return JSON.stringify(plan);
    if (args.includes("state") && args.includes("pull")) {
      pulls += 1;
      if (!applied) { const error = new Error("No state file was found!"); error.stderr = "No state file was found!"; throw error; }
      return installedState;
    }
    if (args.includes("apply")) {
      applies += 1;
      appliedPaths.push(args.at(-1));
      assert.equal(fs.existsSync(args.at(-1)), true);
      assert.ok(args.includes("-lock-timeout=60s"));
      assert.ok(!args.includes("-lock=false"));
      if (failApply) throw new Error("lock timeout");
      applied = true;
      return "";
    }
    throw new Error(`unexpected Terraform command: ${args.join(" ")}`);
  };
  const run = (args) => {
    if (args[0] === "sts") return JSON.stringify({ Arn: `arn:aws:sts::368992683803:assumed-role/${INSTALLATION.executionRoleArn.split("/").at(-1)}/run` });
    if (args[1] === "get-open-id-connect-provider") return JSON.stringify({ Url: "token.actions.githubusercontent.com", ClientIDList: ["sts.amazonaws.com"] });
    if (!applied && (args[1] === "get-role" || args[1] === "get-policy")) { const error = new Error("NoSuchEntity"); error.stderr = "NoSuchEntity"; throw error; }
    if (!applied && args[1] === "list-policies") return JSON.stringify({ Policies: [], IsTruncated: false });
    return discoveryRun()(args);
  };
  const args = ["--execute", "--source-sha", sourceSha, "--preparation", preparationPath, "--preparation-file-sha256", crypto.createHash("sha256").update(preparationBytes).digest("hex"), "--authorization", authorizationPath, "--authorization-file-sha256", crypto.createHash("sha256").update(authorizationBytes).digest("hex"), "--plan", planPath, "--plan-file-sha256", crypto.createHash("sha256").update(planBytes).digest("hex"), "--result", resultPath, "--terraform-data-dir", terraformDataDir];
  assert.throws(() => runInstallCli(args, { exec, run, now }), /only inside/);
  assert.equal(applies, 0);
  const workflowEnv = { HOME: os.homedir(), PATH: process.env.PATH, AWS_ACCESS_KEY_ID: "session", AWS_SECRET_ACCESS_KEY: "session", AWS_SESSION_TOKEN: "session", GITHUB_ACTIONS: "true", GITHUB_REPOSITORY: INSTALLATION.repository, GITHUB_WORKFLOW_REF: PRODUCTION_ENVIRONMENT_APPROVAL.installationWorkflowRef, GITHUB_EVENT_NAME: "workflow_dispatch", GITHUB_RUN_ID: "100", GITHUB_RUN_ATTEMPT: "1", GITHUB_ACTOR: "operator" };
  assert.throws(() => runInstallCli(args, { exec, run, now, env: workflowEnv }), /lock timeout/);
  assert.equal(fs.existsSync(appliedPaths[0]), false);
  failApply = false;
  const result = runInstallCli(args, { exec, run, now, env: workflowEnv });
  assert.equal(applies, 2);
  assert.notEqual(appliedPaths[0], appliedPaths[1]);
  assert.equal(fs.existsSync(appliedPaths[1]), false);
  assert.equal(pulls, 3);
  assert.equal(result.applyCount, 1);
  for (const environment of terraformEnvironments) {
    assert.equal(environment.AWS_PROFILE, undefined);
    assert.equal(environment.AWS_ACCESS_KEY_ID, "session");
    assert.equal(environment.AWS_SECRET_ACCESS_KEY, "session");
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
    const result = executeInstallation({ sourceSha, preparation: partialPreparation, authorization: partialAuthorization, planBytes: partialPlanBytes, planJson: partialPlan, executionRoleArn: INSTALLATION.executionRoleArn, livePredecessor: "EXACT_PARTIAL", livePredecessorAddresses: noOpAddresses, applySavedPlan: () => { applies += 1; }, verifyInstalled: () => true, readState: () => Buffer.from(reads++ === 0 ? partialState : installedState), resultPath: path.join(directory, "result.json"), now });
    assert.equal(applies, 1);
    assert.equal(result.applyCount, 1);
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("exact-complete replay performs zero apply", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-install-replay-"));
  let applies = 0;
  const result = executeInstallation({ sourceSha, preparation: completePreparation, authorization: completeAuthorization, planBytes: completePlanBytes, planJson: completePlan, executionRoleArn: INSTALLATION.executionRoleArn, livePredecessor: "EXACT_COMPLETE", livePredecessorAddresses: allAddresses, applySavedPlan: () => { applies += 1; }, verifyInstalled: () => true, readState: () => Buffer.from(installedState), resultPath: path.join(directory, "result.json"), now });
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
  const authorizationPath = path.join(directory, "authorization.json");
  const resultPath = path.join(directory, "result.json");
  fs.writeFileSync(planPath, completePlanBytes, { mode: 0o600 });
  const preparationBytes = Buffer.from(`${JSON.stringify(completePreparation, null, 2)}\n`);
  fs.writeFileSync(preparationPath, preparationBytes, { mode: 0o600 });
  const authorizationBytes = Buffer.from(`${JSON.stringify(completeAuthorization, null, 2)}\n`);
  fs.writeFileSync(authorizationPath, authorizationBytes, { mode: 0o600 });
  let applies = 0;
  const exec = (command, args) => {
    if (command === "git") return args[0] === "status" ? "" : sourceSha;
    if (args.includes("init")) return "";
    if (args.includes("workspace")) return "default\n";
    if (args.includes("show")) return JSON.stringify(completePlan);
    if (args.includes("state") && args.includes("pull")) return installedState;
    if (args.includes("apply")) { applies += 1; throw new Error("complete replay must not apply"); }
    throw new Error(`unexpected command: ${command} ${args.join(" ")}`);
  };
  const assumedArn = `arn:aws:sts::368992683803:assumed-role/${INSTALLATION.executionRoleArn.split("/").at(-1)}/run`;
  const run = (args) => args[0] === "sts" ? JSON.stringify({ Arn: assumedArn }) : discoveryRun()(args);
  const workflowEnv = { HOME: os.homedir(), PATH: process.env.PATH, AWS_ACCESS_KEY_ID: "session", AWS_SECRET_ACCESS_KEY: "session", AWS_SESSION_TOKEN: "session", GITHUB_ACTIONS: "true", GITHUB_REPOSITORY: INSTALLATION.repository, GITHUB_WORKFLOW_REF: PRODUCTION_ENVIRONMENT_APPROVAL.installationWorkflowRef, GITHUB_EVENT_NAME: "workflow_dispatch", GITHUB_RUN_ID: "100", GITHUB_RUN_ATTEMPT: "1", GITHUB_ACTOR: "operator" };
  const result = runInstallCli(["--execute", "--source-sha", sourceSha, "--preparation", preparationPath, "--preparation-file-sha256", crypto.createHash("sha256").update(preparationBytes).digest("hex"), "--authorization", authorizationPath, "--authorization-file-sha256", crypto.createHash("sha256").update(authorizationBytes).digest("hex"), "--plan", planPath, "--plan-file-sha256", crypto.createHash("sha256").update(completePlanBytes).digest("hex"), "--result", resultPath, "--terraform-data-dir", terraformDataDir], { exec, run, now, env: workflowEnv });
  assert.equal(result.applyCount, 0);
  assert.equal(applies, 0);
  fs.rmSync(directory, { recursive: true, force: true });
});

test("exact-complete replay rejects absent state instead of adopting live resources", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-install-replay-state-"));
  assert.throws(() => executeInstallation({ sourceSha, preparation: completePreparation, authorization: completeAuthorization, planBytes: completePlanBytes, planJson: completePlan, executionRoleArn: INSTALLATION.executionRoleArn, livePredecessor: "EXACT_COMPLETE", livePredecessorAddresses: allAddresses, applySavedPlan: () => { throw new Error("must not apply"); }, verifyInstalled: () => true, readState: () => undefined, resultPath: path.join(directory, "result.json"), now }), /state/);
  fs.rmSync(directory, { recursive: true, force: true });
});

test("ambiguous apply recovers only through a successful read-only verifier", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-install-ambiguous-"));
  let applies = 0;
  let reads = 0;
  const result = executeInstallation({ sourceSha, preparation, authorization, planBytes, planJson: plan, executionRoleArn: INSTALLATION.executionRoleArn, livePredecessor: "ABSENT", livePredecessorAddresses: [], applySavedPlan: () => { applies += 1; throw new Error("transport lost after commit"); }, verifyInstalled: () => true, readState: () => { if (reads++ === 0) return undefined; if (reads === 2) return Buffer.from(installedState); throw new Error("recovery state must be captured once"); }, resultPath: path.join(directory, "result.json"), now });
  assert.equal(applies, 1);
  assert.equal(reads, 2);
  assert.equal(result.recoveredFromAmbiguousApply, true);
  assert.deepEqual(result.state, stateIdentity(Buffer.from(installedState)));
  fs.rmSync(directory, { recursive: true, force: true });
});

test("ambiguous apply never retries when read-only verification fails", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-install-ambiguous-fail-"));
  let applies = 0;
  assert.throws(() => executeInstallation({ sourceSha, preparation, authorization, planBytes, planJson: plan, executionRoleArn: INSTALLATION.executionRoleArn, livePredecessor: "ABSENT", livePredecessorAddresses: [], applySavedPlan: () => { applies += 1; throw new Error("transport lost"); }, verifyInstalled: () => { throw new Error("not complete"); }, readState: () => undefined, resultPath: path.join(directory, "result.json"), now }), /transport lost/);
  assert.equal(applies, 1);
  fs.rmSync(directory, { recursive: true, force: true });
});

test("unsafe state and plan changes fail before apply", () => {
  assert.deepEqual(stateIdentity(undefined), { stateExists: false });
  assert.throws(() => createInstallationPreparation({ sourceSha, state: stateIdentity(undefined), livePredecessor: "UNEXPECTED", livePredecessorAddresses: [], planJson: plan, planBytes }), /Unexpected|classification/);
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-install-fail-"));
  let applies = 0;
  assert.throws(() => executeInstallation({ sourceSha, preparation, authorization, planBytes: Buffer.from("changed"), planJson: plan, executionRoleArn: INSTALLATION.executionRoleArn, livePredecessor: "ABSENT", livePredecessorAddresses: [], applySavedPlan: () => { applies += 1; }, verifyInstalled: () => true, resultPath: path.join(directory, "result.json"), now }), /saved plan/);
  assert.equal(applies, 0);
  fs.rmSync(directory, { recursive: true, force: true });
});

test("no installation artifact contains credential-shaped material", () => {
  const serialized = JSON.stringify({ preparation, authorization });
  assert.doesNotMatch(serialized, /AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN|MFA/i);
  assert.ok(crypto.createHash("sha256").update(planBytes).digest("hex") === preparation.savedPlanSha256);
  assert.notEqual(preparation.preparationArtifactSha256, crypto.createHash("sha256").update(JSON.stringify(preparation, null, 2)).digest("hex"));
});

test("stale embedded preparation digest fails closed", () => {
  const tampered = { ...preparation, savedPlanByteLength: preparation.savedPlanByteLength + 1 };
  assert.throws(() => assertInstallationPreparation(tampered, { sourceSha, planBytes }), /hash/);
});

test("installation capability is purpose-bound and cannot consume the runtime target", () => {
  assert.equal(capability.sourceOnly, false);
  assert.equal(capability.terraformRoot, INSTALLATION.terraformRoot);
  assert.equal(capability.terraformVersion, INSTALLATION.terraformVersion);
  assert.equal(capability.concurrencyGroup, "production-deploy");
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

test("generated preparation normalizes Terraform outputs before private reads", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-install-prepare-modes-"));
  fs.chmodSync(directory, 0o700);
  const terraformDataDir = path.join(directory, "terraform");
  const outputPath = path.join(directory, "preparation.json");
  const backendMetadata = JSON.parse(fs.readFileSync("scripts/tests/fixtures/production-green-stage-b-s3-backend-metadata.json", "utf8"));
  backendMetadata.backend.config.key = INSTALLATION.backend.key;
  const exec = (command, args) => {
    if (command === "git") return args[0] === "status" ? "" : sourceSha;
    if (args.includes("init")) {
      fs.writeFileSync(path.join(terraformDataDir, "terraform.tfstate"), JSON.stringify(backendMetadata), { mode: 0o644 });
      return "";
    }
    if (args.includes("workspace")) return "default\n";
    if (args.includes("state") && args.includes("pull")) throw Object.assign(new Error("No state file was found!"), { stderr: "No state file was found!\n\nState management commands require a state file.\n" });
    if (args.includes("plan")) {
      fs.writeFileSync(args[args.indexOf("-out") + 1], planBytes, { mode: 0o644 });
      return "";
    }
    if (args.includes("show")) return JSON.stringify(plan);
    throw new Error(`unexpected command: ${command} ${args.join(" ")}`);
  };
  const prepared = runPrepareCli(["--prepare", "--source-sha", sourceSha, "--admin-profile", "mscqr-production-root", "--output", outputPath, "--terraform-data-dir", terraformDataDir, "--state-absent"], { exec, run: discoveryRun({ role: false, policy: false }) });
  assert.equal(prepared.livePredecessor, "ABSENT");
  assert.equal(fs.statSync(path.join(terraformDataDir, "terraform.tfstate")).mode & 0o777, 0o600);
  assert.equal(fs.statSync(path.join(directory, "installation.tfplan")).mode & 0o777, 0o600);
  fs.rmSync(directory, { recursive: true, force: true });
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
    (candidate) => { candidate.terraform_version = "1.15.7"; },
    (candidate) => { candidate.format_version = "1.1"; },
    (candidate) => { candidate.resource_drift = [{ address: "aws_iam_role.reconciler" }]; },
    (candidate) => { candidate.errored = true; },
  ]) {
    const changed = structuredClone(plan);
    mutate(changed);
    assert.throws(() => assertInstallationPlan(changed), /plan envelope/);
  }
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
  const authorizationStep = workflow.match(/- name: Produce exact installation authorization[\s\S]*?(?=\n      - name: Configure exact bootstrap role credentials)/)?.[0];
  assert.ok(authorizationStep);
  const shell = authorizationStep.split("\n        run: |\n")[1];
  assert.doesNotMatch(shell, /\$\{\{/);
  assert.match(authorizationStep, /PREPARATION_ARTIFACT_BASE64: \$\{\{ inputs\.preparation_artifact_base64 \}\}/);
  assert.match(shell, /printf '%s' "\$PREPARATION_ARTIFACT_BASE64"/);
  assert.match(shell, /--environment-approval-sha256 "\$ENVIRONMENT_APPROVAL_SHA256"/);
});

test("bootstrap role trust and permissions are exact and non-administrative", () => {
  const trustPolicy = JSON.parse(fs.readFileSync(INSTALLATION_BOOTSTRAP.trustPath, "utf8"));
  assert.deepEqual(trustPolicy.Statement, [{
    Sid: "GitHubProductionEnvironmentOnly", Effect: "Allow",
    Principal: { Federated: "arn:aws:iam::368992683803:oidc-provider/token.actions.githubusercontent.com" },
    Action: "sts:AssumeRoleWithWebIdentity",
    Condition: { StringEquals: { "token.actions.githubusercontent.com:aud": "sts.amazonaws.com", "token.actions.githubusercontent.com:sub": `repo:T-ej2003/genuine-scan-main:environment:${INSTALLATION_BOOTSTRAP.environment}` } },
  }]);
  const policy = JSON.parse(fs.readFileSync(INSTALLATION_BOOTSTRAP.permissionsPath, "utf8"));
  const serialized = JSON.stringify(policy);
  assert.doesNotMatch(serialized, /AdministratorAccess|PowerUserAccess|"iam:\*"|"s3:\*"/);
  assert.doesNotMatch(serialized, /CreatePolicyVersion|UpdateAssumeRolePolicy|PutRolePolicy|CreateUser|CreateAccessKey/);
  const mutations = policy.Statement.flatMap((statement) => (Array.isArray(statement.Action) ? statement.Action : [statement.Action])).filter((action) => /^(iam:(Create|Attach|Tag)|s3:(Put|Delete))/.test(action));
  assert.deepEqual(mutations.sort(), ["iam:AttachRolePolicy", "iam:CreatePolicy", "iam:CreateRole", "iam:TagPolicy", "iam:TagRole", "s3:DeleteObject", "s3:PutObject"].sort());
  assert.match(serialized, new RegExp(INITIAL_ACTIVATION_RECONCILER.roleArn));
  assert.match(serialized, new RegExp(INITIAL_ACTIVATION_RECONCILER.policyArn));
  assert.doesNotMatch(serialized, new RegExp(`${INSTALLATION_BOOTSTRAP.roleArn}(?:"|/)`));
  assert.notEqual(trustPolicy.Statement[0].Condition.StringEquals["token.actions.githubusercontent.com:sub"], "repo:T-ej2003/genuine-scan-main:environment:production");
});

test("bootstrap and installation implementation modules have an exact command dependency closure", () => {
  const commands = (file) => [...fs.readFileSync(file, "utf8").matchAll(/\["(iam|sts)", "([a-z0-9-]+)"/g)].map(([, service, operation]) => `${service}:${operation}`);
  assert.deepEqual([...new Set(commands("scripts/aws/production-initial-activation-reconciler-bootstrap.mjs"))].sort(), [
    "iam:create-role", "iam:get-role", "iam:get-role-policy", "iam:list-attached-role-policies", "iam:list-role-policies", "iam:put-role-policy", "sts:get-caller-identity",
  ]);
  assert.deepEqual([...new Set([
    ...commands("scripts/aws/install-production-initial-activation-reconciler.mjs"),
    ...commands("scripts/aws/prepare-production-initial-activation-reconciler-installation.mjs"),
    ...commands("scripts/aws/verify-production-initial-activation-policy-reconciler.mjs"),
  ])].sort(), [
    "iam:get-open-id-connect-provider", "iam:get-policy", "iam:get-policy-version", "iam:get-role", "iam:list-attached-role-policies", "iam:list-entities-for-policy", "iam:list-policies", "iam:list-role-policies", "sts:get-caller-identity",
  ]);
});

test("one-time root bootstrap is exact, resumable, and ambiguity never advances", () => {
  const authorization = createBootstrapAuthorization({ sourceSha, approval: bootstrapApproval, authorizedAt: now.toISOString() });
  assert.doesNotThrow(() => assertBootstrapAuthorization(authorization, { sourceSha, now }));
  const trustPolicy = JSON.parse(fs.readFileSync(INSTALLATION_BOOTSTRAP.trustPath, "utf8"));
  const permissionPolicy = JSON.parse(fs.readFileSync(INSTALLATION_BOOTSTRAP.permissionsPath, "utf8"));
  let role;
  let inline;
  const calls = [];
  const run = (args) => {
    calls.push(args[1] || args[0]);
    if (args[0] === "sts") return JSON.stringify({ Arn: INSTALLATION_BOOTSTRAP.administratorArn });
    if (args[1] === "get-role") { if (!role) throw Object.assign(new Error("NoSuchEntity"), { stderr: "NoSuchEntity" }); return JSON.stringify({ Role: role }); }
    if (args[1] === "list-attached-role-policies") return JSON.stringify({ AttachedPolicies: [] });
    if (args[1] === "list-role-policies") return JSON.stringify({ PolicyNames: inline ? [INSTALLATION_BOOTSTRAP.inlinePolicyName] : [] });
    if (args[1] === "get-role-policy") return JSON.stringify({ PolicyDocument: inline });
    if (args[1] === "create-role") { role = { Arn: INSTALLATION_BOOTSTRAP.roleArn, RoleName: INSTALLATION_BOOTSTRAP.roleName, Path: "/", Description: INSTALLATION_BOOTSTRAP.roleDescription, MaxSessionDuration: 3600, AssumeRolePolicyDocument: trustPolicy, Tags: Object.entries(INSTALLATION_BOOTSTRAP.tags).map(([Key, Value]) => ({ Key, Value })) }; return JSON.stringify({ Role: role }); }
    if (args[1] === "put-role-policy") { inline = permissionPolicy; return ""; }
    throw new Error(`unexpected bootstrap call ${args.join(" ")}`);
  };
  const result = installBootstrapRole({ run, authorization, sourceSha, now });
  assert.deepEqual(result, { status: "COMPLETE", createRoleCount: 1, putRolePolicyCount: 1, recovered: false });
  assert.deepEqual(installBootstrapRole({ run, authorization, sourceSha, now }), { status: "COMPLETE", createRoleCount: 0, putRolePolicyCount: 0, recovered: false });
  assert.equal(calls.filter((call) => call === "create-role").length, 1);
  assert.equal(calls.filter((call) => call === "put-role-policy").length, 1);

  role = undefined;
  inline = undefined;
  const ambiguous = (args) => {
    if (args[1] === "create-role") { run(args); throw new Error("response lost"); }
    return run(args);
  };
  assert.throws(() => installBootstrapRole({ run: ambiguous, authorization, sourceSha, now }), /response lost/);
  assert.equal(discoverBootstrapRole({ run }).classification, "EXACT_PARTIAL");
  assert.equal(installBootstrapRole({ run, authorization, sourceSha, now }).status, "COMPLETE");

  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-bootstrap-result-"));
  const resultPath = path.join(directory, "result.json");
  const cliResult = runBootstrapCli(["--execute", "--source-sha", sourceSha, "--authorization-workflow-run-id", "200", "--authorization-workflow-run-attempt", "1", "--admin-profile", "mscqr-production-root", "--result", resultPath], {
    exec: (_command, args) => args[0] === "status" ? "" : sourceSha,
    resolveAuthorization: () => authorization,
    run,
    now,
  });
  assert.equal(cliResult.status, "COMPLETE");
  assert.equal(JSON.parse(fs.readFileSync(resultPath, "utf8")).authorizationSha256, authorization.authorizationSha256);
  fs.rmSync(directory, { recursive: true, force: true });
});

test("root bootstrap accepts only canonical GitHub run, approval, and artifact provenance", () => {
  const authorization = createBootstrapAuthorization({ sourceSha, approval: bootstrapApproval, authorizedAt: now.toISOString() });
  const archive = Buffer.from("bootstrap-authorization-archive");
  const workflow = { id: 200, repository: { id: 1, full_name: INSTALLATION_BOOTSTRAP.repository }, head_repository: { full_name: INSTALLATION_BOOTSTRAP.repository }, path: INSTALLATION_BOOTSTRAP.workflowPath, event: "workflow_dispatch", head_sha: sourceSha, status: "completed", conclusion: "success", run_attempt: 1, actor: { login: "operator" } };
  const artifact = { id: 12, name: INSTALLATION_BOOTSTRAP.artifactName, expired: false, workflow_run: { id: 200, head_sha: sourceSha, repository_id: 1 }, digest: `sha256:${crypto.createHash("sha256").update(archive).digest("hex")}` };
  const environment = { id: 8, name: INSTALLATION_BOOTSTRAP.environment, can_admins_bypass: false, protection_rules: [{ type: "required_reviewers", prevent_self_review: true, reviewers: [{ type: "User", reviewer: { id: 3, login: "reviewer" } }] }] };
  const githubRun = (command, args) => {
    if (command === "unzip") {
      if (args[0] === "-Z1") return "bootstrap-authorization.json\n";
      if (args[0] === "-p") return Buffer.from(JSON.stringify(authorization));
    }
    const endpoint = args[1];
    if (endpoint.endsWith("/actions/runs/200")) return JSON.stringify(workflow);
    if (endpoint.endsWith("/artifacts")) return JSON.stringify([{ artifacts: [artifact] }]);
    if (endpoint.endsWith("/zip")) return archive;
    if (endpoint.endsWith(`/environments/${INSTALLATION_BOOTSTRAP.environment}`)) return JSON.stringify(environment);
    if (endpoint.endsWith("/approvals")) return JSON.stringify([{ state: "approved", environments: [{ id: 8, name: INSTALLATION_BOOTSTRAP.environment }], user: { id: 3, login: "reviewer" } }]);
    throw new Error(`unexpected provenance call: ${command} ${args.join(" ")}`);
  };
  assert.equal(resolveBootstrapAuthorization({ workflowRunId: "200", workflowRunAttempt: "1", sourceSha, githubRun, now }).authorizationSha256, authorization.authorizationSha256);
  assert.throws(() => resolveBootstrapAuthorization({ workflowRunId: "200", workflowRunAttempt: "1", sourceSha, githubRun: () => { throw new Error("locally forged artifact has no GitHub provenance"); }, now }), /malformed or unavailable/);
  assert.throws(() => resolveBootstrapAuthorization({ workflowRunId: "200", workflowRunAttempt: "2", sourceSha, githubRun, now }), /provenance/);
});

test("bootstrap topology and authorization drift fail closed", () => {
  const authorization = createBootstrapAuthorization({ sourceSha, approval: bootstrapApproval, authorizedAt: now.toISOString() });
  assert.throws(() => assertBootstrapAuthorization({ ...authorization, roleArn: "arn:aws:iam::368992683803:role/other" }, { sourceSha, now }), /binding/);
  assert.throws(() => assertBootstrapAuthorization({ ...authorization, sourceHashes: { ...authorization.sourceHashes, trustPolicySha256: "0".repeat(64) } }, { sourceSha, now }), /binding/);
  const role = { Arn: INSTALLATION_BOOTSTRAP.roleArn, RoleName: INSTALLATION_BOOTSTRAP.roleName, Path: "/", Description: INSTALLATION_BOOTSTRAP.roleDescription, MaxSessionDuration: 3600, AssumeRolePolicyDocument: JSON.parse(fs.readFileSync(INSTALLATION_BOOTSTRAP.trustPath)), Tags: Object.entries(INSTALLATION_BOOTSTRAP.tags).map(([Key, Value]) => ({ Key, Value })) };
  const run = (args) => {
    if (args[1] === "get-role") return JSON.stringify({ Role: role });
    if (args[1] === "list-attached-role-policies") return JSON.stringify({ AttachedPolicies: [{ PolicyArn: "arn:aws:iam::aws:policy/AdministratorAccess" }] });
    if (args[1] === "list-role-policies") return JSON.stringify({ PolicyNames: [] });
    throw new Error(`unexpected call ${args.join(" ")}`);
  };
  assert.throws(() => discoverBootstrapRole({ run }), /unexpected/);
  assert.throws(() => installBootstrapRole({ run: (args) => args[0] === "sts" ? JSON.stringify({ Arn: "arn:aws:iam::368992683803:user/not-root" }) : run(args), authorization, sourceSha, now }), /exact root/);
});

test("installation and bootstrap workflows share the one non-cancelling production queue", () => {
  for (const file of [
    ".github/workflows/authorize-production-initial-activation-policy-reconciler-bootstrap.yml",
    ".github/workflows/authorize-production-initial-activation-policy-reconciler-installation.yml",
    ".github/workflows/release-gate.yml",
  ]) {
    const workflow = fs.readFileSync(file, "utf8");
    assert.match(workflow, /group: production-deploy/);
    assert.match(workflow, /cancel-in-progress: false/);
  }
  const installationWorkflow = fs.readFileSync(".github/workflows/authorize-production-initial-activation-policy-reconciler-installation.yml", "utf8");
  assert.match(installationWorkflow, new RegExp(`environment: ${INSTALLATION.environment}`));
  assert.match(installationWorkflow, new RegExp(`--repository \\\"\\$GITHUB_REPOSITORY\\\" --environment ${INSTALLATION.environment}`));
  assert.match(installationWorkflow, /role-to-assume: arn:aws:iam::368992683803:role\/mscqr-production-initial-activation-policy-reconciler-bootstrap/);
  assert.match(installationWorkflow, /terraform_version: 1\.15\.8/);
  assert.doesNotMatch(installationWorkflow, /mscqr-production-root|mscqr-production-release-deployer|AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY/);
  const installer = fs.readFileSync("scripts/aws/install-production-initial-activation-reconciler.mjs", "utf8");
  assert.doesNotMatch(installer, /--admin-profile|consumptionDirectory|\.consumed|resolveInstallationAuthorizationArtifact/);
  assert.match(installer, /GITHUB_ACTIONS/);
  const bootstrapWorkflow = fs.readFileSync(".github/workflows/authorize-production-initial-activation-policy-reconciler-bootstrap.yml", "utf8");
  assert.match(bootstrapWorkflow, new RegExp(`environment: ${INSTALLATION_BOOTSTRAP.environment}`));
  assert.doesNotMatch(bootstrapWorkflow, /environment: production\s*$/m);
  assert.match(bootstrapWorkflow, /group: production-deploy/);
  assert.match(bootstrapWorkflow, /--require-actual-approval/);
  const workflowFiles = fs.readdirSync(".github/workflows").filter((file) => file.endsWith(".yml") || file.endsWith(".yaml"));
  const allowedBootstrapEnvironmentUsers = new Set(["authorize-production-initial-activation-policy-reconciler-bootstrap.yml", "authorize-production-initial-activation-policy-reconciler-installation.yml"]);
  const otherBootstrapUsers = workflowFiles.filter((file) => !allowedBootstrapEnvironmentUsers.has(file))
    .filter((file) => fs.readFileSync(path.join(".github/workflows", file), "utf8").includes(`environment: ${INSTALLATION_BOOTSTRAP.environment}`));
  assert.deepEqual(otherBootstrapUsers, []);
  const trustPolicy = JSON.parse(fs.readFileSync(INSTALLATION_BOOTSTRAP.trustPath, "utf8"));
  const trustedSubject = trustPolicy.Statement[0].Condition.StringEquals["token.actions.githubusercontent.com:sub"];
  assert.equal(trustedSubject, `repo:${INSTALLATION.repository}:environment:${INSTALLATION.environment}`);
});

test("terraform show failure always removes the unique render copy", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-install-render-cleanup-"));
  fs.chmodSync(directory, 0o700);
  const terraformDataDir = path.join(directory, "terraform");
  fs.mkdirSync(terraformDataDir, { mode: 0o700 });
  const metadata = JSON.parse(fs.readFileSync("scripts/tests/fixtures/production-green-stage-b-s3-backend-metadata.json", "utf8"));
  metadata.backend.config.key = INSTALLATION.backend.key;
  fs.writeFileSync(path.join(terraformDataDir, "terraform.tfstate"), JSON.stringify(metadata), { mode: 0o600 });
  const savedPlan = path.join(directory, "installation.tfplan");
  fs.writeFileSync(savedPlan, planBytes, { mode: 0o600 });
  const exec = (command, args) => {
    if (command === "git") return args[0] === "status" ? "" : sourceSha;
    if (args.includes("workspace")) return "default\n";
    if (args.includes("show")) throw new Error("terraform show failed");
    throw new Error(`unexpected command ${command} ${args.join(" ")}`);
  };
  assert.throws(() => runPrepareCli(["--prepare", "--source-sha", sourceSha, "--admin-profile", "mscqr-production-root", "--output", path.join(directory, "preparation.json"), "--terraform-data-dir", terraformDataDir, "--plan", savedPlan, "--state-absent"], { exec, run: discoveryRun({ role: false, policy: false }) }), /terraform show failed/);
  assert.equal(fs.readdirSync(directory).some((name) => name.includes("render.tfplan")), false);
  fs.rmSync(directory, { recursive: true, force: true });
});
