import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import yaml from "js-yaml";
import { PRODUCTION_ENVIRONMENT_APPROVAL, createProductionEnvironmentApprovalEvidence } from "../aws/production-github-environment-approval.mjs";
import { INITIAL_ACTIVATION_POLICY_RECONCILIATION as CONTRACT, INITIAL_ACTIVATION_TRANSIENT_POLICY_VERSION_READ, assertInitialActivationLifecyclePolicyReconciliationAuthorization, assertInitialActivationLifecyclePolicyState, buildInitialActivationLifecyclePolicyReconciliationResult, createInitialActivationLifecyclePolicyReconciliationAuthorization, executeInitialActivationLifecyclePolicyReconciliation as executeCore, readInitialActivationLifecycleDesiredPolicy, waitForInitialActivationLifecyclePolicyConvergence } from "../aws/production-initial-activation-policy-reconciliation.mjs";
import { createInitialActivationReconciliationCommandRunner, readInitialActivationLifecyclePolicyLiveState, runInitialActivationLifecyclePolicyReconciliation } from "../aws/run-production-initial-activation-lifecycle-policy-reconciliation.mjs";
import { writeStageBPrivateFileExclusive } from "../aws/stage-b-artifact-contract.mjs";
import { canonicalSha256 } from "../aws/stage-b-task-definition-recovery-contract.mjs";
import { sourcePolicyEvidence } from "../aws/validate-production-green-stage-b-permissions.mjs";

const sourceSha = "a".repeat(40);
const desired = readInitialActivationLifecycleDesiredPolicy();
const predecessor = { Version: "2012-10-17", Statement: desired.document.Statement.slice(0, 4).concat(desired.document.Statement.slice(8)) };
const approval = (observedAt = new Date().toISOString()) => createProductionEnvironmentApprovalEvidence({
  environmentConfig: { id: 1, name: "production", can_admins_bypass: false, protection_rules: [{ type: "required_reviewers", prevent_self_review: true, reviewers: [{ type: "User", reviewer: { id: 2, login: "reviewer" } }] }] },
  repository: "T-ej2003/genuine-scan-main", environment: "production", sourceSha,
  workflowRef: "T-ej2003/genuine-scan-main/.github/workflows/authorize-production-initial-activation-lifecycle-policy-reconciliation.yml@refs/heads/main", eventName: "workflow_dispatch", workflowRunId: "1", workflowRunAttempt: "1", executionActor: "operator", observedAt,
  actualApproval: { state: "approved", environmentId: 1, environmentName: "production", userId: 2, userLogin: "reviewer" },
});
const releaseRolePolicyArns = sourcePolicyEvidence().map(({ arn }) => arn).sort();
const state = (overrides = {}) => ({ policyArn: CONTRACT.policyArn, defaultVersionId: "v1", document: predecessor, policyVersionCount: 1, releaseRolePolicyArns, targetPolicyRoles: ["mscqr-production-release-deployer"], targetPolicyUsers: [], targetPolicyGroups: [], permissionsBoundaryUsageCount: 0, ...overrides });
const authorization = (live = state()) => createInitialActivationLifecyclePolicyReconciliationAuthorization({ sourceSha, liveState: live, protectedEnvironmentApprovalEvidence: approval(), desired });
const executeInitialActivationLifecyclePolicyReconciliation = (input) => executeCore(input);

test("required reconciliation uploads run independently and publication failures remain fatal", () => {
  const workflow = yaml.load(fs.readFileSync(".github/workflows/authorize-production-initial-activation-lifecycle-policy-reconciliation.yml", "utf8"));
  const uploads = Object.values(workflow.jobs).flatMap(({ steps }) => steps || []).filter(({ uses }) => uses === "actions/upload-artifact@v4");
  assert.equal(uploads.length, 2);
  for (const [index, kind] of ["authorization", "result"].entries()) {
    const upload = uploads[index];
    assert.equal(upload.if, "always()");
    assert.equal(upload["continue-on-error"], undefined);
    assert.equal(upload.with["if-no-files-found"], "error");
    assert.equal(upload.with.name, `production-initial-activation-lifecycle-policy-reconciliation-${kind}`);
    assert.equal(upload.with.path, `\u0024{{ runner.temp }}/initial-activation-policy-reconciliation/${kind}.json`);
  }
});

test("production mutation subprocess forces one CLI attempt without contaminating reads", () => {
  for (const inherited of [undefined, "2", "10"]) {
    const env = { AWS_ACCESS_KEY_ID: "fixture", AWS_SECRET_ACCESS_KEY: "fixture", AWS_SESSION_TOKEN: "fixture", ...(inherited ? { AWS_MAX_ATTEMPTS: inherited } : {}) };
    const calls = [];
    const run = createInitialActivationReconciliationCommandRunner({ credentialSource: "github-oidc-initial-activation-bootstrap", env, exec: (file, args, options) => { calls.push({ file, args, env: options.env }); return "{}"; } });
    run(["iam", "get-policy", "--policy-arn", CONTRACT.policyArn]);
    run(["iam", "create-policy-version", "--policy-arn", CONTRACT.policyArn, "--policy-document", JSON.stringify(desired.document), "--set-as-default"]);
    run(["iam", "get-policy-version", "--policy-arn", CONTRACT.policyArn, "--version-id", "v2"]);
    assert.equal(calls.length, 3);
    assert.equal(calls[1].file, "aws"); assert.equal(calls[1].env.AWS_MAX_ATTEMPTS, "1");
    assert.equal(calls[0].env.AWS_MAX_ATTEMPTS, undefined); assert.deepEqual(calls[2].env, calls[0].env);
    assert.equal(env.AWS_MAX_ATTEMPTS, inherited);
  }
});

test("exact predecessor authorizes only the fixed target and exact tracked desired policy", () => {
  const value = authorization();
  assert.equal(value.expectedAction, "iam:CreatePolicyVersion"); assert.equal(value.setAsDefault, true);
  assert.deepEqual([value.maxCreatePolicyVersionCount, value.maxSetDefaultPolicyVersionCount, value.maxDeletePolicyVersionCount, value.maxPolicyAttachmentMutations], [1, 0, 0, 0]);
  assert.doesNotThrow(() => assertInitialActivationLifecyclePolicyReconciliationAuthorization(value, { sourceSha }));
  for (const changed of [{ sourceSha: "b".repeat(40) }, { targetPolicyArn: "arn:aws:iam::368992683803:policy/other" }, { predecessorDefaultVersionId: "v2" }, { predecessorPolicySha256: "b".repeat(64) }, { desiredPolicySha256: "b".repeat(64) }, { expectedAction: "iam:SetDefaultPolicyVersion" }, { setAsDefault: false }, { maxDeletePolicyVersionCount: 1 }]) {
    const candidate = { ...value, ...changed }; const { authorizationSha256, ...body } = candidate; candidate.authorizationSha256 = canonicalSha256(body);
    assert.throws(() => assertInitialActivationLifecyclePolicyReconciliationAuthorization(candidate, { sourceSha }), /authorization/);
  }
});

test("production reconciliation is workflow-only under the live purpose-bound OIDC role", () => {
  const workflow = fs.readFileSync(".github/workflows/authorize-production-initial-activation-lifecycle-policy-reconciliation.yml", "utf8");
  assert.match(workflow, /id-token: write/);
  assert.match(workflow, /group: production-deploy[\s\S]*cancel-in-progress: false/);
  assert.match(workflow, /environment: production/);
  assert.match(workflow, /role-to-assume:\s+arn:aws:iam::368992683803:role\/mscqr-production-initial-activation-policy-reconciler/);
  assert.match(workflow, /run-production-initial-activation-lifecycle-policy-reconciliation\.mjs[\s\S]*--execute/);
  assert.match(workflow, /name: production-initial-activation-lifecycle-policy-reconciliation-authorization[\s\S]*if: always\(\)/);
  assert.doesNotMatch(workflow, /--admin-profile|reservation|ROOT_OPERATOR|release-deployer/);
  assert.doesNotMatch(fs.readFileSync("scripts/aws/production-initial-activation-policy-reconciliation.mjs", "utf8"), /s3api|reservation|ROOT_OPERATOR/);
});

test("live policy validation keeps the complete release-role set separate from the target policy entity boundary", () => {
  assert.equal(assertInitialActivationLifecyclePolicyState(state(), { desired }).status, "AUTHENTICATED_PREDECESSOR");
  assert.equal(assertInitialActivationLifecyclePolicyState(state({ document: desired.document, defaultVersionId: "v2" }), { desired }).status, "ALREADY_RECONCILED");
  for (const changed of [
    { policyArn: "arn:aws:iam::368992683803:policy/unrelated" }, { defaultVersionId: "v2" },
    { document: { ...predecessor, Statement: [...predecessor.Statement, { Sid: "extra", Effect: "Allow", Action: "*", Resource: "*" }] } },
    { document: "not-json" }, { releaseRolePolicyArns: releaseRolePolicyArns.slice(1) }, { releaseRolePolicyArns: [...releaseRolePolicyArns, "arn:aws:iam::368992683803:policy/other"] }, { targetPolicyRoles: [] }, { targetPolicyRoles: ["mscqr-production-release-deployer", "other-role"] }, { targetPolicyUsers: ["other-user"] }, { targetPolicyGroups: ["other-group"] }, { permissionsBoundaryUsageCount: 1 },
  ]) assert.throws(() => assertInitialActivationLifecyclePolicyState(state(changed), { desired }));
  assert.throws(() => createInitialActivationLifecyclePolicyReconciliationAuthorization({ sourceSha, liveState: state({ policyVersionCount: 5 }), protectedEnvironmentApprovalEvidence: approval(), desired }), /pruning/);
  assert.throws(() => createInitialActivationLifecyclePolicyReconciliationAuthorization({ sourceSha, liveState: state(), protectedEnvironmentApprovalEvidence: approval(), desired: { ...desired, policySha256: "b".repeat(64) } }));
});

test("policy-centric entity discovery consumes every page and fails closed on incomplete evidence", () => {
  const run = (args) => {
    const operation = args.slice(0, 2).join(" "); const marker = args.includes("--marker") ? args.at(-1) : undefined;
    if (operation === "iam get-policy") return JSON.stringify({ Policy: { Arn: CONTRACT.policyArn, DefaultVersionId: "v1", PermissionsBoundaryUsageCount: 0 } });
    if (operation === "iam get-policy-version") return JSON.stringify({ PolicyVersion: { Document: predecessor } });
    if (operation === "iam list-policy-versions") return JSON.stringify({ Versions: [{ VersionId: "v1" }] });
    if (operation === "iam get-role") return JSON.stringify({ Role: { Arn: CONTRACT.releaseRoleArn } });
    if (operation === "iam list-attached-role-policies") return JSON.stringify(marker ? { AttachedPolicies: releaseRolePolicyArns.slice(4).map((PolicyArn) => ({ PolicyArn })), IsTruncated: false } : { AttachedPolicies: releaseRolePolicyArns.slice(0, 4).map((PolicyArn) => ({ PolicyArn })), IsTruncated: true, Marker: "attached-next" });
    if (operation === "iam list-entities-for-policy") return JSON.stringify(marker ? { PolicyRoles: [{ RoleName: "mscqr-production-release-deployer" }], PolicyUsers: [], PolicyGroups: [], IsTruncated: false } : { PolicyRoles: [], PolicyUsers: [], PolicyGroups: [], IsTruncated: true, Marker: "entities-next" });
    throw new Error(`unexpected ${args.join(" ")}`);
  };
  assert.equal(assertInitialActivationLifecyclePolicyState(readInitialActivationLifecyclePolicyLiveState(run), { desired }).status, "AUTHENTICATED_PREDECESSOR");
  const incomplete = (args) => args[1] === "list-entities-for-policy" ? JSON.stringify({ PolicyRoles: [], PolicyUsers: [], PolicyGroups: [], IsTruncated: true }) : run(args);
  assert.throws(() => readInitialActivationLifecyclePolicyLiveState(incomplete), /incomplete/);
  const diagnostics = [
    'Could not connect to the endpoint URL: "https://iam.amazonaws.com/"',
    'Connect timeout on endpoint URL: "https://iam.amazonaws.com/"',
    'Read timeout on endpoint URL: "https://iam.amazonaws.com/"',
    'Connection was closed before we received a valid response from endpoint URL: "https://iam.amazonaws.com/".',
    'Could not connect to the endpoint URL: "https://iam.eu-west-2.amazonaws.com/"',
    'Connect timeout on endpoint URL: "https://iam.eu-west-2.amazonaws.com/"',
    'Read timeout on endpoint URL: "https://iam.eu-west-2.amazonaws.com/"',
    'Connection was closed before we received a valid response from endpoint URL: "https://iam.eu-west-2.amazonaws.com/".',
  ];
  const transientErrors = [
    ...["Throttling", "ThrottlingException", "TooManyRequestsException", "RequestLimitExceeded", "ServiceUnavailable", "ServiceUnavailableException", "ServiceFailure", "InternalFailure", "InternalError"].map((code) => ({ code })),
    ...diagnostics.map((stderr) => ({ code: 255, stderr: Buffer.from(`\n${stderr}\n`) })),
  ];
  for (const failure of transientErrors) for (const failures of [["get-policy"], ["get-policy-version"], ["list-policy-versions"], ["get-role"], ["list-attached-role-policies"], ["list-entities-for-policy"], ["get-policy", "get-role", "list-entities-for-policy"], Array(6).fill("get-policy")]) {
    let creates = 0; let retries = 0;
    const pending = [...failures];
    const execute = () => executeCore({ authorization: authorization(), sourceSha, desired, sleep: () => { retries += 1; }, createPolicyVersion: () => { creates += 1; return { PolicyVersion: { VersionId: "v2" } }; }, readLiveState: () => readInitialActivationLifecyclePolicyLiveState((args) => {
      if (creates && args[1] === pending[0]) { pending.shift(); throw Object.assign(new Error("Command failed: aws iam read"), failure); }
      const response = JSON.parse(run(args));
      if (creates && args[1] === "get-policy") response.Policy.DefaultVersionId = "v2";
      if (creates && args[1] === "get-policy-version") response.PolicyVersion.Document = desired.document;
      if (creates && args[1] === "list-policy-versions") response.Versions.push({ VersionId: "v2" });
      return JSON.stringify(response);
    }) });
    if (failures.length === 6) assert.throws(execute, /did not converge/);
    else assert.equal(execute().status, "RECONCILED");
    assert.equal(creates, 1); assert.equal(retries, Math.min(failures.length, 5));
  }
  let preMutationCreates = 0;
  assert.throws(() => executeCore({ authorization: authorization(), sourceSha, desired, readLiveState: () => readInitialActivationLifecyclePolicyLiveState(() => { throw Object.assign(new Error("service failure"), { code: "ServiceFailure" }); }), createPolicyVersion: () => { preMutationCreates += 1; }, sleep: () => assert.fail("pre-mutation retry") }));
  assert.equal(preMutationCreates, 0);
  for (const failure of [...transientErrors, ...["AccessDenied", "ValidationError", "MalformedPolicyDocument"].map((code) => ({ code }))]) {
    let reads = 0;
    assert.throws(() => executeCore({ authorization: authorization(), sourceSha, desired, readLiveState: () => { reads += 1; return readInitialActivationLifecyclePolicyLiveState(() => { throw Object.assign(new Error("read failed"), failure); }); }, createPolicyVersion: () => assert.fail("precondition failed"), sleep: () => assert.fail("pre-mutation retry") }));
    assert.equal(reads, 1);
  }
  for (const stderr of ["timeout", "HTTP 500", "AccessDenied NoSuchEntity", ...diagnostics.map((value) => `untrusted prefix ${value}`), ...diagnostics.map((value) => value.replace("iam.amazonaws.com", "evil.example")), "SSL validation failed for https://iam.amazonaws.com/", "An error occurred (AccessDenied) when calling the GetPolicyVersion operation: NoSuchEntity"]) {
    let creates = 0; let observations = 0;
    assert.throws(() => executeCore({ authorization: authorization(), sourceSha, desired, sleep: () => assert.fail("non-transient retry"), createPolicyVersion: () => { creates += 1; return { PolicyVersion: { VersionId: "v2" } }; }, readLiveState: () => {
      if (!creates) return readInitialActivationLifecyclePolicyLiveState(run);
      observations += 1;
      return readInitialActivationLifecyclePolicyLiveState((args) => { if (args[1] === "get-policy-version") throw Object.assign(new Error("CLI failed"), { stderr }); return run(args); });
    } }));
    assert.equal(creates, 1); assert.equal(observations, 1);
  }
  // CLI entrypoint -> private authorization -> real command wrapper -> real snapshot/core -> result.
  for (const ambiguous of [false, true]) {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), "initial-activation-runtime-contract-")); fs.chmodSync(directory, 0o700);
    try {
      const authBytes = Buffer.from(JSON.stringify(authorization()));
      const authPath = path.join(directory, "authorization.json"); fs.writeFileSync(authPath, authBytes, { mode: 0o600 });
      const output = path.join(directory, "result.json");
      let creates = 0; let transientReads = 0; const calls = [];
      const env = { AWS_ACCESS_KEY_ID: "fixture", AWS_SECRET_ACCESS_KEY: "fixture", AWS_SESSION_TOKEN: "fixture", AWS_MAX_ATTEMPTS: "10", GITHUB_ACTIONS: "true", GITHUB_REPOSITORY: "T-ej2003/genuine-scan-main", GITHUB_WORKFLOW_REF: `T-ej2003/genuine-scan-main/${CONTRACT.workflowPath}@refs/heads/main`, GITHUB_EVENT_NAME: "workflow_dispatch", GITHUB_RUN_ID: "1", GITHUB_RUN_ATTEMPT: "1", GITHUB_ACTOR: "operator" };
      const cli = createInitialActivationReconciliationCommandRunner({ credentialSource: "github-oidc-initial-activation-bootstrap", env, exec: (file, args, options) => {
        calls.push({ file, action: args[1], attempts: options.env.AWS_MAX_ATTEMPTS });
        if (args[0] === "sts") return JSON.stringify({ Arn: "arn:aws:sts::368992683803:assumed-role/mscqr-production-initial-activation-policy-reconciler/fixture" });
        if (args[1] === "create-policy-version") {
          creates += 1; assert.equal(creates, 1); assert.equal(options.env.AWS_MAX_ATTEMPTS, "1");
          assert.equal(args[args.indexOf("--policy-arn") + 1], CONTRACT.policyArn);
          assert.deepEqual(JSON.parse(args[args.indexOf("--policy-document") + 1]), desired.document); assert.ok(args.includes("--set-as-default"));
          if (ambiguous) throw Object.assign(new Error("response lost"), { stderr: diagnostics[2] });
          return JSON.stringify({ PolicyVersion: { VersionId: "v2" } });
        }
        if (creates && args[1] === "get-role" && transientReads++ === 0) throw Object.assign(new Error("Command failed: aws iam get-role"), { stderr: Buffer.from(diagnostics[3]), status: 255 });
        const response = JSON.parse(run(args));
        if (creates && args[1] === "get-policy") response.Policy.DefaultVersionId = "v2";
        if (creates && args[1] === "get-policy-version") response.PolicyVersion.Document = desired.document;
        if (creates && args[1] === "list-policy-versions") response.Versions.push({ VersionId: "v2" });
        return JSON.stringify(response);
      } });
      const result = runInitialActivationLifecyclePolicyReconciliation(["--execute", "--source-sha", sourceSha, "--authorization", authPath, "--authorization-file-sha256", crypto.createHash("sha256").update(authBytes).digest("hex"), "--result-out", output], { env, readProtectedCheckout: () => ({ toolingSha: sourceSha }), run: cli });
      assert.equal(result.status, ambiguous ? "COMPLETED_BY_READBACK" : "RECONCILED");
      assert.equal(creates, 1); assert.ok(transientReads > 1);
      assert.ok(calls.filter(({ action }) => action !== "create-policy-version").every(({ attempts }) => attempts === undefined));
      assert.deepEqual(JSON.parse(fs.readFileSync(output)), result);
      const prepareCalls = [];
      const prepareRunner = createInitialActivationReconciliationCommandRunner({ credentialSource: "named-profile", profile: "mscqr-production-root", env: {}, exec: (file, args, options) => {
        prepareCalls.push(args[1]); assert.equal(options.env.AWS_PROFILE, "mscqr-production-root");
        if (args[0] === "sts") return JSON.stringify({ Arn: "arn:aws:iam::368992683803:root" });
        assert.notEqual(args[1], "create-policy-version"); return run(args);
      } });
      const preparation = runInitialActivationLifecyclePolicyReconciliation(["--prepare", "--source-sha", sourceSha, "--admin-profile", "mscqr-production-root", "--live-state-out", path.join(directory, "live.json")], { readProtectedCheckout: () => ({ toolingSha: sourceSha }), run: prepareRunner });
      assert.equal(preparation.status, "AUTHENTICATED_PREDECESSOR");
      assert.deepEqual([...new Set(prepareCalls)].sort(), ["get-caller-identity", "get-policy", "get-policy-version", "list-policy-versions", "get-role", "list-attached-role-policies", "list-entities-for-policy"].sort());
    } finally { fs.rmSync(directory, { recursive: true, force: true }); }
  }
});

test("approval freshness uses a fresh write-boundary clock after live reads", () => {
  const observedAt = "2026-09-04T12:00:00.000Z";
  const entryTime = new Date(new Date(observedAt).getTime() + PRODUCTION_ENVIRONMENT_APPROVAL.maxAgeMs - 1);
  const writeTime = new Date(entryTime.getTime() + 2);
  const value = createInitialActivationLifecyclePolicyReconciliationAuthorization({ sourceSha, liveState: state(), protectedEnvironmentApprovalEvidence: approval(observedAt), desired, now: entryTime });
  assert.doesNotThrow(() => assertInitialActivationLifecyclePolicyReconciliationAuthorization(value, { sourceSha, now: entryTime }));
  let clockReads = 0; let liveReads = 0; let creates = 0;
  assert.throws(() => executeInitialActivationLifecyclePolicyReconciliation({ authorization: value, sourceSha, desired, now: () => { if (clockReads === 1) assert.equal(liveReads, 2, "clock must be read after the final live-state read"); return [entryTime, writeTime][clockReads++]; }, readLiveState: () => { liveReads += 1; return state(); }, createPolicyVersion: () => { creates += 1; } }), /stale/);
  assert.equal(clockReads, 2); assert.equal(liveReads, 2); assert.equal(creates, 0);
});

test("approval valid at the write boundary permits exactly one transition", () => {
  const observedAt = "2026-09-04T12:00:00.000Z";
  const entryTime = new Date(new Date(observedAt).getTime() + PRODUCTION_ENVIRONMENT_APPROVAL.maxAgeMs - 1);
  const writeTime = new Date(new Date(observedAt).getTime() + PRODUCTION_ENVIRONMENT_APPROVAL.maxAgeMs);
  const value = createInitialActivationLifecyclePolicyReconciliationAuthorization({ sourceSha, liveState: state(), protectedEnvironmentApprovalEvidence: approval(observedAt), desired, now: entryTime });
  let live = state(); let clockReads = 0; let creates = 0;
  const result = executeInitialActivationLifecyclePolicyReconciliation({ authorization: value, sourceSha, desired, now: () => [entryTime, writeTime][clockReads++], readLiveState: () => live, createPolicyVersion: () => { creates += 1; live = state({ defaultVersionId: "v2", document: desired.document, policyVersionCount: 2 }); return { PolicyVersion: { VersionId: "v2" } }; } });
  assert.equal(result.status, "RECONCILED"); assert.equal(clockReads, 2); assert.equal(creates, 1);
});

test("approval freshness remains exact at the configured maximum age", () => {
  const observedAt = "2026-09-04T12:00:00.000Z";
  const boundary = new Date(new Date(observedAt).getTime() + PRODUCTION_ENVIRONMENT_APPROVAL.maxAgeMs);
  const value = createInitialActivationLifecyclePolicyReconciliationAuthorization({ sourceSha, liveState: state(), protectedEnvironmentApprovalEvidence: approval(observedAt), desired, now: boundary });
  assert.doesNotThrow(() => assertInitialActivationLifecyclePolicyReconciliationAuthorization(value, { sourceSha, now: boundary }));
});

test("result destination is fully preflighted before entering the mutation executor", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "initial-activation-result-preflight-")); fs.chmodSync(directory, 0o700);
  const auth = authorization(); const authPath = path.join(directory, "authorization.json"); const authBytes = Buffer.from(`${JSON.stringify(auth)}\n`); fs.writeFileSync(authPath, authBytes, { mode: 0o600 });
  const authSha = crypto.createHash("sha256").update(authBytes).digest("hex");
  const roleArn = "arn:aws:iam::368992683803:role/mscqr-production-initial-activation-policy-reconciler";
  let executorCalls = 0;
  const deps = { env: { GITHUB_ACTIONS: "true", GITHUB_REPOSITORY: "T-ej2003/genuine-scan-main", GITHUB_WORKFLOW_REF: `${"T-ej2003/genuine-scan-main"}/${CONTRACT.workflowPath}@refs/heads/main`, GITHUB_EVENT_NAME: "workflow_dispatch", GITHUB_RUN_ID: "1", GITHUB_RUN_ATTEMPT: "1", GITHUB_ACTOR: "operator" }, readProtectedCheckout: () => ({ toolingSha: sourceSha }), run: () => JSON.stringify({ Arn: `arn:aws:sts::368992683803:assumed-role/${roleArn.split("/").at(-1)}/session` }), executeReconciliation: () => { executorCalls += 1; return { status: "ALREADY_RECONCILED", createPolicyVersionCount: 0, postState: assertInitialActivationLifecyclePolicyState(state({ document: desired.document, defaultVersionId: "v2" }), { desired }) }; } };
  const baseArgs = (resultOut) => ["--execute", "--source-sha", sourceSha, "--authorization", authPath, "--authorization-file-sha256", authSha, ...(resultOut === undefined ? [] : ["--result-out", resultOut])];
  const invoke = (args) => runInitialActivationLifecyclePolicyReconciliation(args, deps);
  for (const Arn of ["arn:aws:iam::368992683803:root", "arn:aws:sts::368992683803:assumed-role/mscqr-production-release-deployer/session", "arn:aws:sts::111111111111:assumed-role/mscqr-production-initial-activation-policy-reconciler/session"]) assert.throws(() => runInitialActivationLifecyclePolicyReconciliation(baseArgs(path.join(directory, "wrong-role.json")), { ...deps, run: () => JSON.stringify({ Arn }) }), /exact OIDC reconciler/);
  for (const change of [{ GITHUB_REPOSITORY: "other/repository" }, { GITHUB_WORKFLOW_REF: "wrong-workflow" }, { GITHUB_EVENT_NAME: "push" }, { GITHUB_ACTIONS: "false" }]) assert.throws(() => runInitialActivationLifecyclePolicyReconciliation(baseArgs(path.join(directory, "wrong-workflow.json")), { ...deps, env: { ...deps.env, ...change }, run: () => assert.fail("wrong workflow reached AWS") }), /canonical protected GitHub workflow/);
  assert.throws(() => runInitialActivationLifecyclePolicyReconciliation(baseArgs(path.join(directory, "wrong-source.json")), { ...deps, readProtectedCheckout: () => ({ toolingSha: "b".repeat(40) }), run: () => assert.fail("wrong source reached AWS") }), /authorized protected source/);
  for (const attempt of [undefined, "2", "10"]) assert.throws(() => runInitialActivationLifecyclePolicyReconciliation(baseArgs(path.join(directory, "rerun.json")), { ...deps, env: { ...deps.env, GITHUB_RUN_ATTEMPT: attempt }, run: () => assert.fail("rerun must not reach AWS") }), /reruns are forbidden/);
  const workflow = yaml.load(fs.readFileSync(CONTRACT.workflowPath, "utf8"));
  assert.match(workflow.jobs.authorize.steps.find(({ name }) => name === "Authenticate exact protected source").run, /test "\$GITHUB_RUN_ATTEMPT" = 1/);
  for (const [index, args] of [baseArgs(undefined), baseArgs(""), baseArgs(path.join(directory, "missing", "result.json")), baseArgs(process.cwd()), baseArgs(path.join(directory, "insecure", "result.json")), baseArgs(path.join(directory, "existing.json")), baseArgs(path.join(directory, "result-link.json")), baseArgs(path.join(process.cwd(), "..", path.basename(process.cwd()), "escaped.json")), baseArgs(path.join(directory, "unwritable", "result.json"))].entries()) {
    if (args.some((arg) => arg.endsWith("/insecure/result.json"))) { fs.mkdirSync(path.join(directory, "insecure")); fs.chmodSync(path.join(directory, "insecure"), 0o755); }
    if (args.some((arg) => arg.endsWith("/existing.json"))) fs.writeFileSync(path.join(directory, "existing.json"), "existing");
    if (args.some((arg) => arg.endsWith("/result-link.json"))) fs.symlinkSync(path.join(directory, "other.json"), path.join(directory, "result-link.json"));
    if (args.some((arg) => arg.endsWith("/unwritable/result.json"))) { fs.mkdirSync(path.join(directory, "unwritable")); fs.chmodSync(path.join(directory, "unwritable"), 0o500); }
    assert.throws(() => invoke(args), undefined, `invalid result destination case ${index}`);
  }
  assert.equal(executorCalls, 0);
  const valid = path.join(directory, "valid", "result.json"); fs.mkdirSync(path.dirname(valid)); fs.chmodSync(path.dirname(valid), 0o700);
  assert.doesNotThrow(() => invoke(baseArgs(valid))); assert.equal(executorCalls, 1); assert.equal(fs.existsSync(valid), true);
  fs.rmSync(directory, { recursive: true, force: true });
});

test("the final exclusive result writer still rejects a target created after preflight", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "initial-activation-result-race-")); fs.chmodSync(directory, 0o700);
  const result = path.join(directory, "result.json"); fs.writeFileSync(result, "race", { mode: 0o600 });
  assert.throws(() => writeStageBPrivateFileExclusive({ filePath: result, bytes: Buffer.from("new"), repositoryRoot: process.cwd(), label: "Initial activation lifecycle policy result" }));
  fs.rmSync(directory, { recursive: true, force: true });
});

test("one atomic CreatePolicyVersion transitions the exact predecessor and preserves both attachment boundaries", () => {
  let live = state(); let creates = 0;
  const result = executeInitialActivationLifecyclePolicyReconciliation({ authorization: authorization(), sourceSha, desired, readLiveState: () => live, createPolicyVersion: (request) => {
    creates += 1; assert.deepEqual(request, { PolicyArn: CONTRACT.policyArn, PolicyDocument: desired.document, SetAsDefault: true });
    live = state({ defaultVersionId: "v2", document: desired.document, policyVersionCount: 2 }); return { PolicyVersion: { VersionId: "v2" } };
  } });
  assert.equal(result.status, "RECONCILED"); assert.equal(result.createPolicyVersionCount, 1); assert.equal(creates, 1);
  const replay = executeInitialActivationLifecyclePolicyReconciliation({ authorization: authorization(), sourceSha, desired, readLiveState: () => live, createPolicyVersion: () => { creates += 1; throw new Error("must not create"); } });
  assert.equal(replay.status, "ALREADY_RECONCILED"); assert.equal(replay.createPolicyVersionCount, 0); assert.equal(creates, 1);
  const completion = buildInitialActivationLifecyclePolicyReconciliationResult({ authorization: authorization(), outcome: result });
  assert.equal(completion.postPolicySha256, desired.policySha256);
});

test("execution rejects every non-equivalent pre or post mutation state and never targets another policy", () => {
  const cases = [
    { name: "wrong source", source: "b".repeat(40), live: state(), matcher: /identity/ },
    { name: "unexpected pre drift", source: sourceSha, live: state({ document: { ...predecessor, Statement: [] } }), matcher: /neither/ },
    { name: "wrong version", source: sourceSha, live: state({ defaultVersionId: "v2" }), matcher: /neither/ },
    { name: "wrong policy arn", source: sourceSha, live: state({ policyArn: "arn:aws:iam::368992683803:policy/nope" }), matcher: /identity/ },
  ];
  for (const item of cases) assert.throws(() => executeInitialActivationLifecyclePolicyReconciliation({ authorization: authorization(), sourceSha: item.source, desired, readLiveState: () => item.live, createPolicyVersion: () => { throw new Error("write prohibited"); } }), item.matcher);
  for (const after of [
    state({ defaultVersionId: "v1", document: desired.document, policyVersionCount: 2 }),
    state({ defaultVersionId: "v2", document: predecessor, policyVersionCount: 2 }),
    state({ defaultVersionId: "v2", document: desired.document, policyVersionCount: 2, targetPolicyRoles: ["mscqr-production-release-deployer", "other-role"] }),
  ]) {
    let reads = 0;
    assert.throws(() => executeInitialActivationLifecyclePolicyReconciliation({ authorization: authorization(), sourceSha, desired, readLiveState: () => (++reads === 1 ? state() : after), createPolicyVersion: () => ({ PolicyVersion: { VersionId: "v2" } }) }));
  }
});

test("ambiguous successful create converges by exact desired readback without a second version", () => {
  let live = state(); let creates = 0;
  const outcome = executeInitialActivationLifecyclePolicyReconciliation({ authorization: authorization(), sourceSha, desired, readLiveState: () => live, createPolicyVersion: () => {
    creates += 1; live = state({ defaultVersionId: "v2", document: desired.document, policyVersionCount: 2 }); throw new Error("transport response lost");
  } });
  assert.equal(outcome.status, "COMPLETED_BY_READBACK"); assert.equal(outcome.createPolicyVersionCount, 1); assert.equal(creates, 1);
});

test("IAM convergence accepts temporary predecessor visibility, bounds polling, and rejects unexpected state", () => {
  const value = authorization(); let reads = 0; const sleeps = []; const states = [state(), state(), state(), state(), state(), state({ defaultVersionId: "v2", document: desired.document, policyVersionCount: 2 })];
  const result = waitForInitialActivationLifecyclePolicyConvergence({ readLiveState: () => states[reads++], before: assertInitialActivationLifecyclePolicyState(state(), { desired }), authorization: value, desired, expectedVersionId: "v2", sleep: (milliseconds) => sleeps.push(milliseconds) });
  assert.equal(result.status, "ALREADY_RECONCILED"); assert.deepEqual(sleeps, [100, 200, 400, 800, 1000]); assert.equal(reads, 6);
  assert.throws(() => waitForInitialActivationLifecyclePolicyConvergence({ readLiveState: () => state({ defaultVersionId: "v2", document: desired.document, policyVersionCount: 3 }), before: assertInitialActivationLifecyclePolicyState(state(), { desired }), authorization: value, desired, expectedVersionId: "v2", sleep: () => {} }), /unexpected default version/);
});

test("IAM convergence retries only the authenticated transient policy-version read failure", () => {
  let reads = 0; const sleeps = [];
  const result = waitForInitialActivationLifecyclePolicyConvergence({ readLiveState: () => {
    if (reads++ < 2) { const error = new Error("NoSuchEntity"); error.code = INITIAL_ACTIVATION_TRANSIENT_POLICY_VERSION_READ; throw error; }
    return state({ defaultVersionId: "v2", document: desired.document, policyVersionCount: 2 });
  }, before: assertInitialActivationLifecyclePolicyState(state(), { desired }), authorization: authorization(), desired, expectedVersionId: "v2", sleep: (milliseconds) => sleeps.push(milliseconds) });
  assert.equal(result.status, "ALREADY_RECONCILED"); assert.equal(reads, 3); assert.deepEqual(sleeps, [100, 200]);
});

test("IAM convergence retries authenticated partially converged snapshots", () => {
  const value = authorization(); const before = assertInitialActivationLifecyclePolicyState(state(), { desired }); const sleeps = []; let reads = 0;
  const snapshots = [
    state({ defaultVersionId: "v2", document: desired.document, policyVersionCount: 1 }),
    state({ defaultVersionId: "v1", document: predecessor, policyVersionCount: 2 }),
    state({ defaultVersionId: "v2", document: desired.document, policyVersionCount: 2 }),
  ];
  const result = waitForInitialActivationLifecyclePolicyConvergence({ readLiveState: () => snapshots[reads++], before, authorization: value, desired, expectedVersionId: "v2", sleep: (milliseconds) => sleeps.push(milliseconds) });
  assert.equal(result.status, "ALREADY_RECONCILED"); assert.equal(reads, 3); assert.deepEqual(sleeps, [100, 200]);
});

test("unclassified IAM read failures fail closed without retry", () => {
  let reads = 0; assert.throws(() => waitForInitialActivationLifecyclePolicyConvergence({ readLiveState: () => { reads += 1; throw new Error("AccessDenied"); }, before: assertInitialActivationLifecyclePolicyState(state(), { desired }), authorization: authorization(), desired, sleep: () => { throw new Error("must not sleep"); } }), /AccessDenied/); assert.equal(reads, 1);
});

test("transient IAM read failures exhaust the bounded convergence window without a retry write", () => {
  let reads = 0; const sleeps = [];
  assert.throws(() => waitForInitialActivationLifecyclePolicyConvergence({ readLiveState: () => { const error = new Error("NoSuchEntity"); error.code = INITIAL_ACTIVATION_TRANSIENT_POLICY_VERSION_READ; reads += 1; throw error; }, before: assertInitialActivationLifecyclePolicyState(state(), { desired }), authorization: authorization(), desired, sleep: (milliseconds) => sleeps.push(milliseconds) }), /did not converge/);
  assert.equal(reads, 6); assert.deepEqual(sleeps, [100, 200, 400, 800, 1000]);
});

test("all snapshot operations retry only recognized read errors after one mutation", () => {
  const operations = ["GetPolicy", "GetPolicyVersion", "ListPolicyVersions", "GetRole", "ListAttachedRolePolicies", "ListEntitiesForPolicy"];
  for (const code of ["Throttling", "ThrottlingException", "TooManyRequestsException", "RequestLimitExceeded", "ServiceUnavailable", "ServiceUnavailableException", "ServiceFailure", "InternalFailure", "InternalError", "AccessDenied", "ValidationError", "MalformedPolicyDocument", "500", "UnknownError"]) {
    for (const operation of operations) {
      let creates = 0; let reads = 0; let sleeps = 0;
      const transient = !["AccessDenied", "ValidationError", "MalformedPolicyDocument", "500", "UnknownError"].includes(code);
      const run = () => executeCore({ authorization: authorization(), sourceSha, desired, sleep: () => { sleeps += 1; }, createPolicyVersion: () => { creates += 1; return { PolicyVersion: { VersionId: "v2" } }; }, readLiveState: () => {
        reads += 1;
        if (!creates) return state();
        if (reads === 3) throw Object.assign(new Error("Command failed: aws"), { stderr: Buffer.from(`An error occurred (${code}) when calling the ${operation} operation (reached max retries: 2): service error`) });
        return state({ defaultVersionId: "v2", document: desired.document, policyVersionCount: 2 });
      } });
      if (transient) assert.equal(run().status, "RECONCILED"); else assert.throws(run);
      assert.equal(creates, 1); assert.equal(reads, transient ? 4 : 3); assert.equal(sleeps, transient ? 1 : 0);
    }
  }
});

test("successive read failures and exhaustion never retry the mutation or bypass pre-mutation CAS", () => {
  for (const failureCount of [3, 6]) {
    let creates = 0; let reads = 0; let sleeps = 0;
    const run = () => executeCore({ authorization: authorization(), sourceSha, desired, sleep: () => { sleeps += 1; }, createPolicyVersion: () => { creates += 1; return { PolicyVersion: { VersionId: "v2" } }; }, readLiveState: () => {
      reads += 1;
      if (!creates) return state();
      if (reads <= failureCount + 2) throw Object.assign(new Error("service unavailable"), { code: "ServiceUnavailable" });
      return state({ defaultVersionId: "v2", document: desired.document, policyVersionCount: 2 });
    } });
    if (failureCount === 3) assert.equal(run().status, "RECONCILED"); else assert.throws(run, /did not converge/);
    assert.equal(creates, 1); assert.equal(sleeps, failureCount === 3 ? 3 : 5);
  }
  let creates = 0;
  assert.throws(() => executeCore({ authorization: authorization(), sourceSha, desired, readLiveState: () => { throw Object.assign(new Error("throttled"), { code: "Throttling" }); }, createPolicyVersion: () => { creates += 1; }, sleep: () => assert.fail("pre-mutation retry") }));
  assert.equal(creates, 0);
});

test("IAM convergence exhaustion never authorizes a second policy version", () => {
  const value = authorization(); let creates = 0; const sleeps = [];
  assert.throws(() => executeInitialActivationLifecyclePolicyReconciliation({ authorization: value, sourceSha, desired, readLiveState: () => state(), sleep: (milliseconds) => sleeps.push(milliseconds), createPolicyVersion: () => { creates += 1; return { PolicyVersion: { VersionId: "v2" } }; } }), /did not converge/);
  assert.equal(creates, 1); assert.deepEqual(sleeps, [100, 200, 400, 800, 1000]);
});
