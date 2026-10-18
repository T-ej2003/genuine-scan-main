import test from "node:test";
import assert from "node:assert/strict";
import { APP_ONLY } from "../aws/production-app-only-contract.mjs";
import { APP_ONLY_PROVISIONING, APP_ONLY_VERIFIER, appOnlyDeployerPolicy, appOnlyVerifierBoundaryPolicy,
  appOnlyVerifierLauncherPolicy, appOnlyProductionOidcTrust, appOnlyVerifierNetwork } from "../aws/production-app-only-policy.mjs";
import { createAppOnlyRequirements } from "../aws/production-app-only-requirements.mjs";
import { buildAppOnlyVerifierDefinition } from "../aws/production-app-only-verifier-command.mjs";
import { observeAppOnlyProvisioning, verifyAppOnlyEffectivePermissions } from "../aws/production-app-only-provisioning.mjs";
import { canonicalSha256 } from "../aws/production-green-stage-b-contract.mjs";
import { recoverCompletedAppOnlyVerifierRegistration, assertRecoveredAppOnlyVerifierRegistration } from "../aws/production-app-only-verifier-recovery.mjs";

const sourceSha = "a".repeat(40), currentSourceSha = "b".repeat(40);
const verifierArn = `arn:aws:ecs:${APP_ONLY.region}:${APP_ONLY.account}:task-definition/${APP_ONLY_VERIFIER.family}:19`;
const predecessorArn = `arn:aws:ecs:${APP_ONLY.region}:${APP_ONLY.account}:task-definition/${APP_ONLY.family}:24`;

function fixture() {
  const identity = { sourceSha, candidateSourceSha: "c".repeat(40), candidateDigest: `sha256:${"1".repeat(64)}`,
    account: APP_ONLY.account, region: APP_ONLY.region, clusterArn: APP_ONLY.clusterArn, serviceArn: APP_ONLY.serviceArn,
    predecessorTaskDefinition: predecessorArn, predecessorBackendDigest: `sha256:${"2".repeat(64)}`,
    verifierImageDigest: `sha256:${"3".repeat(64)}`, databaseHostname: "reviewed.eu-west-2.rds.amazonaws.com" };
  const requirements = createAppOnlyRequirements({ repositoryRoot: process.cwd(), sourceSha,
    candidateSourceSha: identity.candidateSourceSha, packageChecksums: { fixture: true },
    catalogue: { routines: [{ schema: "app_auth", name: "fixed", arguments: "" }], tables: [{ name: "Example" }],
      policies: [{ table: "Example", name: "isolation" }], schemas: [{ name: "app_auth" }], roles: [{ name: "mscqr_prod_rls_canary_read" }] } });
  const databaseSecretArn = `arn:aws:secretsmanager:${APP_ONLY.region}:${APP_ONLY.account}:secret:${APP_ONLY_VERIFIER.databaseSecretName}-ABC123`;
  const definition = buildAppOnlyVerifierDefinition({ requirements, identity, repositoryRoot: process.cwd(), databaseSecretArn });
  const body = { schemaVersion: 1, kind: "APP_ONLY_VERIFIER_PREPARATION", sourceSha, eligible: false,
    identity, databaseSecretArn, predecessor: { taskDefinitionArn: predecessorArn },
    definitionSha256: canonicalSha256(definition.definition), verificationContractSha256: definition.verificationContractSha256,
    evidence: { requirements: requirements.requirementsSha256 }, networkSha256: canonicalSha256(appOnlyVerifierNetwork()) };
  const preparation = { ...body, preparationSha256: canonicalSha256(body) };
  const inputs = { schemaVersion: 1, kind: "APP_ONLY_VERIFIER_INPUTS", preparation, requirements };
  const calls = [];
  const run = (args) => {
    calls.push(args); const value = (flag) => args[args.indexOf(flag) + 1], name = value("--role-name");
    switch (args[1]) {
      case "get-caller-identity": return JSON.stringify({ Account: APP_ONLY.account });
      case "describe-task-definition": return JSON.stringify({ taskDefinition: { ...definition.definition,
        taskDefinitionArn: verifierArn, revision: 19, status: "ACTIVE" }, tags: [] });
      case "get-policy": return JSON.stringify({ Policy: { Arn: value("--policy-arn"), DefaultVersionId: "v3" } });
      case "get-policy-version": return JSON.stringify({ PolicyVersion: { VersionId: "v3", IsDefaultVersion: true,
        Document: value("--policy-arn") === APP_ONLY_PROVISIONING.verifierBoundaryArn
          ? appOnlyVerifierBoundaryPolicy() : appOnlyDeployerPolicy() } });
      case "get-role": if (name !== APP_ONLY_VERIFIER.roleName) throw new Error("NoSuchEntity");
        return JSON.stringify({ Role: { Arn: `arn:aws:iam::${APP_ONLY.account}:role/${name}`, RoleName: name,
          RoleId: "AROATESTROLE", Path: "/", MaxSessionDuration: 3600, Tags: [],
          PermissionsBoundary: { PermissionsBoundaryArn: APP_ONLY_PROVISIONING.verifierBoundaryArn, PermissionsBoundaryType: "Policy" },
          AssumeRolePolicyDocument: appOnlyProductionOidcTrust(name) } });
      case "list-attached-role-policies": return JSON.stringify({ AttachedPolicies: [] });
      case "list-role-policies": return JSON.stringify({ PolicyNames: name === APP_ONLY_VERIFIER.roleName
        ? [APP_ONLY_PROVISIONING.inlinePolicyName] : [] });
      case "get-role-policy": return JSON.stringify({ RoleName: name, PolicyName: APP_ONLY_PROVISIONING.inlinePolicyName,
        PolicyDocument: appOnlyVerifierLauncherPolicy(verifierArn) });
      case "simulate-principal-policy": {
        const action = value("--action-names"), resource = value("--resource-arns");
        const context = Object.fromEntries(JSON.parse(value("--context-entries"))
          .map(({ ContextKeyName, ContextKeyValues }) => [ContextKeyName, ContextKeyValues[0]]));
        const allowed = action === "ecs:runtask" && resource === verifierArn
          && context["ecs:cluster"] === APP_ONLY.clusterArn;
        return JSON.stringify({ EvaluationResults: [{ EvalActionName: action, EvalResourceName: resource,
          EvalDecision: allowed ? "allowed" : "implicitDeny", MissingContextValues: [],
          PermissionsBoundaryDecisionDetail: { AllowedByPermissionsBoundary: allowed } }] });
      }
      default: assert.fail(`Unexpected or mutating AWS operation ${args[1]}`);
    }
  };
  const roles = observeAppOnlyProvisioning({ run, verifierArn });
  const effective = verifyAppOnlyEffectivePermissions({ run, verifierArn, predecessorArn, phase: "VERIFIER" });
  calls.length = 0;
  const chain = (kind, preparationSha256, events) => {
    let previousSha256 = null;
    return events.map((event, index) => {
      const body = { schemaVersion: 1, kind: "APP_ONLY_EXECUTION_JOURNAL", sourceSha, preparationSha256,
        sequence: index + 1, previousSha256,
        event: { schemaVersion: 1, kind, sourceSha, preparationSha256, ...event } };
      const evidenceSha256 = canonicalSha256(body); previousSha256 = evidenceSha256;
      return { ...body, evidenceSha256 };
    });
  };
  const registrationJournal = chain("APP_ONLY_VERIFIER_REGISTRATION", preparation.preparationSha256, [
    { status: "REGISTRATION_INTENT" }, { status: "REGISTERED_READBACK_PENDING", taskDefinitionArn: verifierArn },
    { status: "REGISTERED_VERIFIED", taskDefinitionArn: verifierArn,
      preparationSha256: preparation.preparationSha256, definitionSha256: body.definitionSha256,
      verificationContractSha256: body.verificationContractSha256 }]);
  const permissionJournal = chain("APP_ONLY_PERMISSION_RESULT", "d".repeat(64), [
    { status: "PRE_MUTATION", writesAttempted: 0 },
    { status: "PUT_POLICY_INTENT", writesAttempted: 0,
      roleArn: `arn:aws:iam::${APP_ONLY.account}:role/${APP_ONLY_VERIFIER.roleName}` },
    { status: "VERIFIED", writesAttempted: 1, roles, effective }]);
  const options = { inputs, sourceSha, currentSourceSha, registrationJournal, permissionJournal, run,
    repositoryRoot: process.cwd(), isProtectedAncestor: (before, after) => before === sourceSha && after === currentSourceSha,
    originalRunId: "39088069169" };
  return { options, calls, chain, definition };
}

test("completed revision and IAM journals recover a terminal result with read-only AWS calls, repeatedly", () => {
  const { options, calls } = fixture();
  const first = recoverCompletedAppOnlyVerifierRegistration(options);
  const second = recoverCompletedAppOnlyVerifierRegistration(options);
  assert.deepEqual(second, first);
  assert.equal(first.taskDefinitionArn, verifierArn);
  const result = { ...first, resultSha256: canonicalSha256(first) };
  assert.equal(assertRecoveredAppOnlyVerifierRegistration({ result, ...options }), result);
  assert.equal(assertRecoveredAppOnlyVerifierRegistration({ result, ...options,
    run: (args) => { assert.notEqual(args[0], "iam", "Launcher cannot read or simulate its own IAM policy"); return options.run(args); } }), result);
  assert.ok(calls.length > 0);
  assert.ok(calls.every(([service, action]) => service === "sts" || service === "ecs" && action === "describe-task-definition"
    || service === "iam" && ["get-policy", "get-policy-version", "get-role", "list-attached-role-policies",
      "list-role-policies", "get-role-policy", "simulate-principal-policy"].includes(action)));
});

test("lost registration response, missing success journal and conflicting evidence fail without replay", () => {
  for (const change of [
    (f) => { f.options.registrationJournal[2].event.status = "REGISTRATION_OUTCOME_UNCERTAIN"; },
    (f) => { f.options.registrationJournal.pop(); },
    (f) => { f.options.registrationJournal[1].event.taskDefinitionArn = verifierArn.replace(/:19$/, ":20"); },
    (f) => { f.options.registrationJournal[2].previousSha256 = "0".repeat(64); },
    (f) => { f.options.permissionJournal[2].event.roles[1].policySha256 = "0".repeat(64); },
    (f) => { f.options.sourceSha = "f".repeat(40); },
    (f) => { f.options.currentSourceSha = "f".repeat(40); },
    (f) => { f.options.inputs.preparation.definitionSha256 = "0".repeat(64); },
    (f) => { const original = f.options.run; f.options.run = (args) => {
      const result = original(args);
      if (args[1] !== "describe-task-definition") return result;
      const response = JSON.parse(result); response.taskDefinition.containerDefinitions[0].command = ["sh"];
      return JSON.stringify(response);
    }; },
    (f) => { const original = f.options.run; f.options.run = (args) => {
      const result = original(args);
      if (args[1] !== "get-role-policy") return result;
      const response = JSON.parse(result); response.PolicyDocument.Statement.push({ Effect: "Allow", Action: "ecs:UpdateService", Resource: "*" });
      return JSON.stringify(response);
    }; },
  ]) {
    const f = fixture(); change(f);
    assert.throws(() => recoverCompletedAppOnlyVerifierRegistration(f.options));
    assert.ok(f.calls.every(([, action]) => !["register-task-definition", "put-role-policy"].includes(action)));
  }
});
