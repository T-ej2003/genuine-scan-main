import assert from "node:assert/strict";
import { APP_ONLY, APP_ONLY_DOMAINS } from "./production-app-only-contract.mjs";
import { APP_ONLY_PROVISIONING, APP_ONLY_VERIFIER, appOnlyCompatibilityReadPolicy, appOnlyDeployerPolicy, appOnlyVerifierBoundaryPolicy,
  appOnlyVerifierLauncherPolicy, appOnlyProductionOidcTrust, appOnlyProductionOidcTrustPredecessors } from "./production-app-only-policy.mjs";
import { canonicalJson, canonicalSha256 } from "./production-green-stage-b-contract.mjs";
import { normalizeIamPolicyDocument } from "./iam-policy-document.mjs";
import { canonicalizeStageAProductionArtifactsPolicy } from "./production-stage-a-control-plane.mjs";
import { STAGE_B_TERRAFORM_BACKEND } from "./stage-b-terraform-backend-contract.mjs";

const policyHash = (value) => canonicalSha256(canonicalizeStageAProductionArtifactsPolicy(normalizeIamPolicyDocument(value, "App-only provisioning policy")));
const trustHash = (value) => canonicalSha256(normalizeIamPolicyDocument(value, "App-only OIDC trust"));
const specifications = (verifierArn) => [
  { arn: APP_ONLY.roleArn, boundaryArn: APP_ONLY_PROVISIONING.deployerBoundaryArn,
    boundary: appOnlyDeployerPolicy(), policy: appOnlyDeployerPolicy() },
  { arn: `arn:aws:iam::${APP_ONLY.account}:role/${APP_ONLY_VERIFIER.roleName}`, boundaryArn: APP_ONLY_PROVISIONING.verifierBoundaryArn,
    boundary: appOnlyVerifierBoundaryPolicy(), policy: appOnlyVerifierLauncherPolicy(verifierArn) },
];
const jsonRunner = (run) => (args) => {
  const value = run([...args, "--output", "json", "--no-cli-pager"]);
  return typeof value === "string" ? JSON.parse(value || "{}") : value;
};
const absent = (error) => /\bNoSuchEntity(?:Exception)?\b/.test(String(error?.stderr || error?.message || ""));
const assertPhase = (phase) => assert.ok(["VERIFIER", "DEPLOYER"].includes(phase), "Explicit provisioning phase required");
const selectedRole = (phase, arn) => phase === "DEPLOYER" ? arn === APP_ONLY.roleArn : arn !== APP_ONLY.roleArn;
function eligibilityBinding(phase, eligibility, sourceSha, now) {
  assertPhase(phase);
  if (phase === "VERIFIER") {
    assert.equal(eligibility, undefined, "Verifier provisioning must not carry deployment authorization");
    return null;
  }
  assert.ok(eligibility, "Deployment permissions require authenticated eligibility");
  const { preparationSha256, ...body } = eligibility;
  assert.equal(preparationSha256, canonicalSha256(body));
  assert.equal(body.kind, "APP_ONLY_DEPLOYMENT_PREPARATION");
  assert.equal(body.schemaVersion, 1); assert.equal(body.sourceSha, sourceSha); assert.equal(body.eligible, true);
  assert.deepEqual(Object.keys(body.domains).sort(), [...APP_ONLY_DOMAINS].sort());
  for (const value of Object.values(body.domains)) assert.equal(value, "ALREADY_APPLIED_COMPATIBLE");
  for (const name of ["images", "iam", "runtime", "database", "requirements", "verificationContractSha256"])
    assert.match(body.evidence[name] || "", /^[a-f0-9]{64}$/);
  const age = now - Date.parse(body.generatedAt);
  assert.ok(Number.isFinite(age) && age >= 0 && age <= APP_ONLY.maxEvidenceAgeMs, "Stale deployment eligibility");
  return preparationSha256;
}

// Bootstrap installs immutable outer boundaries separately. No operation here
// creates/versions a managed policy or changes an existing role's trust/boundary.
export function observeAppOnlyProvisioning({ run, verifierArn }) {
  const aws = jsonRunner(run);
  assert.equal(aws(["sts", "get-caller-identity"]).Account, APP_ONLY.account);
  return specifications(verifierArn).map((spec) => {
    const policy = aws(["iam", "get-policy", "--policy-arn", spec.boundaryArn]).Policy;
    assert.equal(policy?.Arn, spec.boundaryArn); assert.match(policy.DefaultVersionId, /^v[1-9][0-9]*$/);
    const version = aws(["iam", "get-policy-version", "--policy-arn", spec.boundaryArn, "--version-id", policy.DefaultVersionId]).PolicyVersion;
    assert.equal(version?.VersionId, policy.DefaultVersionId); assert.equal(version.IsDefaultVersion, true);
    assert.equal(policyHash(version.Document), policyHash(spec.boundary), "Outer permission boundary differs from reviewed source");
    const result = { arn: spec.arn, boundaryArn: spec.boundaryArn, boundaryVersion: policy.DefaultVersionId,
      boundarySha256: policyHash(spec.boundary), roleId: null, policySha256: null };
    const name = spec.arn.split("/").at(-1);
    let role;
    try { role = aws(["iam", "get-role", "--role-name", name]).Role; }
    catch (error) { if (absent(error)) return result; throw error; }
    assert.equal(role?.Arn, spec.arn); assert.equal(role.RoleName, name); assert.equal(role.Path, "/");
    assert.equal(role.MaxSessionDuration, 3600); assert.equal((role.Tags || []).length, 0);
    assert.equal(role.PermissionsBoundary?.PermissionsBoundaryArn, spec.boundaryArn);
    assert.equal(role.PermissionsBoundary.PermissionsBoundaryType, "Policy");
    const observedTrustSha256 = trustHash(role.AssumeRolePolicyDocument);
    assert.ok(appOnlyProductionOidcTrustPredecessors(name).some((trust) => trustHash(trust) === observedTrustSha256), "Unreviewed predecessor OIDC trust");
    assert.ok(typeof role.RoleId === "string" && role.RoleId.length > 0);
    const attached = aws(["iam", "list-attached-role-policies", "--role-name", name]);
    const inline = aws(["iam", "list-role-policies", "--role-name", name]);
    assert.ok(!attached.IsTruncated && !inline.IsTruncated, "Incomplete role policy census");
    assert.deepEqual(attached.AttachedPolicies, []);
    assert.ok(Array.isArray(inline.PolicyNames) && inline.PolicyNames.length <= 1);
    if (inline.PolicyNames.length) {
      assert.deepEqual(inline.PolicyNames, [APP_ONLY_PROVISIONING.inlinePolicyName]);
      const response = aws(["iam", "get-role-policy", "--role-name", name, "--policy-name", APP_ONLY_PROVISIONING.inlinePolicyName]);
      assert.equal(response.RoleName, name); assert.equal(response.PolicyName, APP_ONLY_PROVISIONING.inlinePolicyName);
      const document = normalizeIamPolicyDocument(response.PolicyDocument, "Existing app capability");
      // A future verifier preparation can replace only a previously exact
      // launcher revision, never broaden or repair an unexpected policy.
      const priorArn = document.Statement?.find((s) => s.Sid === "RunExactReadOnlyVerifier")?.Resource;
      const expected = spec.arn === APP_ONLY.roleArn ? appOnlyDeployerPolicy()
        : priorArn === undefined ? appOnlyCompatibilityReadPolicy() : appOnlyVerifierLauncherPolicy(priorArn);
      assert.equal(policyHash(document), policyHash(expected), "Unreviewed predecessor inline policy");
      result.policySha256 = policyHash(document);
    }
    return { ...result, roleId: role.RoleId, trustSha256: observedTrustSha256 };
  });
}

export function prepareAppOnlyProvisioning({ sourceSha, verifierArn, phase, eligibility, run, now = Date.now() }) {
  assert.match(sourceSha || "", /^[a-f0-9]{40}$/);
  const eligibilitySha256 = eligibilityBinding(phase, eligibility, sourceSha, now);
  const desired = specifications(verifierArn).filter(({ arn }) => selectedRole(phase, arn))
    .map(({ arn, boundaryArn, policy }) => ({ arn, boundaryArn, policySha256: policyHash(policy) }));
  const predecessor = observeAppOnlyProvisioning({ run, verifierArn });
  assert.deepEqual(observeAppOnlyProvisioning({ run, verifierArn }), predecessor, "IAM changed during preparation");
  const body = { schemaVersion: 1, kind: "APP_ONLY_PERMISSION_PREPARATION", sourceSha, verifierArn, phase, eligibilitySha256,
    generatedAt: new Date(now).toISOString(), trustSha256: canonicalSha256(specifications(verifierArn).map(({ arn }) => appOnlyProductionOidcTrust(arn.split("/").at(-1)))), predecessor, desired };
  return { ...body, preparationSha256: canonicalSha256(body) };
}

// Fixed positive AND negative probes against installed identities. Simulation
// is combined with the exact policy/boundary census, never used in its place.
export function verifyAppOnlyEffectivePermissions({ run, verifierArn, predecessorArn, phase }) {
  assertPhase(phase);
  appOnlyVerifierLauncherPolicy(verifierArn);
  const family = `arn:aws:ecs:${APP_ONLY.region}:${APP_ONLY.account}:task-definition/${APP_ONLY.family}:`;
  assert.match(predecessorArn || "", new RegExp(`^${family}[1-9][0-9]*$`));
  const verifierRole = `arn:aws:iam::${APP_ONLY.account}:role/${APP_ONLY_VERIFIER.roleName}`;
  const context = (definition = `${family}2147483647`, cluster = APP_ONLY.clusterArn, passedTo = "ecs-tasks.amazonaws.com") => [
    ["aws:RequestedRegion", APP_ONLY.region, "string"], ["ecs:cluster", cluster, "string"],
    ["ecs:task-definition", definition, "string"], ["ecs:enable-execute-command", "false", "string"],
    ["iam:PassedToService", passedTo, "string"],
  ].map(([ContextKeyName, value, ContextKeyType]) => ({ ContextKeyName, ContextKeyValues: [value], ContextKeyType }));
  const cases = [
    ["candidate-family-activation", APP_ONLY.roleArn, "ecs:UpdateService", APP_ONLY.serviceArn, true, context()],
    ["exact-predecessor-rollback", APP_ONLY.roleArn, "ecs:UpdateService", APP_ONLY.serviceArn, true, context(predecessorArn)],
    ["other-service", APP_ONLY.roleArn, "ecs:UpdateService", `${APP_ONLY.serviceArn}-other`, false, context()],
    ["other-cluster", APP_ONLY.roleArn, "ecs:UpdateService", APP_ONLY.serviceArn, false, context(undefined, `${APP_ONLY.clusterArn}-other`)],
    ["other-family", APP_ONLY.roleArn, "ecs:UpdateService", APP_ONLY.serviceArn, false, context(verifierArn)],
    ["register-candidate-family", APP_ONLY.roleArn, "ecs:RegisterTaskDefinition", `${family}2147483647`, true, context()],
    ["register-other-family", APP_ONLY.roleArn, "ecs:RegisterTaskDefinition", verifierArn, false, context()],
    ...[APP_ONLY.taskRoleArn, APP_ONLY.executionRoleArn].map((arn, i) => [`pass-fixed-role-${i}`, APP_ONLY.roleArn, "iam:PassRole", arn, true, context()]),
    ["pass-other-role", APP_ONLY.roleArn, "iam:PassRole", APP_ONLY_VERIFIER.taskRoleArn, false, context()],
    ["pass-non-ecs", APP_ONLY.roleArn, "iam:PassRole", APP_ONLY.taskRoleArn, false, context(undefined, undefined, "lambda.amazonaws.com")],
    ["app-run-task", APP_ONLY.roleArn, "ecs:RunTask", verifierArn, false, context(verifierArn)],
    ["app-exec", APP_ONLY.roleArn, "ecs:ExecuteCommand", `arn:aws:ecs:${APP_ONLY.region}:${APP_ONLY.account}:task/${APP_ONLY.cluster}/${"1".repeat(32)}`, false, context()],
    ["app-iam-write", APP_ONLY.roleArn, "iam:PutRolePolicy", APP_ONLY.roleArn, false, context()],
    ["app-state-write", APP_ONLY.roleArn, "s3:PutObject", STAGE_B_TERRAFORM_BACKEND.stateArn, false, context()],
    ["verifier-exact-task", verifierRole, "ecs:RunTask", verifierArn, true, context(verifierArn)],
    ["verifier-other-revision", verifierRole, "ecs:RunTask", verifierArn.replace(/:[0-9]+$/, ":2147483646"), false, context(verifierArn)],
    ["verifier-other-cluster", verifierRole, "ecs:RunTask", verifierArn, false, context(verifierArn, `${APP_ONLY.clusterArn}-other`)],
    ["verifier-deploy", verifierRole, "ecs:UpdateService", APP_ONLY.serviceArn, false, context()],
  ];
  const aws = jsonRunner(run);
  const observations = cases.filter(([, roleArn]) => selectedRole(phase, roleArn)).map(([id, roleArn, action, resource, expected, ContextEntries]) => {
    const response = aws(["iam", "simulate-principal-policy", "--policy-source-arn", roleArn, "--action-names", action.toLowerCase(),
      "--resource-arns", resource, "--context-entries", JSON.stringify(ContextEntries)]);
    assert.ok(!response.IsTruncated); assert.equal(response.EvaluationResults?.length, 1);
    const result = response.EvaluationResults[0];
    assert.equal(result.EvalActionName?.toLowerCase(), action.toLowerCase()); assert.equal(result.EvalResourceName, resource);
    assert.equal((result.MissingContextValues || []).length, 0, "Permission simulation has missing context");
    assert.ok(["allowed", "implicitDeny", "explicitDeny"].includes(result.EvalDecision));
    assert.equal(result.EvalDecision === "allowed", expected, `Effective permission mismatch: ${id}`);
    if (expected && result.PermissionsBoundaryDecisionDetail) assert.equal(result.PermissionsBoundaryDecisionDetail.AllowedByPermissionsBoundary, true);
    return { id, roleArn, action, resource, decision: result.EvalDecision };
  });
  return { verified: true, observations, observationsSha256: canonicalSha256(observations) };
}

// Internal execution primitive. The production entrypoint must authenticate
// protected source, exact preparation artifact and production approval; it
// supplies that check as authenticate, repeated before EVERY IAM write. For
// DEPLOYER it must also authenticate the exact eligibility producer artifact;
// content hashes alone are not provenance or approval.
export async function executeAppOnlyProvisioning({ preparation, sourceSha, eligibility, run, authenticate, writeEvidence, verifyEffective, now = Date.now }) {
  assert.equal(typeof authenticate, "function"); assert.equal(typeof writeEvidence, "function"); assert.equal(typeof verifyEffective, "function");
  const { preparationSha256, ...body } = preparation;
  assert.equal(preparationSha256, canonicalSha256(body));
  assert.equal(body.schemaVersion, 1); assert.equal(body.kind, "APP_ONLY_PERMISSION_PREPARATION");
  assert.match(sourceSha || "", /^[a-f0-9]{40}$/); assert.equal(body.sourceSha, sourceSha);
  assert.equal(body.trustSha256, canonicalSha256(specifications(body.verifierArn).map(({ arn }) => appOnlyProductionOidcTrust(arn.split("/").at(-1)))));
  const specs = specifications(body.verifierArn);
  assert.equal(body.eligibilitySha256, eligibilityBinding(body.phase, eligibility, sourceSha, now()));
  assert.deepEqual(body.desired, specs.filter(({ arn }) => selectedRole(body.phase, arn))
    .map(({ arn, boundaryArn, policy }) => ({ arn, boundaryArn, policySha256: policyHash(policy) })));
  const fresh = () => {
    const age = now() - Date.parse(body.generatedAt);
    assert.ok(Number.isFinite(age) && age >= 0 && age <= APP_ONLY.maxEvidenceAgeMs, "Stale IAM preparation");
    assert.equal(body.eligibilitySha256, eligibilityBinding(body.phase, eligibility, sourceSha, now()));
  };
  const aws = jsonRunner(run);
  let expected = body.predecessor;
  let writesAttempted = 0;
  const record = async (status, details = {}) => writeEvidence({ schemaVersion: 1, kind: "APP_ONLY_PERMISSION_RESULT",
    sourceSha, preparationSha256, status, writesAttempted, ...details });
  const beforeWrite = async () => {
    fresh(); await authenticate(preparation, eligibility);
    assert.deepEqual(observeAppOnlyProvisioning({ run, verifierArn: body.verifierArn }), expected, "IAM predecessor CAS changed");
  };
  await beforeWrite();
  assert.match(aws(["sts", "get-caller-identity"]).Arn || "", new RegExp(`^arn:aws:sts::${APP_ONLY.account}:assumed-role/${APP_ONLY_PROVISIONING.roleName}/[^/]+$`), "Only the separate provisioner can write app permissions");
  await record("PRE_MUTATION");
  try {
    for (let i = 0; i < specs.length; i++) {
      const spec = specs[i], name = spec.arn.split("/").at(-1);
      if (!selectedRole(body.phase, spec.arn)) continue;
      if (!expected[i].roleId) {
        await beforeWrite(); await record("CREATE_ROLE_INTENT", { roleArn: spec.arn }); writesAttempted++;
        aws(["iam", "create-role", "--role-name", name, "--path", "/", "--max-session-duration", "3600",
          "--permissions-boundary", spec.boundaryArn, "--assume-role-policy-document", canonicalJson(appOnlyProductionOidcTrust(name))]);
        const observed = observeAppOnlyProvisioning({ run, verifierArn: body.verifierArn });
        assert.ok(observed[i].roleId); assert.equal(observed[i].policySha256, null);
        const next = structuredClone(expected); next[i].roleId = observed[i].roleId; next[i].trustSha256 = observed[i].trustSha256;
        assert.deepEqual(observed, next, "Unexpected IAM change after role creation"); expected = observed;
      }
      const expectedTrustSha256 = trustHash(appOnlyProductionOidcTrust(name));
      if (expected[i].trustSha256 !== expectedTrustSha256) {
        assert.equal(spec.arn, APP_ONLY.roleArn, "Only the app deployer has an approved trust transition");
        await beforeWrite(); await record("UPDATE_TRUST_INTENT", { roleArn: spec.arn }); writesAttempted++;
        aws(["iam", "update-assume-role-policy", "--role-name", name, "--policy-document", canonicalJson(appOnlyProductionOidcTrust(name))]);
        const observed = observeAppOnlyProvisioning({ run, verifierArn: body.verifierArn });
        const next = structuredClone(expected); next[i].trustSha256 = expectedTrustSha256;
        assert.deepEqual(observed, next, "IAM trust readback is not exact"); expected = observed;
      }
      if (expected[i].policySha256 !== policyHash(spec.policy)) {
        await beforeWrite(); await record("PUT_POLICY_INTENT", { roleArn: spec.arn }); writesAttempted++;
        aws(["iam", "put-role-policy", "--role-name", name, "--policy-name", APP_ONLY_PROVISIONING.inlinePolicyName,
          "--policy-document", canonicalJson(spec.policy)]);
        const observed = observeAppOnlyProvisioning({ run, verifierArn: body.verifierArn });
        const next = structuredClone(expected); next[i].policySha256 = policyHash(spec.policy);
        assert.deepEqual(observed, next, "IAM policy readback is not exact"); expected = observed;
      }
    }
    fresh(); await authenticate(preparation, eligibility);
    const effective = await verifyEffective(body.phase);
    assert.equal(effective?.verified, true, "Effective permissions are unproven");
    assert.deepEqual(observeAppOnlyProvisioning({ run, verifierArn: body.verifierArn }), expected);
    await record("VERIFIED", { roles: expected, effective });
    return { status: "VERIFIED", writesAttempted, roles: expected, effective };
  } catch (cause) {
    await record(writesAttempted ? "PROVISIONING_OUTCOME_REQUIRES_READBACK" : "FAILED_BEFORE_MUTATION");
    throw new Error("App-only permission provisioning stopped; preserve evidence and do not retry writes blindly", { cause });
  }
}
