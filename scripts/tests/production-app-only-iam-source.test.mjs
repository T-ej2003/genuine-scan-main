import test from "node:test";
import assert from "node:assert/strict";
import { evaluateAppOnlySourceIam, collectAppOnlyLiveIamCompatibility, collectAppOnlyVerifierIamCompatibility } from "../aws/production-app-only-iam-source.mjs";
import { APP_ONLY_VERIFIER } from "../aws/production-app-only-policy.mjs";
import { APP_ONLY } from "../aws/production-app-only-contract.mjs";
import { RUNTIME_CONSUMABILITY } from "../aws/production-ecs-runtime-consumability.mjs";

const repositoryRoot = process.cwd();
const identity = { sourceSha: "a".repeat(40), candidateSourceSha: "b".repeat(40), account: APP_ONLY.account, region: APP_ONLY.region,
  clusterArn: APP_ONLY.clusterArn, serviceArn: APP_ONLY.serviceArn,
  predecessorTaskDefinition: `arn:aws:ecs:${APP_ONLY.region}:${APP_ONLY.account}:task-definition/${APP_ONLY.family}:14`,
  predecessorBackendDigest: `sha256:${"1".repeat(64)}`, candidateDigest: `sha256:${"2".repeat(64)}` };
const expected = evaluateAppOnlySourceIam({ repositoryRoot });
const databaseSecretArn = `arn:aws:secretsmanager:${APP_ONLY.region}:${APP_ONLY.account}:secret:${APP_ONLY_VERIFIER.databaseSecretName}-ABC123`;
const verifierExpected = evaluateAppOnlySourceIam({ repositoryRoot, databaseSecretArn });
const documents = {
  [APP_ONLY_VERIFIER.executionRoleArn.split("/").at(-1)]: { "stage-b-exact-image-logs-and-secrets": verifierExpected.policies.execution },
  [APP_ONLY_VERIFIER.taskRoleArn.split("/").at(-1)]: {},
  [APP_ONLY.executionRoleArn.split("/").at(-1)]: { "stage-b-exact-image-logs-and-secrets": expected.policies.execution },
  [APP_ONLY.taskRoleArn.split("/").at(-1)]: { "stage-b-object-storage": expected.policies.object_storage, "stage-b-backend-ecs-exec-ssm-channels": expected.policies.ecs_exec },
};

test("verifier roles match source with zero task permissions and only the exact canary secret", () => {
  assert.deepEqual(verifierExpected.policies.execution.Statement.find((s) => s.Sid === "ReadOnlyExactInjectedSecrets").Resource, [databaseSecretArn]);
  const evidence = collectAppOnlyVerifierIamCompatibility({ repositoryRoot, identity, databaseSecretArn, run: reader().run });
  assert.equal(evidence.scope, "READ_ONLY_VERIFIER_ROLES");
  assert.deepEqual(evidence.roles.find((r) => r.arn === APP_ONLY_VERIFIER.taskRoleArn).policies, {});
  for (const mutate of [
    (r) => { if (r.PolicyNames) r.PolicyNames.push("unnecessary-write-authority"); },
    (r) => { if (r.AttachedPolicies) r.AttachedPolicies.push({ PolicyArn: "unreviewed" }); },
    (r) => { if (r.PolicyDocument) r.PolicyDocument.Statement.at(-1).Resource = "*"; },
    (r) => { if (r.Role) r.Role.PermissionsBoundary = { PermissionsBoundaryArn: "unproven" }; },
  ]) assert.throws(() => collectAppOnlyVerifierIamCompatibility({ repositoryRoot, identity, databaseSecretArn, run: reader(mutate).run }));
});
function reader(mutate = () => {}) {
  const calls = [];
  return { calls, run(args) {
    calls.push(args);
    const name = args[args.indexOf("--role-name") + 1], policyName = args[args.indexOf("--policy-name") + 1];
    let result;
    switch (args[1]) {
      case "get-caller-identity": result = { Account: APP_ONLY.account }; break;
      case "get-role": result = { Role: { Arn: `arn:aws:iam::${APP_ONLY.account}:role/${name}`, RoleName: name, RoleId: `fixture-${name}`, AssumeRolePolicyDocument: RUNTIME_CONSUMABILITY.ecsTaskTrust } }; break;
      case "list-role-policies": result = { PolicyNames: Object.keys(documents[name]) }; break;
      case "list-attached-role-policies": result = { AttachedPolicies: [] }; break;
      case "get-role-policy": result = { RoleName: name, PolicyName: policyName, PolicyDocument: structuredClone(documents[name][policyName]) }; break;
      default: throw new Error("Forbidden command");
    }
    mutate(result, args, calls); return result;
  } };
}
test("real Terraform expression evaluation derives exact backend policy scope without a backend/provider", () => {
  const policies = expected.policies;
  assert.equal(policies.execution.Statement.length, 4);
  assert.equal(policies.execution.Statement.find((s) => s.Sid === "PullOnlyApprovedRepository").Resource, `arn:aws:ecr:${APP_ONLY.region}:${APP_ONLY.account}:repository/mscqr-backend`);
  assert.equal(policies.object_storage.Statement.length, 2);
  assert.ok(policies.execution.Statement.find((s) => s.Sid === "ReadOnlyExactInjectedSecrets").Resource.length > 20);
});
test("live IAM semantic equality accepts array ordering and does not inspect Terraform state", () => {
  const aws = reader((response) => {
    if (response.PolicyDocument) response.PolicyDocument.Statement.reverse();
  });
  const evidence = collectAppOnlyLiveIamCompatibility({ repositoryRoot, identity, run: aws.run });
  assert.equal(evidence.status, "ALREADY_APPLIED_COMPATIBLE");
  assert.equal(evidence.sourceToLiveIamSemanticDifferences, 0);
  assert.deepEqual([...new Set(aws.calls.map(([service]) => service))].sort(), ["iam", "sts"]);
});
test("unexpected permissions, boundaries, trust, account and live policy races fail closed", () => {
  for (const mutate of [
    (r) => { if (r.Account) r.Account = "000000000000"; },
    (r) => { if (r.Role) r.Role.PermissionsBoundary = { PermissionsBoundaryArn: "unproven" }; },
    (r) => { if (r.Role) r.Role.AssumeRolePolicyDocument = { Version: "2012-10-17", Statement: [] }; },
    (r) => { if (r.AttachedPolicies) r.AttachedPolicies.push({ PolicyArn: "unreviewed" }); },
    (r) => { if (r.PolicyNames) r.PolicyNames.push("unreviewed"); },
    (r) => { if (r.PolicyNames) r.IsTruncated = true; },
    (r) => { if (r.PolicyDocument) r.PolicyDocument.Statement[0].Action = "iam:*"; },
    (r, args, calls) => { if (r.Role && calls.filter((a) => a[1] === "get-role").length > 2) r.Role.RoleId = "replacement"; },
  ]) {
    assert.throws(() => collectAppOnlyLiveIamCompatibility({ repositoryRoot, identity, run: reader(mutate).run }));
  }
});
