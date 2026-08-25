import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import test from "node:test";
import { createAwsCliAdapter, createRuntimePolicyConvergenceAuthorization, planProductionEcsRuntimePolicyConvergence, convergeProductionEcsRuntimePolicy, PRODUCTION_ECS_RUNTIME_POLICY } from "../aws/converge-production-ecs-runtime-policy.mjs";
import { buildLegacyBackendRecoveryCandidate } from "../aws/production-backend-health-recovery-contract.mjs";
import { buildRuntimeDependencyInventory, deriveEcsRuntimeDependencies, signRuntimeDependencyInventory, RUNTIME_CONSUMABILITY } from "../aws/production-ecs-runtime-consumability.mjs";
import { canonicalSha256 } from "../aws/stage-b-task-definition-recovery-contract.mjs";

const sourceSha = "b".repeat(40);
const current = JSON.parse(fs.readFileSync(new URL("./fixtures/mscqr-backend-47.task-definition.json", import.meta.url)));
const bindings = Object.fromEntries(["PRIVATE_KEY_CURRENT", "PUBLIC_KEY_CURRENT", "ACTIVE_KEY_VERSION", "PUBLIC_KEYS_JSON"].map((suffix) => [`ARTIFACT_SIGN_${suffix}`, `arn:aws:secretsmanager:eu-west-2:368992683803:secret:mscqr/production/rls-green/artifact-signing/${suffix.toLowerCase().replaceAll("_", "-")}-AbCd12`]));
const candidate = buildLegacyBackendRecoveryCandidate({ currentTaskDefinition: current, recoveryImageDigest: `sha256:${"6".repeat(64)}`, imageReleaseSha: sourceSha, artifactSigningBindings: bindings });
const secretVersionId = `fixture_version_${"0".repeat(16)}`;
const metadata = Object.fromEntries(deriveEcsRuntimeDependencies(candidate).flatMap(({ action, resource }) => {
  if (action === "secretsmanager:GetSecretValue") {
    const selector = deriveEcsRuntimeDependencies(candidate).find((dependency) => dependency.action === action && dependency.resource === resource).context.secretSelector;
    const versionIdsToStages = { [secretVersionId]: ["AWSCURRENT"] }; const secretVersions = [{ versionId: secretVersionId, versionStages: ["AWSCURRENT"] }];
    const selectorResolutions = [{ selector, resolvedVersionId: secretVersionId, resolvedVersionStage: "AWSCURRENT", jsonKeyState: selector.jsonKey ? "PRESENT" : "NOT_REQUESTED" }];
    const state = { ARN: resource, KmsKeyId: null, availability: "AVAILABLE", deletedDate: null, versionIdsToStages, secretVersions, selectorResolutions };
    return [[resource, { resource, encryption: "AWS_MANAGED", kmsKeyArn: null, availability: state.availability, deletedDate: state.deletedDate, versionIdsToStages, secretVersions, selectorResolutions, resourcePolicySha256: canonicalSha256(null), resourcePolicyAccess: "NO_RESOURCE_POLICY", metadataSha256: canonicalSha256(state) }]];
  }
  if (action.startsWith("ecr:") && resource !== "*") {
    const state = { resource, repositoryName: resource.split("repository/")[1], imageDigest: candidate.containerDefinitions[0].image.split("@")[1], imageAvailability: "EXISTS", repositoryPolicyState: "NO_POLICY", repositoryPolicySha256: canonicalSha256(null) };
    return [[resource, { ...state, metadataSha256: canonicalSha256(state) }]];
  }
  if (action.startsWith("logs:")) {
    const groupArn = resource.split(":log-stream:")[0]; const logGroupName = groupArn.split(":log-group:")[1];
    const state = { resource: groupArn, logGroupName, availability: "EXISTENCE_PROVEN", createGroup: deriveEcsRuntimeDependencies(candidate).some((dependency) => dependency.action === "logs:CreateLogGroup" && dependency.resource === groupArn) };
    return [[groupArn, { ...state, metadataSha256: canonicalSha256(state) }]];
  }
  return [];
}));
const oldPolicy = { Version: "2012-10-17", Statement: [{ Effect: "Allow", Action: "secretsmanager:GetSecretValue", Resource: "arn:aws:secretsmanager:eu-west-2:368992683803:secret:mscqr/prod/*" }] };
const candidateFileSha256 = crypto.createHash("sha256").update(`${JSON.stringify(candidate, null, 2)}\n`).digest("hex");
const runtimeInventory = buildRuntimeDependencyInventory({ sourceSha, candidate, candidateFileSha256, resourceMetadata: metadata, generatedAt: "2026-08-24T18:00:00.000Z" });
let inventorySignedDigest;
const runtimeInventoryEnvelope = signRuntimeDependencyInventory(runtimeInventory, { signedAt: "2026-08-24T18:00:00.000Z", sign: ({ digest }) => { inventorySignedDigest = Buffer.from(digest); return "AQ=="; } });
const verifyInventory = ({ digest }) => Buffer.from(digest).equals(inventorySignedDigest);
const convergenceContext = { sourceSha, candidate, candidateFileSha256, runtimeInventoryEnvelope, verifyInventory, now: Date.parse("2026-08-24T18:01:00.000Z") };
const planContext = { candidate, candidateFileSha256, runtimeInventory };
const expectedPlan = planProductionEcsRuntimePolicyConvergence({ ...planContext, livePolicyDocument: oldPolicy });
const role = { Arn: PRODUCTION_ECS_RUNTIME_POLICY.roleArn, AssumeRolePolicyDocument: RUNTIME_CONSUMABILITY.ecsTaskTrust };
const attachments = [{ PolicyName: "AmazonECSTaskExecutionRolePolicy", PolicyArn: "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy" }];
const convergenceAuthorization = () => {
  return createRuntimePolicyConvergenceAuthorization({ sourceSha, plan: expectedPlan, ticket: "INC-49", approvedBy: "operator", approverRole: "Production Operator", reason: "candidate-derived runtime closure", verificationRef: "https://example.invalid/49" });
};
const response = (args, policyDocument) => {
  const operation = args.slice(0, 2).join(" ");
  if (operation === "sts get-caller-identity") return { Account: "368992683803", Arn: "arn:aws:sts::368992683803:assumed-role/mscqr-production-bootstrap-mfa/operator" };
  if (operation === "iam get-role") return { Role: structuredClone(role) };
  if (operation === "iam get-role-policy") return { RoleName: PRODUCTION_ECS_RUNTIME_POLICY.roleName, PolicyName: PRODUCTION_ECS_RUNTIME_POLICY.policyName, PolicyDocument: structuredClone(policyDocument) };
  if (operation === "iam list-attached-role-policies") return { AttachedPolicies: structuredClone(attachments) };
  throw new Error(`unexpected ${operation}`);
};

test("source-owned execution policy is exact, candidate-derived, and least privilege", () => {
  const plan = planProductionEcsRuntimePolicyConvergence({ ...planContext, livePolicyDocument: oldPolicy });
  assert.equal(plan.roleArn, PRODUCTION_ECS_RUNTIME_POLICY.roleArn);
  assert.equal(plan.convergenceRequired, true);
  assert.equal(plan.missingActions.includes("secretsmanager:GetSecretValue"), true);
  assert.equal(plan.missingResources.includes(bindings.ARTIFACT_SIGN_PRIVATE_KEY_CURRENT), true);
  const secretStatement = plan.expectedPolicyDocument.Statement.find(({ Action }) => Action.includes("secretsmanager:GetSecretValue"));
  assert.deepEqual(secretStatement.Resource.sort(), Object.keys(metadata).filter((resource) => resource.startsWith("arn:aws:secretsmanager:")).sort());
  assert.equal(JSON.stringify(plan.expectedPolicyDocument).includes('"Resource":"*"'), false);
  assert.deepEqual(plan.expectedPolicyDocument.Statement.find(({ Action }) => Action.includes("logs:CreateLogGroup"))?.Resource, ["arn:aws:logs:eu-west-2:368992683803:log-group:/ecs/mscqr-backend"]);
});

test("governed convergence mutates one inline policy and proves attachments and trust unchanged", async () => {
  let policy = oldPolicy; let writes = 0; const operations = [];
  const aws = async (args) => {
    const operation = args.slice(0, 2).join(" ");
    operations.push(operation);
    if (operation === "sts get-caller-identity") return { Account: "368992683803", Arn: "arn:aws:sts::368992683803:assumed-role/mscqr-production-bootstrap-mfa/operator" };
    if (operation === "iam get-role") return { Role: role };
    if (operation === "iam get-role-policy") return { RoleName: PRODUCTION_ECS_RUNTIME_POLICY.roleName, PolicyName: PRODUCTION_ECS_RUNTIME_POLICY.policyName, PolicyDocument: policy };
    if (operation === "iam list-attached-role-policies") return { AttachedPolicies: [{ PolicyName: "AmazonECSTaskExecutionRolePolicy", PolicyArn: "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy" }] };
    if (operation === "iam put-role-policy") { writes += 1; policy = JSON.parse(args.at(-1)); return {}; }
    throw new Error(`unexpected ${operation}`);
  };
  const result = await convergeProductionEcsRuntimePolicy({ ...convergenceContext, authorization: convergenceAuthorization(), execute: true, aws, protectedMain: () => {} });
  assert.equal(result.applied, true); assert.equal(writes, 1); assert.equal(result.attachmentsChanged, false); assert.equal(result.trustChanged, false);
  const writeIndex = operations.indexOf("iam put-role-policy");
  assert.equal(operations[writeIndex - 1], "iam get-role-policy");
  assert.equal(operations[writeIndex + 1], "iam get-role-policy");
});

test("AWS CLI adapter preserves successful empty writes and exact postwrite readback", async () => {
  let policy = oldPolicy; const operations = [];
  const execute = (_command, args) => {
    const operation = args.slice(0, 2).join(" "); operations.push(operation);
    if (operation === "iam put-role-policy") {
      policy = JSON.parse(args[args.indexOf("--policy-document") + 1]);
      return " \n";
    }
    return JSON.stringify(response(args, policy));
  };
  const result = await convergeProductionEcsRuntimePolicy({ ...convergenceContext, authorization: convergenceAuthorization(), execute: true, aws: createAwsCliAdapter(execute), protectedMain: () => {} });
  assert.equal(result.applied, true);
  assert.deepEqual(operations.slice(-4), ["iam put-role-policy", "iam get-role-policy", "iam get-role", "iam list-attached-role-policies"]);
  assert.throws(() => createAwsCliAdapter(() => "{not-json")(["sts", "get-caller-identity"]), SyntaxError);

  const failedOperations = [];
  const failed = createAwsCliAdapter((_command, args) => {
    const operation = args.slice(0, 2).join(" "); failedOperations.push(operation);
    if (operation === "iam put-role-policy") throw new Error("PutRolePolicy failed");
    return JSON.stringify(response(args, oldPolicy));
  });
  await assert.rejects(() => convergeProductionEcsRuntimePolicy({ ...convergenceContext, authorization: convergenceAuthorization(), execute: true, aws: failed, protectedMain: () => {} }), /PutRolePolicy failed/);
  assert.equal(failedOperations.filter((operation) => operation === "iam get-role-policy").length, 2);
  assert.equal(failedOperations.at(-1), "iam put-role-policy");
});

test("authorization binds the exact canonical live-to-source policy transition", async () => {
  const reorderedAndEncoded = encodeURIComponent(JSON.stringify({ Statement: [{ Resource: oldPolicy.Statement[0].Resource, Action: oldPolicy.Statement[0].Action, Effect: "Allow" }], Version: "2012-10-17" }));
  assert.equal(planProductionEcsRuntimePolicyConvergence({ ...planContext, livePolicyDocument: reorderedAndEncoded }).livePolicySha256, expectedPlan.livePolicySha256);

  for (const field of ["expectedLivePolicySha256", "sourcePolicySha256", "candidateFileSha256", "candidateCanonicalSha256", "candidateFingerprint", "runtimeInventorySha256"]) {
    let writes = 0;
    const authorization = { ...convergenceAuthorization(), [field]: "f".repeat(64) };
    const body = { ...authorization }; delete body.authorizationSha256;
    authorization.authorizationSha256 = canonicalSha256(body);
    await assert.rejects(() => convergeProductionEcsRuntimePolicy({ ...convergenceContext, authorization, execute: true, aws: async (args) => {
      if (args[1] === "put-role-policy") { writes += 1; return {}; }
      return response(args, oldPolicy);
    }, protectedMain: () => {} }), field === "expectedLivePolicySha256" ? /LIVE_POLICY_CHANGED_SINCE_APPROVAL/ : /authorization/);
    assert.equal(writes, 0);
  }
});

test("stale approval rejects changed live policy before the IAM write", async () => {
  const changedPolicy = { Version: "2012-10-17", Statement: [{ Effect: "Allow", Action: "secretsmanager:GetSecretValue", Resource: "arn:aws:secretsmanager:eu-west-2:368992683803:secret:intervening" }] };
  for (const changeAtFinalRecheck of [false, true]) {
    let writes = 0; let reads = 0;
    const aws = async (args) => {
      if (args[1] === "get-role-policy") return response(args, !changeAtFinalRecheck || ++reads === 2 ? changedPolicy : oldPolicy);
      if (args[1] === "put-role-policy") { writes += 1; return {}; }
      return response(args, oldPolicy);
    };
    let rejection;
    try { await convergeProductionEcsRuntimePolicy({ ...convergenceContext, authorization: convergenceAuthorization(), execute: true, aws, protectedMain: () => {} }); } catch (error) { rejection = error; }
    assert.ok(rejection);
    assert.equal(rejection.report.status, "LIVE_POLICY_CHANGED_SINCE_APPROVAL");
    assert.equal(rejection.report.iamWrites, 0);
    assert.equal(writes, 0);
  }
});

test("postwrite mismatch records the one bounded mutation", async () => {
  let writes = 0;
  const aws = async (args) => {
    if (args[1] === "put-role-policy") { writes += 1; return {}; }
    return response(args, oldPolicy);
  };
  let rejection;
  try { await convergeProductionEcsRuntimePolicy({ ...convergenceContext, authorization: convergenceAuthorization(), execute: true, aws, protectedMain: () => {} }); } catch (error) { rejection = error; }
  assert.ok(rejection);
  assert.equal(rejection.report.status, "POSTWRITE_POLICY_READBACK_MISMATCH");
  assert.equal(rejection.report.iamWrites, 1);
  assert.equal(writes, 1);
});

test("missing inline policy is not treated as authorization to create one", async () => {
  let writes = 0;
  await assert.rejects(() => convergeProductionEcsRuntimePolicy({ ...convergenceContext, authorization: convergenceAuthorization(), execute: true, aws: async (args) => {
    if (args[1] === "get-role-policy") { const error = new Error("NoSuchEntity"); error.name = "NoSuchEntityException"; throw error; }
    if (args[1] === "put-role-policy") { writes += 1; return {}; }
    return response(args, oldPolicy);
  }, protectedMain: () => {} }), /NoSuchEntity/);
  assert.equal(writes, 0);
});

test("incomplete post-write role, trust, policy, or attachment readback fails closed", async () => {
  for (const [operation, corrupt] of [
    ["get-role", (result) => { result.Role = undefined; }],
    ["get-role", (result) => { delete result.Role.AssumeRolePolicyDocument; }],
    ["get-role", (result) => { result.Role.Arn = "arn:aws:iam::368992683803:role/wrong"; }],
    ["list-attached-role-policies", (result) => { result.AttachedPolicies = undefined; }],
    ["get-role-policy", (result) => { result.PolicyName = "wrong"; }],
  ]) {
    let writes = 0; let afterWrite = false; let policyReads = 0;
    const aws = async (args) => {
      if (args[1] === "put-role-policy") { writes += 1; afterWrite = true; return {}; }
      const result = response(args, afterWrite ? expectedPlan.expectedPolicyDocument : oldPolicy);
      if (args[1] === "get-role-policy") policyReads += 1;
      if (afterWrite && args[1] === operation) corrupt(result);
      return result;
    };
    await assert.rejects(() => convergeProductionEcsRuntimePolicy({ ...convergenceContext, authorization: convergenceAuthorization(), execute: true, aws, protectedMain: () => ({}) }), /READBACK|readback|Postwrite/);
    assert.equal(writes, 1);
    assert.equal(policyReads, 3);
  }
});

test("wrong role and wildcard source policy are rejected before IAM mutation", () => {
  assert.throws(() => planProductionEcsRuntimePolicyConvergence({ ...planContext, candidate: { ...candidate, executionRoleArn: candidate.taskRoleArn }, livePolicyDocument: oldPolicy }), /exact legacy/);
  const changed = structuredClone(candidate); changed.containerDefinitions[0].secrets.push({ name: "ARBITRARY", valueFrom: "*" });
  assert.throws(() => planProductionEcsRuntimePolicyConvergence({ ...planContext, candidate: changed, livePolicyDocument: oldPolicy }), /Unknown production ECS runtime reference|different candidate/);
});

test("execute requires exact human authorization before the IAM write", async () => {
  let writes = 0;
  const aws = async (args) => {
    const operation = args.slice(0, 2).join(" ");
    if (operation === "sts get-caller-identity") return { Account: "368992683803", Arn: "arn:aws:iam::368992683803:root" };
    if (operation === "iam get-role") return { Role: { Arn: PRODUCTION_ECS_RUNTIME_POLICY.roleArn, AssumeRolePolicyDocument: RUNTIME_CONSUMABILITY.ecsTaskTrust } };
    if (operation === "iam get-role-policy") return { RoleName: PRODUCTION_ECS_RUNTIME_POLICY.roleName, PolicyName: PRODUCTION_ECS_RUNTIME_POLICY.policyName, PolicyDocument: oldPolicy };
    if (operation === "iam list-attached-role-policies") return { AttachedPolicies: [] };
    if (operation === "iam put-role-policy") { writes += 1; return {}; }
    throw new Error(operation);
  };
  await assert.rejects(() => convergeProductionEcsRuntimePolicy({ ...convergenceContext, authorization: null, execute: true, aws, protectedMain: () => {} }), /authorization/);
  assert.equal(writes, 0);
});
