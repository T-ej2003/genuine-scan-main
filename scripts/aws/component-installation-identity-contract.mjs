import assert from "node:assert/strict";
import { digest, installationIdentity, installationCapabilitySet, provisionerTargetPolicy, terraformExecutorPolicyGeneration } from "./component-iam-installation-contract.mjs";
import { normalizeIamPolicyDocument } from "./iam-policy-document.mjs";

// First-bootstrap ownership is deliberately separate from component IAM and
// Terraform ownership. None of these session roles can deploy their broker.
export const identityBootstrap = Object.freeze({
  transitionType: "INITIAL_IDENTITY_BOOTSTRAP",
  environment: "production-component-installation-identity-bootstrap",
  account: installationIdentity.account,
  region: installationIdentity.region,
  installationRole: "mscqr-production-component-installation-session",
  cleanupRole: "mscqr-production-component-cleanup-session",
  authorizationRole: "mscqr-production-component-installation-authorizer",
  sessionSeconds: 900,
  maxSessionDuration: 3600, // IAM's minimum role maximum; issuance requests 900.
  expiryMarginSeconds: 120,
  bucket: "mscqr-production-terraform-state-368992683803-eu-west-2",
  prefix: "mscqr/production/component-deployment-state/",
});
export const componentRoleArn = (name) => `arn:aws:iam::${identityBootstrap.account}:role/${name}`;
export const componentBrokerArn = `arn:aws:lambda:${identityBootstrap.region}:${identityBootstrap.account}:function:${installationIdentity.functionName}`;
const policy = (Statement) => ({ Version: "2012-10-17", Statement });
const human = `arn:aws:iam::${identityBootstrap.account}:user/mscqr-production-bootstrap-operator`;
const humanTrust = () => policy([{ Effect: "Allow", Principal: { AWS: human }, Action: "sts:AssumeRole", Condition: { Bool: { "aws:MultiFactorAuthPresent": "true" } } }]);
// Separate immutable entry versions prevent cleanup credentials invoking the
// installation entry point directly. Unqualified invocation is never granted.
const invoke = (version) => policy([{ Effect: "Allow", Action: "lambda:InvokeFunction", Resource: `${componentBrokerArn}:${version}`, Condition: { StringEquals: { "aws:RequestedRegion": identityBootstrap.region } } }]);
// Kept local to avoid a configuration/identity import cycle. The public
// broker configuration module independently pins these same immutable sets.
const bootstrapEntryPoints = Object.freeze({ INSTALL: "1", CLEANUP: "2", AUTHORIZE: "3" });
const changedEntryPoints = Object.freeze({ INSTALL: "4", CLEANUP: "5", AUTHORIZE: "6" });
const successorEntryPoints = Object.freeze({ INSTALL: "7", CLEANUP: "8", AUTHORIZE: "9" });
const assertEntryPoints = (entryPoints) => {
  assert([bootstrapEntryPoints, changedEntryPoints, successorEntryPoints].includes(entryPoints), "Identity entry-point override forbidden");
  return entryPoints;
};

function sessionIdentities(entryPoints) {
  assertEntryPoints(entryPoints);
  const roles = [
    { role: identityBootstrap.installationRole, policyName: "MSCQRComponentInstallationSession", trust: humanTrust(), policy: invoke(entryPoints.INSTALL) },
    { role: identityBootstrap.cleanupRole, policyName: "MSCQRComponentCleanupSession", trust: humanTrust(), policy: invoke(entryPoints.CLEANUP) },
    { role: identityBootstrap.authorizationRole, policyName: "MSCQRComponentInstallationAuthorization", trust: policy([{
      Effect: "Allow", Principal: { Federated: `arn:aws:iam::${identityBootstrap.account}:oidc-provider/token.actions.githubusercontent.com` },
      Action: "sts:AssumeRoleWithWebIdentity", Condition: { StringEquals: {
        "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
        "token.actions.githubusercontent.com:sub": `repo:${installationIdentity.repository}:environment:${installationIdentity.authorizationEnvironment}`,
        "token.actions.githubusercontent.com:repository_owner_id": "183396573",
        "token.actions.githubusercontent.com:repository_id": "1145608538",
        "token.actions.githubusercontent.com:actor_id": "183396573",
        "token.actions.githubusercontent.com:ref": "refs/heads/main",
        "token.actions.githubusercontent.com:job_workflow_ref": `${installationIdentity.repository}/.github/workflows/component-iam-authorization-publisher.yml@refs/heads/main`,
      } },
    }]), policy: invoke(entryPoints.AUTHORIZE) },
  ];
  return roles.map((role) => ({ ...role, arn: componentRoleArn(role.role), path: "/", maxSessionDuration: identityBootstrap.maxSessionDuration,
    tags: { ManagedBy: "GovernedComponentIdentityBootstrap", Environment: "production", Component: "component-installation" },
    trustSha256: digest(role.trust), policySha256: digest(role.policy) }));
}

export function componentSessionIdentities() {
  assert.equal(arguments.length, 0, "Identity overrides are forbidden");
  return sessionIdentities(bootstrapEntryPoints);
}

// This is used solely by the governed BROKER_CHANGE controller and trust
// anchor. Callers cannot provide a custom version map.
export function brokerChangeSessionIdentities() {
  assert.equal(arguments.length, 0, "Identity overrides are forbidden");
  return sessionIdentities(changedEntryPoints);
}

export function assertExpiredSession(session, now) {
  assert.equal(session?.account, identityBootstrap.account);
  assert.equal(session?.region, identityBootstrap.region);
  assert.match(session?.sourceSha || "", /^[a-f0-9]{40}$/);
  assert.match(session?.transitionId || "", /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/);
  assert.match(session?.authorizationSha256 || "", /^[a-f0-9]{64}$/);
  assert.match(session?.principal || "", new RegExp(`^arn:aws:sts::${identityBootstrap.account}:assumed-role/${identityBootstrap.installationRole}/[^/]+$`));
  const issued = Date.parse(session.issuedAt);
  const expires = Date.parse(session.expiresAt);
  assert(Number.isFinite(issued) && Number.isFinite(expires) && Number.isFinite(now));
  assert(expires > issued && expires - issued <= identityBootstrap.sessionSeconds * 1000, "Invalid AWS session lifetime");
  assert(now > expires + identityBootstrap.expiryMarginSeconds * 1000, "Prior session is not safely expired");
  // Authentication of this metadata against AWS issuance evidence is a caller
  // prerequisite; this pure predicate is not proof from unsigned local JSON.
  return true;
}

export function assertPostBootstrapCapabilitySeparation(identities = componentSessionIdentities()) {
  assert.deepEqual(identities, componentSessionIdentities(), "Unexpected permanent session authority");
  for (const [index, target] of identities.entries()) {
    assert.deepEqual(target.policy, invoke(index + 1));
    assert(!target.policy.Statement.some(({ Action }) => [].concat(Action).some((action) => action.startsWith("iam:"))));
  }
  const terraform = installationCapabilitySet().terraform;
  for (const statement of terraform.Statement) {
    for (const action of [].concat(statement.Action)) {
      if (action.startsWith("lambda:")) assert.deepEqual(statement, invoke(1).Statement[0]);
      assert(!action.startsWith("iam:") || /^iam:(Get|List)/.test(action));
    }
  }
  return true;
}

function managedIdentities(entryPoints) {
  assertEntryPoints(entryPoints);
  const capabilities = installationCapabilitySet();
  const terraformInvocation = capabilities.terraform.Statement.find(({ Action }) => Action === "lambda:InvokeFunction");
  assert(terraformInvocation); terraformInvocation.Resource = `${componentBrokerArn}:${entryPoints.INSTALL}`;
  // The successor broker still rejects a resource-policy bypass on every
  // retained immutable version, but it has no mutation capability for any of
  // them. Fresh bootstrap keeps the original three-version read surface.
  const brokerVersions = entryPoints === bootstrapEntryPoints ? Object.values(entryPoints) : [...Object.values(bootstrapEntryPoints), ...Object.values(changedEntryPoints), ...(entryPoints === successorEntryPoints ? Object.values(successorEntryPoints) : [])];
  const objects = ["installation-authorization.json", "iam-installation.json", "permission-installation.json", "installation-session.json"].map((name) => `arn:aws:s3:::${identityBootstrap.bucket}/${identityBootstrap.prefix}${name}`);
  const brokerPolicy = provisionerTargetPolicy();
  brokerPolicy.Statement.push(
    // LookupEvents has no resource-level IAM support. Read-only, regional and
    // callable only from this fixed broker; the handler selects AssumeRole only.
    { Effect: "Allow", Action: "cloudtrail:LookupEvents", Resource: "*", Condition: { StringEquals: { "aws:RequestedRegion": identityBootstrap.region } } },
    { Effect: "Allow", Action: "s3:ListBucket", Resource: `arn:aws:s3:::${identityBootstrap.bucket}`, Condition: { StringEquals: { "s3:prefix": objects.map((arn) => arn.split(`${identityBootstrap.bucket}/`)[1]) } } },
    { Effect: "Allow", Action: "s3:GetObject", Resource: objects },
    { Effect: "Allow", Action: "s3:GetObject", Resource: `arn:aws:s3:::${identityBootstrap.bucket}/${identityBootstrap.prefix}identity-bootstrap.json` },
    { Effect: "Allow", Action: "s3:PutObject", Resource: objects, Condition: { StringEquals: { "s3:x-amz-server-side-encryption": "AES256" } } },
    { Effect: "Allow", Action: ["lambda:GetFunction", "lambda:GetFunctionConfiguration", "lambda:GetFunctionCodeSigningConfig", "lambda:GetRuntimeManagementConfig", "lambda:GetFunctionConcurrency", "lambda:GetPolicy"], Resource: [componentBrokerArn, ...brokerVersions.map((version) => `${componentBrokerArn}:${version}`)] },
    { Effect: "Allow", Action: ["iam:GetRole", "iam:GetRolePolicy", "iam:ListRolePolicies", "iam:ListAttachedRolePolicies", "iam:ListRoleTags"], Resource: [installationIdentity.provisionerRole, installationIdentity.terraformRole, identityBootstrap.installationRole, identityBootstrap.cleanupRole, identityBootstrap.authorizationRole].map(componentRoleArn) },
  );
  for (const statement of brokerPolicy.Statement) statement.Condition = { ...statement.Condition, ArnEquals: { "lambda:SourceFunctionArn": componentBrokerArn } };
  const roles = [
    { role: installationIdentity.provisionerRole, policyName: "MSCQRComponentInstallationBroker", trust: capabilities.provisionerTrust, policy: brokerPolicy },
    { role: installationIdentity.terraformRole, policyName: "MSCQRComponentTableExecutor", trust: capabilities.terraformTrust, policy: capabilities.terraform },
  ].map((role) => ({ ...role, arn: componentRoleArn(role.role), path: "/", maxSessionDuration: identityBootstrap.maxSessionDuration,
    tags: { ManagedBy: "GovernedComponentIdentityBootstrap", Environment: "production", Component: "component-installation" },
    trustSha256: digest(role.trust), policySha256: digest(role.policy) }));
  return [...roles, ...sessionIdentities(entryPoints)];
}

export function brokerPolicySuccessorManagedIdentities() {
  const identities = managedIdentities(successorEntryPoints);
  const terraform = identities.find(({ role }) => role === installationIdentity.terraformRole);
  terraform.policy = terraformExecutorPolicyGeneration("7", true);
  terraform.policySha256 = digest(terraform.policy);
  return identities;
}

export function bootstrapManagedIdentities() {
  assert.equal(arguments.length, 0, "Bootstrap identity overrides are forbidden");
  return managedIdentities(bootstrapEntryPoints);
}

export function brokerChangeManagedIdentities() {
  assert.equal(arguments.length, 0, "Identity overrides are forbidden");
  return managedIdentities(changedEntryPoints);
}

// Read-only, fixed identity inventory. The caller cannot substitute IAM targets
// or documents; the same verifier serves initial bootstrap and broker readback.
async function inspectManagedIdentities(iam, targets) {
  const inventory = async (operation, role, field) => {
    const values = [];
    const markers = new Set();
    let marker;
    do {
      const page = await iam(operation, { RoleName: role, ...(marker ? { Marker: marker } : {}) });
      assert(Array.isArray(page[field]), "Incomplete IAM inventory");
      values.push(...page[field]);
      assert.equal(typeof page.IsTruncated, "boolean");
      if (!page.IsTruncated) return values;
      assert(typeof page.Marker === "string" && page.Marker && !markers.has(page.Marker) && markers.size < 20, "Invalid IAM pagination");
      marker = page.Marker;
      markers.add(marker);
    } while (marker);
  };
  const result = [];
  for (const target of targets) {
    let response;
    try { response = await iam("GetRole", { RoleName: target.role }); }
    catch (error) {
      if (!["NoSuchEntity", "NoSuchEntityException"].includes(error.name)) throw error;
      result.push({ arn: target.arn, role: "ABSENT", policy: "ABSENT" });
      continue;
    }
    const role = response.Role;
    for (const [field, expected] of Object.entries({ RoleName: target.role, Arn: target.arn, Path: target.path, MaxSessionDuration: target.maxSessionDuration })) assert.equal(role[field], expected, `Unexpected bootstrap role ${field}`);
    assert.equal(role.PermissionsBoundary, undefined);
    assert.equal(digest(normalizeIamPolicyDocument(role.AssumeRolePolicyDocument)), target.trustSha256, "Unexpected bootstrap trust");
    const tags = await inventory("ListRoleTags", target.role, "Tags");
    assert.equal(tags.length, Object.keys(target.tags).length);
    assert.equal(digest(Object.fromEntries(tags.map(({ Key, Value }) => [Key, Value]))), digest(target.tags), "Unexpected bootstrap tags");
    assert.deepEqual(await inventory("ListAttachedRolePolicies", target.role, "AttachedPolicies"), []);
    const names = await inventory("ListRolePolicies", target.role, "PolicyNames");
    assert(names.length === 0 || (names.length === 1 && names[0] === target.policyName), "Unexpected bootstrap inline policy inventory");
    if (names.length) {
      const inline = await iam("GetRolePolicy", { RoleName: target.role, PolicyName: target.policyName });
      assert.equal(inline.RoleName, target.role);
      assert.equal(inline.PolicyName, target.policyName);
      assert.equal(digest(normalizeIamPolicyDocument(inline.PolicyDocument)), target.policySha256, "Unexpected bootstrap inline policy");
    }
    result.push({ arn: target.arn, role: "EXPECTED", policy: names.length ? "EXPECTED" : "ABSENT" });
  }
  return result;
}

export async function inspectBootstrapIdentities(iam) {
  assert.equal(arguments.length, 1, "Identity overrides are forbidden");
  return inspectManagedIdentities(iam, bootstrapManagedIdentities());
}

export async function inspectBrokerChangeIdentities(iam) {
  assert.equal(arguments.length, 1, "Identity overrides are forbidden");
  return inspectManagedIdentities(iam, brokerChangeManagedIdentities());
}

export async function inspectBrokerPolicySuccessorIdentities(iam) {
  assert.equal(arguments.length, 1, "Identity overrides are forbidden");
  return inspectManagedIdentities(iam, brokerPolicySuccessorManagedIdentities());
}

// This is the source-owned mutation envelope for the exceptional first bootstrap,
// not a policy attached to any normal session and not a claim to restrict root.
export function identityBootstrapCapabilitySet() {
  assert.equal(arguments.length, 0);
  const resources = bootstrapManagedIdentities().map(({ arn }) => arn);
  const evidence = `arn:aws:s3:::${identityBootstrap.bucket}/${identityBootstrap.prefix}identity-bootstrap.json`;
  return policy([
    { Effect: "Allow", Action: ["iam:GetRole", "iam:GetRolePolicy", "iam:ListRolePolicies", "iam:ListAttachedRolePolicies", "iam:ListRoleTags"], Resource: resources },
    { Effect: "Allow", Action: ["iam:CreateRole", "iam:TagRole", "iam:PutRolePolicy"], Resource: resources },
    { Effect: "Allow", Action: "iam:PassRole", Resource: componentRoleArn(installationIdentity.provisionerRole), Condition: { StringEquals: { "iam:PassedToService": "lambda.amazonaws.com" } } },
    { Effect: "Allow", Action: ["lambda:CreateFunction", "lambda:PublishVersion", "lambda:UpdateFunctionConfiguration", "lambda:PutFunctionConcurrency", "lambda:PutRuntimeManagementConfig", "lambda:GetFunction", "lambda:GetFunctionConfiguration", "lambda:GetFunctionCodeSigningConfig", "lambda:GetFunctionConcurrency", "lambda:GetRuntimeManagementConfig", "lambda:ListVersionsByFunction", "lambda:GetPolicy"], Resource: componentBrokerArn, Condition: { StringEquals: { "aws:RequestedRegion": identityBootstrap.region } } },
    { Effect: "Allow", Action: ["lambda:GetFunction", "lambda:GetFunctionConfiguration", "lambda:GetRuntimeManagementConfig", "lambda:GetPolicy"], Resource: [1, 2, 3].map((version) => `${componentBrokerArn}:${version}`), Condition: { StringEquals: { "aws:RequestedRegion": identityBootstrap.region } } },
    { Effect: "Allow", Action: "s3:ListBucket", Resource: `arn:aws:s3:::${identityBootstrap.bucket}`, Condition: { StringEquals: { "s3:prefix": `${identityBootstrap.prefix}identity-bootstrap.json` } } },
    { Effect: "Allow", Action: "s3:GetObject", Resource: evidence },
    { Effect: "Allow", Action: "s3:PutObject", Resource: evidence, Condition: { StringEquals: { "s3:x-amz-server-side-encryption": "AES256" } } },
  ]);
}
