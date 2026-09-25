#!/usr/bin/env node
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { createProductionCommandRunner, PRODUCTION_AWS_CREDENTIAL_SOURCE } from "./production-cutover-production-adapters.mjs";
import { normalizeIamPolicyDocument } from "./iam-policy-document.mjs";
import { readStageBProtectedMainCheckout } from "./stage-b-deployment-identity.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const account = "368992683803";
const roleName = "mscqr-production-web-image-publisher";
const boundaryName = "MSCQRProductionWebImagePublisherBoundary";
const releaseRoleName = "mscqr-production-release-deployer";
const publisherPolicyName = "MSCQRProductionWebImagePublisher";
const activationPolicyName = "MSCQRProductionFrontendActivation";
const publisherTags = [
  { Key: "Environment", Value: "production" },
  { Key: "ManagedBy", Value: "Terraform" },
  { Key: "Stack", Value: "production-web-release" },
];
const readJson = (run, args) => JSON.parse(run([...args, "--output", "json", "--no-cli-pager"]));
const source = (file) => JSON.parse(fs.readFileSync(path.join(root, "infra/aws/terraform/production-web-release", file), "utf8"));
const canonical = (value) => JSON.stringify(normalizeIamPolicyDocument(value, "production web release IAM document"));
const fileValue = (file) => `file://${path.join(root, "infra/aws/terraform/production-web-release", file)}`;
function defaultPolicyVersionId(response) {
  assert.ok(response && typeof response === "object" && !Array.isArray(response), "Permissions boundary policy-version response is malformed.");
  assert.ok(response.IsTruncated === undefined || response.IsTruncated === false, "Permissions boundary policy-version response is incomplete.");
  assert.ok(!Object.hasOwn(response, "Marker") && !Object.hasOwn(response, "NextToken"), "Permissions boundary policy-version response is incomplete.");
  assert.ok(Array.isArray(response.Versions) && response.Versions.length > 0, "Permissions boundary policy-version response is malformed.");
  assert.ok(response.Versions.every((version) => version && typeof version.VersionId === "string" && /^v[1-9]\d*$/.test(version.VersionId) && typeof version.IsDefaultVersion === "boolean"), "Permissions boundary policy-version response is malformed.");
  const defaults = response.Versions.filter(({ IsDefaultVersion }) => IsDefaultVersion);
  assert.equal(defaults.length, 1, "Permissions boundary must have exactly one default policy version.");
  return defaults[0].VersionId;
}

export const WEB_RELEASE_IAM = Object.freeze({ account, roleName, boundaryName, releaseRoleName, publisherPolicyName, activationPolicyName });

export function bootstrapProductionWebReleaseIam({ run, sourceSha }) {
  assert.equal(typeof run, "function");
  assert.match(sourceSha || "", /^[a-f0-9]{40}$/, "Exact protected source SHA is required.");
  const identity = readJson(run, ["sts", "get-caller-identity"]);
  assert.equal(identity.Account, account, "IAM bootstrap must use the production account.");
  assert.equal(identity.Arn, `arn:aws:iam::${account}:root`, "Exact web IAM bootstrap requires the governed root configuration profile.");

  const boundaryArn = `arn:aws:iam::${account}:policy/${boundaryName}`;
  const roleArn = `arn:aws:iam::${account}:role/${roleName}`;
  const publisher = source("publisher-permissions-policy.json");
  const trust = source("publisher-trust-policy.json");
  const activation = source("frontend-activation-policy.json");
  const actions = [];
  const optional = (args, select) => {
    try { return select(readJson(run, args)); }
    catch (error) { if (/NoSuchEntity/.test(`${error?.message || ""} ${error?.stderr || ""}`)) return null; throw error; }
  };

  const boundary = optional(["iam", "get-policy", "--policy-arn", boundaryArn], (value) => value.Policy);
  if (boundary) {
    assert.equal(boundary.Arn, boundaryArn, "Unexpected permissions boundary identity.");
    assert.equal(boundary.PolicyName, boundaryName, "Unexpected permissions boundary name.");
    assert.equal(boundary.Path, "/", "Unexpected permissions boundary path.");
    assert.equal(boundary.Description, "Terraform-managed production web publisher permissions boundary.", "Permissions boundary description differs from Terraform source.");
    const versions = readJson(run, ["iam", "list-policy-versions", "--policy-arn", boundaryArn]);
    const versionId = defaultPolicyVersionId(versions);
    const liveBoundary = readJson(run, ["iam", "get-policy-version", "--policy-arn", boundaryArn, "--version-id", versionId]).PolicyVersion.Document;
    assert.equal(canonical(liveBoundary), canonical(publisher), "Permissions boundary differs from reviewed source.");
  }

  const role = optional(["iam", "get-role", "--role-name", roleName], (value) => value.Role);
  if (role) {
    assert.equal(role.RoleName, roleName);
    assert.equal(role.Arn, roleArn);
    assert.equal(role.Path, "/");
    assert.equal(role.Description, "GitHub OIDC only: publish the reviewed production web image.");
    assert.equal(role.PermissionsBoundary?.PermissionsBoundaryArn, boundaryArn);
    assert.equal(role.MaxSessionDuration, 3600);
    assert.equal(canonical(role.AssumeRolePolicyDocument), canonical(trust), "Publisher trust differs from reviewed source.");
    assert.deepEqual([...(role.Tags || [])].sort((a, b) => a.Key.localeCompare(b.Key)), publisherTags, "Publisher tags differ from reviewed source.");
    const rolePolicies = readJson(run, ["iam", "list-role-policies", "--role-name", roleName]);
    assert.equal(rolePolicies.IsTruncated ?? false, false);
    assert.deepEqual(rolePolicies.PolicyNames.filter((name) => name !== publisherPolicyName), [], "Unexpected publisher inline policy exists.");
    const attached = readJson(run, ["iam", "list-attached-role-policies", "--role-name", roleName]);
    assert.equal(attached.IsTruncated ?? false, false);
    assert.deepEqual(attached.AttachedPolicies, [], "Unexpected publisher managed-policy attachment exists.");
  }
  const livePublisherPolicy = role && optional(["iam", "get-role-policy", "--role-name", roleName, "--policy-name", publisherPolicyName], (value) => value.PolicyDocument);
  if (livePublisherPolicy) assert.equal(canonical(livePublisherPolicy), canonical(publisher), "Publisher inline policy differs from reviewed source.");
  const releaseRole = readJson(run, ["iam", "get-role", "--role-name", releaseRoleName]).Role;
  assert.equal(releaseRole.Arn, `arn:aws:iam::${account}:role/${releaseRoleName}`, "Release deployer identity changed.");
  const liveActivation = optional(["iam", "get-role-policy", "--role-name", releaseRoleName, "--policy-name", activationPolicyName], (value) => value.PolicyDocument);
  if (liveActivation) assert.equal(canonical(liveActivation), canonical(activation), "Frontend activation policy differs from reviewed source.");

  if (!boundary) {
    run(["iam", "create-policy", "--policy-name", boundaryName, "--policy-document", fileValue("publisher-permissions-policy.json"), "--description", "Terraform-managed production web publisher permissions boundary."]);
    actions.push("CREATE_BOUNDARY");
    const created = readJson(run, ["iam", "get-policy", "--policy-arn", boundaryArn]).Policy;
    assert.equal(created.Arn, boundaryArn);
    assert.equal(created.Path, "/");
    assert.equal(created.Description, "Terraform-managed production web publisher permissions boundary.");
    const versions = readJson(run, ["iam", "list-policy-versions", "--policy-arn", boundaryArn]);
    const versionId = defaultPolicyVersionId(versions);
    const live = readJson(run, ["iam", "get-policy-version", "--policy-arn", boundaryArn, "--version-id", versionId]).PolicyVersion.Document;
    assert.equal(canonical(live), canonical(publisher), "Created boundary readback differs from source.");
  }
  if (!role) {
    run(["iam", "create-role", "--role-name", roleName, "--description", "GitHub OIDC only: publish the reviewed production web image.", "--max-session-duration", "3600", "--assume-role-policy-document", fileValue("publisher-trust-policy.json"), "--permissions-boundary", boundaryArn, "--tags", "Key=ManagedBy,Value=Terraform", "Key=Environment,Value=production", "Key=Stack,Value=production-web-release"]);
    actions.push("CREATE_PUBLISHER_ROLE");
    const created = readJson(run, ["iam", "get-role", "--role-name", roleName]).Role;
    assert.equal(canonical(created.AssumeRolePolicyDocument), canonical(trust));
    assert.equal(created.PermissionsBoundary?.PermissionsBoundaryArn, boundaryArn);
    assert.equal(created.MaxSessionDuration, 3600);
    assert.deepEqual([...(created.Tags || [])].sort((a, b) => a.Key.localeCompare(b.Key)), publisherTags);
  }
  const installIfStillAbsent = (targetRole, policyName, document) => {
    const current = optional(["iam", "get-role-policy", "--role-name", targetRole, "--policy-name", policyName], (value) => value.PolicyDocument);
    if (current) { assert.equal(canonical(current), canonical(document), `${policyName} changed after preflight.`); return; }
    run(["iam", "put-role-policy", "--role-name", targetRole, "--policy-name", policyName, "--policy-document", JSON.stringify(document)]);
    actions.push(`INSTALL_${policyName}`);
    assert.equal(canonical(readJson(run, ["iam", "get-role-policy", "--role-name", targetRole, "--policy-name", policyName]).PolicyDocument), canonical(document), `${policyName} readback differs from source.`);
  };
  installIfStillAbsent(roleName, publisherPolicyName, publisher);
  installIfStillAbsent(releaseRoleName, activationPolicyName, activation);
  return Object.freeze({ status: "WEB_RELEASE_IAM_SOURCE_VERIFIED", sourceSha, roleArn, boundaryArn, actions: Object.freeze(actions) });
}

function args(argv) {
  const result = new Map();
  for (let i = 0; i < argv.length; i += 2) {
    const key = argv[i], value = argv[i + 1];
    if (!key?.startsWith("--") || !value || value.startsWith("--") || result.has(key)) throw new Error(`Invalid or duplicate argument: ${key || "<missing>"}`);
    result.set(key, value);
  }
  assert.deepEqual([...result.keys()].sort(), ["--admin-profile", "--source-sha"]);
  return result;
}

if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  const values = args(process.argv.slice(2));
  const sourceSha = values.get("--source-sha");
  const checkout = readStageBProtectedMainCheckout({ cwd: root, expectedSourceSha: sourceSha, requireCanonicalRepository: true });
  assert.equal(checkout.currentHead, sourceSha, "IAM bootstrap source is not exact protected main.");
  const result = bootstrapProductionWebReleaseIam({ sourceSha, run: createProductionCommandRunner({ credentialSource: PRODUCTION_AWS_CREDENTIAL_SOURCE.NAMED_PROFILE, profile: values.get("--admin-profile") }) });
  process.stdout.write(`${JSON.stringify(result)}\n`);
}
