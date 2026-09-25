import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";
import { bootstrapProductionWebReleaseIam, WEB_RELEASE_IAM } from "../aws/bootstrap-production-web-release-iam.mjs";

const root = "infra/aws/terraform/production-web-release";
const read = (name) => JSON.parse(fs.readFileSync(`${root}/${name}`, "utf8"));
const policy = read("publisher-permissions-policy.json");
const trust = read("publisher-trust-policy.json");
const activation = read("frontend-activation-policy.json");
function fixture({ liveActivation = null, existingBoundary = false, existingRole = false, boundaryDescription = "Terraform-managed production web publisher permissions boundary.", versionsResponse = { Versions: [{ VersionId: "v1", IsDefaultVersion: true }] } } = {}) {
  let boundary = existingBoundary ? policy : null;
  let role = existingRole ? { RoleName: WEB_RELEASE_IAM.roleName, Arn: `arn:aws:iam::368992683803:role/${WEB_RELEASE_IAM.roleName}`, Path: "/", Description: "GitHub OIDC only: publish the reviewed production web image.", PermissionsBoundary: { PermissionsBoundaryArn: `arn:aws:iam::368992683803:policy/${WEB_RELEASE_IAM.boundaryName}` }, MaxSessionDuration: 3600, AssumeRolePolicyDocument: trust, Tags: [{ Key: "ManagedBy", Value: "Terraform" }, { Key: "Environment", Value: "production" }, { Key: "Stack", Value: "production-web-release" }] } : null;
  let publisherPolicy = existingRole ? policy : null, activationPolicy = liveActivation;
  const calls = [];
  const run = (args) => {
    calls.push(args);
    const [service, operation] = args;
    const value = (flag) => args[args.indexOf(flag) + 1];
    const output = (data) => JSON.stringify(data);
    if (service === "sts" && operation === "get-caller-identity") return output({ Account: "368992683803", Arn: "arn:aws:iam::368992683803:root" });
    if (service !== "iam") throw new Error(`Unexpected call: ${service} ${operation}`);
    if (operation === "get-policy") { if (!boundary) throw new Error("NoSuchEntity"); return output({ Policy: { Arn: `arn:aws:iam::368992683803:policy/${WEB_RELEASE_IAM.boundaryName}`, PolicyName: WEB_RELEASE_IAM.boundaryName, Path: "/", Description: boundaryDescription } }); }
    if (operation === "create-policy") { boundary = policy; return ""; }
    if (operation === "list-policy-versions") return output(versionsResponse);
    if (operation === "get-policy-version") return output({ PolicyVersion: { Document: boundary } });
    if (operation === "get-role") {
      if (value("--role-name") === WEB_RELEASE_IAM.releaseRoleName) return output({ Role: { Arn: `arn:aws:iam::368992683803:role/${WEB_RELEASE_IAM.releaseRoleName}` } });
      if (!role) throw new Error("NoSuchEntity");
      return output({ Role: role });
    }
    if (operation === "create-role") { role = { RoleName: WEB_RELEASE_IAM.roleName, Arn: `arn:aws:iam::368992683803:role/${WEB_RELEASE_IAM.roleName}`, Path: "/", Description: "GitHub OIDC only: publish the reviewed production web image.", PermissionsBoundary: { PermissionsBoundaryArn: value("--permissions-boundary") }, MaxSessionDuration: Number(value("--max-session-duration")), AssumeRolePolicyDocument: trust, Tags: [{ Key: "ManagedBy", Value: "Terraform" }, { Key: "Environment", Value: "production" }, { Key: "Stack", Value: "production-web-release" }] }; return ""; }
    if (operation === "list-role-policies") return output({ IsTruncated: false, PolicyNames: publisherPolicy ? [WEB_RELEASE_IAM.publisherPolicyName] : [] });
    if (operation === "list-attached-role-policies") return output({ IsTruncated: false, AttachedPolicies: [] });
    if (operation === "get-role-policy") {
      if (value("--role-name") === WEB_RELEASE_IAM.releaseRoleName && activationPolicy) return output({ PolicyDocument: activationPolicy });
      if (value("--role-name") === WEB_RELEASE_IAM.roleName && publisherPolicy) return output({ PolicyDocument: publisherPolicy });
      throw new Error("NoSuchEntity");
    }
    if (operation === "put-role-policy") {
      const document = JSON.parse(value("--policy-document"));
      if (value("--role-name") === WEB_RELEASE_IAM.roleName) publisherPolicy = document;
      else if (value("--role-name") === WEB_RELEASE_IAM.releaseRoleName) activationPolicy = document;
      else throw new Error("Unexpected target role");
      return "";
    }
    throw new Error(`Unexpected IAM call: ${operation}`);
  };
  return { run, calls, getState: () => ({ boundary, role, publisherPolicy, activationPolicy }) };
}

test("web IAM bootstrap creates only source-defined resources and is idempotent", () => {
  const value = fixture();
  const first = bootstrapProductionWebReleaseIam({ run: value.run, sourceSha: "a".repeat(40) });
  assert.deepEqual(first.actions, ["CREATE_BOUNDARY", "CREATE_PUBLISHER_ROLE", `INSTALL_${WEB_RELEASE_IAM.publisherPolicyName}`, `INSTALL_${WEB_RELEASE_IAM.activationPolicyName}`]);
  const second = bootstrapProductionWebReleaseIam({ run: value.run, sourceSha: "a".repeat(40) });
  assert.deepEqual(second.actions, []);
  assert.equal(value.calls.filter((args) => args[0] === "iam" && ["create-policy", "create-role", "put-role-policy"].includes(args[1])).length, 4);
  for (const args of value.calls.filter(([service, operation]) => service === "iam" && ["create-policy", "create-role", "put-role-policy"].includes(operation))) {
    const operation = args[1];
    if (operation === "create-policy") assert.equal(args[args.indexOf("--policy-name") + 1], WEB_RELEASE_IAM.boundaryName);
    if (operation === "create-role") assert.equal(args[args.indexOf("--role-name") + 1], WEB_RELEASE_IAM.roleName);
    if (operation === "put-role-policy") {
      const target = [args[args.indexOf("--role-name") + 1], args[args.indexOf("--policy-name") + 1]];
      assert.equal([[WEB_RELEASE_IAM.roleName, WEB_RELEASE_IAM.publisherPolicyName], [WEB_RELEASE_IAM.releaseRoleName, WEB_RELEASE_IAM.activationPolicyName]].some(([roleName, policyName]) => roleName === target[0] && policyName === target[1]), true);
    }
  }
  const mutations = value.calls.filter(([service, operation]) => service === "iam" && /^(create|put|attach|update|delete)/.test(operation));
  assert.deepEqual(mutations.map(([, operation]) => operation).sort(), ["create-policy", "create-role", "put-role-policy", "put-role-policy"]);
  assert.deepEqual(value.calls.filter(([service, operation]) => service === "iam" && operation === "get-policy-version").map((args) => args[args.indexOf("--version-id") + 1]), ["v1", "v1"]);
  const source = fs.readFileSync("scripts/aws/bootstrap-production-web-release-iam.mjs", "utf8");
  assert.match(source, /readStageBProtectedMainCheckout\(\{ cwd: root, expectedSourceSha: sourceSha, requireCanonicalRepository: true \}\)/);
  assert.match(source, /checkout\.currentHead, sourceSha/);
  const terraform = fs.readFileSync(`${root}/main.tf`, "utf8");
  const boundaryDescription = terraform.match(/resource "aws_iam_policy" "publisher_boundary" \{[^}]*description\s*=\s*"([^"]+)"/s)?.[1];
  assert.ok(boundaryDescription, "Terraform must own the imported boundary description.");
  assert.ok(source.includes(`"--description", ${JSON.stringify(boundaryDescription)}`), "Bootstrap and Terraform must create the boundary with the same description to preserve a no-op import plan.");
});

test("AWS list-policy-versions Versions response selects the sole default even when it is not first", () => {
  for (const existingBoundary of [false, true]) {
    const value = fixture({ existingBoundary, versionsResponse: { IsTruncated: false, Versions: [{ VersionId: "v1", IsDefaultVersion: false }, { VersionId: "v2", IsDefaultVersion: true }] } });
    bootstrapProductionWebReleaseIam({ run: value.run, sourceSha: "a".repeat(40) });
    assert.equal(value.calls.some((args) => args[0] === "iam" && args[1] === "get-policy-version" && args[args.indexOf("--version-id") + 1] === "v2"), true);
    assert.equal(value.calls.some((args) => args[0] === "iam" && /^(create|delete)-policy-version$/.test(args[1])), false);
  }
});

test("AWS CLI aggregated Versions response without IsTruncated is accepted", () => {
  const value = fixture({ versionsResponse: { Versions: [{ VersionId: "v1", IsDefaultVersion: true }] } });
  bootstrapProductionWebReleaseIam({ run: value.run, sourceSha: "a".repeat(40) });
  const call = value.calls.find((args) => args[0] === "iam" && args[1] === "list-policy-versions");
  assert.ok(call);
  assert.equal(call.some((arg) => ["--no-paginate", "--max-items", "--page-size", "--starting-token", "--query"].includes(arg)), false);
  assert.equal(value.calls.some((args) => args[0] === "iam" && args[1] === "get-policy-version"), true);
});

test("canonical existing boundary is preserved while bootstrap recovers the production partial state", () => {
  const value = fixture({ existingBoundary: true });
  const result = bootstrapProductionWebReleaseIam({ run: value.run, sourceSha: "a".repeat(40) });
  assert.equal(result.actions.includes("CREATE_BOUNDARY"), false);
  assert.deepEqual(result.actions, ["CREATE_PUBLISHER_ROLE", `INSTALL_${WEB_RELEASE_IAM.publisherPolicyName}`, `INSTALL_${WEB_RELEASE_IAM.activationPolicyName}`]);
  assert.equal(value.calls.some((args) => args[0] === "iam" && args[1] === "create-policy"), false);
  assert.deepEqual(value.getState().boundary, policy);
});

test("malformed policy-version responses fail closed on both existing and newly-created boundary paths", () => {
  const malformed = [
    {},
    { IsTruncated: false, PolicyVersions: [{ VersionId: "v1", IsDefaultVersion: true }] },
    { IsTruncated: false },
    { IsTruncated: false, Versions: null },
    { IsTruncated: false, Versions: [] },
    { IsTruncated: true, Versions: [{ VersionId: "v1", IsDefaultVersion: true }] },
    { IsTruncated: "false", Versions: [{ VersionId: "v1", IsDefaultVersion: true }] },
    { IsTruncated: false, Marker: "more-results", Versions: [{ VersionId: "v1", IsDefaultVersion: true }] },
    { NextToken: "more-results", Versions: [{ VersionId: "v1", IsDefaultVersion: true }] },
    { IsTruncated: false, Versions: [{ IsDefaultVersion: true }] },
    { IsTruncated: false, Versions: [{ VersionId: "v1" }] },
    { IsTruncated: false, Versions: [{ VersionId: "v1", IsDefaultVersion: false }] },
    { IsTruncated: false, Versions: [{ VersionId: "v1", IsDefaultVersion: true }, { VersionId: "v2", IsDefaultVersion: true }] },
  ];
  for (const existingBoundary of [false, true]) for (const versionsResponse of malformed) {
    const value = fixture({ existingBoundary, versionsResponse });
    assert.throws(() => bootstrapProductionWebReleaseIam({ run: value.run, sourceSha: "a".repeat(40) }));
    assert.equal(value.calls.some((args) => args[0] === "iam" && ["create-role", "put-role-policy"].includes(args[1])), false);
    if (existingBoundary) assert.equal(value.calls.some((args) => args[0] === "iam" && args[1] === "create-policy"), false);
  }
});

test("fully converged bootstrap rerun is a no-op", () => {
  const value = fixture();
  bootstrapProductionWebReleaseIam({ run: value.run, sourceSha: "a".repeat(40) });
  const callsBeforeRerun = value.calls.length;
  const result = bootstrapProductionWebReleaseIam({ run: value.run, sourceSha: "a".repeat(40) });
  assert.deepEqual(result.actions, []);
  assert.equal(value.calls.slice(callsBeforeRerun).some((args) => args[0] === "iam" && /^(create|put|attach|update|delete)/.test(args[1])), false);
});

test("unexpected caller, changed boundary or policy drift stops before further writes", () => {
  const wrongCaller = fixture();
  const original = wrongCaller.run;
  wrongCaller.run = (args) => args[0] === "sts" ? JSON.stringify({ Account: "368992683803", Arn: "arn:aws:iam::368992683803:user/operator" }) : original(args);
  assert.throws(() => bootstrapProductionWebReleaseIam({ run: wrongCaller.run, sourceSha: "a".repeat(40) }), /root configuration profile/);

  const wrongAccount = fixture();
  const accountRunner = wrongAccount.run;
  wrongAccount.run = (args) => args[0] === "sts" ? JSON.stringify({ Account: "111111111111", Arn: "arn:aws:iam::111111111111:root" }) : accountRunner(args);
  assert.throws(() => bootstrapProductionWebReleaseIam({ run: wrongAccount.run, sourceSha: "a".repeat(40) }), /production account/);
  assert.equal(wrongAccount.calls.filter(([service]) => service === "iam").length, 0);

  const value = fixture();
  bootstrapProductionWebReleaseIam({ run: value.run, sourceSha: "a".repeat(40) });
  const callsBefore = value.calls.length;
  value.run = ((run) => (args) => {
    if (args[0] === "iam" && args[1] === "get-policy-version") return JSON.stringify({ PolicyVersion: { Document: { Version: "2012-10-17", Statement: [{ Effect: "Allow", Action: "*", Resource: "*" }] } } });
    return run(args);
  })(value.run);
  assert.throws(() => bootstrapProductionWebReleaseIam({ run: value.run, sourceSha: "a".repeat(40) }), /differs from reviewed source/);
  assert.equal(value.calls.slice(callsBefore).some((args) => args[0] === "iam" && ["create-role", "put-role-policy"].includes(args[1])), false);
});

test("release-deployer policy drift fails in the preflight before any IAM mutation", () => {
  const value = fixture({ liveActivation: { Version: "2012-10-17", Statement: [{ Effect: "Allow", Action: "iam:*", Resource: "*" }] } });
  assert.throws(() => bootstrapProductionWebReleaseIam({ run: value.run, sourceSha: "a".repeat(40) }), /Frontend activation policy differs/);
  assert.equal(value.calls.some((args) => args[0] === "iam" && ["create-policy", "create-role", "put-role-policy"].includes(args[1])), false);
});

test("existing permissions boundary metadata must converge with Terraform before import", () => {
  const value = fixture({ existingBoundary: true, boundaryDescription: "Unexpected immutable description" });
  assert.throws(() => bootstrapProductionWebReleaseIam({ run: value.run, sourceSha: "a".repeat(40) }), /description differs from Terraform source/);
  assert.equal(value.calls.some((args) => args[0] === "iam" && /^(create|put|attach|update|delete)/.test(args[1])), false);
});

test("every bootstrapped IAM object matches the imported Terraform attributes", () => {
  const terraform = fs.readFileSync(`${root}/main.tf`, "utf8");
  const source = fs.readFileSync("scripts/aws/bootstrap-production-web-release-iam.mjs", "utf8");
  const role = terraform.match(/resource "aws_iam_role" "publisher" \{([\s\S]*?)\n\}/)?.[1];
  const boundary = terraform.match(/resource "aws_iam_policy" "publisher_boundary" \{([\s\S]*?)\n\}/)?.[1];
  const publisherInline = terraform.match(/resource "aws_iam_role_policy" "publisher" \{([\s\S]*?)\n\}/)?.[1];
  const activationInline = terraform.match(/resource "aws_iam_role_policy" "frontend_activation" \{([\s\S]*?)\n\}/)?.[1];
  assert.ok(role && boundary && publisherInline && activationInline);
  assert.match(role, /name\s*=\s*local\.publisher_role/);
  assert.match(role, /description\s*=\s*"GitHub OIDC only: publish the reviewed production web image\."/);
  assert.match(role, /max_session_duration\s*=\s*3600/);
  assert.match(role, /assume_role_policy\s*=\s*file\("\$\{path\.module\}\/publisher-trust-policy\.json"\)/);
  assert.match(role, /permissions_boundary\s*=\s*aws_iam_policy\.publisher_boundary\.arn/);
  assert.match(role, /tags\s*=\s*local\.tags/);
  assert.match(source, /"--description", "GitHub OIDC only: publish the reviewed production web image\."/);
  assert.match(source, /"--max-session-duration", "3600"/);
  for (const tag of ["Key=ManagedBy,Value=Terraform", "Key=Environment,Value=production", "Key=Stack,Value=production-web-release"]) assert.ok(source.includes(tag));
  assert.equal(source.includes('"--path"'), false, "The bootstrap must use IAM's same default '/' path as Terraform.");
  assert.match(boundary, /name\s*=\s*"MSCQRProductionWebImagePublisherBoundary"/);
  assert.match(boundary, /description\s*=\s*"Terraform-managed production web publisher permissions boundary\."/);
  assert.match(boundary, /policy\s*=\s*file\("\$\{path\.module\}\/publisher-permissions-policy\.json"\)/);
  assert.match(source, /"--description", "Terraform-managed production web publisher permissions boundary\."/);
  assert.match(publisherInline, /name\s*=\s*"MSCQRProductionWebImagePublisher"/);
  assert.match(publisherInline, /role\s*=\s*aws_iam_role\.publisher\.id/);
  assert.match(publisherInline, /publisher-permissions-policy\.json/);
  assert.match(activationInline, /name\s*=\s*"MSCQRProductionFrontendActivation"/);
  assert.match(activationInline, /role\s*=\s*data\.aws_iam_role\.release_deployer\.id/);
  assert.match(activationInline, /frontend-activation-policy\.json/);
  assert.match(source, /installIfStillAbsent\(roleName, publisherPolicyName, publisher\)/);
  assert.match(source, /installIfStillAbsent\(releaseRoleName, activationPolicyName, activation\)/);
});

test("operator backend policy has exact state/lock scope and no IAM mutation or escalation", () => {
  const document = JSON.parse(fs.readFileSync("documents/ops/iam/MSCQRProductionBootstrapOperator-v1.json", "utf8"));
  const statements = document.Statement;
  const state = statements.find(({ Action }) => Array.isArray(Action) && Action.includes("s3:GetObject"));
  const lock = statements.find(({ Action }) => Action === "s3:DeleteObject");
  const bucket = statements.find(({ Action }) => Action === "s3:ListBucket");
  const roleReads = statements.find(({ Action }) => Array.isArray(Action) && Action.includes("iam:GetRole"));
  const boundaryReads = statements.find(({ Action }) => Array.isArray(Action) && Action.includes("iam:ListPolicyVersions"));
  assert.deepEqual(state.Action, ["s3:GetObject", "s3:PutObject"]);
  const stateObject = "arn:aws:s3:::mscqr-production-terraform-state-368992683803-eu-west-2/mscqr/production/web-release/terraform.tfstate";
  assert.deepEqual(state.Resource, [stateObject, `${stateObject}.tflock`]);
  assert.equal(lock.Resource, `${stateObject}.tflock`);
  assert.deepEqual(lock.Action, "s3:DeleteObject");
  assert.equal(state.Action.includes("s3:DeleteObject"), false);
  assert.equal(bucket.Condition.StringLike["s3:prefix"], "mscqr/production/web-release/terraform.tfstate");
  assert.deepEqual(roleReads.Resource, ["arn:aws:iam::368992683803:role/mscqr-production-web-image-publisher", "arn:aws:iam::368992683803:role/mscqr-production-release-deployer"]);
  assert.deepEqual(roleReads.Action, ["iam:GetRole", "iam:GetRolePolicy", "iam:ListRolePolicies", "iam:ListAttachedRolePolicies"]);
  assert.deepEqual(boundaryReads, { Effect: "Allow", Action: ["iam:GetPolicy", "iam:GetPolicyVersion", "iam:ListPolicyVersions"], Resource: "arn:aws:iam::368992683803:policy/MSCQRProductionWebImagePublisherBoundary" });
  assert.equal(JSON.stringify(document).length <= 2048, true, "The bootstrap operator inline policy must remain within the AWS 2,048-character quota.");
  const allActions = statements.flatMap(({ Action }) => Array.isArray(Action) ? Action : [Action]);
  for (const action of ["iam:CreateRole", "iam:CreatePolicy", "iam:PutRolePolicy", "iam:AttachRolePolicy", "iam:UpdateAssumeRolePolicy", "iam:PassRole", "iam:List*", "iam:Get*", "iam:*"]) assert.equal(allActions.includes(action), false, action);
  assert.equal(statements.some(({ Resource }) => Resource === "*" || (Array.isArray(Resource) && Resource.includes("*"))), false);
});
