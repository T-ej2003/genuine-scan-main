#!/usr/bin/env node
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { createProductionCommandRunner, PRODUCTION_AWS_CREDENTIAL_SOURCE } from "./production-cutover-production-adapters.mjs";
import { digest } from "./component-iam-installation-contract.mjs";
import { normalizeIamPolicyDocument } from "./iam-policy-document.mjs";
import { readStageBProtectedMainCheckout } from "./stage-b-deployment-identity.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const roleName = "mscqr-production-normal-deployer";
const roleArn = `arn:aws:iam::368992683803:role/${roleName}`;
const predecessor = {
  Version: "2012-10-17", Statement: [{ Effect: "Allow", Action: "sts:AssumeRoleWithWebIdentity",
    Principal: { Federated: "arn:aws:iam::368992683803:oidc-provider/token.actions.githubusercontent.com" },
    Condition: { StringEquals: {
      "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
      "token.actions.githubusercontent.com:sub": "repo:T-ej2003/genuine-scan-main:environment:production-normal-deploy",
    } },
  }],
};
const target = JSON.parse(fs.readFileSync(path.join(root, "infra/aws/terraform/production-component-deployment-state/normal-deployer-trust-policy.json"), "utf8"));
const claims = target.Statement?.[0]?.Condition?.StringEquals;
const workflowPaths = ["production-normal-deployment-operation.yml", "production-green-backend-recovery-operation.yml", "production-historical-green-completion-operation.yml"];
const refs = claims?.["token.actions.githubusercontent.com:job_workflow_ref"];
assert.equal(target.Statement?.length, 1);
assert.equal(target.Version, "2012-10-17");
assert.deepEqual(Object.keys(target.Statement[0]).sort(), ["Effect", "Action", "Principal", "Condition"].sort());
assert.equal(target.Statement[0].Effect, "Allow");
assert.equal(target.Statement[0].Action, "sts:AssumeRoleWithWebIdentity");
assert.deepEqual(target.Statement[0].Principal, { Federated: "arn:aws:iam::368992683803:oidc-provider/token.actions.githubusercontent.com" });
assert.deepEqual(Object.keys(target.Statement[0].Condition), ["StringEquals"]);
assert.deepEqual(Object.keys(claims || {}).sort(), ["token.actions.githubusercontent.com:aud", "token.actions.githubusercontent.com:sub", "token.actions.githubusercontent.com:repository_id", "token.actions.githubusercontent.com:repository_owner_id", "token.actions.githubusercontent.com:ref", "token.actions.githubusercontent.com:job_workflow_ref"].sort());
assert.equal(claims["token.actions.githubusercontent.com:aud"], "sts.amazonaws.com");
assert.equal(claims["token.actions.githubusercontent.com:sub"], "repo:T-ej2003/genuine-scan-main:environment:production-normal-deploy");
assert.equal(claims["token.actions.githubusercontent.com:repository_id"], "1145608538");
assert.equal(claims["token.actions.githubusercontent.com:repository_owner_id"], "183396573");
assert.equal(claims["token.actions.githubusercontent.com:ref"], "refs/heads/main");
assert.ok(Array.isArray(refs) && refs.length === workflowPaths.length);
const pinned = refs[0]?.split("@")[1];
assert.match(pinned || "", /^[a-f0-9]{40}$/);
assert.deepEqual(refs, workflowPaths.map((name) => `T-ej2003/genuine-scan-main/.github/workflows/${name}@${pinned}`));
const hash = (value) => digest(normalizeIamPolicyDocument(value, "normal-deployer trust"));
const expectedPredecessor = hash(predecessor);
const expectedTarget = hash(target);
const json = (run, args) => JSON.parse(run([...args, "--output", "json", "--no-cli-pager"]));

export function convergeNormalDeployerTrust({ run, sourceSha } = {}) {
  assert.match(sourceSha || "", /^[a-f0-9]{40}$/);
  const principal = json(run, ["sts", "get-caller-identity"]);
  assert.equal(principal.Arn, "arn:aws:iam::368992683803:user/mscqr-ops-admin", "Only the established non-root infrastructure administrator can converge trust.");
  const read = () => {
    const role = json(run, ["iam", "get-role", "--role-name", roleName]).Role;
    assert.equal(role?.Arn, roleArn);
    return hash(role.AssumeRolePolicyDocument);
  };
  const before = read();
  assert.ok([expectedPredecessor, expectedTarget].includes(before), "Live normal-deployer trust is neither the reviewed predecessor nor target.");
  let writeError;
  if (before === expectedPredecessor) {
    try { run(["iam", "update-assume-role-policy", "--role-name", roleName, "--policy-document", JSON.stringify(target), "--no-cli-pager"]); }
    catch (error) { writeError = error; }
  }
  const after = read();
  if (after !== expectedTarget) {
    const error = new Error("Normal-deployer trust readback does not match the approved protected source.");
    if (writeError) error.cause = writeError;
    throw error;
  }
  return Object.freeze({ sourceSha, roleArn, predecessorSha256: before, trustSha256: after, iamWrites: Number(before === expectedPredecessor) });
}

if (import.meta.url === pathToFileURL(process.argv[1] || "").href) {
  assert.equal(process.argv.length, 6);
  const [sourceFlag, sourceSha, profileFlag, profile] = process.argv.slice(2);
  assert.equal(sourceFlag, "--source-sha"); assert.equal(profileFlag, "--admin-profile");
  assert.equal(profile, "mscqr-ops-admin");
  readStageBProtectedMainCheckout({ cwd: root, expectedSourceSha: sourceSha, requireCanonicalRepository: true });
  execFileSync("git", ["merge-base", "--is-ancestor", pinned, sourceSha], { cwd: root, stdio: "ignore" });
  for (const name of workflowPaths) {
    const workflow = `.github/workflows/${name}`;
    execFileSync("git", ["cat-file", "-e", `${pinned}:${workflow}`], { cwd: root, stdio: "ignore" });
    assert.equal(execFileSync("git", ["diff", "--name-only", pinned, sourceSha, "--", workflow], { cwd: root, encoding: "utf8" }), "", `${workflow} changed after its pinned identity.`);
  }
  const result = convergeNormalDeployerTrust({ sourceSha, run: createProductionCommandRunner({ credentialSource: PRODUCTION_AWS_CREDENTIAL_SOURCE.NAMED_PROFILE, profile }) });
  process.stdout.write(`${JSON.stringify(result)}\n`);
}
