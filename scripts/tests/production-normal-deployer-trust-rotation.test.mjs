import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import test from "node:test";
import yaml from "js-yaml";
import { convergeNormalDeployerTrust } from "../aws/converge-production-normal-deployer-trust.mjs";

const role = "mscqr-production-normal-deployer";
const arn = `arn:aws:iam::368992683803:role/${role}`;
const target = JSON.parse(fs.readFileSync("infra/aws/terraform/production-component-deployment-state/normal-deployer-trust-policy.json", "utf8"));
const predecessor = structuredClone(target);
for (const claim of ["repository_id", "repository_owner_id", "ref", "job_workflow_ref"])
  delete predecessor.Statement[0].Condition.StringEquals[`token.actions.githubusercontent.com:${claim}`];
const condition = target.Statement[0].Condition.StringEquals;
const refs = condition["token.actions.githubusercontent.com:job_workflow_ref"];
const caller = { "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
  "token.actions.githubusercontent.com:sub": "repo:T-ej2003/genuine-scan-main:environment:production-normal-deploy",
  "token.actions.githubusercontent.com:repository_id": "1145608538",
  "token.actions.githubusercontent.com:repository_owner_id": "183396573",
  "token.actions.githubusercontent.com:ref": "refs/heads/main" };
const permitted = (claims) => Object.entries(condition).every(([key, expected]) =>
  Array.isArray(expected) ? expected.includes(claims[key]) : expected === claims[key]);

test("only three immutable approved operations match the reviewed IAM OIDC trust", () => {
  assert.equal(refs.length, 3);
  assert.equal(new Set(refs.map((ref) => ref.split("@")[1])).size, 1);
  for (const ref of refs) assert.equal(permitted({ ...caller, "token.actions.githubusercontent.com:job_workflow_ref": ref }), true);
  for (const changed of [
    { "token.actions.githubusercontent.com:job_workflow_ref": "T-ej2003/genuine-scan-main/.github/workflows/production-deploy.yml@refs/heads/main" },
    { "token.actions.githubusercontent.com:job_workflow_ref": refs[0].replace(/@[a-f0-9]{40}$/, `@${"f".repeat(40)}`) },
    { "token.actions.githubusercontent.com:ref": "refs/heads/feature" },
    { "token.actions.githubusercontent.com:sub": "repo:T-ej2003/genuine-scan-main:environment:production" },
    { "token.actions.githubusercontent.com:repository_id": "0" },
    { "token.actions.githubusercontent.com:repository_owner_id": "0" },
  ]) assert.equal(permitted({ ...caller, "token.actions.githubusercontent.com:job_workflow_ref": refs[0], ...changed }), false);
});

test("all role consumers authenticate immutable tooling before repository code or OIDC assumption", () => {
  for (const [callerFile, jobName, index] of [["production-deploy.yml", "deploy", 0], ["release-gate.yml", "execute-green-backend-recovery", 1], ["complete-historical-green-backend-recovery.yml", "complete", 2]]) {
    const callerWorkflow = yaml.load(fs.readFileSync(`.github/workflows/${callerFile}`, "utf8"));
    assert.equal(callerWorkflow.jobs[jobName].uses, refs[index], `${callerFile} must call only its IAM-approved immutable operation`);
  }
  const paths = [".github/actions", "scripts/aws", "scripts/lib", "scripts/security", "scripts/rls/lib", "scripts/smoke-release.mjs", "backend/scripts/security", "infra/aws/terraform/lambda/production-rls-approval-broker", "package.json", "package-lock.json"];
  const sourceTree = execFileSync("git", ["ls-tree", "-r", "HEAD", "--", ...paths]);
  const sourceDigest = crypto.createHash("sha256").update(sourceTree).digest("hex");
  for (const name of ["production-normal-deployment-operation.yml", "production-green-backend-recovery-operation.yml", "production-historical-green-completion-operation.yml"]) {
    const workflow = yaml.load(fs.readFileSync(`.github/workflows/${name}`, "utf8"));
    const job = workflow.jobs.deploy || workflow.jobs["execute-green-backend-recovery"] || workflow.jobs.complete;
    const steps = job.steps;
    const gate = steps.findIndex((step) => step.name === "Authenticate caller and reviewed host tooling before credentials");
    const assume = steps.findIndex((step) => step.uses?.startsWith("aws-actions/configure-aws-credentials@"));
    assert.equal(gate, name === "production-normal-deployment-operation.yml" ? 1 : 2,
      `${name} must authenticate immediately after checkout and source readback`);
    assert.ok(assume > gate, `${name} must authenticate before requesting AWS credentials`);
    assert.equal(steps.filter((step) => step.name === "Authenticate caller and reviewed host tooling before credentials").length, 1);
    assert.match(steps[gate].run, /git ls-tree -r HEAD/);
    assert.match(steps[gate].run, new RegExp(sourceDigest));
    assert.equal(job.environment, "production-normal-deploy");
    const pinned = refs.find((ref) => ref.includes(`/${name}@`)).split("@")[1];
    assert.equal(execFileSync("git", ["show", `${pinned}:.github/workflows/${name}`], { encoding: "utf8" }), fs.readFileSync(`.github/workflows/${name}`, "utf8"));
  }
});

const adapter = ({ initial = predecessor, principal = "arn:aws:iam::368992683803:user/mscqr-ops-admin", lost = false } = {}) => {
  let live = structuredClone(initial), writes = 0;
  const run = (args) => {
    if (args[0] === "sts") return JSON.stringify({ Arn: principal, Account: "368992683803" });
    if (args[0] === "iam" && args[1] === "get-role") return JSON.stringify({ Role: { Arn: arn, RoleName: role, AssumeRolePolicyDocument: live } });
    if (args[0] === "iam" && args[1] === "update-assume-role-policy") {
      assert.equal(args[args.indexOf("--role-name") + 1], role);
      live = JSON.parse(args[args.indexOf("--policy-document") + 1]); writes++;
      if (lost) throw new Error("simulated lost AWS response");
      return "";
    }
    throw new Error(`Unexpected AWS operation: ${args.join(" ")}`);
  };
  return { run, get writes() { return writes; }, get live() { return live; } };
};

test("exact predecessor converges once, adopts a lost response, and rejects unrelated trust", () => {
  const sourceSha = "a".repeat(40);
  const normal = adapter();
  assert.equal(convergeNormalDeployerTrust({ run: normal.run, sourceSha }).iamWrites, 1);
  assert.deepEqual(normal.live, target);
  assert.equal(convergeNormalDeployerTrust({ run: normal.run, sourceSha }).iamWrites, 0);
  assert.equal(normal.writes, 1);
  const lost = adapter({ lost: true });
  assert.equal(convergeNormalDeployerTrust({ run: lost.run, sourceSha }).iamWrites, 1);
  assert.deepEqual(lost.live, target);
  const unrelated = adapter({ initial: { Version: "2012-10-17", Statement: [] } });
  assert.throws(() => convergeNormalDeployerTrust({ run: unrelated.run, sourceSha }), /neither the reviewed predecessor nor target/);
  assert.equal(unrelated.writes, 0);
  const root = adapter({ principal: "arn:aws:iam::368992683803:root" });
  assert.throws(() => convergeNormalDeployerTrust({ run: root.run, sourceSha }), /non-root infrastructure administrator/);
  assert.equal(root.writes, 0);
});
