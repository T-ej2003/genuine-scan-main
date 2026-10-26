import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";
import yaml from "js-yaml";
import { PRODUCTION_ENVIRONMENT_APPROVAL } from "../aws/production-github-environment-approval.mjs";

const file = ".github/workflows/complete-historical-green-backend-recovery.yml";
const source = fs.readFileSync(file, "utf8");
const workflow = yaml.load(source);

test("historical completion uses an independently approved normal-deployer job on protected main", () => {
  assert.deepEqual(Object.keys(workflow.jobs), ["complete"]);
  assert.deepEqual(workflow.concurrency, { group: "production-deploy", "cancel-in-progress": false });
  const job = workflow.jobs.complete;
  assert.equal(job.environment, "production-normal-deploy");
  assert.equal(job.if, "${{ github.ref == 'refs/heads/main' }}");
  assert.equal(job.permissions["id-token"], "write");
  const steps = job.steps;
  const approval = steps.findIndex((step) => step.name === "Authenticate fresh independent environment approval");
  const assume = steps.findIndex((step) => step.name === "Assume exact normal-deployer role");
  const complete = steps.findIndex((step) => step.name === "Complete the original claim and component state");
  assert.ok(approval > 0 && assume > approval && complete > assume);
  assert.equal(steps[assume].with["role-to-assume"], "arn:aws:iam::368992683803:role/mscqr-production-normal-deployer");
  assert.match(steps[approval].run, /--require-actual-approval/);
  assert.match(steps[complete].run, /complete-production-historical-green-backend-recovery\.mjs/);
  assert.match(steps[complete].run, /export MSCQR_AWS_CREDENTIAL_SOURCE=github-oidc-normal-deployer/);
  assert.doesNotMatch(steps[complete].run, /\$\{\{\s*inputs\./);
  assert.equal(PRODUCTION_ENVIRONMENT_APPROVAL.historicalGreenCompletionWorkflowRef,
    `T-ej2003/genuine-scan-main/${file}@refs/heads/main`);
});

test("historical completion source contains no ECS mutation invocation or dispatch claim", () => {
  const cli = fs.readFileSync("scripts/aws/complete-production-historical-green-backend-recovery.mjs", "utf8");
  const core = fs.readFileSync("scripts/aws/production-green-backend-historical-completion.mjs", "utf8");
  assert.doesNotMatch(cli, /\["ecs",\s*"(?:update-service|register-task-definition|run-task)"/);
  assert.doesNotMatch(core, /\.claimOperation\(/);
  assert.doesNotMatch(source, /aws ecs (?:update-service|register-task-definition|run-task)/);
  assert.match(core, /update: \(\) => \{ throw new Error\("Historical completion cannot invoke ECS UpdateService"\)/);
});

test("normal-deployer has only regional CloudTrail read access for historical binding", () => {
  const policy = JSON.parse(fs.readFileSync("infra/aws/terraform/production-component-deployment-state/normal-deployer-policy.json", "utf8"));
  assert.deepEqual(policy.Statement.find(({ Sid }) => Sid === "ReadHistoricalGreenUpdateEvent"), {
    Sid: "ReadHistoricalGreenUpdateEvent", Effect: "Allow", Action: "cloudtrail:LookupEvents", Resource: "*",
    Condition: { StringEquals: { "aws:RequestedRegion": "eu-west-2" } },
  });
  assert.equal(policy.Statement.filter(({ Action }) => JSON.stringify(Action).includes("cloudtrail:")).length, 1);
});
