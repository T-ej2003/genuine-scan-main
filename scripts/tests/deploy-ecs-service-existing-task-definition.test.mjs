import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";

const script = path.resolve("scripts/aws/deploy-ecs-service.sh");
const region = "eu-west-2";
const account = "368992683803";
const service = "mscqr-backend-servi-euw2";
const cluster = "mscqr-prod-euw2-main";
const containerName = "backend";
const fromArn = `arn:aws:ecs:${region}:${account}:task-definition/mscqr-backend:47`;
const targetArn = `arn:aws:ecs:${region}:${account}:task-definition/mscqr-production-rls-green-backend-candidate:1`;
const targetFamily = "mscqr-production-rls-green-backend-candidate";
const sourceSha = "5e12983f1fe733473cacb6b213c0c02ef9f38098";
const digest = "sha256:0f8bf5cdbdfb5b67c00a1a6d5c27a7445b40fee7a1c15b525fab7f1846437e05";

const serviceResponse = (taskDefinition, deployments = [
  { status: "PRIMARY", taskDefinition, pendingCount: 0, runningCount: 2, rolloutState: "COMPLETED" },
]) => ({ failures: [], services: [{ status: "ACTIVE", taskDefinition, desiredCount: 2, deployments }] });

function writeFixture(data, options = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "ecs-existing-target-"));
  const fakeBin = path.join(dir, "bin");
  fs.mkdirSync(fakeBin);
  const tempDir = path.join(dir, "tmp");
  fs.mkdirSync(tempDir);
  const state = path.join(dir, "state");
  fs.writeFileSync(state, options.alreadyActive ? targetArn : fromArn);
  const includeSourceMetadata = options.includeSourceMetadata
    ?? Boolean(options.versionUrl || options.expectedGitSha || options.releaseGitSha);
  const target = {
    taskDefinition: {
      taskDefinitionArn: options.targetResponseArn || targetArn,
      status: options.status || "ACTIVE",
      family: options.family || targetFamily,
      containerDefinitions: [{
        name: containerName,
        image: `368992683803.dkr.ecr.eu-west-2.amazonaws.com/mscqr-backend@${options.targetDigest || digest}`,
        environment: !includeSourceMetadata
          ? []
          : [{ name: "RELEASE_GIT_SHA", value: options.releaseGitSha || sourceSha }],
      }],
      runtimePlatform: options.runtimePlatform === undefined ? { cpuArchitecture: "X86_64" } : options.runtimePlatform,
    },
  };
  const normal = {
    taskDefinition: {
      taskDefinitionArn: fromArn,
      family: "mscqr-backend",
      containerDefinitions: [{ name: containerName, image: "old-image" }],
      runtimePlatform: { cpuArchitecture: "X86_64" },
    },
  };
  const pre = serviceResponse(options.currentTaskDefinition || (options.alreadyActive ? targetArn : fromArn), options.concurrent
    ? [
      { status: "PRIMARY", taskDefinition: options.currentTaskDefinition || fromArn, pendingCount: 0, runningCount: 2, rolloutState: "COMPLETED" },
      { status: "ACTIVE", taskDefinition: fromArn, pendingCount: 1, runningCount: 1 },
    ]
    : undefined);
  const post = serviceResponse(targetArn);
  const tasks = {
    failures: [],
    tasks: [1, 2].map((n) => ({
      lastStatus: "RUNNING",
      taskDefinitionArn: options.runningTaskDefinitionArn || targetArn,
      containers: [{ name: containerName, imageDigest: options.runningDigest || digest }],
      taskArn: `arn:aws:ecs:${region}:${account}:task/${cluster}/${n}`,
    })),
  };
  const taskArns = options.taskArnsResponse || { taskArns: tasks.tasks.map((task) => task.taskArn) };
  for (const [name, value] of Object.entries({ target, normal, pre, post, tasks, taskArns })) {
    fs.writeFileSync(path.join(dir, `${name}.json`), JSON.stringify(value));
  }
  const aws = `#!/usr/bin/env bash
set -euo pipefail
echo "$*" >> "$FAKE_DATA/calls.log"
if [[ "$1 $2" == "sts get-caller-identity" ]]; then
  printf '%s\\n' "${options.callerArn || "arn:aws:sts::368992683803:assumed-role/mscqr-production-release-deployer/test"}"
elif [[ "$1 $2" == "ecs describe-task-definition" ]]; then
  task_definition=""
  for ((i=1; i<=$#; i++)); do
    if [[ "\${!i}" == "--task-definition" ]]; then j=$((i + 1)); task_definition="\${!j}"; fi
  done
  if [[ "$task_definition" == "${fromArn}" || "$task_definition" == "mscqr-backend" ]]; then cat "$FAKE_DATA/normal.json"; else cat "$FAKE_DATA/target.json"; fi
elif [[ "$1 $2" == "ecs describe-services" ]]; then
  current="$(cat "$FAKE_DATA/state")"
  if [[ "$current" == "${targetArn}" ]]; then cat "$FAKE_DATA/post.json"; else cat "$FAKE_DATA/pre.json"; fi
elif [[ "$1 $2" == "ecs update-service" ]]; then
  task_definition=""
  for ((i=1; i<=$#; i++)); do
    if [[ "\${!i}" == "--task-definition" ]]; then j=$((i + 1)); task_definition="\${!j}"; fi
  done
  if [[ ("$FAKE_SCENARIO" == "update-failure" && "$task_definition" == "${targetArn}") || ("$FAKE_SCENARIO" == "rollback-failure" && "$task_definition" == "${fromArn}") ]]; then exit 31; fi
  printf '%s' "$task_definition" > "$FAKE_DATA/state"
elif [[ "$1 $2" == "ecs wait" ]]; then
  if [[ ("$FAKE_SCENARIO" == "stable-failure" || "$FAKE_SCENARIO" == "rollback-failure") && ! -f "$FAKE_DATA/stable-failed" ]]; then touch "$FAKE_DATA/stable-failed"; exit 32; fi
elif [[ "$1 $2" == "ecs list-tasks" ]]; then cat "$FAKE_DATA/taskArns.json"
elif [[ "$1 $2" == "ecs describe-tasks" ]]; then cat "$FAKE_DATA/tasks.json"
elif [[ "$1 $2" == "ecs register-task-definition" ]]; then printf '%s\\n' "${targetArn}"
fi
`;
  const fakeAws = path.join(fakeBin, "aws");
  fs.writeFileSync(fakeAws, aws, { mode: 0o755 });
  const curl = `#!/usr/bin/env bash
set -euo pipefail
echo "curl $*" >> "$FAKE_DATA/calls.log"
if [[ "$FAKE_SCENARIO" == "version-endpoint-failure" ]]; then exit 41; fi
if [[ "$FAKE_SCENARIO" == "wrong-version" ]]; then printf '%s\\n' '{"gitSha":"${"a".repeat(40)}"}'; else printf '%s\\n' '{"gitSha":"${sourceSha}"}'; fi
`;
  const fakeCurl = path.join(fakeBin, "curl");
  fs.writeFileSync(fakeCurl, curl, { mode: 0o755 });
  return { dir, fakeBin, state, tempDir, calls: path.join(dir, "calls.log") };
}

function runExisting(options = {}, extraArgs = []) {
  const fixture = writeFixture({}, options);
  const expectedGitSha = options.includeExpectedGitSha === false
    ? undefined
    : options.includeExpectedGitSha === true || options.versionUrl || options.expectedGitSha || options.releaseGitSha
    ? options.expectedGitSha || sourceSha
    : undefined;
  const result = spawnSync("bash", [script, "--existing-task-definition", options.targetArgument || targetArn, "--expected-current-task-definition", options.expectedCurrent || fromArn, "--expected-family", options.expectedFamily || targetFamily, "--expected-image-digest", options.expectedDigestArgument || digest, ...extraArgs], {
    cwd: path.resolve("."),
    encoding: "utf8",
    env: {
      ...process.env,
      PATH: `${fixture.fakeBin}:${process.env.PATH}`,
      AWS_REGION: options.awsRegion || region,
      CLUSTER_NAME: cluster,
      SERVICE_NAME: service,
      CONTAINER_NAME: containerName,
      ...(expectedGitSha ? { EXPECTED_GIT_SHA: expectedGitSha } : {}),
      ...(options.versionUrl ? { VERSION_URL: options.versionUrl } : {}),
      FAKE_DATA: fixture.dir,
      FAKE_SCENARIO: options.scenario || "",
      TMPDIR: fixture.tempDir,
    },
  });
  const calls = fs.existsSync(fixture.calls) ? fs.readFileSync(fixture.calls, "utf8") : "";
  return { ...result, calls, fixture };
}

function assertFailure(result, pattern) {
  assert.notEqual(result.status, 0, result.stdout + result.stderr);
  if (pattern) assert.match(result.stderr, pattern);
  assertTempClean(result);
}

function assertTempClean(result) {
  assert.deepEqual(fs.readdirSync(result.fixture.tempDir), []);
}

test("existing production-shaped target switches once without registering", () => {
  const result = runExisting();
  assert.equal(result.status, 0, result.stderr);
  assert.equal((result.calls.match(/ecs update-service/g) || []).length, 1);
  assert.equal((result.calls.match(/ecs register-task-definition/g) || []).length, 0);
  assert.match(result.stdout, new RegExp(targetArn.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
  assertTempClean(result);
});

test("existing mode rejects an unrevisioned target", () => assertFailure(runExisting({ targetArgument: `arn:aws:ecs:${region}:${account}:task-definition/${targetFamily}` }), /full ARN.*revision/));
test("existing mode rejects wrong account and region", () => {
  assertFailure(runExisting({ targetArgument: `arn:aws:ecs:${region}:123456789012:task-definition/${targetFamily}:1` }), /account/);
  assertFailure(runExisting({ targetArgument: `arn:aws:ecs:us-east-1:${account}:task-definition/${targetFamily}:1` }), /region/);
});
test("existing mode rejects inactive, wrong-family, and wrong-digest targets", () => {
  assertFailure(runExisting({ status: "INACTIVE" }), /ACTIVE/);
  assertFailure(runExisting({ family: "other-family" }), /family/);
  assertFailure(runExisting({ targetDigest: "sha256:" + "1".repeat(64) }), /digest/);
});
test("existing mode enforces the normal X86_64 runtime guard", () => {
  const arm = runExisting({ runtimePlatform: { cpuArchitecture: "ARM64" } });
  assertFailure(arm, /cpuArchitecture/);
  assert.equal((arm.calls.match(/ecs update-service/g) || []).length, 0);
  assert.equal((arm.calls.match(/ecs register-task-definition/g) || []).length, 0);
  assertTempClean(arm);

  const missing = runExisting({ runtimePlatform: null });
  assert.equal(missing.status, 0, missing.stderr);
  assert.equal((missing.calls.match(/ecs update-service/g) || []).length, 1);
  assertTempClean(missing);
});
test("existing mode rejects a mismatched current service or concurrent deployment", () => {
  assertFailure(runExisting({ currentTaskDefinition: `arn:aws:ecs:${region}:${account}:task-definition/mscqr-backend:46` }), /expected current/);
  assertFailure(runExisting({ concurrent: true }), /concurrent/);
});
test("existing mode requires source metadata to match when present", () => {
  assertFailure(runExisting({ releaseGitSha: "a".repeat(40), versionUrl: "https://example.test/version" }), /RELEASE_GIT_SHA/);
});
test("existing mode verifies the deployed version before disarming rollback", () => {
  const success = runExisting({ versionUrl: "https://example.test/version" });
  assert.equal(success.status, 0, success.stderr);
  assert.equal((success.calls.match(/curl /g) || []).length, 1);
  assert.equal((success.calls.match(/ecs update-service/g) || []).length, 1);
  assertTempClean(success);

  for (const scenario of ["wrong-version", "version-endpoint-failure"]) {
    const result = runExisting({ versionUrl: "https://example.test/version", scenario });
    assertFailure(result);
    assert.equal((result.calls.match(/curl /g) || []).length, 1);
    assert.equal((result.calls.match(/ecs update-service/g) || []).length, 2);
    const events = result.calls.trim().split("\n");
    assert.ok(events.findIndex((event) => event.startsWith("curl ")) < events.findIndex((event) => event.includes(`--task-definition ${fromArn}`)));
    assertTempClean(result);
  }
});
test("existing mode rejects incomplete version verification inputs before update", () => {
  const urlOnly = runExisting({ versionUrl: "https://example.test/version", includeExpectedGitSha: false, includeSourceMetadata: false });
  assertFailure(urlOnly, /EXPECTED_GIT_SHA/);
  assert.equal((urlOnly.calls.match(/ecs update-service/g) || []).length, 0);

  const shaOnly = runExisting({ includeExpectedGitSha: true, includeSourceMetadata: false });
  assertFailure(shaOnly, /VERSION_URL/);
  assert.equal((shaOnly.calls.match(/ecs update-service/g) || []).length, 0);

  const neither = runExisting({ includeExpectedGitSha: false, includeSourceMetadata: false });
  assert.equal(neither.status, 0, neither.stderr);
  assert.equal((neither.calls.match(/curl /g) || []).length, 0);
  assert.equal((neither.calls.match(/ecs update-service/g) || []).length, 1);
});
test("existing mode requires the release-deployer and exact described target", () => {
  assertFailure(runExisting({ callerArn: "arn:aws:iam::368992683803:root" }), /release-deployer/);
  assertFailure(runExisting({ targetResponseArn: fromArn }), /exact requested ARN/);
});
test("already-active target is a verified no-op", () => {
  const result = runExisting({ alreadyActive: true, expectedCurrent: targetArn });
  assert.equal(result.status, 0, result.stderr);
  assert.equal((result.calls.match(/ecs update-service/g) || []).length, 0);
  assert.equal((result.calls.match(/ecs register-task-definition/g) || []).length, 0);
  assertTempClean(result);
});
test("update failure does not trigger an invented rollback", () => {
  const result = runExisting({ scenario: "update-failure" });
  assertFailure(result);
  assert.equal((result.calls.match(/ecs update-service/g) || []).length, 1);
  assertTempClean(result);
});
test("stabilization failure rolls back the exact previous ARN", () => {
  const result = runExisting({ scenario: "stable-failure" });
  assertFailure(result);
  assert.equal((result.calls.match(/ecs update-service/g) || []).length, 2);
  assert.match(result.calls, new RegExp(`--task-definition ${fromArn.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}`));
  assert.equal(fs.readFileSync(result.fixture.state, "utf8"), fromArn);
  assertTempClean(result);
});
test("list-tasks validates the real response schema and rejects pagination", () => {
  for (const [taskArnsResponse, pattern] of [
    [{}, /taskArns/],
    [{ taskArns: "not-an-array" }, /taskArns/],
    [{ taskArns: ["not-an-arn"] }, /running ECS tasks/],
    [{ taskArns: [`arn:aws:ecs:${region}:${account}:task/${cluster}/1`], nextToken: "next" }, /running ECS tasks/],
  ]) {
    const result = runExisting({ taskArnsResponse });
    assertFailure(result, pattern);
    assert.equal((result.calls.match(/ecs update-service/g) || []).length, 2);
    assertTempClean(result);
  }

  const empty = runExisting({ taskArnsResponse: { taskArns: [] } });
  assertFailure(empty, /No running ECS tasks/);
  assert.equal((empty.calls.match(/ecs update-service/g) || []).length, 2);
  assertTempClean(empty);
});
test("rollback failure still cleans every temporary file", () => {
  const result = runExisting({ scenario: "rollback-failure" });
  assertFailure(result);
  assert.match(result.stderr, /Canonical rollback failed/);
  assert.equal((result.calls.match(/ecs update-service/g) || []).length, 2);
  assertTempClean(result);
});
test("running task-definition and digest mismatches fail closed and roll back", () => {
  const taskMismatch = runExisting({ runningTaskDefinitionArn: fromArn });
  assertFailure(taskMismatch, /exact target/);
  assert.equal((taskMismatch.calls.match(/ecs update-service/g) || []).length, 2);
  const digestMismatch = runExisting({ runningDigest: "sha256:" + "2".repeat(64) });
  assertFailure(digestMismatch, /approved image digest/);
  assert.equal((digestMismatch.calls.match(/ecs update-service/g) || []).length, 2);
});

test("normal mode still registers a new revision before updating the service", () => {
  const fixture = writeFixture({});
  const result = spawnSync("bash", [script], {
    cwd: path.resolve("."),
    encoding: "utf8",
    env: {
      ...process.env,
      PATH: `${fixture.fakeBin}:${process.env.PATH}`,
      AWS_REGION: region,
      CLUSTER_NAME: cluster,
      SERVICE_NAME: service,
      TASK_DEFINITION: "mscqr-backend",
      CONTAINER_NAME: containerName,
      IMAGE_URI: `368992683803.dkr.ecr.eu-west-2.amazonaws.com/mscqr-backend@${digest}`,
      FAKE_DATA: fixture.dir,
      FAKE_SCENARIO: "",
      TMPDIR: fixture.tempDir,
    },
  });
  assert.equal(result.status, 0, result.stderr);
  assert.equal((fs.readFileSync(fixture.calls, "utf8").match(/ecs register-task-definition/g) || []).length, 1);
  assertTempClean({ fixture });
});

test("normal mode retains its existing version verification behavior", () => {
  const fixture = writeFixture({});
  const result = spawnSync("bash", [script], {
    cwd: path.resolve("."),
    encoding: "utf8",
    env: {
      ...process.env,
      PATH: `${fixture.fakeBin}:${process.env.PATH}`,
      AWS_REGION: region,
      CLUSTER_NAME: cluster,
      SERVICE_NAME: service,
      TASK_DEFINITION: "mscqr-backend",
      CONTAINER_NAME: containerName,
      IMAGE_URI: `368992683803.dkr.ecr.eu-west-2.amazonaws.com/mscqr-backend@${digest}`,
      VERSION_URL: "https://example.test/version",
      EXPECTED_GIT_SHA: sourceSha,
      FAKE_DATA: fixture.dir,
      FAKE_SCENARIO: "",
      TMPDIR: fixture.tempDir,
    },
  });
  assert.equal(result.status, 0, result.stderr);
  assert.equal((fs.readFileSync(fixture.calls, "utf8").match(/ecs register-task-definition/g) || []).length, 1);
  assert.equal((fs.readFileSync(fixture.calls, "utf8").match(/curl /g) || []).length, 1);
  assertTempClean({ fixture });
});

test("the operator runbook exposes both explicit modes and existing-mode bindings", () => {
  const runbook = fs.readFileSync("documents/aws/ECS_FARGATE_IMAGE_ARCHITECTURE.md", "utf8");
  assert.match(runbook, /NEW_REVISION_MODE/);
  assert.match(runbook, /EXISTING_TASK_DEFINITION_MODE/);
  for (const argument of ["--existing-task-definition", "--expected-current-task-definition", "--expected-family", "--expected-image-digest"]) {
    assert.match(runbook, new RegExp(argument.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
  }
  assert.match(runbook, /never registers a\s+task-definition revision/i);
});
