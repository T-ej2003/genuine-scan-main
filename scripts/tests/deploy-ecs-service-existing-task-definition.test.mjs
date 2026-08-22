import assert from "node:assert/strict";
import { createHash } from "node:crypto";
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
const targetArn = `arn:aws:ecs:${region}:${account}:task-definition/mscqr-production-rls-green-backend-candidate:7`;
const targetFamily = "mscqr-production-rls-green-backend-candidate";
const sourceSha = "5e12983f1fe733473cacb6b213c0c02ef9f38098";
const digest = "sha256:32cf5587dff017354e637c147a3d985f286933129af83091d48edf35bee4e656";
const serviceLoadBalancers = [{ targetGroupArn: "arn:aws:elasticloadbalancing:eu-west-2:368992683803:targetgroup/mscqr-backend-tg-euw2-v2/example", containerName: "backend", containerPort: 4000 }];
const validBackendPortMappings = [{ containerPort: 4000, hostPort: 4000, protocol: "tcp", name: "backend-4000-tcp", appProtocol: "http" }];

const serviceResponse = (taskDefinition, deployments = [
  { status: "PRIMARY", taskDefinition, pendingCount: 0, runningCount: 2, rolloutState: "COMPLETED" },
], enableExecuteCommand = false, propagateTags) => ({ failures: [], services: [{ status: "ACTIVE", taskDefinition, desiredCount: 2, loadBalancers: serviceLoadBalancers, deployments, enableExecuteCommand, ...(propagateTags ? { propagateTags } : {}) }] });

function writeFixture(data, options = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "ecs-existing-target-"));
  const fakeBin = path.join(dir, "bin");
  fs.mkdirSync(fakeBin);
  const tempDir = path.join(dir, "tmp");
  fs.mkdirSync(tempDir);
  const state = path.join(dir, "state");
  fs.writeFileSync(state, options.alreadyActive ? targetArn : fromArn);
  const readiness = path.join(dir, "readiness.json");
  const readinessEvidence = Object.fromEntries([
    ["evidenceVersion", 1],
    ["sourceSha", sourceSha],
    ["rotationId", "rotation-test-1234"],
    ["rotationStateSha256", "b".repeat(64)],
    ["generatedAt", new Date().toISOString()],
    ...["imageAuthorization", "iamPreflight", "rootDrop", "releaseIdentity", "verifierIdentity", "stageA", "artifactSigning", "overlapTaskDefinition", "inventory", "rotationPrepare"].map((stage) => [stage, { valid: true, evidenceRef: `test://${stage}`, evidenceSha256: "c".repeat(64), identityBindings: { sourceSha } }]),
    ["rotationPrepared", true],
    ["ecsUpdateServiceCount", 0],
  ]);
  const readinessBytes = `${JSON.stringify(readinessEvidence)}\n`;
  fs.writeFileSync(readiness, readinessBytes, { mode: 0o600 });
  const readinessSha256 = createHash("sha256").update(readinessBytes).digest("hex");
  const includeSourceMetadata = options.includeSourceMetadata
    ?? Boolean(options.versionUrl || options.expectedGitSha || options.releaseGitSha);
  const target = {
    tags: options.targetTags === undefined ? [{ key: "MSCQRExecTarget", value: "production-backend" }] : options.targetTags,
    taskDefinition: {
      taskDefinitionArn: options.targetResponseArn || targetArn,
      status: options.status || "ACTIVE",
      family: options.family || targetFamily,
      containerDefinitions: [{
        name: options.targetContainerName || containerName,
        image: `368992683803.dkr.ecr.eu-west-2.amazonaws.com/mscqr-backend@${options.targetDigest || digest}`,
        portMappings: options.targetPortMappings === undefined ? validBackendPortMappings : options.targetPortMappings,
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
      containerDefinitions: [{ name: containerName, image: "old-image", portMappings: options.normalPortMappings === undefined ? validBackendPortMappings : options.normalPortMappings }],
      runtimePlatform: { cpuArchitecture: "X86_64" },
    },
  };
  const pre = serviceResponse(options.currentTaskDefinition || (options.alreadyActive ? targetArn : fromArn), options.concurrent
    ? [
      { status: "PRIMARY", taskDefinition: options.currentTaskDefinition || fromArn, pendingCount: 0, runningCount: 2, rolloutState: "COMPLETED" },
      { status: "ACTIVE", taskDefinition: fromArn, pendingCount: 1, runningCount: 1 },
    ]
    : undefined, options.initialExecEnabled === true, options.currentPropagateTags);
  const post = serviceResponse(targetArn, undefined, options.postExecEnabled ?? options.enableExecuteCommand === true, options.postPropagateTags ?? options.currentPropagateTags ?? (options.propagateTags ? "TASK_DEFINITION" : undefined));
  const targetDeployment = serviceResponse(fromArn, [
    { status: "PRIMARY", taskDefinition: fromArn, pendingCount: 1, runningCount: 2, rolloutState: "IN_PROGRESS" },
    { status: "ACTIVE", taskDefinition: targetArn, pendingCount: 0, runningCount: 0 },
  ]);
  const unrelatedTaskDefinition = `arn:aws:ecs:${region}:${account}:task-definition/unreviewed:9`;
  const unrelated = serviceResponse(unrelatedTaskDefinition);
  const foreignDeployment = serviceResponse(targetArn, [
    { status: "PRIMARY", taskDefinition: targetArn, pendingCount: 0, runningCount: 2, rolloutState: "COMPLETED" },
    { status: "ACTIVE", taskDefinition: unrelatedTaskDefinition, pendingCount: 0, runningCount: 0 },
  ]);
  const tasks = {
    failures: [],
    tasks: [1, 2].map((n) => ({
      lastStatus: "RUNNING",
      taskDefinitionArn: options.runningTaskDefinitionArn || targetArn,
      containers: [{ name: containerName, imageDigest: options.runningDigest || digest }],
      taskArn: `arn:aws:ecs:${region}:${account}:task/${cluster}/${n}`,
      tags: options.taskTags === undefined ? [{ key: "MSCQRExecTarget", value: "production-backend" }] : options.taskTags,
    })),
  };
  const taskArns = options.taskArnsResponse || { taskArns: tasks.tasks.map((task) => task.taskArn) };
  for (const [name, value] of Object.entries({ target, normal, pre, post, targetDeployment, unrelated, foreignDeployment, tasks, taskArns })) {
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
  if [[ "$FAKE_SCENARIO" == "reconcile-failure" && -f "$FAKE_DATA/update-attempted" ]]; then exit 51; fi
  if [[ "$FAKE_SCENARIO" == "ownership-read-failure" && -f "$FAKE_DATA/stable-failed" ]]; then exit 51; fi
  if [[ "$FAKE_SCENARIO" == "malformed-then-target" && -f "$FAKE_DATA/update-attempted" && ! -f "$FAKE_DATA/rollback-attempted" ]]; then
    count=0
    [[ -f "$FAKE_DATA/settlement-count" ]] && count="$(cat "$FAKE_DATA/settlement-count")"
    count=$((count + 1))
    printf '%s' "$count" > "$FAKE_DATA/settlement-count"
    if ((count == 1)); then printf '%s' '{}' ; exit 0; fi
    if ((count >= 2)); then printf '%s' "${targetArn}" > "$FAKE_DATA/state"; fi
  fi
  if [[ "$FAKE_SCENARIO" == "transient-then-target" && -f "$FAKE_DATA/update-attempted" && ! -f "$FAKE_DATA/rollback-attempted" ]]; then
    count=0
    [[ -f "$FAKE_DATA/settlement-count" ]] && count="$(cat "$FAKE_DATA/settlement-count")"
    count=$((count + 1))
    printf '%s' "$count" > "$FAKE_DATA/settlement-count"
    if ((count == 1)); then exit 51; fi
    if ((count >= 3)); then printf '%s' "${targetArn}" > "$FAKE_DATA/state"; fi
  fi
  if [[ "$FAKE_SCENARIO" == "late-target-after-window" && -f "$FAKE_DATA/update-attempted" && ! -f "$FAKE_DATA/rollback-attempted" ]]; then
    count=0
    [[ -f "$FAKE_DATA/settlement-count" ]] && count="$(cat "$FAKE_DATA/settlement-count")"
    count=$((count + 1))
    printf '%s' "$count" > "$FAKE_DATA/settlement-count"
    if ((count == 6)); then touch "$FAKE_DATA/late-target-ready"; fi
    if ((count >= 7)); then printf '%s' "${targetArn}" > "$FAKE_DATA/state"; fi
  fi
  if [[ "$FAKE_SCENARIO" == "delayed-accepted" && -f "$FAKE_DATA/update-attempted" && ! -f "$FAKE_DATA/rollback-attempted" ]]; then
    count=0
    [[ -f "$FAKE_DATA/settlement-count" ]] && count="$(cat "$FAKE_DATA/settlement-count")"
    count=$((count + 1))
    printf '%s' "$count" > "$FAKE_DATA/settlement-count"
    if ((count >= 2)); then printf '%s' "${targetArn}" > "$FAKE_DATA/state"; fi
  fi
  current="$(cat "$FAKE_DATA/state")"
  if [[ "$FAKE_SCENARIO" == "target-deployment" && -f "$FAKE_DATA/update-attempted" && ! -f "$FAKE_DATA/rollback-attempted" ]]; then cat "$FAKE_DATA/targetDeployment.json"; elif [[ "$FAKE_SCENARIO" == "foreign-deployment-after-update" && -f "$FAKE_DATA/update-attempted" && ! -f "$FAKE_DATA/rollback-attempted" ]]; then cat "$FAKE_DATA/foreignDeployment.json"; elif [[ "$current" == "${targetArn}" ]]; then cat "$FAKE_DATA/post.json"; elif [[ "$current" == "${fromArn}" ]]; then cat "$FAKE_DATA/pre.json"; else cat "$FAKE_DATA/unrelated.json"; fi
elif [[ "$1 $2" == "ecs update-service" ]]; then
  task_definition=""
  for ((i=1; i<=$#; i++)); do
    if [[ "\${!i}" == "--task-definition" ]]; then j=$((i + 1)); task_definition="\${!j}"; fi
  done
  if [[ "$task_definition" == "${targetArn}" ]]; then touch "$FAKE_DATA/update-attempted"; fi
  if [[ "$FAKE_SCENARIO" == "update-failure" && "$task_definition" == "${targetArn}" ]]; then exit 31; fi
  if [[ "$FAKE_SCENARIO" == "ambiguous-target" && "$task_definition" == "${targetArn}" ]]; then printf '%s' "$task_definition" > "$FAKE_DATA/state"; exit 31; fi
  if [[ "$FAKE_SCENARIO" == "ambiguous-unrelated" && "$task_definition" == "${targetArn}" ]]; then printf '%s' "${unrelatedTaskDefinition}" > "$FAKE_DATA/state"; exit 31; fi
  if [[ "$FAKE_SCENARIO" == "reconcile-failure" && "$task_definition" == "${targetArn}" ]]; then printf '%s' "$task_definition" > "$FAKE_DATA/state"; exit 31; fi
  if [[ "$FAKE_SCENARIO" == "delayed-accepted" && "$task_definition" == "${targetArn}" ]]; then exit 31; fi
  if [[ "$FAKE_SCENARIO" == "transient-then-target" && "$task_definition" == "${targetArn}" ]]; then exit 31; fi
  if [[ "$FAKE_SCENARIO" == "late-target-after-window" && "$task_definition" == "${targetArn}" ]]; then exit 31; fi
  if [[ "$FAKE_SCENARIO" == "malformed-then-target" && "$task_definition" == "${targetArn}" ]]; then exit 31; fi
  if [[ "$FAKE_SCENARIO" == "target-deployment" && "$task_definition" == "${targetArn}" ]]; then touch "$FAKE_DATA/update-attempted"; exit 31; fi
  if [[ "$task_definition" == "${fromArn}" ]]; then touch "$FAKE_DATA/rollback-attempted"; fi
  if [[ "$FAKE_SCENARIO" == "rollback-failure" && "$task_definition" == "${fromArn}" ]]; then exit 31; fi
  printf '%s' "$task_definition" > "$FAKE_DATA/state"
elif [[ "$1 $2" == "ecs wait" ]]; then
  if [[ ("$FAKE_SCENARIO" == "stable-failure" || "$FAKE_SCENARIO" == "rollback-failure") && ! -f "$FAKE_DATA/stable-failed" ]]; then touch "$FAKE_DATA/stable-failed"; exit 32; fi
  if [[ "$FAKE_SCENARIO" == "foreign-after-update" && ! -f "$FAKE_DATA/stable-failed" ]]; then touch "$FAKE_DATA/stable-failed"; printf '%s' "${unrelatedTaskDefinition}" > "$FAKE_DATA/state"; exit 32; fi
  if [[ "$FAKE_SCENARIO" == "previous-before-exit" && ! -f "$FAKE_DATA/stable-failed" ]]; then touch "$FAKE_DATA/stable-failed"; printf '%s' "${fromArn}" > "$FAKE_DATA/state"; exit 32; fi
  if [[ "$FAKE_SCENARIO" == "ownership-read-failure" && ! -f "$FAKE_DATA/stable-failed" ]]; then touch "$FAKE_DATA/stable-failed"; exit 32; fi
elif [[ "$1 $2" == "ecs list-tasks" ]]; then cat "$FAKE_DATA/taskArns.json"
elif [[ "$1 $2" == "ecs describe-tasks" ]]; then cat "$FAKE_DATA/tasks.json"
elif [[ "$1 $2" == "ecs register-task-definition" ]]; then printf '%s\\n' "${targetArn}"
fi
`;
  const fakeAws = path.join(fakeBin, "aws");
  fs.writeFileSync(fakeAws, aws, { mode: 0o755 });
  const sleep = path.join(fakeBin, "sleep");
  fs.writeFileSync(sleep, "#!/usr/bin/env bash\nexit 0\n", { mode: 0o755 });
  const curl = `#!/usr/bin/env bash
set -euo pipefail
echo "curl $*" >> "$FAKE_DATA/calls.log"
if [[ "$FAKE_SCENARIO" == "version-endpoint-failure" || "$FAKE_SCENARIO" == "version-timeout" ]]; then exit $([[ "$FAKE_SCENARIO" == "version-timeout" ]] && echo 28 || echo 41); fi
if [[ "$FAKE_SCENARIO" == "malformed-health" ]]; then printf '%s\\n' '{"status":"ok","release":{"gitSha":"not-a-sha"}}'; elif [[ "$FAKE_SCENARIO" == "wrong-version" ]]; then printf '%s\\n' '{"status":"ok","release":{"gitSha":"${"a".repeat(40)}"}}'; else printf '%s\\n' '{"status":"ok","release":{"gitSha":"${sourceSha}"}}'; fi
`;
  const fakeCurl = path.join(fakeBin, "curl");
  fs.writeFileSync(fakeCurl, curl, { mode: 0o755 });
  return { dir, fakeBin, state, tempDir, calls: path.join(dir, "calls.log"), readiness, readinessSha256 };
}

function runExisting(options = {}, extraArgs = []) {
  const fixture = writeFixture({}, options);
  const expectedGitSha = options.includeExpectedGitSha === false
    ? undefined
    : options.includeExpectedGitSha === true || options.versionUrl || options.expectedGitSha || options.releaseGitSha
    ? options.expectedGitSha || sourceSha
    : undefined;
  const normalBinding = path.join(fixture.dir, "normal-activation-binding.json");
  const normalBindingBytes = `${JSON.stringify({
    releaseMode: "normal",
    sourceSha,
    targetArn,
    expectedCurrentTaskDefinitionArn: options.expectedCurrent || fromArn,
    digest,
    clusterArn: `arn:aws:ecs:${region}:${account}:cluster/${cluster}`,
    serviceArn: `arn:aws:ecs:${region}:${account}:service/${cluster}/${service}`,
  })}\n`;
  fs.writeFileSync(normalBinding, normalBindingBytes, { mode: 0o600 });
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
      DEPLOYMENT_SOURCE_SHA: sourceSha,
      MSCQR_GOVERNED_ORCHESTRATOR: "1",
      ...(options.normalStageB ? {
        MSCQR_EXISTING_TASK_DEPLOYMENT_MODE: "normal-stage-b",
        NORMAL_ACTIVATION_BINDING_FILE: normalBinding,
        NORMAL_ACTIVATION_BINDING_SHA256: options.normalBindingSha256 || createHash("sha256").update(normalBindingBytes).digest("hex"),
      } : {}),
      ...(options.versionUrl ? { VERSION_URL: options.versionUrl } : {}),
      ...(options.enableExecuteCommand ? { ENABLE_EXECUTE_COMMAND: "true" } : {}),
      ...(options.propagateTags ? { PROPAGATE_TAGS: options.propagateTags } : {}),
      ...(options.omitReadiness ? {} : {
        OVERLAP_READINESS_EVIDENCE_FILE: fixture.readiness,
        OVERLAP_READINESS_EVIDENCE_SHA256: fixture.readinessSha256,
        ROTATION_ID: "rotation-test-1234",
        ROTATION_STATE_SHA256: "b".repeat(64),
      }),
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

test("normal Stage-B mode consumes its exact authenticated binding without registration", () => {
  const result = runExisting({ normalStageB: true, versionUrl: "https://www.mscqr.com/api/health" });
  assert.equal(result.status, 0, result.stderr);
  assert.equal((result.calls.match(/ecs update-service/g) || []).length, 1);
  assert.equal((result.calls.match(/ecs register-task-definition/g) || []).length, 0);

  const forged = runExisting({ normalStageB: true, versionUrl: "https://www.mscqr.com/api/health", normalBindingSha256: "0".repeat(64) });
  assertFailure(forged, /binding changed/);
  assert.equal((forged.calls.match(/ecs update-service/g) || []).length, 0);
});

test("existing mode rejects an unmarked definition before UpdateService and a replacement task without the marker", () => {
  const unmarkedDefinition = runExisting({ targetTags: [] });
  assertFailure(unmarkedDefinition, /MSCQRExecTarget/);
  assert.equal((unmarkedDefinition.calls.match(/ecs update-service/g) || []).length, 0);
  const unmarkedTask = runExisting({ taskTags: [] });
  assertFailure(unmarkedTask, /propagated MSCQRExecTarget/);
  assert.equal((unmarkedTask.calls.match(/ecs update-service/g) || []).length, 2);
});
test("existing mode enforces the independent service load-balancer port contract", () => {
  const missing = runExisting({ targetPortMappings: [] });
  assertFailure(missing, /backend:4000/);
  assert.equal((missing.calls.match(/ecs update-service/g) || []).length, 0);

  const wrongPort = runExisting({ targetPortMappings: [{ containerPort: 4001, hostPort: 4001, protocol: "tcp" }] });
  assertFailure(wrongPort, /backend:4000/);
  assert.equal((wrongPort.calls.match(/ecs update-service/g) || []).length, 0);

  const wrongName = runExisting({ targetContainerName: "not-backend" });
  assertFailure(wrongName, /exactly one backend container/);
  assert.equal((wrongName.calls.match(/ecs update-service/g) || []).length, 0);

  const candidate6Shape = runExisting({ targetPortMappings: [] });
  assertFailure(candidate6Shape, /backend:4000/);
  assert.equal((candidate6Shape.calls.match(/ecs update-service/g) || []).length, 0);

  const corrected = runExisting({ targetPortMappings: validBackendPortMappings });
  assert.equal(corrected.status, 0, corrected.stderr);
  assert.equal((corrected.calls.match(/ecs update-service/g) || []).length, 1);
  assert.equal((corrected.calls.match(/ecs register-task-definition/g) || []).length, 0);
  assertTempClean(corrected);
});
test("existing mode enables ECS Exec in the same canonical service update", () => {
  const result = runExisting({ enableExecuteCommand: true });
  assert.equal(result.status, 0, result.stderr);
  assert.equal((result.calls.match(/ecs update-service/g) || []).length, 1);
  assert.match(result.calls, /--enable-execute-command/);
  assertTempClean(result);
});
test("existing mode passes propagate-tags when the service does not already propagate task-definition tags", () => {
  const result = runExisting({ propagateTags: "TASK_DEFINITION", currentPropagateTags: "" });
  assert.equal(result.status, 0, result.stderr);
  const update = result.calls.split("\n").find((line) => line.startsWith("ecs update-service"));
  assert.match(update, /--propagate-tags TASK_DEFINITION/);
  assert.equal((result.calls.match(/ecs update-service/g) || []).length, 1);
  assertTempClean(result);
});
test("existing mode does not update solely for propagation when TASK_DEFINITION is already active", () => {
  const result = runExisting({ alreadyActive: true, expectedCurrent: targetArn, propagateTags: "TASK_DEFINITION", currentPropagateTags: "TASK_DEFINITION" });
  assert.equal(result.status, 0, result.stderr);
  assert.equal((result.calls.match(/ecs update-service/g) || []).length, 0);
  assertTempClean(result);
});
test("existing mode combines execute-command enablement and propagation in one UpdateService call", () => {
  const result = runExisting({ enableExecuteCommand: true, propagateTags: "TASK_DEFINITION", currentPropagateTags: "" });
  assert.equal(result.status, 0, result.stderr);
  const updates = result.calls.split("\n").filter((line) => line.startsWith("ecs update-service"));
  assert.equal(updates.length, 1);
  assert.match(updates[0], /--enable-execute-command/);
  assert.match(updates[0], /--propagate-tags TASK_DEFINITION/);
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
  assertFailure(runExisting({ expectedFamily: "mscqr-backend" }), /family/);
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
  const success = runExisting({ versionUrl: "https://www.mscqr.com/api/health" });
  assert.equal(success.status, 0, success.stderr);
  assert.equal((success.calls.match(/curl /g) || []).length, 1);
  assert.equal((success.calls.match(/ecs update-service/g) || []).length, 1);
  assertTempClean(success);

  for (const scenario of ["wrong-version", "malformed-health", "version-endpoint-failure", "version-timeout"]) {
    const result = runExisting({ versionUrl: "https://www.mscqr.com/api/health", scenario });
    assertFailure(result);
    assert.equal((result.calls.match(/curl /g) || []).length, 1);
    assert.equal((result.calls.match(/ecs update-service/g) || []).length, 2);
    if (scenario === "version-timeout") {
      assert.match(result.calls, /curl .*--connect-timeout 5 .*--max-time 15/);
    }
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
test("existing mode rejects missing readiness evidence before any UpdateService call", () => {
  const result = runExisting({ omitReadiness: true });
  assertFailure(result, /OVERLAP_READINESS_EVIDENCE_FILE/);
  assert.equal((result.calls.match(/ecs update-service/g) || []).length, 0);
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
test("all previous settlement remains ambiguous without rollback", () => {
  const result = runExisting({ scenario: "update-failure" });
  assertFailure(result, /AMBIGUOUS_UPDATE_OUTCOME/);
  assert.equal((result.calls.match(/ecs update-service/g) || []).length, 1);
  assertTempClean(result);
});
test("previous reads through the old window do not prove a later target was rejected", () => {
  const result = runExisting({ scenario: "late-target-after-window" });
  assertFailure(result, /AMBIGUOUS_UPDATE_OUTCOME/);
  assert.equal((result.calls.match(/ecs update-service/g) || []).length, 1);
  assert.equal(fs.existsSync(path.join(result.fixture.dir, "late-target-ready")), true);
  assert.equal(fs.readFileSync(result.fixture.state, "utf8"), fromArn);
  assert.doesNotMatch(result.stderr, /NO_TARGET_OBSERVED|UPDATE_FAILED_NO_TARGET_OBSERVED/);
  assertTempClean(result);
});
test("transient reconciliation failure is retried before delayed target detection and rollback", () => {
  const result = runExisting({ scenario: "transient-then-target" });
  assertFailure(result, /AMBIGUOUS_UPDATE_OUTCOME/);
  assert.equal((result.calls.match(/ecs update-service/g) || []).length, 2);
  assert.equal((result.calls.match(/ecs describe-services/g) || []).length >= 5, true);
  assert.equal(fs.readFileSync(result.fixture.state, "utf8"), fromArn);
  assert.match(result.calls, new RegExp(`--task-definition ${fromArn.replace(/[.*+?^${}()|[\\]\\]/g, "\\\\$&")}`));
  assertTempClean(result);
});
test("delayed accepted UpdateService is detected after an initial previous read and rolled back", () => {
  const result = runExisting({ scenario: "delayed-accepted" });
  assertFailure(result, /AMBIGUOUS_UPDATE_OUTCOME/);
  assert.equal((result.calls.match(/ecs update-service/g) || []).length, 2);
  assert.equal(fs.readFileSync(result.fixture.state, "utf8"), fromArn);
  const events = result.calls.trim().split("\n");
  const descriptions = events.reduce((indexes, event, index) => event.startsWith("ecs describe-services") ? [...indexes, index] : indexes, []);
  const updates = events.reduce((indexes, event, index) => event.startsWith("ecs update-service") ? [...indexes, index] : indexes, []);
  assert.ok(descriptions.length >= 4);
  assert.ok(descriptions[1] < descriptions[2]);
  assert.ok(descriptions[2] < updates[1]);
  assert.match(events[updates[1]], new RegExp(`--task-definition ${fromArn.replace(/[.*+?^${}()|[\\]\\]/g, "\\\\$&")}`));
  assertTempClean(result);
});
test("target deployment metadata is treated as accepted before the service primary flips", () => {
  const result = runExisting({ scenario: "target-deployment" });
  assertFailure(result, /AMBIGUOUS_UPDATE_OUTCOME/);
  assert.equal((result.calls.match(/ecs update-service/g) || []).length, 2);
  assert.equal(fs.readFileSync(result.fixture.state, "utf8"), fromArn);
  assertTempClean(result);
});
test("ambiguous accepted UpdateService response reconciles and rolls back the exact previous ARN", () => {
  const result = runExisting({ scenario: "ambiguous-target" });
  assertFailure(result, /AMBIGUOUS_UPDATE_OUTCOME/);
  assert.equal((result.calls.match(/ecs update-service/g) || []).length, 2);
  assert.equal(fs.readFileSync(result.fixture.state, "utf8"), fromArn);
  const events = result.calls.trim().split("\n");
  const updates = events.reduce((indexes, event, index) => event.startsWith("ecs update-service") ? [...indexes, index] : indexes, []);
  const descriptions = events.reduce((indexes, event, index) => event.startsWith("ecs describe-services") ? [...indexes, index] : indexes, []);
  assert.equal(updates.length, 2);
  assert.ok(updates[0] < descriptions[1] && descriptions[1] < descriptions[2] && descriptions[2] < updates[1] && updates[1] < descriptions[3]);
  assert.match(events[updates[1]], new RegExp(`--task-definition ${fromArn.replace(/[.*+?^${}()|[\\]\\]/g, "\\\\$&")}`));
  assertTempClean(result);
});
test("ambiguous UpdateService response with unrelated state fails closed without overwrite", () => {
  const result = runExisting({ scenario: "ambiguous-unrelated" });
  assertFailure(result, /AMBIGUOUS_UPDATE_OUTCOME/);
  assert.equal((result.calls.match(/ecs update-service/g) || []).length, 1);
  assert.notEqual(fs.readFileSync(result.fixture.state, "utf8"), fromArn);
  assertTempClean(result);
});
test("ambiguous UpdateService response with unreadable state fails closed", () => {
  const result = runExisting({ scenario: "reconcile-failure" });
  assertFailure(result, /UNKNOWN_SERVICE_STATE/);
  assert.equal((result.calls.match(/ecs update-service/g) || []).length, 1);
  assert.equal((result.calls.match(/ecs describe-services/g) || []).length, 7);
  assertTempClean(result);
});
test("malformed reconciliation response is retried before target detection", () => {
  const result = runExisting({ scenario: "malformed-then-target" });
  assertFailure(result, /AMBIGUOUS_UPDATE_OUTCOME/);
  assert.equal((result.calls.match(/ecs update-service/g) || []).length, 2);
  assert.equal(fs.readFileSync(result.fixture.state, "utf8"), fromArn);
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
test("foreign state appearing before rollback is preserved", () => {
  const result = runExisting({ scenario: "foreign-after-update" });
  assertFailure(result, /CONCURRENT_SERVICE_STATE/);
  assert.equal((result.calls.match(/ecs update-service/g) || []).length, 1);
  assert.equal(fs.readFileSync(result.fixture.state, "utf8"), `arn:aws:ecs:${region}:${account}:task-definition/unreviewed:9`);
  assertTempClean(result);
});
test("foreign deployment alongside the target prevents rollback", () => {
  const result = runExisting({ scenario: "foreign-deployment-after-update" });
  assertFailure(result, /CONCURRENT_SERVICE_STATE/);
  assert.equal((result.calls.match(/ecs update-service/g) || []).length, 1);
  assertTempClean(result);
});
test("previous task definition already restored before rollback needs no mutation", () => {
  const result = runExisting({ scenario: "previous-before-exit" });
  assertFailure(result, /already restored/);
  assert.equal((result.calls.match(/ecs update-service/g) || []).length, 1);
  assert.equal(fs.readFileSync(result.fixture.state, "utf8"), fromArn);
  assertTempClean(result);
});
test("rollback ownership read failure fails closed without rollback", () => {
  const result = runExisting({ scenario: "ownership-read-failure" });
  assertFailure(result, /UNKNOWN_ROLLBACK_OWNERSHIP/);
  assert.equal((result.calls.match(/ecs update-service/g) || []).length, 1);
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

test("explicit new-revision mode still registers before updating the service", () => {
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

test("explicit new-revision mode rejects an incompatible payload before registration", () => {
  const fixture = writeFixture({}, { normalPortMappings: [] });
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
  assert.notEqual(result.status, 0, result.stdout + result.stderr);
  assert.match(result.stderr, /backend:4000/);
  assert.equal((fs.readFileSync(fixture.calls, "utf8").match(/ecs register-task-definition/g) || []).length, 0);
  assertTempClean({ fixture });
});

test("explicit new-revision mode retains its existing version verification behavior", () => {
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
  const nginx = fs.readFileSync("nginx.https.conf", "utf8");
  const existingMode = runbook.split("### Switching to an already-registered task definition", 2)[1].split("The wrapper verifies", 1)[0];
  assert.match(runbook, /NEW_REVISION_MODE/);
  assert.match(runbook, /EXISTING_TASK_DEFINITION_MODE/);
  for (const argument of ["--existing-task-definition", "--expected-current-task-definition", "--expected-family", "--expected-image-digest"]) {
    assert.match(existingMode, new RegExp(argument.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
  }
  for (const variable of ["AWS_PROFILE", "AWS_REGION", "CLUSTER_NAME", "SERVICE_NAME", "CONTAINER_NAME", "VERSION_URL", "EXPECTED_GIT_SHA"]) {
    assert.match(existingMode, new RegExp(`export ${variable}=`));
  }
  assert.match(existingMode, /export VERSION_URL=https:\/\/www\.mscqr\.com\/api\/health/);
  assert.doesNotMatch(existingMode, /export VERSION_URL=https:\/\/www\.mscqr\.com\/(?:version|health)(?:\s|$)/);
  const documentedTarget = existingMode.match(/--existing-task-definition\s+([^\s\\]+)/)?.[1];
  const documentedDigest = existingMode.match(/--expected-image-digest\s+([^\s\\]+)/)?.[1];
  const documentedGitSha = existingMode.match(/export EXPECTED_GIT_SHA=([a-f0-9]{40})/)?.[1];
  assert.equal(documentedTarget, "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-production-rls-green-backend-candidate:7");
  assert.equal(documentedTarget.endsWith(":7"), true);
  assert.doesNotMatch(existingMode, /mscqr-production-rls-green-backend-candidate:6/);
  assert.doesNotMatch(existingMode, /mscqr-production-rls-green-backend-candidate:\*/);
  assert.equal(documentedDigest, "sha256:32cf5587dff017354e637c147a3d985f286933129af83091d48edf35bee4e656");
  assert.equal(digest, "sha256:32cf5587dff017354e637c147a3d985f286933129af83091d48edf35bee4e656");
  assert.equal(documentedDigest, digest);
  assert.equal(documentedGitSha, "5e12983f1fe733473cacb6b213c0c02ef9f38098");
  assert.equal(documentedGitSha, sourceSha);
  assert.equal(documentedTarget.endsWith(":7") && documentedDigest === digest && documentedGitSha === sourceSha, true);
  assert.match(nginx, /location\s+~\s+\^\/api\/health\/\?\(\.\*\)\$\s*\{[\s\S]*rewrite\s+\^\/api\/health\/\?\(\.\*\)\$\s+\/health\/\$1\s+break;[\s\S]*proxy_pass\s+\$backend_upstream;/);
  assert.doesNotMatch(existingMode, /example\.com/);
  assert.match(existingMode, /never registers a\s+task-definition revision/i);
});
