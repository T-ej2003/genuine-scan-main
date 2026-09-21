import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

const script = path.resolve("scripts/aws/rollback-ecs-service.sh");
const previous = "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-frontend:20";
const candidate = "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-frontend:21";

function run(current) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-normal-rollback-"));
  const log = path.join(directory, "aws.log");
  const aws = path.join(directory, "aws");
  fs.writeFileSync(aws, `#!/bin/sh\nprintf '%s\\n' "$*" >> "$AWS_LOG"\ncase "$1 $2" in
  'ecs describe-services') printf '%s\\n' "$CURRENT_TASK" ;;
  'ecs update-service'|'ecs wait') exit 0 ;;
  *) exit 1 ;;
esac\n`, { mode: 0o755 });
  const result = spawnSync(script, [], { encoding: "utf8", env: {
    ...process.env, PATH: `${directory}:${process.env.PATH}`, AWS_LOG: log, CURRENT_TASK: current,
    AWS_ACCESS_KEY_ID: "test", AWS_SECRET_ACCESS_KEY: "test", AWS_SESSION_TOKEN: "test",
    MSCQR_AWS_CREDENTIAL_SOURCE: "github-oidc-release-deployer", AWS_REGION: "eu-west-2",
    CLUSTER_NAME: "mscqr-prod-euw2-main", SERVICE_NAME: "mscqr-frontend-servi-euw2",
    PREVIOUS_TASK_DEFINITION_ARN: previous, EXPECTED_FAILED_TASK_DEFINITION_ARN: candidate,
  }});
  return { result, calls: fs.existsSync(log) ? fs.readFileSync(log, "utf8") : "" };
}

test("rollback restores only the exact failed candidate", () => {
  const { result, calls } = run(candidate);
  assert.equal(result.status, 0, result.stderr);
  assert.match(calls, /ecs update-service/);
  assert.match(calls, /ecs wait services-stable/);
});

test("rollback is a no-op when the predecessor is already active", () => {
  const { result, calls } = run(previous);
  assert.equal(result.status, 0, result.stderr);
  assert.doesNotMatch(calls, /ecs update-service/);
});

test("rollback refuses an unrelated concurrent task definition", () => {
  const { result, calls } = run(candidate.replace(":21", ":22"));
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /unexpected task definition/);
  assert.doesNotMatch(calls, /ecs update-service/);
});
