import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";

const root = new URL("../../", import.meta.url);
const read = (path) => fs.readFileSync(new URL(path, root), "utf8");

test("support email mode starts only its outbox after database and Redis checks", () => {
  const source = read("backend/src/worker.ts");
  const mode = source.slice(source.indexOf('if (workerMode === "support-response-email")'), source.indexOf("startSecurityEventOutboxWorker();", source.indexOf('if (workerMode === "support-response-email")')));
  assert.match(mode, /await prisma\.\$queryRaw`SELECT 1`/);
  assert.match(mode, /await getRedisHealth\(\)/);
  assert.match(mode, /startSupportResponseEmailOutboxWorker\(\)/);
  assert.match(mode, /return;/);
  assert.match(source, /if \(workerMode !== "all"\) throw new Error/);
});

test("worker service prepares at zero tasks with only the existing SMTP secret grant", () => {
  const terraform = read("infra/aws/terraform/production-support-email-worker/main.tf");
  assert.match(terraform, /default = 0/);
  assert.match(terraform, /contains\(\[0, 1\], var\.desired_count\)/);
  assert.match(terraform, /MSCQR_WORKER_MODE", value = "support-response-email"/);
  assert.match(terraform, /production-green-stage-b\/task-definitions\/green-worker-candidate\.json/);
  assert.match(terraform, /Action\s*= \["secretsmanager:GetSecretValue"\]/);
  assert.match(terraform, /secret:mscqr\/prod\/smtp-pass-arDHq6/);
  assert.doesNotMatch(terraform, /Action\s*= \["\*"\]|Resource\s*= "\*"/);
  assert.match(terraform, /wait_for_steady_state\s*= true/);
});
