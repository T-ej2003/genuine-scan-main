import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const read = (path) => readFileSync(new URL(`../../${path}`, import.meta.url), "utf8");

test("printing mode starts only the existing reconciler after dependency checks", () => {
  const worker = read("backend/src/worker.ts");
  const printing = worker.slice(worker.indexOf('if (workerMode === "printing")'), worker.indexOf('if (workerMode !== "all")'));
  assert.match(printing, /await prisma\.\$queryRaw`SELECT 1`/);
  assert.match(printing, /getRedisHealth\(\)/);
  assert.match(printing, /startPrintConfirmationReconciler\(\)/);
  assert.match(printing, /startKeepAlive\(\)/);
  assert.match(printing, /return;/);
  assert.doesNotMatch(printing, /startSupportResponseEmailOutboxWorker|startAuditLogOutboxWorker|startSecurityEventOutboxWorker|startCompliancePackScheduler/);
});

test("printing task is isolated and bound to the reviewed worker image and credentials", () => {
  const terraform = read("infra/aws/terraform/production-printing-worker/main.tf");
  assert.match(terraform, /default = 0/);
  assert.match(terraform, /contains\(\[0, 1\], var\.desired_count\)/);
  assert.match(terraform, /MSCQR_WORKER_MODE", value = "printing"/);
  assert.match(terraform, /production-green-stage-b\/task-definitions\/green-worker-candidate\.json/);
  assert.match(terraform, /item\.name != "SMTP_PASS"/);
  assert.match(terraform, /!startswith\(item\.name, "SMTP_"\)/);
  assert.match(terraform, /data\.aws_ecr_image\.worker\.image_digest == split\("@", var\.worker_image\)\[1\]/);
  assert.match(terraform, /deployment_circuit_breaker[\s\S]*rollback = true/);
  assert.match(terraform, /deployment_maximum_percent\s*= 200/);
});
