#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";

const root = process.cwd();
const read = (repoPath) => fs.readFileSync(path.join(root, repoPath), "utf8");
const exists = (repoPath) => fs.existsSync(path.join(root, repoPath));

const failures = [];
const warnings = [];

const requireFile = (repoPath) => {
  if (!exists(repoPath)) {
    failures.push(`Missing required file: ${repoPath}`);
    return "";
  }
  return read(repoPath);
};

const requireMatch = (label, source, pattern, message) => {
  if (!pattern.test(source)) failures.push(`${label}: ${message}`);
};

const doc = requireFile("documents/ops/aws-asg-multi-instance-readiness.md");
const checklistRaw = requireFile("documents/ops/aws-asg-multi-instance-readiness.checklist.json");
const packageJsonRaw = requireFile("package.json");
const compose = requireFile("docker-compose.yml");
const backendDockerfile = requireFile("backend/Dockerfile");
const backendStartup = requireFile("backend/docker/start-runtime.sh");
const backendIndex = requireFile("backend/src/index.ts");
const backendWorker = requireFile("backend/src/worker.ts");
const healthController = requireFile("backend/src/controllers/healthController.ts");
const routes = requireFile("backend/src/routes/index.ts");
const redisService = requireFile("backend/src/services/redisService.ts");
const publicRateLimit = requireFile("backend/src/middleware/publicRateLimit.ts");
const objectStorageService = requireFile("backend/src/services/objectStorageService.ts");
const compliancePackService = requireFile("backend/src/services/compliancePackService.ts");
const incidentUpload = requireFile("backend/src/middleware/incidentUpload.ts");
const supportIssueUpload = requireFile("backend/src/middleware/supportIssueUpload.ts");
const drAutomation = requireFile("documents/ops/aws-dr-automation.md");
const drRunbook = requireFile("documents/ops/aws-multi-region-disaster-recovery-runbook.md");
const protectedEnv = requireFile("documents/ops/aws-dr-protected-environments.md");

let checklist = null;
try {
  checklist = JSON.parse(checklistRaw);
} catch (error) {
  failures.push(`Checklist JSON is invalid: ${error.message}`);
}

if (checklist) {
  if (checklist.asgStatus !== "BLOCKED") {
    failures.push(`Checklist asgStatus must stay BLOCKED until node-local state and operator inputs are proven; found ${checklist.asgStatus}`);
  }

  const blockerIds = new Set((checklist.blockers || []).map((item) => item.id));
  for (const id of [
    "REDIS_SHARED_ENDPOINT_NOT_PROVEN",
    "LOCAL_MINIO_IN_COMPOSE",
    "ASG_SECRET_INJECTION_NOT_PROVEN",
    "WORKER_SINGLETON_TOPOLOGY_NOT_PROVEN",
    "ROLLING_DEPLOY_POLICY_NOT_APPLIED",
  ]) {
    if (!blockerIds.has(id)) failures.push(`Checklist is missing blocker id ${id}`);
  }

  if (!Array.isArray(checklist.requiredValidationCommands) || !checklist.requiredValidationCommands.includes("node scripts/dr/check-asg-multi-instance-readiness.mjs")) {
    failures.push("Checklist must include this validation script in requiredValidationCommands.");
  }
}

requireMatch("readiness doc", doc, /ASG_STATUS=BLOCKED/, "must clearly mark ASG_STATUS=BLOCKED.");
requireMatch("readiness doc", doc, /Do not create ASGs/i, "must retain the no-ASG-creation safety rule.");
requireMatch("readiness doc", doc, /Do not perform production DNS cutover/i, "must retain the no-DNS-cutover safety rule.");
requireMatch("readiness doc", doc, /Redis/i, "must cover Redis/session behavior.");
requireMatch("readiness doc", doc, /MinIO|object storage/i, "must cover MinIO/object storage behavior.");
requireMatch("readiness doc", doc, /RUN_DB_MIGRATIONS_ON_START=false/, "must document migration-on-start gating.");
requireMatch("readiness doc", doc, /RUN_BACKGROUND_WORKERS=false/, "must document disabled background workers on web nodes.");
requireMatch("readiness doc", doc, /\/healthz/, "must document shallow liveness health semantics.");
requireMatch("readiness doc", doc, /\/api\/health\/ready/, "must document dependency readiness health semantics.");
requireMatch("readiness doc", doc, /deregistration delay/i, "must document rolling deploy drain behavior.");
requireMatch("readiness doc", doc, /Secrets Manager|SSM/i, "must document safe secret injection expectations.");

const packageJson = packageJsonRaw ? JSON.parse(packageJsonRaw) : { scripts: {} };
if (!packageJson.scripts?.["check:asg-multi-instance-readiness"]) {
  failures.push("package.json must expose check:asg-multi-instance-readiness.");
}
if (!String(packageJson.scripts?.["verify:guardrails"] || "").includes("check:asg-multi-instance-readiness")) {
  failures.push("verify:guardrails must run check:asg-multi-instance-readiness.");
}

requireMatch("docker-compose", compose, /\bredis:\n\s+image:\s+redis:/, "must expose the local Redis service so the blocker remains visible.");
requireMatch("docker-compose", compose, /\bminio:\n\s+image:\s+minio\/minio:/, "must expose the local MinIO service so the blocker remains visible.");
requireMatch("docker-compose", compose, /RUN_DB_MIGRATIONS_ON_START:\s+\$\{RUN_DB_MIGRATIONS_ON_START:-false\}/, "backend migrations must default off.");
requireMatch("docker-compose", compose, /RUN_BACKGROUND_WORKERS:\s+"false"/, "web backend nodes must default background workers off.");
requireMatch("docker-compose", compose, /RUN_BACKGROUND_WORKERS:\s+"true"/, "worker service must be explicitly separate from web.");
requireMatch("backend Dockerfile", backendDockerfile, /ENV RUN_DB_MIGRATIONS_ON_START=false/, "runtime image must default startup migrations off.");
requireMatch("backend startup", backendStartup, /RUN_DB_MIGRATIONS_ON_START:-false/, "startup migration gate must be explicit.");

requireMatch("backend index", backendIndex, /production requires Redis coordination/, "production startup must require Redis.");
requireMatch("backend index", backendIndex, /production requires object storage/, "production startup must require object storage.");
requireMatch("backend index", backendIndex, /const runBackgroundWorkers = parseBool\(process\.env\.RUN_BACKGROUND_WORKERS, true\)/, "background workers must be controlled by env.");
requireMatch("backend worker", backendWorker, /startHotEventPartitionMaintenanceWorker/, "dedicated worker should own hot partition maintenance.");
requireMatch("health controller", healthController, /dependencies\.database\.ready/, "readiness must validate database.");
requireMatch("health controller", healthController, /dependencies\.redis\.configured && dependencies\.redis\.ready/, "production readiness must validate Redis.");
requireMatch("health controller", healthController, /dependencies\.objectStorage\.configured && dependencies\.objectStorage\.ready/, "production readiness must validate object storage.");
requireMatch("routes", routes, /\/health\/ready/, "backend routes must expose dependency readiness.");
requireMatch("routes", routes, /\/healthz/, "backend routes must expose liveness/status.");

requireMatch("redis service", redisService, /REDIS_URL|REDIS_HOST/, "Redis must be environment-configured.");
requireMatch("rate limiter", publicRateLimit, /RedisStore/, "public rate limiter must use RedisStore when Redis is configured.");
requireMatch("object storage service", objectStorageService, /S3Client/, "object storage must use S3-compatible client.");
requireMatch("object storage service", objectStorageService, /uploadObjectBuffer/, "object storage must support generated artifact buffers.");
requireMatch("compliance packs", compliancePackService, /uploadObjectBuffer/, "compliance packs must write generated artifacts to object storage when configured.");
requireMatch("compliance packs", compliancePackService, /storageMode/, "compliance pack job summary must record storage mode.");
requireMatch("incident uploads", incidentUpload, /multer\.diskStorage/, "incident upload local staging must remain visible in the audit.");
requireMatch("support uploads", supportIssueUpload, /multer\.diskStorage/, "support upload local staging must remain visible in the audit.");

for (const [label, source] of [
  ["DR automation", drAutomation],
  ["DR runbook", drRunbook],
  ["protected environments", protectedEnv],
]) {
  requireMatch(label, source, /aws-asg-multi-instance-readiness/, "must link to the ASG readiness document.");
  requireMatch(label, source, /ASG_STATUS=BLOCKED/, "must state the current blocked ASG status.");
}

if (/ASG_STATUS=READY/.test(`${doc}\n${drAutomation}\n${drRunbook}\n${protectedEnv}`)) {
  failures.push("Docs must not claim ASG_STATUS=READY while local Redis/MinIO and operator input blockers remain.");
}

if (/OBJECT_STORAGE_ENDPOINT=http:\/\/minio:9000/.test(requireFile(".env.production.mumbai.example"))) {
  warnings.push("Mumbai production example still points at Compose MinIO; keep ASG_STATUS=BLOCKED until replaced with shared S3/managed object storage.");
}

if (failures.length > 0) {
  console.error("ASG multi-instance readiness guardrail failed:");
  for (const failure of failures) console.error(`- ${failure}`);
  process.exit(1);
}

console.log("ASG multi-instance readiness guardrail passed.");
if (checklist) {
  console.log(`ASG_STATUS=${checklist.asgStatus}`);
  console.log(`Blockers=${(checklist.blockers || []).length}`);
}
for (const warning of warnings) console.warn(`warning: ${warning}`);
