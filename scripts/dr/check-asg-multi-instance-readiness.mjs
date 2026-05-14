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
const asgWebCompose = requireFile("docker-compose.asg-web.yml");
const asgBootstrap = requireFile("scripts/dr/bootstrap-asg-web-node.sh");
const asgSsmManifestRaw = requireFile("documents/ops/aws-asg-web-ssm-parameter-manifest.json");
const asgInstancePolicyRaw = requireFile("ops/aws/iam/dr/asg-web-instance-profile-policy.template.json");
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
const mumbaiEnvExample = requireFile(".env.production.mumbai.example");
const capetownEnvExample = requireFile(".env.production.capetown.example");

let checklist = null;
let asgSsmManifest = null;
let asgInstancePolicy = null;
try {
  checklist = JSON.parse(checklistRaw);
} catch (error) {
  failures.push(`Checklist JSON is invalid: ${error.message}`);
}
try {
  asgSsmManifest = JSON.parse(asgSsmManifestRaw);
} catch (error) {
  failures.push(`ASG SSM manifest JSON is invalid: ${error.message}`);
}
try {
  asgInstancePolicy = JSON.parse(asgInstancePolicyRaw);
} catch (error) {
  failures.push(`ASG instance-profile IAM template JSON is invalid: ${error.message}`);
}

if (checklist) {
  if (checklist.asgStatus !== "BLOCKED") {
    failures.push(`Checklist asgStatus must stay BLOCKED until secret/bootstrap and rolling deploy evidence are proven; found ${checklist.asgStatus}`);
  }

  const blockerIds = new Set((checklist.blockers || []).map((item) => item.id));
  for (const id of [
    "ROLLING_DEPLOY_POLICY_NOT_APPLIED",
  ]) {
    if (!blockerIds.has(id)) failures.push(`Checklist is missing blocker id ${id}`);
  }

  for (const retiredBlocker of [
    "REDIS_SHARED_ENDPOINT_NOT_PROVEN",
    "LOCAL_MINIO_IN_COMPOSE",
    "WORKER_SINGLETON_TOPOLOGY_NOT_PROVEN",
    "ASG_SECRET_BOOTSTRAP_INJECTION_NOT_PROVEN",
    "ASG_SECRET_INJECTION_NOT_PROVEN",
  ]) {
    if (blockerIds.has(retiredBlocker)) failures.push(`Checklist should move ${retiredBlocker} to proofs instead of blockers.`);
  }

  const proofIds = new Set((checklist.proofs || []).map((item) => item.id));
  for (const id of [
    "REDIS_SHARED_ENDPOINT_PROVEN",
    "OBJECT_STORAGE_SHARED_PROVEN",
    "WORKER_TOPOLOGY_CONDITIONALLY_PROVEN",
    "ASG_SECRET_BOOTSTRAP_CONDITIONALLY_PROVEN",
  ]) {
    if (!proofIds.has(id)) failures.push(`Checklist is missing proof id ${id}`);
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
requireMatch("readiness doc", doc, /docker-compose\.asg-web\.yml/, "must document ASG web-node compose mode.");
requireMatch("readiness doc", doc, /docker compose --profile worker up -d --build backend worker frontend/, "must document intentional singleton worker profile command.");
requireMatch("readiness doc", doc, /COMPLIANCE_PACK_SCHEDULER_ENABLED=false/, "must document compliance scheduler disabled condition.");
requireMatch("readiness doc", doc, /Worker topology is conditionally proven/, "must mark worker topology conditionally proven.");
requireMatch("readiness doc", doc, /scripts\/dr\/bootstrap-asg-web-node\.sh/, "must document ASG web bootstrap script.");
requireMatch("readiness doc", doc, /documents\/ops\/aws-asg-web-ssm-parameter-manifest\.json/, "must document ASG SSM parameter manifest.");
requireMatch("readiness doc", doc, /\/mscqr\/prod\/ap-south-1\/asg-web\//, "must document Mumbai SSM prefix.");
requireMatch("readiness doc", doc, /\/mscqr\/prod\/af-south-1\/asg-web\//, "must document Cape Town SSM prefix.");
requireMatch("readiness doc", doc, /asg-web-instance-profile-policy\.template\.json/, "must document ASG instance-profile IAM template.");
requireMatch("readiness doc", doc, /Secrets\/bootstrap is conditionally proven/, "must mark secrets/bootstrap conditionally proven.");
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
requireMatch("docker-compose", compose, /worker:\n(?:.*\n){1,8}\s+profiles:\n\s+- worker/, "worker service must be behind the explicit worker profile.");
requireMatch("asg web compose", asgWebCompose, /\bbackend:/, "ASG web mode must define backend.");
requireMatch("asg web compose", asgWebCompose, /\bfrontend:/, "ASG web mode must define frontend.");
requireMatch("asg web compose", asgWebCompose, /RUN_BACKGROUND_WORKERS:\s+"false"/, "ASG web backend must force workers off.");
requireMatch("asg web compose", asgWebCompose, /REDIS_URL:\s+\$\{REDIS_URL:\?Set shared regional REDIS_URL/, "ASG web mode must require shared regional Redis.");
requireMatch("asg web compose", asgWebCompose, /REDIS_TLS:\s+\$\{REDIS_TLS:-true\}/, "ASG web mode must default Redis TLS on.");
requireMatch("asg web compose", asgWebCompose, /OBJECT_STORAGE_BUCKET:\s+\$\{OBJECT_STORAGE_BUCKET:\?Set shared regional OBJECT_STORAGE_BUCKET/, "ASG web mode must require shared regional object storage.");
if (/\n\s+worker:/.test(asgWebCompose)) failures.push("ASG web compose must not define a worker service.");
if (/\n\s+redis:/.test(asgWebCompose)) failures.push("ASG web compose must not define a local Redis service.");
if (/\n\s+minio:/.test(asgWebCompose)) failures.push("ASG web compose must not define a local MinIO service.");
requireMatch("ASG bootstrap", asgBootstrap, /aws ssm get-parameters-by-path/, "bootstrap must fetch parameters from SSM by path.");
requireMatch("ASG bootstrap", asgBootstrap, /--with-decryption/, "bootstrap must decrypt SecureString parameters.");
requireMatch("ASG bootstrap", asgBootstrap, /root_env_path=.*\/\.env/, "bootstrap must write project .env.");
requireMatch("ASG bootstrap", asgBootstrap, /backend_env_path=.*backend\/\.env/, "bootstrap must write backend/.env.");
requireMatch("ASG bootstrap", asgBootstrap, /fs\.chmodSync\(filePath, 0o600\)/, "bootstrap must chmod generated env files to 0600.");
requireMatch("ASG bootstrap", asgBootstrap, /Forbidden ASG web-node parameter is present in SSM/, "bootstrap must reject forbidden parameters such as MinIO secrets.");
requireMatch("ASG bootstrap", asgBootstrap, /RUN_BACKGROUND_WORKERS: "false"/, "bootstrap must force workers off.");
requireMatch("ASG bootstrap", asgBootstrap, /RUN_DB_MIGRATIONS_ON_START: "false"/, "bootstrap must force startup migrations off.");
requireMatch("ASG bootstrap", asgBootstrap, /COMPLIANCE_PACK_SCHEDULER_ENABLED: "false"/, "bootstrap must force compliance scheduler off.");
requireMatch("ASG bootstrap", asgBootstrap, /REDIS_TLS: "true"/, "bootstrap must force Redis TLS on.");
requireMatch("ASG bootstrap", asgBootstrap, /OBJECT_STORAGE_ENDPOINT: ""/, "bootstrap must force object endpoint empty.");
requireMatch("ASG bootstrap", asgBootstrap, /OBJECT_STORAGE_ACCESS_KEY: ""/, "bootstrap must force static object access key empty.");
requireMatch("ASG bootstrap", asgBootstrap, /OBJECT_STORAGE_SECRET_KEY: ""/, "bootstrap must force static object secret key empty.");
requireMatch("ASG bootstrap", asgBootstrap, /OBJECT_STORAGE_FORCE_PATH_STYLE: "false"/, "bootstrap must force path-style false.");
requireMatch("ASG bootstrap", asgBootstrap, /docker compose -f docker-compose\.asg-web\.yml up -d --build --remove-orphans backend frontend/, "bootstrap must start ASG web compose only.");
requireMatch("ASG bootstrap", asgBootstrap, /http:\/\/127\.0\.0\.1\/healthz/, "bootstrap must check frontend health through localhost.");
requireMatch("ASG bootstrap", asgBootstrap, /http:\/\/127\.0\.0\.1\/api\/health\/ready/, "bootstrap must check backend readiness through frontend/Nginx path.");
requireMatch("ASG bootstrap", asgBootstrap, /deps\.database\?\.ready === true/, "bootstrap must require database readiness.");
requireMatch("ASG bootstrap", asgBootstrap, /deps\.redis\?\.configured === true/, "bootstrap must require Redis configured.");
requireMatch("ASG bootstrap", asgBootstrap, /deps\.redis\?\.ready === true/, "bootstrap must require Redis readiness.");
requireMatch("ASG bootstrap", asgBootstrap, /deps\.objectStorage\?\.configured === true/, "bootstrap must require object storage configured.");
requireMatch("ASG bootstrap", asgBootstrap, /deps\.objectStorage\?\.ready === true/, "bootstrap must require object storage readiness.");
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
for (const [label, source, region] of [
  ["Mumbai env example", mumbaiEnvExample, "mumbai"],
  ["Cape Town env example", capetownEnvExample, "capetown"],
]) {
  requireMatch(label, source, /REDIS_URL=rediss:\/\/regional-elasticache:6379\/0/, `${region} env example must document regional rediss Redis.`);
  requireMatch(label, source, /REDIS_TLS=true/, `${region} env example must document Redis TLS.`);
  requireMatch(label, source, /OBJECT_STORAGE_ENDPOINT=\n/, `${region} env example must keep object endpoint empty for S3/default credentials.`);
  requireMatch(label, source, /OBJECT_STORAGE_ACCESS_KEY=\n/, `${region} env example must keep static object access key empty.`);
  requireMatch(label, source, /OBJECT_STORAGE_SECRET_KEY=\n/, `${region} env example must keep static object secret key empty.`);
  requireMatch(label, source, /OBJECT_STORAGE_FORCE_PATH_STYLE=false/, `${region} env example must disable path-style for native S3.`);
  requireMatch(label, source, /COMPLIANCE_PACK_SCHEDULER_ENABLED=false/, `${region} env example must keep compliance scheduler disabled.`);
}

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

if (/OBJECT_STORAGE_ENDPOINT=http:\/\/minio:9000/.test(`${mumbaiEnvExample}\n${capetownEnvExample}`)) {
  failures.push("Regional production env examples must not point object storage at node-local MinIO.");
}

if (asgSsmManifest) {
  const rootRequired = new Set(asgSsmManifest.rootEnv?.requiredFromSsm || []);
  for (const key of ["AWS_REGION", "OBJECT_STORAGE_BUCKET", "OBJECT_STORAGE_REGION", "REDIS_URL"]) {
    if (!rootRequired.has(key)) failures.push(`ASG SSM manifest rootEnv.requiredFromSsm is missing ${key}.`);
  }
  const backendRequired = new Set(asgSsmManifest.backendEnv?.requiredFromSsm || []);
  for (const key of [
    "DATABASE_URL",
    "JWT_SECRET_CURRENT",
    "COOKIE_SECURE",
    "QR_SIGN_PRIVATE_KEY",
    "QR_SIGN_PUBLIC_KEY",
    "TOKEN_HASH_SECRET_CURRENT",
    "IP_HASH_SALT_CURRENT",
    "CUSTOMER_VERIFY_OTP_SECRET",
    "CUSTOMER_VERIFY_TOKEN_SECRET",
    "SCAN_FINGERPRINT_SECRET",
    "PRINTER_SSE_SIGN_SECRET_CURRENT",
    "INCIDENT_HASH_SALT_CURRENT",
    "AUTH_MFA_ENCRYPTION_KEY",
  ]) {
    if (!backendRequired.has(key)) failures.push(`ASG SSM manifest backendEnv.requiredFromSsm is missing ${key}.`);
  }
  for (const [sectionName, forced] of [
    ["rootEnv", asgSsmManifest.rootEnv?.forced || {}],
    ["backendEnv", asgSsmManifest.backendEnv?.forced || {}],
  ]) {
    for (const [key, expected] of Object.entries({
      REDIS_TLS: "true",
      OBJECT_STORAGE_ENDPOINT: "",
      OBJECT_STORAGE_ACCESS_KEY: "",
      OBJECT_STORAGE_SECRET_KEY: "",
      OBJECT_STORAGE_FORCE_PATH_STYLE: "false",
    })) {
      if (forced[key] !== expected) failures.push(`ASG SSM manifest ${sectionName}.forced.${key} must be ${JSON.stringify(expected)}.`);
    }
  }
  const backendForced = asgSsmManifest.backendEnv?.forced || {};
  for (const [key, expected] of Object.entries({
    RUN_BACKGROUND_WORKERS: "false",
    RUN_DB_MIGRATIONS_ON_START: "false",
    COMPLIANCE_PACK_SCHEDULER_ENABLED: "false",
  })) {
    if (backendForced[key] !== expected) failures.push(`ASG SSM manifest backendEnv.forced.${key} must be ${JSON.stringify(expected)}.`);
  }
}

if (asgInstancePolicy) {
  const actions = JSON.stringify(asgInstancePolicy.Statement || []);
  for (const action of [
    "ssm:GetParameter",
    "ssm:GetParameters",
    "ssm:GetParametersByPath",
    "kms:Decrypt",
    "s3:GetObject",
    "s3:PutObject",
    "ecr:GetAuthorizationToken",
    "ecr:BatchGetImage",
    "ecr:GetDownloadUrlForLayer",
  ]) {
    if (!actions.includes(action)) failures.push(`ASG instance-profile IAM template is missing ${action}.`);
  }
  if (!actions.includes("/mscqr/prod/<TARGET_REGION>/asg-web/*")) {
    failures.push("ASG instance-profile IAM template must scope SSM access to /mscqr/prod/<TARGET_REGION>/asg-web/*.");
  }
  if (!actions.includes("<REGIONAL_ARTIFACT_BUCKET>")) {
    failures.push("ASG instance-profile IAM template must scope S3 access to <REGIONAL_ARTIFACT_BUCKET>.");
  }
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
