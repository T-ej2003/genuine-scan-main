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
const asgRollingPolicyDoc = requireFile("documents/ops/aws-asg-rolling-deploy-policy.md");
const asgRollingPolicyChecklistRaw = requireFile("documents/ops/aws-asg-rolling-deploy-policy.checklist.json");
const asgApplyPlanScript = requireFile("scripts/dr/generate-asg-apply-plan.sh");
const asgApplyScript = requireFile("scripts/dr/apply-asg-launch-template-approved.sh");
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
let asgRollingPolicyChecklist = null;
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
try {
  asgRollingPolicyChecklist = JSON.parse(asgRollingPolicyChecklistRaw);
} catch (error) {
  failures.push(`ASG rolling policy checklist JSON is invalid: ${error.message}`);
}

if (checklist) {
  if (checklist.asgStatus !== "CONDITIONALLY_READY") {
    failures.push(`Checklist asgStatus must be CONDITIONALLY_READY once repo-side rollout evidence is committed; found ${checklist.asgStatus}`);
  }

  const blockerIds = new Set((checklist.blockers || []).map((item) => item.id));
  if (blockerIds.size > 0) {
    failures.push(`Checklist blockers must be empty once repo-side ASG rollout policy is committed; found ${[...blockerIds].join(", ")}`);
  }

  for (const retiredBlocker of [
    "REDIS_SHARED_ENDPOINT_NOT_PROVEN",
    "LOCAL_MINIO_IN_COMPOSE",
    "WORKER_SINGLETON_TOPOLOGY_NOT_PROVEN",
    "ASG_SECRET_BOOTSTRAP_INJECTION_NOT_PROVEN",
    "ASG_SECRET_INJECTION_NOT_PROVEN",
    "ROLLING_DEPLOY_POLICY_NOT_APPLIED",
  ]) {
    if (blockerIds.has(retiredBlocker)) failures.push(`Checklist should move ${retiredBlocker} to proofs instead of blockers.`);
  }

  const proofIds = new Set((checklist.proofs || []).map((item) => item.id));
  for (const id of [
    "REDIS_SHARED_ENDPOINT_PROVEN",
    "OBJECT_STORAGE_SHARED_PROVEN",
    "WORKER_TOPOLOGY_CONDITIONALLY_PROVEN",
    "ASG_SECRET_BOOTSTRAP_CONDITIONALLY_PROVEN",
    "ROLLING_DEPLOY_POLICY_CONDITIONALLY_PROVEN",
  ]) {
    if (!proofIds.has(id)) failures.push(`Checklist is missing proof id ${id}`);
  }

  if (!Array.isArray(checklist.requiredValidationCommands) || !checklist.requiredValidationCommands.includes("node scripts/dr/check-asg-multi-instance-readiness.mjs")) {
    failures.push("Checklist must include this validation script in requiredValidationCommands.");
  }
  if (!Array.isArray(checklist.operatorInputsRequiredForConditionalReady) || !checklist.operatorInputsRequiredForConditionalReady.some((item) => /replacement-instance drill/i.test(item))) {
    failures.push("Checklist must keep the replacement-instance drill as the remaining live operator input.");
  }
}

requireMatch("readiness doc", doc, /ASG_STATUS=CONDITIONALLY_READY/, "must clearly mark ASG_STATUS=CONDITIONALLY_READY.");
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
requireMatch("readiness doc", doc, /ASG_WEB_INSTANCE_PROFILE_ARN/, "must document explicit ASG web instance profile ARN input.");
requireMatch("readiness doc", doc, /ASG_WEB_INSTANCE_PROFILE_NAME/, "must document explicit ASG web instance profile name input.");
requireMatch("readiness doc", doc, /ASG_ASSOCIATE_PUBLIC_IP/, "must document explicit ASG public IP association input.");
requireMatch("readiness doc", doc, /ASG_KEY_NAME/, "must document optional ASG SSH KeyName input.");
requireMatch("readiness doc", doc, /ASG_REPO_URL/, "must document ASG repository URL input.");
requireMatch("readiness doc", doc, /ASG_REPO_BRANCH/, "must document ASG repository branch input.");
requireMatch("readiness doc", doc, /ASG_REPO_DIR/, "must document ASG repository directory input.");
requireMatch("readiness doc", doc, /plain Ubuntu 22\.04|blank Ubuntu/i, "must document plain Ubuntu host bootstrap support.");
requireMatch("readiness doc", doc, /mscqr-prod-mumbai/, "must document Mumbai debug retry KeyName.");
requireMatch("readiness doc", doc, /NetworkInterfaces\[0\]\.AssociatePublicIpAddress=true/, "must document public-IP launch template networking shape.");
requireMatch("readiness doc", doc, /SecurityGroupIds=\[SOURCE_SECURITY_GROUP\]/, "must document non-public-IP launch template networking shape.");
requireMatch("readiness doc", doc, /MapPublicIpOnLaunch=false/, "must document the Mumbai retry subnet public-IP reason.");
requireMatch("readiness doc", doc, /NAT Gateway or VPC endpoints/, "must document the preferred private subnet production design.");
requireMatch("readiness doc", doc, /UserData/, "must document launch-template UserData bootstrap.");
requireMatch("readiness doc", doc, /aws-asg-rolling-deploy-policy/, "must document the committed rolling deploy policy.");
requireMatch("readiness doc", doc, /Rolling deploy policy is conditionally proven/, "must mark rolling deploy policy conditionally proven.");
requireMatch("readiness doc", doc, /\/healthz/, "must document shallow liveness health semantics.");
requireMatch("readiness doc", doc, /\/api\/health\/ready/, "must document dependency readiness health semantics.");
requireMatch("readiness doc", doc, /deregistration delay/i, "must document rolling deploy drain behavior.");
requireMatch("readiness doc", doc, /Secrets Manager|SSM/i, "must document safe secret injection expectations.");
requireMatch("readiness doc", doc, /replacement-instance drill/i, "must document the remaining live replacement-instance drill.");
requireMatch("readiness doc", doc, /Keep production DNS on London EC2/i, "must document no DNS cutover during rollout validation.");
requireMatch("rolling policy doc", asgRollingPolicyDoc, /ASG_STATUS=CONDITIONALLY_READY/, "must mark the rolling policy document conditionally ready.");
requireMatch("rolling policy doc", asgRollingPolicyDoc, /ASG_WEB_INSTANCE_PROFILE_ARN/, "must define explicit ASG web instance profile ARN input.");
requireMatch("rolling policy doc", asgRollingPolicyDoc, /ASG_WEB_INSTANCE_PROFILE_NAME/, "must define explicit ASG web instance profile name input.");
requireMatch("rolling policy doc", asgRollingPolicyDoc, /ASG_ASSOCIATE_PUBLIC_IP/, "must define explicit ASG public IP association input.");
requireMatch("rolling policy doc", asgRollingPolicyDoc, /ASG_KEY_NAME/, "must define optional ASG SSH KeyName input.");
requireMatch("rolling policy doc", asgRollingPolicyDoc, /ASG_REPO_URL/, "must define ASG repository URL input.");
requireMatch("rolling policy doc", asgRollingPolicyDoc, /ASG_REPO_BRANCH/, "must define ASG repository branch input.");
requireMatch("rolling policy doc", asgRollingPolicyDoc, /ASG_REPO_DIR/, "must define ASG repository directory input.");
requireMatch("rolling policy doc", asgRollingPolicyDoc, /mscqr-prod-mumbai/, "must recommend Mumbai debug retry KeyName.");
requireMatch("rolling policy doc", asgRollingPolicyDoc, /NetworkInterfaces\[0\]\.AssociatePublicIpAddress=true/, "must define public-IP launch template networking shape.");
requireMatch("rolling policy doc", asgRollingPolicyDoc, /SecurityGroupIds=\[SOURCE_SECURITY_GROUP\]/, "must define non-public-IP launch template networking shape.");
requireMatch("rolling policy doc", asgRollingPolicyDoc, /UserData/, "must define UserData bootstrap.");
requireMatch("rolling policy doc", asgRollingPolicyDoc, /deregistration delay/i, "must define the target group deregistration delay.");
requireMatch("rolling policy doc", asgRollingPolicyDoc, /health check grace period: 180 seconds/i, "must define 180 second health grace.");
requireMatch("rolling policy doc", asgRollingPolicyDoc, /default instance warmup: 180 seconds/i, "must define 180 second default instance warmup.");
requireMatch("rolling policy doc", asgRollingPolicyDoc, /minimum healthy percentage: 100/i, "must define 100 percent min healthy.");
requireMatch("rolling policy doc", asgRollingPolicyDoc, /checkpoint/i, "must define refresh checkpoints.");
requireMatch("rolling policy doc", asgRollingPolicyDoc, /CloudWatch alarms/i, "must define rollback alarm expectations.");
requireMatch("rolling policy doc", asgRollingPolicyDoc, /\/healthz/, "must require /healthz smoke tests.");
requireMatch("rolling policy doc", asgRollingPolicyDoc, /\/api\/health\/ready/, "must require /api/health/ready smoke tests.");
requireMatch("rolling policy doc", asgRollingPolicyDoc, /manual rollback/i, "must document manual rollback.");
requireMatch("rolling policy doc", asgRollingPolicyDoc, /replacement-instance drill/i, "must document the replacement-instance drill.");
requireMatch("rolling policy doc", asgRollingPolicyDoc, /Do not perform production DNS cutover during ASG rollout validation/i, "must forbid DNS cutover during validation.");

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
requireMatch("DR common", requireFile("scripts/dr/common.sh"), /write_asg_web_launch_template_json/, "common helpers must generate ASG web launch template JSON.");
requireMatch("DR common", requireFile("scripts/dr/common.sh"), /validate_asg_launch_template_json/, "common helpers must validate ASG web launch template JSON.");
requireMatch("DR common", requireFile("scripts/dr/common.sh"), /ASG_WEB_INSTANCE_PROFILE_ARN or ASG_WEB_INSTANCE_PROFILE_NAME is required/, "common helpers must require explicit ASG web instance profile input.");
requireMatch("DR common", requireFile("scripts/dr/common.sh"), /ASG_ASSOCIATE_PUBLIC_IP must be true or false/, "common helpers must validate ASG_ASSOCIATE_PUBLIC_IP.");
requireMatch("DR common", requireFile("scripts/dr/common.sh"), /ASG_KEY_NAME must not contain whitespace/, "common helpers must validate ASG_KEY_NAME.");
requireMatch("DR common", requireFile("scripts/dr/common.sh"), /ASG_REPO_URL is required for self-sufficient ASG web-node bootstrap/, "common helpers must require ASG_REPO_URL.");
requireMatch("DR common", requireFile("scripts/dr/common.sh"), /ASG_REPO_URL must be a non-secret URL without whitespace or embedded credentials/, "common helpers must reject secret-looking repo URLs.");
requireMatch("DR common", requireFile("scripts/dr/common.sh"), /ASG_REPO_BRANCH must be non-empty and must not contain whitespace/, "common helpers must validate ASG_REPO_BRANCH.");
requireMatch("DR common", requireFile("scripts/dr/common.sh"), /ASG_REPO_DIR must be non-empty and must not contain whitespace/, "common helpers must validate ASG_REPO_DIR.");
requireMatch("DR common", requireFile("scripts/dr/common.sh"), /data\.KeyName = keyName/, "common helpers must emit KeyName when ASG_KEY_NAME is set.");
requireMatch("DR common", requireFile("scripts/dr/common.sh"), /Launch template data must omit KeyName when ASG_KEY_NAME is not set/, "launch template validation must reject unexpected KeyName.");
requireMatch("DR common", requireFile("scripts/dr/common.sh"), /UserData: Buffer\.from\(userData, "utf8"\)\.toString\("base64"\)/, "common helpers must base64 encode launch template UserData.");
requireMatch("DR common", requireFile("scripts/dr/common.sh"), /\/var\/log\/mscqr-asg-bootstrap\.log/, "UserData must log to the ASG bootstrap log file.");
requireMatch("DR common", requireFile("scripts/dr/common.sh"), /tee -a "\$log_file"/, "UserData must mirror non-secret status lines to console and log file.");
requireMatch("DR common", requireFile("scripts/dr/common.sh"), /trap on_exit EXIT/, "UserData must install a failure trap.");
requireMatch("DR common", requireFile("scripts/dr/common.sh"), /current_step=/, "UserData failure trap must report the current step.");
requireMatch("DR common", requireFile("scripts/dr/common.sh"), /safe_diagnostics/, "UserData must include safe diagnostics on failure.");
requireMatch("DR common", requireFile("scripts/dr/common.sh"), /cloud-init-output\.log/, "UserData failure message must point operators to cloud-init output.");
requireMatch("DR common", requireFile("scripts/dr/common.sh"), /export DEBIAN_FRONTEND=noninteractive/, "UserData must use noninteractive package installation.");
requireMatch("DR common", requireFile("scripts/dr/common.sh"), /apt-get install -y git ca-certificates curl/, "UserData must install git prerequisites when missing.");
requireMatch("DR common", requireFile("scripts/dr/common.sh"), /apt-get install -y docker\.io docker-compose-plugin/, "UserData must install Docker and Compose plugin when missing.");
requireMatch("DR common", requireFile("scripts/dr/common.sh"), /systemctl enable --now docker/, "UserData must enable and start Docker.");
requireMatch("DR common", requireFile("scripts/dr/common.sh"), /docker compose version/, "UserData must verify Docker Compose plugin.");
requireMatch("DR common", requireFile("scripts/dr/common.sh"), /git clone --branch "\$ASG_REPO_BRANCH" --depth 1 "\$ASG_REPO_URL" "\$ASG_REPO_DIR"/, "UserData must clone the repo when missing.");
requireMatch("DR common", requireFile("scripts/dr/common.sh"), /repo directory exists but is not a git checkout/, "UserData must fail clearly when ASG_REPO_DIR exists but is not a git checkout.");
requireMatch("DR common", requireFile("scripts/dr/common.sh"), /docker --version/, "UserData safe diagnostics must include docker version when available.");
requireMatch("DR common", requireFile("scripts/dr/common.sh"), /systemctl is-active docker/, "UserData safe diagnostics must include docker service state when available.");
requireMatch("DR common", requireFile("scripts/dr/common.sh"), /git --version/, "UserData safe diagnostics must include git version when available.");
requireMatch("DR common", requireFile("scripts/dr/common.sh"), /\/bin\/ls -ld \/home\/ubuntu/, "UserData safe diagnostics must list /home/ubuntu only.");
requireMatch("DR common", requireFile("scripts/dr/common.sh"), /\/bin\/ls -ld "\$ASG_REPO_DIR"/, "UserData safe diagnostics must list only ASG_REPO_DIR.");
requireMatch("DR common", requireFile("scripts/dr/common.sh"), /git fetch origin "\$ASG_REPO_BRANCH"/, "UserData must fetch configured branch.");
requireMatch("DR common", requireFile("scripts/dr/common.sh"), /git reset --hard "origin\/\$ASG_REPO_BRANCH"/, "UserData must reset to configured branch.");
requireMatch("DR common", requireFile("scripts/dr/common.sh"), /scripts\/dr\/bootstrap-asg-web-node\.sh "\$TARGET_REGION_GROUP" "\$AWS_REGION"/, "UserData must run the ASG bootstrap script with region inputs.");
requireMatch("DR common", requireFile("scripts/dr/common.sh"), /MetadataOptions\?\.HttpTokens !== "required"/, "launch template validation must require IMDSv2 token enforcement.");
requireMatch("DR common", requireFile("scripts/dr/common.sh"), /data\.IamInstanceProfile/, "launch template validation must require IamInstanceProfile.");
requireMatch("DR common", requireFile("scripts/dr/common.sh"), /data\.UserData/, "launch template validation must require UserData.");
requireMatch("DR common", requireFile("scripts/dr/common.sh"), /NetworkInterfaces = \[/, "common helpers must emit NetworkInterfaces when ASG_ASSOCIATE_PUBLIC_IP=true.");
requireMatch("DR common", requireFile("scripts/dr/common.sh"), /AssociatePublicIpAddress: true/, "common helpers must support public IP association.");
requireMatch("DR common", requireFile("scripts/dr/common.sh"), /data\.SecurityGroupIds = \[securityGroup\]/, "common helpers must keep SecurityGroupIds when ASG_ASSOCIATE_PUBLIC_IP=false.");
requireMatch("DR common", requireFile("scripts/dr/common.sh"), /must not set top-level SecurityGroupIds when ASG_ASSOCIATE_PUBLIC_IP=true/, "launch template validation must reject mixed public-IP networking shape.");
requireMatch("DR common", requireFile("scripts/dr/common.sh"), /must not set NetworkInterfaces when ASG_ASSOCIATE_PUBLIC_IP=false/, "launch template validation must reject NetworkInterfaces when public IP association is false.");
requireMatch("DR common", requireFile("scripts/dr/common.sh"), /Groups must include SOURCE_SECURITY_GROUP/, "launch template validation must require SOURCE_SECURITY_GROUP in NetworkInterfaces groups.");
requireMatch("DR common", requireFile("scripts/dr/common.sh"), /SecurityGroupIds must include SOURCE_SECURITY_GROUP/, "launch template validation must require SOURCE_SECURITY_GROUP in SecurityGroupIds.");
requireMatch("ASG apply plan", asgApplyPlanScript, /aws-asg-rolling-deploy-policy\.checklist\.json/, "apply plan must read the rolling policy checklist.");
requireMatch("ASG apply plan", asgApplyPlanScript, /render_asg_rolling_policy_env/, "apply plan must validate the rolling policy through common helpers.");
requireMatch("ASG apply plan", asgApplyPlanScript, /ASG_WEB_INSTANCE_PROFILE_ARN/, "apply plan must accept explicit ASG web instance profile ARN.");
requireMatch("ASG apply plan", asgApplyPlanScript, /ASG_WEB_INSTANCE_PROFILE_NAME/, "apply plan must accept explicit ASG web instance profile name.");
requireMatch("ASG apply plan", asgApplyPlanScript, /ASG_ASSOCIATE_PUBLIC_IP/, "apply plan must accept ASG_ASSOCIATE_PUBLIC_IP.");
requireMatch("ASG apply plan", asgApplyPlanScript, /ASG_KEY_NAME/, "apply plan must accept ASG_KEY_NAME.");
requireMatch("ASG apply plan", asgApplyPlanScript, /ASG_REPO_URL/, "apply plan must accept ASG_REPO_URL.");
requireMatch("ASG apply plan", asgApplyPlanScript, /ASG_REPO_BRANCH/, "apply plan must accept ASG_REPO_BRANCH.");
requireMatch("ASG apply plan", asgApplyPlanScript, /ASG_REPO_DIR/, "apply plan must accept ASG_REPO_DIR.");
requireMatch("ASG apply plan", asgApplyPlanScript, /Package bootstrap: enabled/, "apply plan must show package bootstrap is enabled.");
requireMatch("ASG apply plan", asgApplyPlanScript, /Repository URL/, "apply plan must show repository URL.");
requireMatch("ASG apply plan", asgApplyPlanScript, /KeyName: provided|KeyName: not provided/, "apply plan must show KeyName state.");
requireMatch("ASG apply plan", asgApplyPlanScript, /ASG_KEY_NAME=mscqr-prod-mumbai/, "apply plan must warn about Mumbai debug retry KeyName.");
requireMatch("ASG apply plan", asgApplyPlanScript, /ASG_REPO_URL=https:\/\/github\.com\/T-ej2003\/genuine-scan-main\.git/, "apply plan must warn about Mumbai debug retry repo URL.");
requireMatch("ASG apply plan", asgApplyPlanScript, /Associate public IP/, "apply plan must include public IP association state in the markdown plan.");
requireMatch("ASG apply plan", asgApplyPlanScript, /write_asg_web_launch_template_json/, "apply plan must generate launch template through shared helper.");
requireMatch("ASG apply plan", asgApplyPlanScript, /validate_asg_launch_template_json/, "apply plan must validate proposed launch template JSON.");
requireMatch("ASG apply plan", asgApplyPlanScript, /HealthCheckGracePeriod/, "apply plan must include health check grace period in the plan artifact.");
requireMatch("ASG apply plan", asgApplyPlanScript, /DefaultInstanceWarmup/, "apply plan must include default instance warmup in the plan artifact.");
requireMatch("ASG apply plan", asgApplyPlanScript, /Target deregistration delay required on target group/, "apply plan must include deregistration delay.");
requireMatch("ASG apply plan", asgApplyPlanScript, /Remaining live go\/no-go/, "apply plan must call out the remaining live drill.");
requireMatch("ASG apply", asgApplyScript, /aws-asg-rolling-deploy-policy\.checklist\.json/, "apply script must read the rolling policy checklist.");
requireMatch("ASG apply", asgApplyScript, /render_asg_rolling_policy_env/, "apply script must validate the rolling policy through common helpers.");
requireMatch("ASG apply", asgApplyScript, /ASG_WEB_INSTANCE_PROFILE_ARN/, "apply script must accept explicit ASG web instance profile ARN.");
requireMatch("ASG apply", asgApplyScript, /ASG_WEB_INSTANCE_PROFILE_NAME/, "apply script must accept explicit ASG web instance profile name.");
requireMatch("ASG apply", asgApplyScript, /ASG_ASSOCIATE_PUBLIC_IP/, "apply script must accept ASG_ASSOCIATE_PUBLIC_IP.");
requireMatch("ASG apply", asgApplyScript, /ASG_ASSOCIATE_PUBLIC_IP must be true or false/, "apply script must validate ASG_ASSOCIATE_PUBLIC_IP.");
requireMatch("ASG apply", asgApplyScript, /ASG_KEY_NAME/, "apply script must accept ASG_KEY_NAME.");
requireMatch("ASG apply", asgApplyScript, /ASG_KEY_NAME must not contain whitespace/, "apply script must validate ASG_KEY_NAME.");
requireMatch("ASG apply", asgApplyScript, /ASG_REPO_URL/, "apply script must accept ASG_REPO_URL.");
requireMatch("ASG apply", asgApplyScript, /ASG_REPO_URL is required for self-sufficient ASG web-node bootstrap/, "apply script must require ASG_REPO_URL.");
requireMatch("ASG apply", asgApplyScript, /ASG_REPO_BRANCH/, "apply script must accept ASG_REPO_BRANCH.");
requireMatch("ASG apply", asgApplyScript, /ASG_REPO_DIR/, "apply script must accept ASG_REPO_DIR.");
requireMatch("ASG apply", asgApplyScript, /source instance profile is not reused automatically/, "apply script must refuse implicit source instance profile reuse.");
requireMatch("ASG apply", asgApplyScript, /write_asg_web_launch_template_json/, "apply script must generate launch template through shared helper.");
requireMatch("ASG apply", asgApplyScript, /validate_asg_launch_template_json/, "apply script must validate launch template JSON.");
requireMatch("ASG apply", asgApplyScript, /create-launch-template-version/, "apply script must create a new launch template version when a template already exists.");
if (/--source-version/.test(asgApplyScript)) {
  failures.push("ASG apply script must not use --source-version when creating replacement launch template versions.");
}
requireMatch("ASG apply", asgApplyScript, /live-launch-template-data-latest\.json/, "apply script must write latest live launch template data for comparison.");
requireMatch("ASG apply", asgApplyScript, /live-launch-template-data\.json/, "apply script must write intended live launch template data after selecting the version.");
requireMatch("ASG apply", asgApplyScript, /modify-launch-template/, "apply script must set the intended launch template version as default.");
requireMatch("ASG apply", asgApplyScript, /ASG launch template mismatch before capacity update/, "apply script must refuse capacity changes when ASG is not on intended launch template version.");
requireMatch("ASG apply", asgApplyScript, /update-asg-capacity\.log/, "apply script must update ASG capacity only after version verification.");
requireMatch("ASG apply", asgApplyScript, /--launch-template "LaunchTemplateId=\$launch_template_id,Version=\$launch_template_version"/, "apply script must update ASG to the validated launch template version.");
requireMatch("ASG apply", asgApplyScript, /Refusing ASG apply without concrete rollback alarm names/, "apply script must refuse placeholder rollback alarm names.");
requireMatch("ASG apply", asgApplyScript, /describe-target-group-attributes/, "apply script must verify target group attributes before apply.");
requireMatch("ASG apply", asgApplyScript, /deregistration_delay\.timeout_seconds/, "apply script must check target group deregistration delay.");
requireMatch("ASG apply", asgApplyScript, /default-instance-warmup/, "apply script must enforce default instance warmup.");
requireMatch("ASG apply", asgApplyScript, /health-check-grace-period/, "apply script must enforce health check grace period.");
requireMatch("ASG apply", asgApplyScript, /health-check-type/, "apply script must enforce ASG health check type.");
requireMatch("ASG apply", asgApplyScript, /target count .* below policy requirement|below policy requirement/, "apply script must enforce healthy target count policy.");
if (/IamInstanceProfile\.Arn/.test(asgApplyScript)) {
  failures.push("ASG apply script must not copy IamInstanceProfile from SOURCE_INSTANCE_ID.");
}
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
  requireMatch(label, source, /CONDITIONALLY_READY/, "must state the current conditional ASG status.");
}

if (/(^|\n)ASG_STATUS=READY(\n|$)/m.test(`${doc}\n${drAutomation}\n${drRunbook}\n${protectedEnv}\n${asgRollingPolicyDoc}`)) {
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

if (asgRollingPolicyChecklist) {
  if (asgRollingPolicyChecklist.asgStatus !== "CONDITIONALLY_READY") {
    failures.push(`ASG rolling policy checklist asgStatus must be CONDITIONALLY_READY; found ${asgRollingPolicyChecklist.asgStatus}`);
  }
  for (const [field, expected] of Object.entries({
    health_check_type: "ELB",
    deregistration_delay_seconds: 60,
    health_check_grace_period_seconds: 180,
    default_instance_warmup_seconds: 180,
    instance_refresh_min_healthy_percentage: 100,
    desired_capacity_initial: 2,
    min_size_initial: 2,
    max_size_initial: 4,
    target_group_health_required: 2,
  })) {
    if (asgRollingPolicyChecklist[field] !== expected) {
      failures.push(`ASG rolling policy checklist ${field} must be ${JSON.stringify(expected)}.`);
    }
  }
  if (asgRollingPolicyChecklist.instance_refresh_max_healthy_percentage !== 150) {
    failures.push("ASG rolling policy checklist instance_refresh_max_healthy_percentage must be 150.");
  }
  if (asgRollingPolicyChecklist.instance_refresh_checkpoint_delay_seconds !== 300) {
    failures.push("ASG rolling policy checklist instance_refresh_checkpoint_delay_seconds must be 300.");
  }
  const checkpoints = JSON.stringify(asgRollingPolicyChecklist.instance_refresh_checkpoint_percentages || []);
  if (checkpoints !== JSON.stringify([50, 100])) {
    failures.push("ASG rolling policy checklist instance_refresh_checkpoint_percentages must be [50,100].");
  }
  if (asgRollingPolicyChecklist.no_production_dns_cutover_during_validation !== true) {
    failures.push("ASG rolling policy checklist must keep no_production_dns_cutover_during_validation=true.");
  }
  if (asgRollingPolicyChecklist.replacement_instance_drill_required !== true) {
    failures.push("ASG rolling policy checklist must keep replacement_instance_drill_required=true.");
  }
  const requiredInputs = new Set(asgRollingPolicyChecklist.launch_template_required_inputs || []);
  for (const input of ["ASG_WEB_INSTANCE_PROFILE_ARN", "ASG_WEB_INSTANCE_PROFILE_NAME", "ASG_ASSOCIATE_PUBLIC_IP", "ASG_KEY_NAME", "ASG_REPO_URL", "ASG_REPO_BRANCH", "ASG_REPO_DIR"]) {
    if (!requiredInputs.has(input)) failures.push(`ASG rolling policy checklist launch_template_required_inputs must include ${input}.`);
  }
  if (asgRollingPolicyChecklist.key_name_optional !== true) {
    failures.push("ASG rolling policy checklist key_name_optional must be true.");
  }
  if (asgRollingPolicyChecklist.key_name_recommended_for_mumbai_debug_retry !== "mscqr-prod-mumbai") {
    failures.push("ASG rolling policy checklist must recommend mscqr-prod-mumbai for Mumbai debug retry KeyName.");
  }
  if (asgRollingPolicyChecklist.associate_public_ip_default !== false) {
    failures.push("ASG rolling policy checklist associate_public_ip_default must be false.");
  }
  const publicIpAllowed = JSON.stringify(asgRollingPolicyChecklist.associate_public_ip_allowed_values || []);
  if (publicIpAllowed !== JSON.stringify([true, false])) {
    failures.push("ASG rolling policy checklist associate_public_ip_allowed_values must be [true,false].");
  }
  const requiredFields = new Set(asgRollingPolicyChecklist.launch_template_required_fields || []);
  for (const field of [
    "IamInstanceProfile",
    "UserData",
    "MetadataOptions.HttpTokens=required",
    "SecurityGroupIds when ASG_ASSOCIATE_PUBLIC_IP=false",
    "NetworkInterfaces[0].AssociatePublicIpAddress=true and Groups when ASG_ASSOCIATE_PUBLIC_IP=true",
    "ImageId",
    "InstanceType",
  ]) {
    if (!requiredFields.has(field)) failures.push(`ASG rolling policy checklist launch_template_required_fields must include ${field}.`);
  }
  const userDataBehaviors = JSON.stringify(asgRollingPolicyChecklist.userdata_required_behaviors || []);
  for (const behavior of [
    "#!/bin/sh",
    "set -eu",
    "/var/log/mscqr-asg-bootstrap.log",
    "mirror non-secret status and failure lines to cloud-init console output",
    "install failure trap with current step",
    "install/check git",
    "install/check docker",
    "install/check docker compose",
    "clone ASG_REPO_URL into ASG_REPO_DIR when missing",
    "git fetch origin ASG_REPO_BRANCH",
    "git reset --hard origin/ASG_REPO_BRANCH",
    "scripts/dr/bootstrap-asg-web-node.sh",
    "print safe diagnostics after failure only",
  ]) {
    if (!userDataBehaviors.includes(behavior)) failures.push(`ASG rolling policy checklist userdata_required_behaviors must include ${behavior}.`);
  }
  const smokeTests = new Set(asgRollingPolicyChecklist.smoke_tests || []);
  for (const name of ["/healthz", "/api/health/ready", "target_group_healthy_count", "alb_5xx", "target_5xx", "target_response_time"]) {
    if (!smokeTests.has(name)) failures.push(`ASG rolling policy checklist smoke_tests must include ${name}.`);
  }
  for (const region of ["mumbai", "capetown"]) {
    const names = asgRollingPolicyChecklist.rollback_alarm_names?.[region];
    if (!Array.isArray(names) || names.length < 4) {
      failures.push(`ASG rolling policy checklist rollback_alarm_names.${region} must define at least four placeholder alarm names.`);
    }
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
