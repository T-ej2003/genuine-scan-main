#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";

const root = process.cwd();
const failures = [];

const read = (repoPath) => {
  const filePath = path.join(root, repoPath);
  if (!fs.existsSync(filePath)) {
    failures.push(`Missing required file: ${repoPath}`);
    return "";
  }
  return fs.readFileSync(filePath, "utf8");
};

const requireMatch = (label, source, pattern, message) => {
  if (!pattern.test(source)) failures.push(`${label}: ${message}`);
};

const forbidMatch = (label, source, pattern, message) => {
  if (pattern.test(source)) failures.push(`${label}: ${message}`);
};

const parseJson = (repoPath, source) => {
  try {
    return JSON.parse(source);
  } catch (error) {
    failures.push(`${repoPath}: invalid JSON: ${error.message}`);
    return null;
  }
};

const asgCompose = read("docker-compose.asg-web.yml");
const productionCompose = read("docker-compose.yml");
const localCompose = read("docker-compose.local.yml");
const deployPlaybook = read("ops/deploy/deploy.yml");
const standbyDeployPlaybook = read("ops/deploy/deploy-standby.yml");
const bootstrap = read("scripts/dr/bootstrap-asg-web-node.sh");
const manifestRaw = read("documents/ops/aws-asg-web-ssm-parameter-manifest.json");
const packageJsonRaw = read("package.json");
const topRunbook = read("documents/ops/aws-multi-region-disaster-recovery-runbook.md");
const phaseRunbook = read("documents/ops/aws-multi-region-phase-6.md");
const phaseCRunbook = read("documents/ops/object-storage-recovery/minio-decommission-s3-proof-runbook.md");
const recoveryReadme = read("documents/ops/object-storage-recovery/README.md");

const manifest = parseJson("documents/ops/aws-asg-web-ssm-parameter-manifest.json", manifestRaw);
const packageJson = parseJson("package.json", packageJsonRaw);

forbidMatch("production compose", productionCompose, /^\s{2}minio:/m, "docker-compose.yml must not define a production MinIO service.");
forbidMatch("production compose", productionCompose, /^\s{2}minio-init:/m, "docker-compose.yml must not define a production MinIO init service.");
forbidMatch("production compose", productionCompose, /minio\/(?:minio|mc)/i, "docker-compose.yml must not use MinIO images in the production path.");
forbidMatch("production compose", productionCompose, /\bminio_data\b/i, "docker-compose.yml must not define or mount MinIO volumes in the production path.");
forbidMatch("production compose", productionCompose, /depends_on:[\s\S]{0,240}\bminio(?:-init)?\b/i, "production services must not depend on MinIO.");
requireMatch("local compose override", localCompose, /^\s{2}minio:\n\s+image:\s+minio\/minio:/m, "docker-compose.local.yml must keep MinIO for local development.");
requireMatch("local compose override", localCompose, /^\s+profiles:\n\s+- local-minio/m, "local MinIO must require the explicit local-minio profile.");
requireMatch("local compose override", localCompose, /^\s{2}minio-init:\n\s+image:\s+minio\/mc:/m, "docker-compose.local.yml must keep MinIO bucket bootstrap for local development.");
requireMatch("local compose override", localCompose, /^\s{2}minio_data:/m, "docker-compose.local.yml must keep the local MinIO volume declaration.");

for (const [label, source] of [
  ["production deploy playbook", deployPlaybook],
  ["standby deploy playbook", standbyDeployPlaybook],
]) {
  requireMatch(label, source, /docker compose --profile worker build backend worker frontend/, "deploy builds must target production services explicitly.");
  requireMatch(label, source, /docker compose --profile worker up -d --no-build redis backend worker frontend/, "deploy up must target redis, backend, worker, and frontend explicitly.");
  forbidMatch(label, source, /docker compose --profile worker up -d --no-build\s*(?:\n|$)/, "deploy must not run a bare profile up that can start local-only services.");
}

forbidMatch("ASG compose", asgCompose, /^\s{2}minio:/m, "docker-compose.asg-web.yml must not define a MinIO service.");
forbidMatch("ASG compose", asgCompose, /^\s{2}minio-init:/m, "docker-compose.asg-web.yml must not define a MinIO init service.");
forbidMatch("ASG compose", asgCompose, /minio\/(?:minio|mc)/i, "docker-compose.asg-web.yml must not use MinIO images.");
forbidMatch("ASG compose", asgCompose, /\bminio_data\b/i, "docker-compose.asg-web.yml must not define or mount MinIO volumes.");
forbidMatch("ASG compose", asgCompose, /condition:\s+service_(?:healthy|completed_successfully)[\s\S]{0,120}\bminio\b/i, "ASG web services must not depend on MinIO.");
requireMatch("ASG compose", asgCompose, /OBJECT_STORAGE_BUCKET:\s+\$\{OBJECT_STORAGE_BUCKET:\?Set shared regional OBJECT_STORAGE_BUCKET/, "ASG web mode must require shared regional S3 object storage.");
requireMatch("ASG compose", asgCompose, /OBJECT_STORAGE_ENDPOINT:\s+\$\{OBJECT_STORAGE_ENDPOINT:-\}/, "ASG web mode must default object storage endpoint to empty.");
requireMatch("ASG compose", asgCompose, /OBJECT_STORAGE_ACCESS_KEY:\s+\$\{OBJECT_STORAGE_ACCESS_KEY:-\}/, "ASG web mode must default static object storage access key to empty.");
requireMatch("ASG compose", asgCompose, /OBJECT_STORAGE_SECRET_KEY:\s+\$\{OBJECT_STORAGE_SECRET_KEY:-\}/, "ASG web mode must default static object storage secret key to empty.");
requireMatch("ASG compose", asgCompose, /OBJECT_STORAGE_FORCE_PATH_STYLE:\s+\$\{OBJECT_STORAGE_FORCE_PATH_STYLE:-false\}/, "ASG web mode must default path-style addressing to false.");

requireMatch("ASG bootstrap", bootstrap, /forbiddenObjectStorageInputs/, "bootstrap must explicitly reject object-storage endpoint/static credential SSM inputs.");
requireMatch("ASG bootstrap", bootstrap, /OBJECT_STORAGE_ENDPOINT[\s\S]*MinIO\/custom object-storage endpoints are forbidden/, "bootstrap must reject MinIO/custom object-storage endpoints in ASG web mode.");
requireMatch("ASG bootstrap", bootstrap, /OBJECT_STORAGE_ACCESS_KEY[\s\S]*static object-storage access keys are forbidden/, "bootstrap must reject static object-storage access keys in ASG web mode.");
requireMatch("ASG bootstrap", bootstrap, /OBJECT_STORAGE_SECRET_KEY[\s\S]*static object-storage secret keys are forbidden/, "bootstrap must reject static object-storage secret keys in ASG web mode.");
requireMatch("ASG bootstrap", bootstrap, /OBJECT_STORAGE_FORCE_PATH_STYLE=true is forbidden/, "bootstrap must reject MinIO-style path addressing in ASG web mode.");
requireMatch("ASG bootstrap", bootstrap, /Remove \$\{ssmPrefix\}\$\{key\}; value was not printed/, "bootstrap must not print rejected object-storage parameter values.");

if (manifest) {
  const rootForced = manifest.rootEnv?.forced || {};
  const backendForced = manifest.backendEnv?.forced || {};
  const rootExcluded = new Set(manifest.rootEnv?.excluded || []);
  const backendExcluded = new Set(manifest.backendEnv?.excluded || []);
  for (const key of ["MINIO_ROOT_USER", "MINIO_ROOT_PASSWORD"]) {
    if (!rootExcluded.has(key) || !backendExcluded.has(key)) {
      failures.push(`ASG SSM manifest must exclude ${key} from rootEnv and backendEnv.`);
    }
  }
  for (const [key, expected] of Object.entries({
    OBJECT_STORAGE_ENDPOINT: "",
    OBJECT_STORAGE_ACCESS_KEY: "",
    OBJECT_STORAGE_SECRET_KEY: "",
    OBJECT_STORAGE_FORCE_PATH_STYLE: "false",
  })) {
    if (rootForced[key] !== expected) failures.push(`ASG SSM manifest rootEnv.forced.${key} must be ${JSON.stringify(expected)}.`);
    if (backendForced[key] !== expected) failures.push(`ASG SSM manifest backendEnv.forced.${key} must be ${JSON.stringify(expected)}.`);
  }
}

requireMatch("top DR runbook", topRunbook, /Phase A[\s\S]*complete/i, "top DR runbook must mark Phase A DB recovery complete.");
requireMatch("top DR runbook", topRunbook, /Phase B[\s\S]*complete for Mumbai/i, "top DR runbook must mark Phase B controlled Route 53 cutover complete for Mumbai.");
requireMatch("top DR runbook", topRunbook, /Phase C[\s\S]*active/i, "top DR runbook must mark Phase C S3 proof active.");
requireMatch("top DR runbook", topRunbook, /Phase D[\s\S]*blocked until Phase C is complete/i, "top DR runbook must keep Phase D automatic failover blocked.");
forbidMatch("top DR runbook", topRunbook, /production DNS (?:is |remains |currently )?(?:rolled back to|on|points to) London/i, "top DR runbook must not describe current production DNS as London.");

requireMatch("Phase C overview", phaseRunbook, /S3 proof/i, "Phase C overview must describe the active S3 proof phase.");
requireMatch("Phase C overview", phaseRunbook, /Do not delete MinIO data automatically/i, "Phase C overview must explicitly forbid automatic MinIO data deletion.");
requireMatch("Phase C overview", phaseRunbook, /automatic failover[\s\S]*blocked until Phase C is complete/i, "Phase C overview must block automatic failover until Phase C is complete.");
forbidMatch("Phase C overview", phaseRunbook, /No MinIO cleanup approval/i, "Phase C overview must not say the Phase C proof is excluded.");
forbidMatch("Phase C overview", phaseRunbook, /Do not decommission MinIO\./i, "Phase C overview must not prohibit the Phase C proof itself; it must prohibit automatic deletion instead.");

for (const [label, source] of [
  ["Phase C runbook", phaseCRunbook],
  ["object-storage recovery README", recoveryReadme],
]) {
  requireMatch(label, source, /Phase C/i, "must identify Phase C.");
  requireMatch(label, source, /S3 proof/i, "must identify S3 proof.");
  requireMatch(label, source, /Do not delete MinIO data automatically/i, "must explicitly forbid automatic MinIO data deletion.");
  requireMatch(label, source, /read-path proof/i, "must include read-path proof.");
  requireMatch(label, source, /write gate approval/i, "must gate write-path proof.");
}

if (packageJson) {
  const scripts = packageJson.scripts || {};
  if (scripts["check:minio-decommission-readiness"] !== "node scripts/dr/check-minio-decommission-readiness.mjs") {
    failures.push("package.json must expose check:minio-decommission-readiness.");
  }
  if (!String(scripts["verify:guardrails"] || "").includes("check:minio-decommission-readiness")) {
    failures.push("verify:guardrails must run check:minio-decommission-readiness.");
  }
}

if (failures.length > 0) {
  console.error("Phase C S3 proof readiness check failed:");
  for (const failure of failures) console.error(`- ${failure}`);
  process.exit(1);
}

console.log("Phase C S3 proof readiness check passed.");
