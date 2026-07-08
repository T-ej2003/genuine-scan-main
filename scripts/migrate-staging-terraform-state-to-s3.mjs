#!/usr/bin/env node
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import process from "node:process";
import { spawnSync } from "node:child_process";
import { pathToFileURL } from "node:url";

import { backendConfig, evaluateBackendBootstrapIdentity, validateBackendProfile } from "./bootstrap-staging-terraform-backend.mjs";

const repoRoot = path.resolve(new URL("..", import.meta.url).pathname);
const terraformRoot = "infra/terraform/staging-api";
const terraformRootAbs = path.join(repoRoot, terraformRoot);
const evidenceDirRel = ".terraform-plans/staging";
const evidenceDirAbs = path.join(repoRoot, evidenceDirRel);
const defaultExpectedCount = 39;
const requiredConfirmation = "MSCQR_MIGRATE_STAGING_TERRAFORM_STATE_ONCE";
const productionPattern = /(^|[^a-z0-9])(prod|production)([^a-z0-9]|$)|mscqr-prod|mscqr\.com/i;
const requiredAddresses = [
  "aws_ecs_service.backend",
  "aws_db_instance.staging",
  "aws_elasticache_replication_group.staging",
  "aws_lb.staging",
  "aws_vpc_security_group_ingress_rule.alb_operator_http[\"46.208.2.24/32\"]",
];

export function usage() {
  return `Usage: node scripts/migrate-staging-terraform-state-to-s3.mjs --source-state <path> [--expected-count 39]

Validates an explicit local staging state backup and, only after explicit gates,
runs terraform init -migrate-state against the configured S3 backend from a
temporary Terraform working copy.

Required gates:
  MSCQR_STAGING_TERRAFORM_STATE_MIGRATION_ENABLED=true
  MSCQR_STAGING_TERRAFORM_STATE_MIGRATION_CONFIRM=MSCQR_MIGRATE_STAGING_TERRAFORM_STATE_ONCE

This script never invents state, never prints state contents, never commits
state, and writes only redacted migration evidence under .terraform-plans/staging/.`;
}

export function checkMigrationEnvGates(env = process.env) {
  const failures = [];
  if (env.MSCQR_STAGING_TERRAFORM_STATE_MIGRATION_ENABLED !== "true") {
    failures.push("MSCQR_STAGING_TERRAFORM_STATE_MIGRATION_ENABLED must be true.");
  }
  if (env.MSCQR_STAGING_TERRAFORM_STATE_MIGRATION_CONFIRM !== requiredConfirmation) {
    failures.push(`MSCQR_STAGING_TERRAFORM_STATE_MIGRATION_CONFIRM must be ${requiredConfirmation}.`);
  }
  return failures;
}

function parseArgs(argv) {
  const parsed = { sourceState: null, expectedCount: defaultExpectedCount };
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === "--source-state") {
      parsed.sourceState = argv[index + 1] || null;
      index += 1;
    } else if (arg === "--expected-count") {
      parsed.expectedCount = Number(argv[index + 1]);
      index += 1;
    } else {
      throw new Error(`Unsupported argument: ${arg}`);
    }
  }
  if (!parsed.sourceState) throw new Error("--source-state is required.");
  if (!Number.isInteger(parsed.expectedCount) || parsed.expectedCount < 1) {
    throw new Error("--expected-count must be a positive integer.");
  }
  return parsed;
}

function addressFor(resource, instance) {
  const prefix = resource.module ? `${resource.module}.` : "";
  const base = `${prefix}${resource.type}.${resource.name}`;
  if (!Object.hasOwn(instance || {}, "index_key")) return base;
  const key = instance.index_key;
  if (typeof key === "number") return `${base}[${key}]`;
  return `${base}[${JSON.stringify(String(key))}]`;
}

function collectProductionLookingPaths(value, currentPath = "$", matches = []) {
  if (matches.length >= 20) return matches;
  if (typeof value === "string") {
    if (productionPattern.test(value)) matches.push(currentPath);
    return matches;
  }
  if (Array.isArray(value)) {
    value.forEach((entry, index) => collectProductionLookingPaths(entry, `${currentPath}[${index}]`, matches));
    return matches;
  }
  if (value && typeof value === "object") {
    for (const [key, entry] of Object.entries(value)) {
      collectProductionLookingPaths(entry, `${currentPath}.${key}`, matches);
      if (matches.length >= 20) break;
    }
  }
  return matches;
}

export function inspectStateSource({ sourceStatePath, expectedCount = defaultExpectedCount } = {}) {
  if (!sourceStatePath) throw new Error("--source-state is required.");
  const sourceStateAbs = path.resolve(repoRoot, sourceStatePath);
  if (!fs.existsSync(sourceStateAbs)) throw new Error("Source state file does not exist.");
  if (!fs.statSync(sourceStateAbs).isFile()) throw new Error("Source state path must be a file.");

  let state;
  try {
    state = JSON.parse(fs.readFileSync(sourceStateAbs, "utf8"));
  } catch {
    throw new Error("Source state file is not valid JSON.");
  }

  const resources = Array.isArray(state.resources) ? state.resources : [];
  const managedAddresses = [];
  for (const resource of resources.filter((entry) => entry.mode === "managed")) {
    const instances = Array.isArray(resource.instances) && resource.instances.length > 0 ? resource.instances : [{}];
    for (const instance of instances) managedAddresses.push(addressFor(resource, instance));
  }
  managedAddresses.sort();

  const missingRequiredAddresses = requiredAddresses.filter((address) => !managedAddresses.includes(address));
  const productionLookingPaths = collectProductionLookingPaths(state);
  const blockers = [];
  if (managedAddresses.length !== expectedCount) blockers.push("managed_resource_count_mismatch");
  if (missingRequiredAddresses.length > 0) blockers.push("missing_required_resource_addresses");
  if (productionLookingPaths.length > 0) blockers.push("production_looking_state_value");

  return {
    sourceStateAbs,
    sourceStateRel: path.relative(repoRoot, sourceStateAbs),
    expectedCount,
    managedResourceCount: managedAddresses.length,
    requiredAddresses,
    missingRequiredAddresses,
    productionLookingPathCount: productionLookingPaths.length,
    productionLookingPaths,
    blockers,
  };
}

function safeBlocked(reason, details = {}) {
  return {
    status: "blocked_before_state_migration",
    reason,
    ...details,
    migrationAttempted: false,
    mutatesBackendStorage: false,
    mutatesAppResources: false,
    rawStatePrinted: false,
    rawSecretValuesPrinted: false,
  };
}

function runAwsIdentity(env) {
  const result = spawnSync("aws", ["sts", "get-caller-identity", "--output", "json"], {
    env,
    encoding: "utf8",
    maxBuffer: 1024 * 1024,
    stdio: ["ignore", "pipe", "pipe"],
  });
  if (result.error?.code === "ENOENT") throw new Error("AWS CLI is not installed or is not on PATH.");
  if (result.error || result.status !== 0) throw new Error("aws sts get-caller-identity failed.");
  return JSON.parse(result.stdout);
}

function copyTerraformRootForMigration(tempRoot, sourceStateAbs) {
  const tempTfRoot = path.join(tempRoot, terraformRoot);
  fs.cpSync(terraformRootAbs, tempTfRoot, {
    recursive: true,
    filter: (src) => {
      const rel = path.relative(terraformRootAbs, src);
      if (!rel) return true;
      const base = path.basename(src);
      if (rel === ".terraform" || rel.startsWith(`.terraform${path.sep}`)) return false;
      if (base === "terraform.tfstate" || base === "terraform.tfstate.backup") return false;
      if (base.endsWith(".tfstate") || base.includes(".tfstate.")) return false;
      if (base === "staging.auto.tfvars" || base === "terraform.tfvars" || base.endsWith(".local.tfvars")) return false;
      return true;
    },
  });
  fs.copyFileSync(sourceStateAbs, path.join(tempTfRoot, "terraform.tfstate"));
  return tempTfRoot;
}

function runTerraformInitMigrate({ sourceStateAbs, env }) {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-staging-state-migration-"));
  try {
    copyTerraformRootForMigration(tempRoot, sourceStateAbs);
    const result = spawnSync("terraform", [
      `-chdir=${path.join(tempRoot, terraformRoot)}`,
      "init",
      "-migrate-state",
      "-force-copy",
      "-input=false",
      "-no-color",
    ], {
      cwd: repoRoot,
      env: {
        ...env,
        TF_IN_AUTOMATION: "1",
        TF_INPUT: "0",
        TF_DATA_DIR: path.join(tempRoot, "tf-data"),
      },
      encoding: "utf8",
      maxBuffer: 128 * 1024 * 1024,
      stdio: ["ignore", "pipe", "pipe"],
    });

    if (result.error?.code === "ENOENT") {
      const error = new Error("Terraform is not installed or is not on PATH.");
      error.migrationAttempted = false;
      throw error;
    }
    if (result.error || result.status !== 0) {
      const error = new Error("terraform init -migrate-state failed; raw output was not printed.");
      error.migrationAttempted = true;
      error.terraformExitStatus = result.status;
      error.terraformSignal = result.signal;
      throw error;
    }
  } finally {
    fs.rmSync(tempRoot, { recursive: true, force: true });
  }
}

function writeEvidence(payload) {
  fs.mkdirSync(evidenceDirAbs, { recursive: true });
  const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
  const rel = path.join(evidenceDirRel, `staging-state-migration-${timestamp}.evidence.json`);
  fs.writeFileSync(path.join(repoRoot, rel), `${JSON.stringify(payload, null, 2)}\n`, "utf8");
  return rel;
}

export function runMigrationWorkflow({
  argv = [],
  env = process.env,
  deps = {
    getIdentity: () => runAwsIdentity(env),
    migrate: runTerraformInitMigrate,
    writeEvidence,
  },
} = {}) {
  if (argv.includes("--help") || argv.includes("-h")) return { exitCode: 0, payload: { usage: usage() } };

  let args;
  let stateInspection;
  try {
    args = parseArgs(argv);
    stateInspection = inspectStateSource({
      sourceStatePath: args.sourceState,
      expectedCount: args.expectedCount,
    });
  } catch (error) {
    return { exitCode: 1, payload: safeBlocked(error.message) };
  }

  if (stateInspection.blockers.length > 0) {
    return {
      exitCode: 1,
      payload: safeBlocked("Source state did not pass migration safety checks.", {
        managedResourceCount: stateInspection.managedResourceCount,
        expectedCount: stateInspection.expectedCount,
        missingRequiredAddresses: stateInspection.missingRequiredAddresses,
        productionLookingPathCount: stateInspection.productionLookingPathCount,
        blockerCodes: stateInspection.blockers,
      }),
    };
  }

  const profileFailures = validateBackendProfile(env);
  const gateFailures = checkMigrationEnvGates(env);
  if (profileFailures.length > 0 || gateFailures.length > 0) {
    return {
      exitCode: 1,
      payload: safeBlocked("Staging Terraform state migration guardrails failed before identity check.", {
        failures: [...profileFailures, ...gateFailures],
      }),
    };
  }

  let identityCheck;
  try {
    identityCheck = evaluateBackendBootstrapIdentity({ identity: deps.getIdentity(), env });
  } catch (error) {
    return { exitCode: 1, payload: safeBlocked("AWS identity guard failed before state migration.", {
      identityCheck: {
        account: null,
        arnType: "unknown",
        classification: "blocked",
        region: env.AWS_REGION || env.AWS_DEFAULT_REGION || null,
        allowed: false,
        refusalReason: error.message,
      },
    }) };
  }
  if (!identityCheck.allowed) {
    return { exitCode: 1, payload: safeBlocked("AWS identity guard failed before state migration.", { identityCheck }) };
  }

  const evidenceBase = {
    checkedAt: new Date().toISOString(),
    terraformRoot,
    backend: {
      bucket: backendConfig.bucket,
      key: backendConfig.key,
      region: backendConfig.region,
      encrypt: true,
      lockMechanism: "s3_lockfile",
      lockKey: backendConfig.lockKey,
    },
    sourceStatePath: stateInspection.sourceStateRel.startsWith("..") ? "<external-source-state>" : stateInspection.sourceStateRel,
    managedResourceCount: stateInspection.managedResourceCount,
    expectedCount: stateInspection.expectedCount,
    requiredAddressesPresent: true,
    identityCheck,
    rawStatePrinted: false,
    rawSecretValuesPrinted: false,
    mutatesAppResources: false,
  };

  try {
    deps.migrate({ sourceStateAbs: stateInspection.sourceStateAbs, env });
    const evidencePath = deps.writeEvidence({
      status: "state_migration_completed",
      ...evidenceBase,
      migrationAttempted: true,
      mutatesBackendStorage: true,
    });
    return {
      exitCode: 0,
      payload: {
        status: "state_migration_completed",
        backend: evidenceBase.backend,
        managedResourceCount: stateInspection.managedResourceCount,
        evidencePath,
        migrationAttempted: true,
        mutatesBackendStorage: true,
        mutatesAppResources: false,
        rawStatePrinted: false,
        rawSecretValuesPrinted: false,
      },
    };
  } catch (error) {
    const evidencePath = deps.writeEvidence({
      status: "state_migration_failed",
      ...evidenceBase,
      migrationAttempted: error.migrationAttempted !== false,
      mutatesBackendStorage: error.migrationAttempted !== false,
      terraformExitStatus: Number.isInteger(error.terraformExitStatus) ? error.terraformExitStatus : null,
      terraformSignal: error.terraformSignal || null,
      errorMessage: error.message,
    });
    return {
      exitCode: 1,
      payload: {
        status: "state_migration_failed",
        reason: error.message,
        evidencePath,
        migrationAttempted: error.migrationAttempted !== false,
        mutatesBackendStorage: error.migrationAttempted !== false,
        mutatesAppResources: false,
        rawStatePrinted: false,
        rawSecretValuesPrinted: false,
      },
    };
  }
}

export function main(argv = process.argv.slice(2), env = process.env) {
  const result = runMigrationWorkflow({ argv, env });
  if (result.payload.usage) console.log(result.payload.usage);
  else console.log(JSON.stringify(result.payload, null, 2));
  return result.exitCode;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  process.exit(main());
}
