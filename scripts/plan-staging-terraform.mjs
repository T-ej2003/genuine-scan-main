#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { spawnSync } from "node:child_process";
import { pathToFileURL } from "node:url";

const repoRoot = path.resolve(new URL("..", import.meta.url).pathname);
const terraformRoot = "infra/terraform/staging-api";
const terraformRootAbs = path.join(repoRoot, terraformRoot);
const planDirRel = ".terraform-plans/staging";
const planDirAbs = path.join(repoRoot, planDirRel);
const requiredConfirmation = "MSCQR_GENERATE_STAGING_PLAN_ONLY";
const requiredPrivateVariables = [
  "account_id",
  "vpc_id",
  "public_subnet_ids",
  "app_private_subnet_ids",
  "db_private_subnet_ids",
  "allowed_operator_cidrs",
  "backend_image_uri",
  "staging_secret_arns",
];
const forbiddenArgFragments = ["apply", "destroy", "import", "taint", "untaint"];

export function usage() {
  return `Usage: node scripts/plan-staging-terraform.mjs

Generates a local-only Terraform plan for infra/terraform/staging-api.

Required confirmation:
  MSCQR_STAGING_TERRAFORM_PLAN_ENABLED=true
  MSCQR_STAGING_TERRAFORM_PLAN_CONFIRM=MSCQR_GENERATE_STAGING_PLAN_ONLY

Private input sources:
  infra/terraform/staging-api/staging.auto.tfvars
  infra/terraform/staging-api/*.local.tfvars
  TF_VAR_* environment variables

Outputs are written under .terraform-plans/staging/ and must not be committed.
This wrapper never runs terraform apply/destroy/import/state/taint/untaint.`;
}

export function findForbiddenPlanArgs(args) {
  const lowerArgs = args.map((arg) => String(arg).toLowerCase());
  const forbidden = [];
  for (const arg of lowerArgs) {
    if (forbiddenArgFragments.some((fragment) => arg.includes(fragment))) {
      forbidden.push(arg);
    }
  }
  for (let index = 0; index < lowerArgs.length - 1; index += 1) {
    if (lowerArgs[index] === "state" && lowerArgs[index + 1] === "rm") {
      forbidden.push("state rm");
    }
  }
  return forbidden;
}

export function checkPlanEnvGates(env = process.env) {
  const failures = [];
  if (env.MSCQR_STAGING_TERRAFORM_PLAN_ENABLED !== "true") {
    failures.push("MSCQR_STAGING_TERRAFORM_PLAN_ENABLED must be true.");
  }
  if (env.MSCQR_STAGING_TERRAFORM_PLAN_CONFIRM !== requiredConfirmation) {
    failures.push(`MSCQR_STAGING_TERRAFORM_PLAN_CONFIRM must be ${requiredConfirmation}.`);
  }
  return failures;
}

function readTopLevelTfvarsAssignments(filePath) {
  const source = fs.readFileSync(filePath, "utf8");
  const names = new Set();
  for (const line of source.split(/\r?\n/)) {
    const match = line.match(/^([A-Za-z_][A-Za-z0-9_]*)\s*=/);
    if (match) names.add(match[1]);
  }
  return names;
}

export function collectPrivateInputState({ root = repoRoot, env = process.env } = {}) {
  const rootAbs = path.join(root, terraformRoot);
  const entries = fs.existsSync(rootAbs) ? fs.readdirSync(rootAbs) : [];
  const allowedTfvars = [];
  const refusedTfvars = [];

  for (const entry of entries) {
    const rel = path.join(terraformRoot, entry);
    if (entry === "staging.auto.tfvars" || entry.endsWith(".local.tfvars")) {
      allowedTfvars.push(rel);
    } else if (
      entry === "terraform.tfvars" ||
      (entry.endsWith(".tfvars") && entry !== "terraform.tfvars.example") ||
      (entry.endsWith(".auto.tfvars") && entry !== "staging.auto.tfvars")
    ) {
      refusedTfvars.push(rel);
    }
  }

  const provided = new Set();
  for (const rel of allowedTfvars) {
    for (const name of readTopLevelTfvarsAssignments(path.join(root, rel))) {
      provided.add(name);
    }
  }
  for (const key of Object.keys(env)) {
    if (key.startsWith("TF_VAR_")) {
      provided.add(key.slice("TF_VAR_".length));
    }
  }

  return {
    allowedTfvars: allowedTfvars.sort(),
    refusedTfvars: refusedTfvars.sort(),
    hasTfVarEnv: Object.keys(env).some((key) => key.startsWith("TF_VAR_")),
    missingRequiredVariables: requiredPrivateVariables.filter((name) => !provided.has(name)),
  };
}

function blocked(reason, details = {}) {
  return {
    status: "blocked_before_plan",
    reason,
    ...details,
    applyAllowed: false,
  };
}

function printSafeJson(payload) {
  console.log(JSON.stringify(payload, null, 2));
}

function runCommand(command, args, options = {}) {
  const result = spawnSync(command, args, {
    cwd: repoRoot,
    env: options.env || process.env,
    encoding: "utf8",
    maxBuffer: 128 * 1024 * 1024,
    stdio: options.capture ? ["ignore", "pipe", "pipe"] : "inherit",
  });

  if (result.error?.code === "ENOENT") {
    throw new Error(`${command} is not installed or is not on PATH.`);
  }
  if (result.error) {
    throw new Error(`${command} failed: ${result.error.message}`);
  }
  if (result.status !== 0) {
    const error = new Error(`${command} ${args.join(" ")} failed with exit code ${result.status}.`);
    error.result = result;
    throw error;
  }
  return result;
}

function runIdentityGuard(env) {
  const result = spawnSync(process.execPath, ["scripts/check-staging-aws-identity.mjs"], {
    cwd: repoRoot,
    env,
    encoding: "utf8",
    maxBuffer: 1024 * 1024,
    stdio: ["ignore", "pipe", "pipe"],
  });

  let parsed = null;
  try {
    parsed = JSON.parse(result.stdout);
  } catch {
    parsed = {
      account: null,
      arnType: "unknown",
      classification: "blocked",
      region: env.AWS_REGION || env.AWS_DEFAULT_REGION || null,
      allowed: false,
      refusalReason: "Identity guard did not return valid JSON.",
    };
  }

  return { ok: result.status === 0 && parsed.allowed === true, identityCheck: parsed };
}

function parsePlanCounts(planText, showJson) {
  const textMatch = planText.match(/Plan:\s+([0-9]+)\s+to add,\s+([0-9]+)\s+to change,\s+([0-9]+)\s+to destroy\./);
  if (textMatch) {
    return {
      add: Number(textMatch[1]),
      change: Number(textMatch[2]),
      destroy: Number(textMatch[3]),
    };
  }

  const counts = { add: 0, change: 0, destroy: 0 };
  for (const resource of showJson?.resource_changes || []) {
    const actions = resource.change?.actions || [];
    if (actions.includes("create") && !actions.includes("delete")) counts.add += 1;
    else if (actions.includes("delete") && !actions.includes("create")) counts.destroy += 1;
    else if (actions.includes("update") || (actions.includes("delete") && actions.includes("create"))) counts.change += 1;
  }
  return counts;
}

export function main(argv = process.argv.slice(2), env = process.env) {
  if (argv.includes("--help") || argv.includes("-h")) {
    console.log(usage());
    return 0;
  }

  const forbidden = findForbiddenPlanArgs(argv);
  if (forbidden.length > 0 || argv.length > 0) {
    printSafeJson(blocked("Unsupported or forbidden arguments were provided.", { forbiddenArgs: forbidden }));
    return 1;
  }

  if (path.resolve(process.cwd()) !== repoRoot) {
    printSafeJson(blocked("Run this wrapper from the repository root."));
    return 1;
  }

  const gateFailures = checkPlanEnvGates(env);
  if (gateFailures.length > 0) {
    printSafeJson(blocked("Missing explicit staging Terraform plan confirmation.", { gateFailures }));
    return 1;
  }

  if (!fs.existsSync(terraformRootAbs)) {
    printSafeJson(blocked("Terraform root not found.", { terraformRoot }));
    return 1;
  }

  const inputState = collectPrivateInputState({ root: repoRoot, env });
  if (inputState.refusedTfvars.length > 0) {
    printSafeJson(blocked("Refusing tfvars outside the approved private local paths.", { inputState }));
    return 1;
  }
  if (inputState.allowedTfvars.length === 0 && !inputState.hasTfVarEnv) {
    printSafeJson(blocked("No private tfvars or TF_VAR_* inputs were found.", { inputState }));
    return 1;
  }
  if (inputState.missingRequiredVariables.length > 0) {
    printSafeJson(blocked("Required private Terraform inputs are missing.", { inputState }));
    return 1;
  }

  const identity = runIdentityGuard(env);
  if (!identity.ok) {
    printSafeJson(blocked("AWS identity guard failed.", { identityCheck: identity.identityCheck }));
    return 1;
  }

  fs.mkdirSync(planDirAbs, { recursive: true });
  const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
  const planBase = `staging-plan-${timestamp}`;
  const planFileRel = path.join(planDirRel, `${planBase}.tfplan`);
  const planTextRel = path.join(planDirRel, `${planBase}.txt`);
  const planSummaryRel = path.join(planDirRel, `${planBase}.summary.json`);
  const planErrorRel = path.join(planDirRel, `${planBase}.error.txt`);
  const planFileAbs = path.join(repoRoot, planFileRel);
  const planTextAbs = path.join(repoRoot, planTextRel);
  const planSummaryAbs = path.join(repoRoot, planSummaryRel);
  const planErrorAbs = path.join(repoRoot, planErrorRel);

  const terraformEnv = {
    ...env,
    TF_IN_AUTOMATION: "1",
    TF_INPUT: "0",
  };
  const localVarArgs = inputState.allowedTfvars
    .filter((rel) => rel.endsWith(".local.tfvars"))
    .flatMap((rel) => [`-var-file=${path.relative(terraformRootAbs, path.join(repoRoot, rel))}`]);

  try {
    console.log(`$ terraform -chdir=${terraformRoot} init`);
    runCommand("terraform", [`-chdir=${terraformRoot}`, "init"], { env: terraformEnv });
    console.log(`$ terraform -chdir=${terraformRoot} fmt -check`);
    runCommand("terraform", [`-chdir=${terraformRoot}`, "fmt", "-check"], { env: terraformEnv });
    console.log(`$ terraform -chdir=${terraformRoot} validate`);
    runCommand("terraform", [`-chdir=${terraformRoot}`, "validate"], { env: terraformEnv });
    console.log(`$ terraform -chdir=${terraformRoot} plan -out=${planFileRel}`);
    const plan = runCommand(
      "terraform",
      [`-chdir=${terraformRoot}`, "plan", `-out=${path.relative(terraformRootAbs, planFileAbs)}`, ...localVarArgs],
      { env: terraformEnv, capture: true },
    );
    fs.writeFileSync(planTextAbs, plan.stdout || "", "utf8");

    const showText = runCommand("terraform", [`-chdir=${terraformRoot}`, "show", "-no-color", path.relative(terraformRootAbs, planFileAbs)], {
      env: terraformEnv,
      capture: true,
    });
    fs.writeFileSync(planTextAbs, showText.stdout || plan.stdout || "", "utf8");

    const showJsonRaw = runCommand("terraform", [`-chdir=${terraformRoot}`, "show", "-json", path.relative(terraformRootAbs, planFileAbs)], {
      env: terraformEnv,
      capture: true,
    }).stdout;
    const showJson = JSON.parse(showJsonRaw);
    const counts = parsePlanCounts(plan.stdout || showText.stdout || "", showJson);
    const summary = {
      status: "plan_generated",
      timestamp,
      terraformRoot,
      modulePath: terraformRoot,
      planFilePath: planFileRel,
      planTextPath: planTextRel,
      planSummaryPath: planSummaryRel,
      counts,
      identityCheck: identity.identityCheck,
      privateInputSources: {
        allowedTfvars: inputState.allowedTfvars,
        hasTfVarEnv: inputState.hasTfVarEnv,
      },
      applyAllowed: false,
    };
    fs.writeFileSync(planSummaryAbs, `${JSON.stringify(summary, null, 2)}\n`, "utf8");
    printSafeJson(summary);
    return counts.destroy > 0 ? 2 : 0;
  } catch (error) {
    const privateError = [
      error.message,
      error.result?.stdout || "",
      error.result?.stderr || "",
    ].filter(Boolean).join("\n");
    fs.writeFileSync(planErrorAbs, privateError, "utf8");
    printSafeJson(blocked("Terraform plan workflow failed before a usable plan was generated.", {
      errorEvidencePath: planErrorRel,
      identityCheck: identity.identityCheck,
    }));
    return 1;
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  process.exit(main());
}
