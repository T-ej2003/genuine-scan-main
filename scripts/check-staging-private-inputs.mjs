#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { spawnSync } from "node:child_process";
import { pathToFileURL } from "node:url";

const repoRoot = path.resolve(new URL("..", import.meta.url).pathname);
const terraformRoot = "infra/terraform/staging-api";
const requiredKeys = [
  "account_id",
  "vpc_id",
  "public_subnet_ids",
  "app_private_subnet_ids",
  "db_private_subnet_ids",
  "allowed_operator_cidrs",
  "backend_image_uri",
  "staging_secret_arns",
];
const gitignoreProbePaths = [
  "infra/terraform/staging-api/staging.auto.tfvars",
  "infra/terraform/staging-api/example.local.tfvars",
];
const productionFragments = [
  "prod",
  "production",
  "mscqr-prod",
  "mscqr-prod-db-proxy",
];
const sensitiveWarningPatterns = [
  { code: "access_key_literal", regex: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g },
  { code: "private_key_block", regex: /-----BEGIN [A-Z ]*PRIVATE KEY-----/g },
  { code: "password_like_key", regex: /\bpassword\b\s*=/gi },
  { code: "token_like_key", regex: /\b(?:token|session)_?[A-Za-z0-9_]*\b\s*=/gi },
  { code: "session_credential_name", regex: /\bAWS_SESSION_TOKEN\b/g },
];

export function usage() {
  return `Usage: node scripts/check-staging-private-inputs.mjs [--strict]

Checks local private staging Terraform input files without printing raw values.

Allowed private tfvars paths:
  infra/terraform/staging-api/staging.auto.tfvars
  infra/terraform/staging-api/*.local.tfvars

Without --strict, missing private tfvars returns status blocked_missing_private_tfvars
with exit code 0. With --strict, missing tfvars or blockers exit nonzero.`;
}

function listPrivateTfvars(root = repoRoot) {
  const rootAbs = path.join(root, terraformRoot);
  if (!fs.existsSync(rootAbs)) return [];
  return fs.readdirSync(rootAbs)
    .filter((entry) => entry === "staging.auto.tfvars" || entry.endsWith(".local.tfvars"))
    .map((entry) => path.join(terraformRoot, entry))
    .sort();
}

function topLevelKeyRegex(key) {
  return new RegExp(`^\\s*${key}\\s*=`, "m");
}

function extractAssignment(source, key) {
  const match = source.match(new RegExp(`^\\s*${key}\\s*=\\s*([^\\n]+)`, "m"));
  return match?.[1] || "";
}

function extractListItems(source, key) {
  const list = source.match(new RegExp(`^\\s*${key}\\s*=\\s*\\[([\\s\\S]*?)\\]`, "m"));
  if (!list) return [];
  return [...list[1].matchAll(/"([^"]*)"/g)].map((match) => match[1]);
}

function addUnique(target, value) {
  if (!target.includes(value)) target.push(value);
}

export function evaluatePrivateInputSource(source) {
  const requiredKeysPresent = Object.fromEntries(
    requiredKeys.map((key) => [key, topLevelKeyRegex(key).test(source)]),
  );
  const blockers = [];
  const warnings = [];

  for (const [key, present] of Object.entries(requiredKeysPresent)) {
    if (!present) addUnique(blockers, `missing_required_key:${key}`);
  }

  const normalized = source.toLowerCase();
  for (const fragment of productionFragments) {
    if (normalized.includes(fragment)) addUnique(blockers, `production_fragment:${fragment}`);
  }

  const secretArnAssignment = extractAssignment(source, "staging_secret_arns");
  const secretBlockMarkerPresent = /mscqr\/staging\//i.test(source) || /REDACTED|ACCOUNT_ID/.test(secretArnAssignment);
  if (requiredKeysPresent.staging_secret_arns && !secretBlockMarkerPresent) {
    addUnique(blockers, "missing_staging_secret_marker");
  }

  const imageAssignment = extractAssignment(source, "backend_image_uri");
  if (requiredKeysPresent.backend_image_uri && !/(staging|stg|STAGING|STG|mscqr-backend)/.test(imageAssignment)) {
    addUnique(blockers, "backend_image_uri_missing_staging_marker");
  }

  for (const cidr of extractListItems(source, "allowed_operator_cidrs")) {
    if (cidr === "0.0.0.0/0" || cidr === "::/0") {
      addUnique(blockers, "operator_cidr_world_open");
      continue;
    }
    const ipv4Prefix = cidr.match(/^[0-9.x]+\/([0-9]{1,2})$/);
    if (ipv4Prefix && Number(ipv4Prefix[1]) < 24) {
      addUnique(blockers, "operator_cidr_too_broad_ipv4");
    }
  }

  for (const pattern of sensitiveWarningPatterns) {
    pattern.regex.lastIndex = 0;
    if (pattern.regex.test(source)) addUnique(warnings, pattern.code);
  }

  return { requiredKeysPresent, blockers, warnings };
}

function checkGitIgnored(root = repoRoot) {
  return Object.fromEntries(gitignoreProbePaths.map((relPath) => {
    const result = spawnSync("git", ["check-ignore", "--quiet", relPath], {
      cwd: root,
      stdio: "ignore",
    });
    return [relPath, result.status === 0];
  }));
}

export function evaluatePrivateInputs({ root = repoRoot } = {}) {
  const tfvarsFiles = listPrivateTfvars(root);
  const gitIgnored = checkGitIgnored(root);
  const gitignoreBlockers = Object.entries(gitIgnored)
    .filter(([, ignored]) => !ignored)
    .map(([relPath]) => `gitignore_missing:${relPath}`);

  if (tfvarsFiles.length === 0) {
    return {
      status: "blocked_missing_private_tfvars",
      foundTfvarsFile: false,
      requiredKeysPresent: Object.fromEntries(requiredKeys.map((key) => [key, false])),
      blockersCount: gitignoreBlockers.length,
      warningsCount: 0,
      blockerCodes: gitignoreBlockers,
      warningCodes: [],
      gitIgnored,
      rawValuesPrinted: false,
    };
  }

  const combined = tfvarsFiles.map((relPath) => fs.readFileSync(path.join(root, relPath), "utf8")).join("\n");
  const evaluated = evaluatePrivateInputSource(combined);
  const blockerCodes = [...evaluated.blockers, ...gitignoreBlockers].sort();
  const warningCodes = evaluated.warnings.sort();

  return {
    status: blockerCodes.length > 0 ? "blocked_private_tfvars_invalid" : "ok",
    foundTfvarsFile: true,
    requiredKeysPresent: evaluated.requiredKeysPresent,
    blockersCount: blockerCodes.length,
    warningsCount: warningCodes.length,
    blockerCodes,
    warningCodes,
    gitIgnored,
    rawValuesPrinted: false,
  };
}

export function main(argv = process.argv.slice(2)) {
  if (argv.includes("--help") || argv.includes("-h")) {
    console.log(usage());
    return 0;
  }

  const strict = argv.includes("--strict");
  const unsupported = argv.filter((arg) => arg !== "--strict");
  if (unsupported.length > 0) {
    console.log(JSON.stringify({
      status: "blocked_unsupported_arguments",
      foundTfvarsFile: false,
      requiredKeysPresent: {},
      blockersCount: 1,
      warningsCount: 0,
      rawValuesPrinted: false,
    }, null, 2));
    return 1;
  }

  if (path.resolve(process.cwd()) !== repoRoot) {
    console.log(JSON.stringify({
      status: "blocked_wrong_working_directory",
      foundTfvarsFile: false,
      requiredKeysPresent: {},
      blockersCount: 1,
      warningsCount: 0,
      rawValuesPrinted: false,
    }, null, 2));
    return 1;
  }

  const result = evaluatePrivateInputs({ root: repoRoot });
  console.log(JSON.stringify(result, null, 2));
  if (result.status === "ok") return 0;
  return strict ? 1 : 0;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  process.exit(main());
}
