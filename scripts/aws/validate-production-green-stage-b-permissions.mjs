#!/usr/bin/env node
import crypto from "node:crypto";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

export const PERMISSION_PREFLIGHT_SCHEMA_VERSION = 1;
export const PERMISSION_PREFLIGHT_MAX_AGE_MS = 15 * 60 * 1000;
export const PERMISSION_PREFLIGHT_CLOCK_SKEW_MS = 60 * 1000;
const ACCOUNT = "368992683803";
const REGION = "eu-west-2";
const RELEASE_ROLE_ARN = `arn:aws:iam::${ACCOUNT}:role/mscqr-production-release-deployer`;
const stageBRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const arnPattern = /^arn:aws:[^:]+:[^:]*:368992683803:.+$/;

const sha256 = (value) => crypto.createHash("sha256").update(value).digest("hex");
const exactActions = (actual, expected) => JSON.stringify(actual || []) === JSON.stringify(expected);

function readOption(argv, option) {
  const index = argv.indexOf(option);
  return index === -1 ? undefined : argv[index + 1];
}

function requireOption(argv, option) {
  const value = readOption(argv, option);
  if (!value || value.startsWith("--")) throw new Error(`${option} is required.`);
  return value;
}

export function parseCli(argv) {
  return {
    roleArn: requireOption(argv, "--role-arn"),
    planJsonPath: requireOption(argv, "--plan-json"),
    manifestPath: requireOption(argv, "--manifest"),
    outputPath: requireOption(argv, "--output"),
    savedPlanPath: requireOption(argv, "--saved-plan"),
    expectedAccount: requireOption(argv, "--expected-account"),
    expectedRegion: requireOption(argv, "--expected-region"),
    generatedAt: readOption(argv, "--generated-at") || new Date().toISOString(),
    policyPublishedAt: requireOption(argv, "--policy-published-at"),
    cloudTrailSessionName: requireOption(argv, "--cloudtrail-session-name"),
  };
}

export function canonicalizeJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalizeJson).join(",")}]`;
  if (value && typeof value === "object") return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalizeJson(value[key])}`).join(",")}}`;
  return JSON.stringify(value);
}

function assertContext(context, label) {
  if (!Array.isArray(context)) throw new Error(`${label} context must be an array.`);
  for (const entry of context) {
    if (!entry || typeof entry.key !== "string" || !entry.key || !["string", "stringList", "boolean", "numeric"].includes(entry.type)) {
      throw new Error(`${label} has malformed context.`);
    }
    if (!Array.isArray(entry.values) || entry.values.length === 0 || entry.values.some((value) => typeof value !== "string")) {
      throw new Error(`${label} has malformed context values.`);
    }
  }
}

const lambdaWriteActions = new Set([
  "lambda:UpdateFunctionConfiguration",
  "lambda:UpdateFunctionCode",
  "lambda:PublishVersion",
  "lambda:UpdateAlias",
]);
const requiredLambdaContext = new Map([
  ["aws:RequestedRegion", ["eu-west-2"]],
  ["aws:ResourceTag/Environment", ["production"]],
  ["aws:ResourceTag/ManagedBy", ["Terraform"]],
  ["aws:ResourceTag/Component", ["full-rls-green-stage-b"]],
]);

function assertExactContextValues(context, expected, label) {
  const actual = new Map(context.map((entry) => [entry.key, entry]));
  for (const [key, values] of expected) {
    const entry = actual.get(key);
    if (!entry || entry.type !== "string" || JSON.stringify(entry.values) !== JSON.stringify(values)) {
      throw new Error(`${label} must include exact ${key} context.`);
    }
  }
}

export function validateManifest(manifest, { account = ACCOUNT, region = REGION } = {}) {
  if (manifest?.schemaVersion !== PERMISSION_PREFLIGHT_SCHEMA_VERSION) throw new Error("Permission manifest schema version is unsupported.");
  if (manifest.accountId !== account || manifest.region !== region) throw new Error("Permission manifest account or region is wrong.");
  if (!Array.isArray(manifest.required) || !Array.isArray(manifest.forbidden)) throw new Error("Permission manifest sections are malformed.");
  const ids = new Set();
  for (const [entry, forbidden] of [...manifest.required.map((entry) => [entry, false]), ...manifest.forbidden.map((entry) => [entry, true])]) {
    if (!entry.id || ids.has(entry.id) || !/^[-a-z0-9]+$/.test(entry.id)) throw new Error(`Permission manifest entry id is invalid: ${entry.id || "missing"}.`);
    ids.add(entry.id);
    if (!/^[a-z0-9]+:[A-Za-z]+$/.test(entry.action || "")) throw new Error(`Permission manifest action is invalid: ${entry.id}.`);
    if (!Array.isArray(entry.resources) || entry.resources.length === 0 || entry.resources.some((resource) => resource !== "*" && !arnPattern.test(resource))) {
      throw new Error(`Permission manifest resources are invalid: ${entry.id}.`);
    }
    assertContext(entry.context, entry.id);
    if (lambdaWriteActions.has(entry.action)) {
      const expectedResource = entry.action === "lambda:UpdateAlias"
        ? "arn:aws:lambda:eu-west-2:368992683803:function:mscqr-production-rls-approval-broker:reviewed"
        : "arn:aws:lambda:eu-west-2:368992683803:function:mscqr-production-rls-approval-broker";
      if (entry.resources.length !== 1 || entry.resources[0] !== expectedResource) {
        throw new Error(`${entry.id} must target only the reviewed broker function.`);
      }
      assertExactContextValues(entry.context, requiredLambdaContext, entry.id);
    }
    if (entry.action === "iam:PassRole") {
      if (entry.resources.some((resource) => resource === "*" || resource.includes("*"))) throw new Error("PassRole may not use wildcard resources.");
      const service = entry.context.find((context) => context.key === "iam:PassedToService");
      if (!service || service.type !== "string" || service.values.length !== 1 || (!forbidden && service.values[0] !== "ecs-tasks.amazonaws.com")) {
        throw new Error(`PassRole entry ${entry.id} must require ECS tasks.`);
      }
    }
    if (entry.plan) {
      if (!entry.plan.type || !Array.isArray(entry.plan.actions)) throw new Error(`Permission manifest plan selector is malformed: ${entry.id}.`);
      if (entry.plan.address && typeof entry.plan.address !== "string") throw new Error(`Permission manifest plan address is malformed: ${entry.id}.`);
    }
  }
  return true;
}

function planMatches(selector, change) {
  if (!selector || change.type !== selector.type || !exactActions(change.change?.actions, selector.actions)) return false;
  if (selector.address && change.address !== selector.address) return false;
  if (selector.family && change.change?.after?.family !== selector.family) return false;
  return true;
}

function evaluation(entry, resource) {
  return {
    id: `${entry.id}:${resource}`,
    manifestId: entry.id,
    action: entry.action,
    resource,
    context: entry.context.map(({ key, type, values }) => ({ key, type, values: [...values] })),
    phase: entry.phase || "unspecified",
  };
}

export function deriveRequiredEvaluations(plan, manifest) {
  const changes = Array.isArray(plan?.resource_changes) ? plan.resource_changes : [];
  const required = manifest.required.filter((entry) => !entry.plan).flatMap((entry) => entry.resources.map((resource) => evaluation(entry, resource)));
  const coveredChanges = new Set();
  for (const change of changes) {
    const actions = change.change?.actions || [];
    if (exactActions(actions, ["no-op"])) continue;
    const matches = manifest.required.filter((entry) => entry.plan && planMatches(entry.plan, change));
    if (matches.length === 0) throw new Error(`No permission manifest entry covers ${change.address} ${JSON.stringify(actions)}.`);
    coveredChanges.add(change.address);
    for (const entry of matches) for (const resource of entry.resources) required.push(evaluation(entry, resource));
  }
  const forbidden = manifest.forbidden.flatMap((entry) => entry.resources.map((resource) => evaluation(entry, resource)));
  return {
    required: required.sort((left, right) => left.id.localeCompare(right.id)),
    forbidden: forbidden.sort((left, right) => left.id.localeCompare(right.id)),
    coveredChanges: [...coveredChanges].sort(),
  };
}

function contextArgs(context) {
  return context.flatMap(({ key, type, values }) => [
    `ContextKeyName=${key},ContextKeyValues=${values.join(",")},ContextKeyType=${type}`,
  ]);
}

export function simulatePrincipalPolicy({ roleArn, evaluation: item, run = (args) => execFileSync("aws", args, { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }) }) {
  const args = [
    "iam", "simulate-principal-policy",
    "--policy-source-arn", roleArn,
    "--action-names", item.action,
    "--resource-arns", item.resource,
    "--output", "json",
  ];
  if (item.context.length > 0) args.push("--context-entries", ...contextArgs(item.context));
  const response = JSON.parse(run(args));
  if (!Array.isArray(response.EvaluationResults) || response.EvaluationResults.length !== 1) {
    throw new Error(`IAM simulation returned malformed EvaluationResults for ${item.id}.`);
  }
  const result = response.EvaluationResults[0];
  if (!result || result.EvalActionName !== item.action || result.EvalResourceName !== item.resource) {
    throw new Error(`IAM simulation action or resource mismatch for ${item.id}.`);
  }
  if (!Array.isArray(result.MatchedStatements) || !Array.isArray(result.MissingContextValues) || result.MissingContextValues.length > 0
    || !["allowed", "explicitDeny", "implicitDeny"].includes(result.EvalDecision)) {
    throw new Error(`IAM simulation returned malformed output for ${item.id}.`);
  }
  return { decision: result.EvalDecision, matchedStatements: result.MatchedStatements.length, missingContextValues: result.MissingContextValues };
}

export function inspectCloudTrailDenials({ sessionName, startTime, requiredActions, run = (args) => execFileSync("aws", args, { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }) }) {
  const response = JSON.parse(run([
    "cloudtrail", "lookup-events",
    "--lookup-attributes", `AttributeKey=Username,AttributeValue=${sessionName}`,
    "--start-time", startTime,
    "--max-results", "50",
    "--output", "json",
  ]));
  const actionNames = new Set(requiredActions.map((action) => action.split(":")[1]));
  const unresolvedDenials = [];
  for (const event of response.Events || []) {
    let detail;
    try { detail = JSON.parse(event.CloudTrailEvent || "{}"); } catch { throw new Error("CloudTrail returned malformed event JSON."); }
    if (/AccessDenied|Unauthorized/i.test(detail.errorCode || "") && actionNames.has(detail.eventName)) {
      unresolvedDenials.push({ eventId: event.EventId || null, eventName: detail.eventName, eventTime: detail.eventTime || event.EventTime || null });
    }
  }
  return { status: unresolvedDenials.length === 0 ? "clear" : "unresolved-denial", eventsChecked: (response.Events || []).length, unresolvedDenials };
}

function validateFreshness(timestamp, now) {
  const timestampMs = Date.parse(timestamp); const nowMs = Date.parse(now);
  if (!Number.isFinite(timestampMs)) throw new Error("Permission report generatedAt is malformed.");
  if (timestampMs > nowMs + PERMISSION_PREFLIGHT_CLOCK_SKEW_MS) throw new Error("Permission report generatedAt is in the future.");
  if (nowMs - timestampMs > PERMISSION_PREFLIGHT_MAX_AGE_MS) throw new Error("Permission report is expired.");
}

export function runPermissionPreflight({
  roleArn,
  plan,
  planBytes,
  savedPlanBytes,
  manifest,
  expectedAccount = ACCOUNT,
  expectedRegion = REGION,
  generatedAt = new Date().toISOString(),
  policyPublishedAt,
  cloudTrailSessionName,
  now = new Date().toISOString(),
  simulate = ({ roleArn: sourceArn, evaluation: item }) => simulatePrincipalPolicy({ roleArn: sourceArn, evaluation: item }),
  cloudTrail = ({ sessionName, startTime, requiredActions }) => inspectCloudTrailDenials({ sessionName, startTime, requiredActions }),
} = {}) {
  if (expectedAccount !== ACCOUNT || expectedRegion !== REGION) throw new Error("Expected account or region is wrong.");
  if (!Buffer.isBuffer(savedPlanBytes) || savedPlanBytes.length === 0) throw new Error("Saved binary plan bytes are required for permission preflight.");
  if (roleArn !== RELEASE_ROLE_ARN) throw new Error("Permission preflight role ARN is not the production release role.");
  validateManifest(manifest, { account: expectedAccount, region: expectedRegion });
  if (!plan?.variables || plan.variables.account_id?.value !== expectedAccount || plan.variables.aws_region?.value !== expectedRegion) throw new Error("Plan account or region is wrong.");
  validateFreshness(generatedAt, now);
  if (!policyPublishedAt || !Number.isFinite(Date.parse(policyPublishedAt))) throw new Error("Policy publication timestamp is required and must be valid.");
  if (!cloudTrailSessionName) throw new Error("CloudTrail session name is required.");
  const derived = deriveRequiredEvaluations(plan, manifest);
  const requiredResults = derived.required.map((item) => ({ ...item, ...simulate({ roleArn, evaluation: item }) }));
  const forbiddenResults = derived.forbidden.map((item) => ({ ...item, ...simulate({ roleArn, evaluation: item }) }));
  const cloudTrailResult = cloudTrail({ sessionName: cloudTrailSessionName, startTime: policyPublishedAt, requiredActions: derived.required.map((item) => item.action) });
  const deniedRequired = requiredResults.filter((item) => item.decision !== "allowed");
  const allowedForbidden = forbiddenResults.filter((item) => item.decision === "allowed");
  const unresolved = cloudTrailResult.unresolvedDenials || [];
  const report = {
    schemaVersion: PERMISSION_PREFLIGHT_SCHEMA_VERSION,
    roleArn,
    planSha256: sha256(planBytes),
    savedPlanSha256: sha256(savedPlanBytes),
    canonicalPlanJsonSha256: sha256(Buffer.from(canonicalizeJson(plan))),
    generatedAt,
    requiredEvaluations: requiredResults,
    forbiddenEvaluations: forbiddenResults,
    cloudTrail: cloudTrailResult,
    allowedCount: requiredResults.filter((item) => item.decision === "allowed").length,
    deniedCount: deniedRequired.length + allowedForbidden.length + unresolved.length,
    status: deniedRequired.length === 0 && allowedForbidden.length === 0 && unresolved.length === 0 ? "valid" : "invalid",
  };
  return report;
}

export function runCli(argv = process.argv.slice(2)) {
  const options = parseCli(argv);
  const planBytes = fs.readFileSync(path.resolve(options.planJsonPath));
  const savedPlanBytes = fs.readFileSync(path.resolve(options.savedPlanPath));
  const plan = JSON.parse(planBytes);
  const manifest = JSON.parse(fs.readFileSync(path.resolve(options.manifestPath), "utf8"));
  const report = runPermissionPreflight({ ...options, plan, planBytes, savedPlanBytes });
  fs.writeFileSync(path.resolve(options.outputPath), `${JSON.stringify(report, null, 2)}\n`, { mode: 0o600 });
  process.stdout.write(`${JSON.stringify({ status: report.status, outputPath: options.outputPath, planSha256: report.planSha256, allowedCount: report.allowedCount, deniedCount: report.deniedCount })}\n`);
  if (report.status !== "valid") process.exitCode = 1;
  return report;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) runCli();
