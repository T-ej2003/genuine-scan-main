#!/usr/bin/env node
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { execFileSync, spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import {
  assertStageBPlan,
} from "./plan-production-green-stage-b.mjs";
import {
  PERMISSION_PREFLIGHT_CLOCK_SKEW_MS,
  PERMISSION_PREFLIGHT_MAX_AGE_MS,
  canonicalizeJson,
} from "./aws/validate-production-green-stage-b-permissions.mjs";
import { assertStageBReleaseCallerArn } from "./plan-production-green-stage-b.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const terraformRoot = "infra/aws/terraform/production-green-stage-b";
const releaseRoleArn = "arn:aws:iam::368992683803:role/mscqr-production-release-deployer";
const requiredConfirmation = "MSCQR_APPLY_PRODUCTION_GREEN_STAGE_B_ONCE";

const sha256 = (value) => crypto.createHash("sha256").update(value).digest("hex");
const readJson = (file) => JSON.parse(fs.readFileSync(path.resolve(root, file), "utf8"));
const readBytes = (file) => fs.readFileSync(path.resolve(root, file));

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
    planPath: requireOption(argv, "--plan"),
    planJsonPath: requireOption(argv, "--plan-json"),
    auditPath: requireOption(argv, "--reference-audit"),
    permissionReportPath: requireOption(argv, "--permission-report"),
    planSha256: requireOption(argv, "--plan-sha256"),
    auditSha256: requireOption(argv, "--audit-sha256"),
    savedPlanSha256: requireOption(argv, "--saved-plan-sha256"),
    canonicalPlanJsonSha256: requireOption(argv, "--canonical-plan-json-sha256"),
    verifyOnly: argv.includes("--verify-only"),
  };
}

export function assertPermissionReport(report, { planSha256, savedPlanSha256, canonicalPlanJsonSha256, now = new Date().toISOString() } = {}) {
  if (report?.schemaVersion !== 1 || report.status !== "valid") throw new Error("A valid permission-preflight report is required.");
  if (report.roleArn !== releaseRoleArn) throw new Error("Permission-preflight report role ARN is wrong.");
  if (report.planSha256 !== planSha256) throw new Error("Permission-preflight report is bound to a different plan.");
  if (report.savedPlanSha256 !== savedPlanSha256) throw new Error("Permission-preflight report is bound to a different saved binary plan.");
  if (report.canonicalPlanJsonSha256 !== canonicalPlanJsonSha256) throw new Error("Permission-preflight report is bound to a different canonical plan JSON.");
  const generatedAtMs = Date.parse(report.generatedAt); const nowMs = Date.parse(now);
  if (!Number.isFinite(generatedAtMs)) throw new Error("Permission-preflight report timestamp is malformed.");
  if (generatedAtMs > nowMs + PERMISSION_PREFLIGHT_CLOCK_SKEW_MS) throw new Error("Permission-preflight report timestamp is in the future.");
  if (nowMs - generatedAtMs > PERMISSION_PREFLIGHT_MAX_AGE_MS) throw new Error("Permission-preflight report is expired.");
  if (!Array.isArray(report.requiredEvaluations) || report.requiredEvaluations.some((item) => item.decision !== "allowed")) throw new Error("Permission-preflight report has a denied required evaluation.");
  if (!Array.isArray(report.forbiddenEvaluations) || report.forbiddenEvaluations.some((item) => item.decision === "allowed")) throw new Error("Permission-preflight report allowed a forbidden evaluation.");
  if (report.cloudTrail?.status !== "clear" || report.cloudTrail.unresolvedDenials?.length !== 0) throw new Error("Permission-preflight report contains an unresolved CloudTrail denial.");
  if (report.deniedCount !== 0) throw new Error("Permission-preflight report has denied evaluations.");
  return true;
}

export function assertApplyArtifacts({ planPath, planJsonPath, auditPath, permissionReportPath, planSha256, auditSha256, savedPlanSha256, canonicalPlanJsonSha256, now = new Date().toISOString(), callerArn, showPlan, validatePlan = assertStageBPlan }) {
  if (!path.isAbsolute(planPath) || !path.isAbsolute(planJsonPath) || !path.isAbsolute(auditPath) || !path.isAbsolute(permissionReportPath)) throw new Error("All Stage B apply artifacts must use absolute paths.");
  if (!fs.existsSync(planPath)) throw new Error("Saved Terraform plan is missing.");
  if (!fs.existsSync(permissionReportPath)) throw new Error("Permission-preflight report is missing.");
  const planBytes = fs.readFileSync(planJsonPath); const auditBytes = fs.readFileSync(auditPath); const savedPlanBytes = fs.readFileSync(planPath); const permissionReport = JSON.parse(fs.readFileSync(permissionReportPath, "utf8"));
  if (!/^[a-f0-9]{64}$/.test(savedPlanSha256) || sha256(savedPlanBytes) !== savedPlanSha256) throw new Error("Saved Terraform plan SHA256 does not match the approved digest.");
  if (!/^[a-f0-9]{64}$/.test(canonicalPlanJsonSha256)) throw new Error("Canonical plan JSON SHA256 is missing or malformed.");
  if (sha256(planBytes) !== planSha256) throw new Error("Plan JSON SHA256 does not match the approved digest.");
  if (sha256(auditBytes) !== auditSha256) throw new Error("Reference audit SHA256 does not match the approved digest.");
  try { assertStageBReleaseCallerArn(callerArn); } catch { throw new Error("Current caller is not the production release-deployer STS assumed-role."); }
  const plan = JSON.parse(planBytes); const audit = JSON.parse(auditBytes);
  if (typeof showPlan !== "function") throw new Error("Terraform show dependency is required to bind the saved plan.");
  const shown = showPlan(planPath);
  const derivedPlanBytes = Buffer.isBuffer(shown) ? shown : Buffer.from(shown);
  let derivedPlan;
  try { derivedPlan = JSON.parse(derivedPlanBytes); } catch { throw new Error("terraform show -json returned malformed plan JSON."); }
  const approvedCanonical = canonicalizeJson(plan);
  const derivedCanonical = canonicalizeJson(derivedPlan);
  const derivedCanonicalPlanJsonSha256 = sha256(Buffer.from(derivedCanonical));
  if (derivedCanonical !== approvedCanonical || derivedCanonicalPlanJsonSha256 !== canonicalPlanJsonSha256) throw new Error("Saved binary Terraform plan does not match the approved plan JSON.");
  assertPermissionReport(permissionReport, { planSha256, savedPlanSha256, canonicalPlanJsonSha256, now });
  validatePlan(plan, {
    referenceAudit: audit,
    referenceAuditBytes: auditBytes,
    referenceAuditSha256: auditSha256,
    planJsonBytes: planBytes,
    planJsonSha256: planSha256,
    trustedCallerArn: callerArn,
    terraformConfiguration: fs.readFileSync(path.join(root, terraformRoot, "main.tf"), "utf8"),
    now: new Date(now),
  });
  if ((plan.resource_changes || []).some((change) => (change.change?.actions || []).includes("delete"))) throw new Error("Stage B apply plan contains a delete action.");
  return { plan, audit, permissionReport, savedPlanSha256, canonicalPlanJsonSha256, derivedPlanJsonSha256: sha256(derivedPlanBytes) };
}

function currentCaller() {
  return JSON.parse(execFileSync("aws", ["sts", "get-caller-identity", "--output", "json"], { encoding: "utf8" })).Arn;
}

function showSavedPlan(planPath) {
  return execFileSync("terraform", ["show", "-json", planPath], { cwd: root, encoding: null, stdio: ["ignore", "pipe", "pipe"] });
}

export function runApply({ argv = process.argv.slice(2), env = process.env, deps = { getCaller: currentCaller, apply: (planPath) => spawnSync("terraform", [`-chdir=${terraformRoot}`, "apply", "-input=false", "-no-color", planPath], { cwd: root, env, encoding: "utf8", stdio: "inherit" }) } } = {}) {
  if (env.MSCQR_STAGE_B_APPLY_ENABLED !== "true" || env.MSCQR_STAGE_B_APPLY_CONFIRM !== requiredConfirmation) throw new Error("Stage B apply gate is not enabled.");
  if (env.TF_WORKSPACE !== "production") throw new Error("Stage B apply requires TF_WORKSPACE=production.");
  const artifacts = parseCli(argv); const callerArn = deps.getCaller();
  const defaultDeps = { getCaller: currentCaller, showPlan: showSavedPlan, validatePlan: assertStageBPlan, apply: (planPath) => spawnSync("terraform", [`-chdir=${terraformRoot}`, "apply", "-input=false", "-no-color", planPath], { cwd: root, env, encoding: "utf8", stdio: "inherit" }) };
  const effectiveDeps = { ...defaultDeps, ...deps };
  const verified = assertApplyArtifacts({ ...artifacts, callerArn, showPlan: effectiveDeps.showPlan, validatePlan: effectiveDeps.validatePlan });
  if (artifacts.verifyOnly) return { status: "ready-to-apply", callerArn, planSha256: artifacts.planSha256, auditSha256: artifacts.auditSha256, savedPlanSha256: artifacts.savedPlanSha256, canonicalPlanJsonSha256: artifacts.canonicalPlanJsonSha256, actionCounts: (verified.plan.resource_changes || []).reduce((counts, change) => { const action = (change.change?.actions || []).join(","); counts[action] = (counts[action] || 0) + 1; return counts; }, {}) };
  const result = effectiveDeps.apply(artifacts.planPath);
  if (result?.status !== undefined && result.status !== 0) throw new Error("Terraform apply failed; stop without retry.");
  return { status: "applied-saved-plan", callerArn, planSha256: artifacts.planSha256, auditSha256: artifacts.auditSha256, actionCounts: (verified.plan.resource_changes || []).reduce((counts, change) => { const action = (change.change?.actions || []).join(","); counts[action] = (counts[action] || 0) + 1; return counts; }, {}) };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try { console.log(JSON.stringify(runApply(), null, 2)); } catch (error) { console.error(error.message); process.exitCode = 1; }
}
