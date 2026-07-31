#!/usr/bin/env node
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import crypto from "node:crypto";
import path from "node:path";
import {
  assertStageBAtomicBrokerPlan,
  assertStageBAtomicBrokerPackagePlan,
  assertStageBBrokerCreatePlan,
  assertStageBReferenceAuditFreshness,
  STAGE_B_TASK_DEFINITION_FAMILIES,
} from "./aws/stage-b-reference-audit-contract.mjs";

const root = "infra/aws/terraform/production-green-stage-b";
const allowed = new Set(["aws_cloudwatch_log_group", "aws_iam_role", "aws_iam_role_policy", "aws_ecs_task_definition", "aws_dynamodb_table", "aws_lambda_function", "aws_lambda_alias", "aws_lambda_permission"]);
const forbidden = /aws_ecs_service|aws_(lb|alb|elbv2)|aws_db_|aws_rds_|aws_secretsmanager_secret(?:_version)?/;
const taskDefinitionFamilies = new Map(Object.entries(STAGE_B_TASK_DEFINITION_FAMILIES));
const exactActions = (actions, expected) => actions.length === expected.length && actions.every((action, index) => action === expected[index]);
const exactReplacePaths = (paths) => Array.isArray(paths) && paths.length === 1 && Array.isArray(paths[0]) && paths[0].length === 1 && paths[0][0] === "container_definitions";
const sha256 = (value) => crypto.createHash("sha256").update(value).digest("hex");

function assertTaskDefinitionScope(change) {
  const expectedFamily = taskDefinitionFamilies.get(change.address);
  if (!expectedFamily) throw new Error(`Stage B task-definition address rejected: ${change.address}`);
  const beforeFamily = change.change.before?.family;
  const afterFamily = change.change.after?.family;
  if (beforeFamily !== undefined && beforeFamily !== expectedFamily) throw new Error(`Stage B task-definition family rejected: ${change.address}`);
  if (afterFamily !== undefined && afterFamily !== expectedFamily) throw new Error(`Stage B task-definition family rejected: ${change.address}`);
}

function assertTaskDefinitionRetentionContract(terraformConfiguration) {
  if (typeof terraformConfiguration !== "string") throw new Error("Stage B task-definition replacement requires Terraform configuration metadata.");
  for (const resourceName of ["candidate", "executor"]) {
    const marker = `resource "aws_ecs_task_definition" "${resourceName}"`;
    const start = terraformConfiguration.indexOf(marker);
    const end = start === -1 ? -1 : terraformConfiguration.indexOf("\nresource ", start + marker.length);
    const block = start === -1 ? "" : terraformConfiguration.slice(start, end === -1 ? terraformConfiguration.length : end);
    if (!/^\s*skip_destroy\s*=\s*true\s*$/m.test(block)) {
      throw new Error(`Stage B task-definition retention contract missing: ${resourceName}`);
    }
  }
}

function assertBoundRollover(plan, change, audit, auditBytes, auditSha256, planBytes, planSha256, now, terraformConfiguration) {
  if (!audit || !auditBytes || !auditSha256 || !planBytes || !planSha256) throw new Error(`Stage B rollover requires an explicit plan-bound reference audit: ${change.address}`);
  if (sha256(auditBytes) !== auditSha256) throw new Error("Stage B reference audit SHA-256 mismatch.");
  if (sha256(planBytes) !== planSha256) throw new Error("Stage B plan JSON SHA-256 mismatch.");
  assertStageBReferenceAuditFreshness(audit.auditedAt, now);
  if (audit.planJsonSha256 !== planSha256) throw new Error("Stage B reference audit is bound to a different plan JSON.");
  const beforeArn = change.change.before?.arn || change.change.before?.id;
  const expectedFamily = taskDefinitionFamilies.get(change.address);
  const arnPattern = new RegExp(`^arn:aws:ecs:eu-west-2:368992683803:task-definition/${expectedFamily.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}:\\d+$`);
  if (!beforeArn || !arnPattern.test(beforeArn)) throw new Error(`Stage B old task-definition ARN rejected: ${change.address}`);
  const entry = (audit.oldTaskDefinitions || []).find((item) => item.terraformAddress === change.address);
  if (!entry || entry.oldTaskDefinitionArn !== beforeArn) throw new Error(`Stage B reference audit old ARN mismatch: ${change.address}`);
  if (entry.family !== expectedFamily || entry.proposedFamily !== expectedFamily || entry.sameFamilyAsReplacement !== true) throw new Error(`Stage B reference audit family mismatch: ${change.address}`);
  if (!exactReplacePaths(entry.replacePaths)) throw new Error(`Stage B reference audit replace path mismatch: ${change.address}`);
  if (!Array.isArray(entry.serviceReferences) || entry.serviceReferences.length !== 0) throw new Error(`Stage B service reference exists: ${change.address}`);
  if (!Array.isArray(entry.runningTaskReferences) || entry.runningTaskReferences.length !== 0) throw new Error(`Stage B running-task reference exists: ${change.address}`);
  if (!Array.isArray(entry.pendingTaskReferences) || entry.pendingTaskReferences.length !== 0) throw new Error(`Stage B pending-task reference exists: ${change.address}`);
  const brokerModes = Array.isArray(entry.brokerReferenceModes) ? entry.brokerReferenceModes : [];
  const atomicRollovers = Array.isArray(audit.plannedAtomicBrokerRollovers) ? audit.plannedAtomicBrokerRollovers : [];
  const atomicForChange = atomicRollovers.filter((item) => item?.taskDefinitionTerraformAddress === change.address);
  if (brokerModes.length === 0 && atomicForChange.length !== 0) throw new Error(`Stage B atomic broker rollover is unexpected: ${change.address}`);
  if (brokerModes.length !== 0) {
    if (entry.brokerReferenceStatus !== "planned-atomic-broker-rollover-v1" || audit.allOldRevisionsUnreferenced !== false || atomicForChange.length !== 1) {
      throw new Error(`Stage B atomic broker rollover proof is missing: ${change.address}`);
    }
    const atomic = atomicForChange[0];
    assertStageBAtomicBrokerPlan(plan, change.address, atomic.mode, terraformConfiguration);
    if (JSON.stringify(brokerModes) !== JSON.stringify([atomic.mode])
      || atomic.brokerTerraformAddress !== "aws_lambda_function.broker"
      || atomic.taskDefinitionArnReference !== `${change.address}.arn`
      || atomic.brokerEnvironmentReference !== "local.broker_task_definition_arns"
      || atomic.family !== expectedFamily
      || atomic.oldTaskDefinitionArn !== beforeArn
      || atomic.planJsonSha256 !== planSha256) {
      throw new Error(`Stage B atomic broker rollover proof does not match the plan: ${change.address}`);
    }
  }
  if (typeof entry.rollbackArn !== "string" || !arnPattern.test(entry.rollbackArn)) throw new Error(`Stage B rollback ARN missing: ${change.address}`);
}

function assertBrokerAuditBinding(plan, brokerChange, audit, auditBytes, auditSha256, planBytes, planSha256, now, terraformConfiguration) {
  if (!audit || !auditBytes || !auditSha256 || !planBytes || !planSha256) throw new Error("Stage B broker update requires an explicit plan-bound reference audit.");
  if (sha256(auditBytes) !== auditSha256) throw new Error("Stage B reference audit SHA-256 mismatch.");
  if (sha256(planBytes) !== planSha256) throw new Error("Stage B plan JSON SHA-256 mismatch.");
  assertStageBReferenceAuditFreshness(audit.auditedAt, now);
  if (audit.planJsonSha256 !== planSha256) throw new Error("Stage B reference audit is bound to a different plan JSON.");
  const broker = audit.broker;
  if (!broker || typeof broker !== "object" || Array.isArray(broker)) throw new Error("Stage B broker update reference audit evidence is missing.");
  const proof = {
    brokerTerraformAddress: "aws_lambda_function.broker",
    brokerEnvironmentReference: "local.broker_approval_expected",
    packageInputReference: "var.package_checksum_sha256",
    packagePath: broker.brokerPackagePath,
    liveReleasePackageChecksumSha256: broker.releasePackageChecksumSha256,
    planBeforeReleasePackageChecksumSha256: broker.planBeforeReleasePackageChecksumSha256,
    plannedReleasePackageChecksumSha256: broker.plannedReleasePackageChecksumSha256,
    brokerZipFileSha256: broker.brokerZipFileSha256,
    plannedBrokerSourceCodeHashBase64: broker.plannedBrokerSourceCodeHashBase64,
    planJsonSha256: broker.planJsonSha256,
  };
  assertStageBAtomicBrokerPackagePlan(plan, proof, terraformConfiguration);
  const plannedChecksum = plan.variables?.package_checksum_sha256?.value;
  if (broker.releasePackageChecksumSha256 !== plannedChecksum) {
    const transition = audit.plannedAtomicPackageChecksumTransition;
    if (!transition || transition.transition !== "plannedAtomicPackageChecksumTransition") throw new Error("Stage B atomic broker release-checksum transition proof is missing.");
    for (const field of ["plannedReleasePackageChecksumSha256", "brokerZipFileSha256", "plannedBrokerSourceCodeHashBase64", "planJsonSha256"]) {
      if (transition[field] !== proof[field]) throw new Error(`Stage B atomic broker release-checksum transition ${field} does not match broker evidence.`);
    }
    if (transition.planJsonSha256 !== planSha256) throw new Error("Stage B atomic broker release-checksum transition is bound to a different plan JSON.");
  } else if (audit.plannedAtomicPackageChecksumTransition !== null && audit.plannedAtomicPackageChecksumTransition !== undefined) {
    throw new Error("Stage B atomic broker release-checksum transition is unexpected when the live checksum already matches.");
  }
}

function assertInitialBrokerCreatePlan(plan, terraformConfiguration) {
  const packagePath = plan.variables?.broker_package_path?.value;
  const releaseChecksum = plan.variables?.package_checksum_sha256?.value;
  if (typeof packagePath !== "string" || !path.isAbsolute(packagePath)) throw new Error("Stage B broker create package path is missing or malformed.");
  if (!/^[a-f0-9]{64}$/.test(releaseChecksum || "")) throw new Error("Stage B broker create release package checksum is missing or malformed.");
  let packageBytes;
  try {
    packageBytes = fs.readFileSync(packagePath);
  } catch {
    throw new Error("Stage B broker create package file is missing or unreadable.");
  }
  const brokerZipFileSha256 = sha256(packageBytes);
  const proof = {
    brokerTerraformAddress: "aws_lambda_function.broker",
    brokerEnvironmentReference: "local.broker_approval_expected",
    packageInputReference: "var.package_checksum_sha256",
    packagePath,
    plannedReleasePackageChecksumSha256: releaseChecksum,
    brokerZipFileSha256,
    plannedBrokerSourceCodeHashBase64: crypto.createHash("sha256").update(packageBytes).digest("base64"),
  };
  const taskDefinitionChanges = (plan.resource_changes || []).filter((change) => change.type === "aws_ecs_task_definition");
  if (taskDefinitionChanges.length !== Object.keys(STAGE_B_TASK_DEFINITION_FAMILIES).length
    || taskDefinitionChanges.some((change) => !STAGE_B_TASK_DEFINITION_FAMILIES[change.address])) {
    throw new Error("Stage B broker create task-definition allowlist is not exact.");
  }
  for (const change of taskDefinitionChanges) assertTaskDefinitionScope(change);
  assertStageBBrokerCreatePlan(plan, proof, terraformConfiguration);
}

export function assertStageBPlan(plan, options = {}) {
  const { referenceAudit, referenceAuditBytes, referenceAuditSha256, planJsonBytes, planJsonSha256, now = new Date(), terraformConfiguration } = options;
  const brokerChange = (plan.resource_changes || []).find((change) => change.address === "aws_lambda_function.broker");
  if (brokerChange) {
    const brokerActions = brokerChange.change?.actions;
    if (!Array.isArray(brokerActions) || brokerActions.length === 0) throw new Error("Stage B broker actions are missing or malformed.");
    if (exactActions(brokerActions, ["create"])) assertInitialBrokerCreatePlan(plan, terraformConfiguration);
    else if (exactActions(brokerActions, ["update"])) assertBrokerAuditBinding(plan, brokerChange, referenceAudit, referenceAuditBytes, referenceAuditSha256, planJsonBytes, planJsonSha256, now, terraformConfiguration);
    else if (!exactActions(brokerActions, ["no-op"])) throw new Error(`Stage B broker actions are unsupported: ${JSON.stringify(brokerActions)}`);
  }
  for (const change of plan.resource_changes || []) {
    const actions = change.change.actions || [];
    if (forbidden.test(change.type) || !allowed.has(change.type)) throw new Error(`Stage B plan rejected: ${change.address}`);
    if (change.type === "aws_ecs_task_definition" && actions.some((action) => action !== "no-op")) {
      assertTaskDefinitionScope(change);
      if (actions.includes("delete")) {
        if (!exactActions(actions, ["delete", "create"]) || !exactReplacePaths(change.change.replace_paths)) throw new Error(`Stage B task-definition rollover rejected: ${change.address}`);
        assertTaskDefinitionRetentionContract(terraformConfiguration);
        assertBoundRollover(plan, change, referenceAudit, referenceAuditBytes, referenceAuditSha256, planJsonBytes, planJsonSha256, now, terraformConfiguration);
      }
    } else if (actions.includes("delete")) {
      throw new Error(`Stage B plan rejected: ${change.address}`);
    }
    const after = JSON.stringify(change.change.after || {});
    if ((after.match(/"image":"([^"@]+):[^"@]+"/) || after.match(/"image"\s*:\s*"[^"@]+:[^"@]+"/)) && !after.includes("@sha256:")) throw new Error(`Stage B image tag rejected: ${change.address}`);
  }
}

function readOption(argv, name) {
  const index = argv.indexOf(name);
  return index === -1 ? undefined : argv[index + 1];
}

if (process.argv[1] === new URL(import.meta.url).pathname) {
  if (process.env.MSCQR_STAGE_B_PLAN_ENABLED !== "true" || process.env.MSCQR_STAGE_B_PLAN_CONFIRM !== "MSCQR_GENERATE_STAGE_B_PLAN_ONLY") throw new Error("Stage B planning requires both explicit plan-only confirmations.");
  const tfvars = process.argv[2];
  if (!tfvars || !path.isAbsolute(tfvars) || !fs.existsSync(tfvars)) throw new Error("Stage B requires an existing absolute private tfvars path.");
  const out = path.resolve(".terraform-plans/production-green-stage-b.tfplan");
  fs.mkdirSync(path.dirname(out), { recursive: true, mode: 0o700 });
  execFileSync("terraform", [`-chdir=${root}`, "workspace", "select", "production"], { stdio: "inherit" });
  execFileSync("terraform", [`-chdir=${root}`, "plan", `-var-file=${tfvars}`, `-out=${out}`], { stdio: "inherit" });
  const planJsonText = execFileSync("terraform", [`-chdir=${root}`, "show", "-json", out], { encoding: "utf8" });
  const plan = JSON.parse(planJsonText);
  const terraformConfiguration = fs.readFileSync(path.resolve(root, "main.tf"), "utf8");
  const referenceAuditPath = readOption(process.argv.slice(3), "--reference-audit");
  const referenceAuditSha256 = readOption(process.argv.slice(3), "--reference-audit-sha256");
  const planJsonSha256 = readOption(process.argv.slice(3), "--plan-json-sha256");
  const referenceAuditBytes = referenceAuditPath ? fs.readFileSync(path.resolve(referenceAuditPath)) : undefined;
  const referenceAudit = referenceAuditBytes ? JSON.parse(referenceAuditBytes) : undefined;
  assertStageBPlan(plan, { referenceAudit, referenceAuditBytes, referenceAuditSha256, planJsonBytes: Buffer.from(planJsonText), planJsonSha256, terraformConfiguration });
  process.stdout.write(JSON.stringify({ status: "approved-plan-only", plan: out }) + "\n");
}
