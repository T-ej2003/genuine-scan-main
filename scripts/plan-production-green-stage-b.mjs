#!/usr/bin/env node
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import crypto from "node:crypto";
import path from "node:path";
import {
  assertStageBAtomicBrokerPlan,
  assertStageBAtomicBrokerPackagePlan,
  assertStageBBrokerCreatePlan,
  assertStageBBrokerTaskDefinitionMapping,
  assertStageBReferenceAuditFreshness,
  assertStageBCurrentTaskDefinitionNoOp,
  STAGE_B_REFERENCE_AUDIT_SCHEMA_VERSION,
  STAGE_B_TASK_DEFINITION_FAMILIES,
  STAGE_B_TASK_DEFINITION_FAMILY_NAMES,
} from "./aws/stage-b-reference-audit-contract.mjs";
import { assertStageBBrokerConfigurationIdentity, STAGE_B, STAGE_B_MODES } from "./aws/production-green-stage-b-contract.mjs";
import { assertStageBPlanImageEvidenceBinding } from "./aws/production-green-stage-b-image-evidence.mjs";

const root = "infra/aws/terraform/production-green-stage-b";
const allowed = new Set(["aws_cloudwatch_log_group", "aws_iam_role", "aws_iam_role_policy", "aws_ecs_task_definition", "aws_dynamodb_table", "aws_lambda_function", "aws_lambda_alias", "aws_lambda_permission"]);
const forbidden = /aws_ecs_service|aws_(lb|alb|elbv2)|aws_db_|aws_rds_|aws_secretsmanager_secret(?:_version)?/;
const taskDefinitionFamilies = new Map(Object.entries(STAGE_B_TASK_DEFINITION_FAMILIES));
const exactActions = (actions, expected) => actions.length === expected.length && actions.every((action, index) => action === expected[index]);
const exactReplacePaths = (paths) => Array.isArray(paths) && paths.length === 1 && Array.isArray(paths[0]) && paths[0].length === 1 && paths[0][0] === "container_definitions";
const sha256 = (value) => crypto.createHash("sha256").update(value).digest("hex");
const retainedAddressPattern = /^aws_ecs_task_definition\.(candidate|executor)_retained\["([^"]+)"\]$/;
const taskDefinitionArnPattern = /^arn:aws:ecs:eu-west-2:368992683803:task-definition\/([^:]+):([1-9][0-9]*)$/;
export const STAGE_B_RELEASE_CALLER_ARN_PATTERN = /^arn:aws:sts::368992683803:assumed-role\/mscqr-production-release-deployer\/[^/\r\n]+$/;
export function assertStageBReleaseCallerArn(value) {
  if (typeof value !== "string" || !STAGE_B_RELEASE_CALLER_ARN_PATTERN.test(value)) {
    throw new Error("Stage B caller must be the exact production release-deployer STS assumed-role ARN.");
  }
  return value;
}
const expectedBrokerFamily = (mode) => mode === "full-rls-application-canary"
  ? STAGE_B_TASK_DEFINITION_FAMILIES['aws_ecs_task_definition.candidate["canary"]']
  : `mscqr-production-full-rls-green-${mode}`;
const expectedBrokerAddress = (mode) => mode === "full-rls-application-canary"
  ? 'aws_ecs_task_definition.candidate["canary"]'
  : `aws_ecs_task_definition.executor["${mode}"]`;

function assertTaskDefinitionScope(change) {
  const expectedFamily = taskDefinitionFamilies.get(change.address);
  if (!expectedFamily) throw new Error(`Stage B task-definition address rejected: ${change.address}`);
  const beforeFamily = change.change.before?.family;
  const afterFamily = change.change.after?.family;
  if (beforeFamily !== undefined && beforeFamily !== expectedFamily) throw new Error(`Stage B task-definition family rejected: ${change.address}`);
  if (afterFamily !== undefined && afterFamily !== expectedFamily) throw new Error(`Stage B task-definition family rejected: ${change.address}`);
}

function retainedTaskDefinitionDescriptor(address) {
  const match = retainedAddressPattern.exec(address || "");
  if (!match) return undefined;
  for (const [currentAddress, family] of taskDefinitionFamilies) {
    const currentKey = /\["([^"]+)"\]$/.exec(currentAddress)?.[1];
    const historyMatch = new RegExp(`^([a-f0-9]{7,40})-${currentKey}$`).exec(match[2]);
    if (currentAddress.startsWith(`aws_ecs_task_definition.${match[1]}[`) && historyMatch) {
      return { family, historyKey: match[2], generationKey: historyMatch[1], currentAddress };
    }
  }
  return { invalid: true, historyKey: match[2] };
}

function retainedTaskDefinitionFamily(address) {
  return retainedTaskDefinitionDescriptor(address)?.family;
}

function assertTaskDefinitionAppendOnlyContract(terraformConfiguration) {
  if (typeof terraformConfiguration !== "string") throw new Error("Stage B append-only task-definition plan requires Terraform configuration metadata.");
  for (const resourceName of ["candidate", "executor", "candidate_retained", "executor_retained"]) {
    const marker = `resource "aws_ecs_task_definition" "${resourceName}"`;
    const start = terraformConfiguration.indexOf(marker);
    const end = start === -1 ? -1 : terraformConfiguration.indexOf("\nresource ", start + marker.length);
    const block = start === -1 ? "" : terraformConfiguration.slice(start, end === -1 ? terraformConfiguration.length : end);
    if (!/^\s*skip_destroy\s*=\s*true\s*$/m.test(block)) throw new Error(`Stage B task-definition retention contract missing: ${resourceName}`);
    if (resourceName.endsWith("_retained") && !/ignore_changes\s*=\s*all/.test(block)) throw new Error(`Stage B retained task-definition contract missing: ${resourceName}`);
  }
}

function assertRetainedTaskDefinition(change) {
  const descriptor = retainedTaskDefinitionDescriptor(change.address);
  if (!descriptor || descriptor.invalid) throw new Error(`Stage B retained task-definition address must be revision-keyed: ${change.address}`);
  const expectedFamily = descriptor.family;
  const actions = change.change?.actions;
  if (!exactActions(actions || [], ["no-op"])) throw new Error(`Stage B retained task-definition must remain no-op: ${change.address}`);
  const before = change.change?.before || {};
  const after = change.change?.after || {};
  const identity = taskDefinitionArnPattern.exec(before.arn || "");
  if (before.family !== expectedFamily || after.family !== expectedFamily || !identity || identity[1] !== expectedFamily) throw new Error(`Stage B retained task-definition identity rejected: ${change.address}`);
  return { family: expectedFamily, arn: before.arn, revision: Number(identity[2]) };
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

function assertTaskDefinitionAppendOnlyPlan(plan, terraformConfiguration) {
  const changes = (plan.resource_changes || []).filter((change) => change.type === "aws_ecs_task_definition");
  const current = [];
  const retainedAddresses = new Set();
  const retainedGenerationFamilies = new Set();
  const retainedByFamily = new Map();
  const retainedByGeneration = new Map();
  const retainedArns = new Set();
  const retainedFamilyRevisions = new Set();
  for (const change of changes) {
    const descriptor = retainedTaskDefinitionDescriptor(change.address);
    if (descriptor?.invalid) throw new Error(`Stage B retained task-definition address must be revision-keyed: ${change.address}`);
    if (descriptor) {
      const retained = assertRetainedTaskDefinition(change);
      retained.address = change.address;
      retained.historyKey = descriptor.historyKey;
      retained.generationKey = descriptor.generationKey;
      if (retainedArns.has(retained.arn)) throw new Error(`Stage B retained task-definition ARN is duplicated: ${retained.arn}`);
      const familyRevision = `${retained.family}:${retained.revision}`;
      if (retainedFamilyRevisions.has(familyRevision)) throw new Error(`Stage B retained task-definition family and revision are duplicated: ${familyRevision}`);
      if (retainedAddresses.has(change.address)) throw new Error(`Stage B retained task-definition address is duplicated: ${change.address}`);
      const generationFamily = `${descriptor.historyKey}|${descriptor.family}`;
      if (retainedGenerationFamilies.has(generationFamily)) throw new Error(`Stage B retained task-definition family is duplicated in one generation: ${descriptor.historyKey}`);
      retainedAddresses.add(change.address);
      retainedGenerationFamilies.add(generationFamily);
      retainedArns.add(retained.arn);
      retainedFamilyRevisions.add(familyRevision);
      retainedByFamily.set(retained.family, [...(retainedByFamily.get(retained.family) || []), retained]);
      retainedByGeneration.set(retained.generationKey, [...(retainedByGeneration.get(retained.generationKey) || []), retained]);
    } else {
      current.push(change);
    }
  }
  const expectedCurrent = new Set(taskDefinitionFamilies.keys());
  const actualCurrent = new Set(current.map((change) => change.address));
  if (current.length !== expectedCurrent.size || actualCurrent.size !== expectedCurrent.size || [...expectedCurrent].some((address) => !actualCurrent.has(address))) {
    throw new Error("Stage B append-only plan must contain exactly the twelve current task-definition addresses.");
  }
  const currentArnByAddress = new Map();
  for (const change of current) {
    assertTaskDefinitionScope(change);
    if (exactActions(change.change?.actions || [], ["create"])) continue;
    if (exactActions(change.change?.actions || [], ["no-op"])) {
      const validated = assertStageBCurrentTaskDefinitionNoOp(change, plan, retainedArns);
      currentArnByAddress.set(change.address, validated.arn);
      continue;
    }
    throw new Error(`Stage B append-only current task-definition must be create-only or no-op: ${change.address}`);
  }
  if (retainedAddresses.size > 0) {
    const readOnlyCanaryFamily = taskDefinitionFamilies.get('aws_ecs_task_definition.candidate["read_only_canary"]');
    const firstRolloverFamilies = new Set([...taskDefinitionFamilies.values()].filter((family) => family !== readOnlyCanaryFamily));
    const backendFamily = taskDefinitionFamilies.get('aws_ecs_task_definition.candidate["backend"]');
    for (const [family, entries] of retainedByFamily) {
      const newest = [...entries].sort((left, right) => right.revision - left.revision)[0];
      if (entries.some((entry) => entry.revision === newest.revision && entry.arn !== newest.arn)) throw new Error(`Stage B retained task-definition newest revision is ambiguous: ${family}`);
    }
    const canaryGenerations = [];
    for (const [generationKey, entries] of retainedByGeneration) {
      const families = new Set(entries.map((entry) => entry.family));
      const hasReadOnlyCanary = families.has(readOnlyCanaryFamily);
      const expectedFamilies = hasReadOnlyCanary ? new Set(taskDefinitionFamilies.values()) : firstRolloverFamilies;
      if (entries.length !== expectedFamilies.size || families.size !== entries.length || [...expectedFamilies].some((family) => !families.has(family))) {
        throw new Error(`Stage B retained generation ${generationKey} must contain exactly ${expectedFamilies.size} complete task-definition families.`);
      }
      const anchor = entries.find((entry) => entry.family === backendFamily);
      if (!anchor) throw new Error(`Stage B retained generation ${generationKey} is missing its backend revision anchor.`);
      if (hasReadOnlyCanary) canaryGenerations.push({ generationKey, entries, anchor });
    }
    if (canaryGenerations.length > 0) {
      const firstCanaryGeneration = [...canaryGenerations].sort((left, right) => left.anchor.revision - right.anchor.revision)[0];
      const firstCanaryRevisionByFamily = new Map(firstCanaryGeneration.entries.map((entry) => [entry.family, entry.revision]));
      for (const [generationKey, entries] of retainedByGeneration) {
        const hasReadOnlyCanary = entries.some((entry) => entry.family === readOnlyCanaryFamily);
        if (hasReadOnlyCanary && generationKey !== firstCanaryGeneration.generationKey) {
          const anchor = entries.find((entry) => entry.family === backendFamily);
          for (const entry of entries) {
            if (entry.revision <= firstCanaryRevisionByFamily.get(entry.family)) {
              throw new Error(`Stage B retained generation ${generationKey} has inconsistent revision ordering for ${entry.family}.`);
            }
          }
          if (anchor.revision <= firstCanaryGeneration.anchor.revision) {
            throw new Error(`Stage B retained generation ${generationKey} has an invalid canary revision ordering.`);
          }
          continue;
        }
        if (hasReadOnlyCanary) continue;
        if (entries.some((entry) => entry.revision >= firstCanaryRevisionByFamily.get(entry.family))) {
          throw new Error(`Stage B post-canary retained generation ${generationKey} must include read-only-canary.`);
        }
      }
    }
  }
  assertTaskDefinitionAppendOnlyContract(terraformConfiguration);
  const currentCreates = current.filter((change) => exactActions(change.change?.actions || [], ["create"])).length;
  const currentNoOps = current.filter((change) => exactActions(change.change?.actions || [], ["no-op"])).length;
  const classification = {
    currentCreates,
    currentNoOps,
    total: currentCreates + currentNoOps,
  };
  const currentEntries = current.map((change) => ({
      address: change.address,
      family: taskDefinitionFamilies.get(change.address),
      classification: exactActions(change.change?.actions || [], ["create"]) ? "create-only" : "no-op",
      priorTaskDefinitionArn: exactActions(change.change?.actions || [], ["no-op"]) ? currentArnByAddress.get(change.address) : null,
    }));
  const retainedEntries = [...retainedByFamily.values()].flat().map((entry) => ({ address: entry.address, historyKey: entry.historyKey, family: entry.family, oldTaskDefinitionArn: entry.arn, revision: entry.revision, classification: "retained-no-op" }));
  Object.defineProperties(classification, {
    currentEntries: { value: currentEntries, enumerable: false },
    retainedEntries: { value: retainedEntries, enumerable: false },
  });
  return classification;
}

export function assertStageBTaskDefinitionStateMigrationPreconditions(stateAddresses, moves) {
  if (!Array.isArray(stateAddresses) || !Array.isArray(moves) || moves.length === 0) throw new Error("Stage B state migration inputs are missing or malformed.");
  const state = new Set(stateAddresses);
  const currentAddresses = new Set(taskDefinitionFamilies.keys());
  const readOnlyCanaryAddress = 'aws_ecs_task_definition.candidate["read_only_canary"]';
  const firstRolloverAddresses = new Set([...currentAddresses].filter((address) => address !== readOnlyCanaryAddress));
  const moveSources = new Set(moves.map((move) => move?.source));
  if (moves.length === firstRolloverAddresses.size) {
    if (state.has(readOnlyCanaryAddress) || moveSources.size !== firstRolloverAddresses.size || [...firstRolloverAddresses].some((address) => !moveSources.has(address))) {
      throw new Error("Stage B first migration must move exactly the eleven existing task-definition addresses.");
    }
  } else if (moves.length === currentAddresses.size) {
    if (!state.has(readOnlyCanaryAddress) || moveSources.size !== currentAddresses.size || [...currentAddresses].some((address) => !moveSources.has(address))) {
      throw new Error("Stage B later migration must move all twelve current task-definition addresses.");
    }
  } else {
    throw new Error("Stage B state migration must move exactly eleven first-rollover or twelve later-rollover task definitions.");
  }
  const sources = new Set();
  const destinations = new Set();
  for (const move of moves) {
    if (!move || typeof move.source !== "string" || typeof move.destination !== "string" || move.source.includes("*") || move.destination.includes("*")) throw new Error("Stage B state migration addresses must be explicit.");
    if (!taskDefinitionFamilies.has(move.source)) throw new Error(`Stage B state migration source is not a current task-definition address: ${move.source}`);
    const destination = retainedTaskDefinitionDescriptor(move.destination);
    if (!destination || destination.invalid) throw new Error(`Stage B state migration destination is not revision-keyed: ${move.destination}`);
    if (sources.has(move.source) || destinations.has(move.destination)) throw new Error("Stage B state migration contains a duplicate source or destination.");
    if (!state.has(move.source)) throw new Error(`Stage B state migration source is missing: ${move.source}`);
    if (state.has(move.destination)) throw new Error(`Stage B state migration destination is occupied: ${move.destination}`);
    if (taskDefinitionFamilies.get(move.source) !== destination.family) throw new Error(`Stage B state migration family mismatch: ${move.destination}`);
    sources.add(move.source);
    destinations.add(move.destination);
  }
}

function assertBrokerAuditBinding(plan, brokerChange, audit, auditBytes, auditSha256, planBytes, planSha256, now, terraformConfiguration) {
  if (!audit || !auditBytes || !auditSha256 || !planBytes || !planSha256) throw new Error("Stage B broker update requires an explicit plan-bound reference audit.");
  if (sha256(auditBytes) !== auditSha256) throw new Error("Stage B reference audit SHA-256 mismatch.");
  if (sha256(planBytes) !== planSha256) throw new Error("Stage B plan JSON SHA-256 mismatch.");
  assertStageBReferenceAuditFreshness(audit.auditedAt, now);
  if (audit.planJsonSha256 !== planSha256) throw new Error("Stage B reference audit is bound to a different plan JSON.");
  const broker = audit.broker;
  if (!broker || typeof broker !== "object" || Array.isArray(broker)) throw new Error("Stage B broker update reference audit evidence is missing.");
  const brokerIdentity = assertStageBBrokerConfigurationIdentity({
    configuration: { FunctionArn: broker.configurationFunctionArn, Version: broker.configurationVersion },
    alias: { AliasArn: broker.aliasArn, Name: broker.aliasName, FunctionVersion: broker.aliasFunctionVersion },
  });
  if (broker.resolvedVersionArn !== brokerIdentity.resolvedVersionArn) throw new Error("Stage B broker resolved version identity does not match the configuration evidence.");
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
  const currentTaskDefinitionChanges = taskDefinitionChanges.filter((change) => !retainedTaskDefinitionDescriptor(change.address));
  if (currentTaskDefinitionChanges.length !== Object.keys(STAGE_B_TASK_DEFINITION_FAMILIES).length
    || new Set(currentTaskDefinitionChanges.map((change) => change.address)).size !== currentTaskDefinitionChanges.length
    || currentTaskDefinitionChanges.some((change) => !STAGE_B_TASK_DEFINITION_FAMILIES[change.address])) {
    throw new Error("Stage B broker create task-definition allowlist is not exact.");
  }
  for (const change of currentTaskDefinitionChanges) assertTaskDefinitionScope(change);
  for (const change of taskDefinitionChanges.filter((item) => !currentTaskDefinitionChanges.includes(item))) assertRetainedTaskDefinition(change);
  assertStageBBrokerCreatePlan(plan, proof, terraformConfiguration);
}

function assertExactAuditEntries(actual, expected, label, project) {
  if (!Array.isArray(actual)) throw new Error(`Stage B append-only reference audit ${label} is missing or malformed.`);
  const actualKeys = actual.map(project);
  if (new Set(actualKeys).size !== actualKeys.length) throw new Error(`Stage B append-only reference audit ${label} contains duplicates.`);
  const expectedKeys = expected.map(project);
  if (actualKeys.length !== expectedKeys.length || actualKeys.some((key) => !expectedKeys.includes(key))) {
    throw new Error(`Stage B append-only reference audit ${label} does not match the exact plan.`);
  }
}

function assertAppendOnlyReferenceAuditBinding(plan, classification, referenceAudit, options = {}) {
  const { referenceAuditBytes, referenceAuditSha256, planJsonBytes, planJsonSha256, trustedCallerArn, now = new Date() } = options;
  if (!referenceAudit || !referenceAuditBytes || !referenceAuditSha256 || !planJsonBytes || !planJsonSha256) {
    throw new Error("Stage B append-only plan requires an explicit plan-bound reference audit.");
  }
  if (sha256(referenceAuditBytes) !== referenceAuditSha256) throw new Error("Stage B append-only reference audit SHA-256 mismatch.");
  if (sha256(planJsonBytes) !== planJsonSha256) throw new Error("Stage B append-only plan JSON SHA-256 mismatch.");
  if (referenceAudit.schemaVersion !== STAGE_B_REFERENCE_AUDIT_SCHEMA_VERSION) throw new Error("Stage B append-only reference audit schema version is missing or unsupported.");
  if (referenceAudit.clusterArn !== STAGE_B.clusterArn) throw new Error("Stage B append-only reference audit cluster identity does not match the production cluster.");
  try { assertStageBReleaseCallerArn(referenceAudit.callerArn); } catch { throw new Error("Stage B append-only reference audit caller identity is missing or unauthorized."); }
  if (typeof trustedCallerArn !== "string" || trustedCallerArn !== referenceAudit.callerArn) throw new Error("Stage B append-only reference audit caller identity is not attested by the trusted validation caller.");
  try { assertStageBReleaseCallerArn(trustedCallerArn); } catch { throw new Error("Stage B append-only reference audit caller identity is not attested by the trusted validation caller."); }
  assertStageBReferenceAuditFreshness(referenceAudit.auditedAt, now);
  if (referenceAudit.planJsonSha256 !== planJsonSha256) throw new Error("Stage B append-only reference audit is bound to a different plan JSON.");

  const current = classification.currentEntries;
  const retained = classification.retainedEntries;
  if (!Array.isArray(current) || current.length !== Object.keys(STAGE_B_TASK_DEFINITION_FAMILIES).length) throw new Error("Stage B append-only plan classification is incomplete.");
  if (!referenceAudit.currentTaskDefinitions || typeof referenceAudit.currentTaskDefinitions !== "object") throw new Error("Stage B append-only reference audit currentTaskDefinitions evidence is missing.");
  if (referenceAudit.currentTaskDefinitions.currentCreates !== classification.currentCreates
    || referenceAudit.currentTaskDefinitions.currentNoOps !== classification.currentNoOps
    || referenceAudit.currentTaskDefinitions.total !== classification.total) {
    throw new Error("Stage B append-only reference audit current classification counts do not match the plan.");
  }
  const currentExpected = current.map((entry) => ({
    terraformAddress: entry.address,
    family: entry.family,
    proposedFamily: entry.family,
    classification: entry.classification,
    priorTaskDefinitionArn: entry.priorTaskDefinitionArn,
  }));
  const currentActual = [
    ...(referenceAudit.createOnlyTaskDefinitions || []),
    ...(referenceAudit.noOpTaskDefinitions || []),
  ];
  assertExactAuditEntries(currentActual, currentExpected, "current task definitions", (entry) => `${entry?.terraformAddress}|${entry?.family}|${entry?.classification}|${entry?.priorTaskDefinitionArn ?? ""}`);
  for (const expected of currentExpected) {
    const actual = currentActual.find((entry) => entry?.terraformAddress === expected.terraformAddress);
    if (!actual || actual.family !== expected.family || actual.proposedFamily !== expected.proposedFamily || actual.classification !== expected.classification || (actual.priorTaskDefinitionArn ?? null) !== expected.priorTaskDefinitionArn) {
      throw new Error(`Stage B append-only reference audit current task definition does not match the plan: ${expected.terraformAddress}`);
    }
  }

  const retainedActual = referenceAudit.retainedTaskDefinitions;
  assertExactAuditEntries(retainedActual, retained, "retained task definitions", (entry) => `${entry?.terraformAddress ?? entry?.address}|${entry?.family}|${entry?.oldTaskDefinitionArn}|${entry?.classification}`);
  for (const expected of retained) {
    const actual = retainedActual.find((entry) => entry?.terraformAddress === expected.address);
    const arn = actual?.oldTaskDefinitionArn || "";
    const identity = taskDefinitionArnPattern.exec(arn);
    const historyKey = /\["([^"]+)"\]$/.exec(expected.address)?.[1];
    if (!actual || actual.family !== expected.family || actual.classification !== "retained-no-op" || arn !== expected.oldTaskDefinitionArn || !identity || identity[1] !== expected.family || Number(identity[2]) !== expected.revision || historyKey !== expected.historyKey) {
      throw new Error(`Stage B append-only reference audit retained task definition does not match the plan: ${expected.address}`);
    }
  }
  const retainedByFamily = new Map();
  for (const entry of retained) retainedByFamily.set(entry.family, [...(retainedByFamily.get(entry.family) || []), entry]);
  const newestExpected = [...retainedByFamily.values()].map((entries) => [...entries].sort((left, right) => right.revision - left.revision)[0]);
  assertExactAuditEntries(referenceAudit.newestRetainedTaskDefinitions, newestExpected, "newest retained task definitions", (entry) => `${entry?.terraformAddress ?? entry?.address}|${entry?.family}|${entry?.oldTaskDefinitionArn}`);
  for (const [family, entries] of retainedByFamily) {
    const newest = [...entries].sort((left, right) => right.revision - left.revision)[0];
    const actual = referenceAudit.newestRetainedTaskDefinitions.find((entry) => entry?.family === family);
    if (!actual || actual.terraformAddress !== newest.address || actual.oldTaskDefinitionArn !== newest.oldTaskDefinitionArn) throw new Error(`Stage B append-only reference audit newest retained revision does not match the plan: ${family}`);
  }

  const currentArnsByFamily = new Map();
  for (const change of (plan.resource_changes || []).filter((item) => item.type === "aws_ecs_task_definition")) {
    const entry = current.find((item) => item.address === change.address);
    if (!entry) continue;
    const arn = entry.classification === "no-op" ? entry.priorTaskDefinitionArn : change.change?.after?.arn;
    if (arn) {
      const identity = taskDefinitionArnPattern.exec(arn);
      if (!identity || identity[1] !== entry.family) throw new Error(`Stage B append-only current task-definition ARN is malformed: ${entry.address}`);
      currentArnsByFamily.set(entry.family, new Set([...(currentArnsByFamily.get(entry.family) || []), identity[0]]));
    }
  }
  const retainedArnsByFamily = new Map();
  for (const entry of retained) retainedArnsByFamily.set(entry.family, new Set([...(retainedArnsByFamily.get(entry.family) || []), entry.oldTaskDefinitionArn]));
  const allowedArnsByFamily = new Map(STAGE_B_TASK_DEFINITION_FAMILY_NAMES.map((family) => [family, new Set([...(currentArnsByFamily.get(family) || []), ...(retainedArnsByFamily.get(family) || [])])]));
  if (!Array.isArray(referenceAudit.services) || !Array.isArray(referenceAudit.runningTasks) || !Array.isArray(referenceAudit.pendingTasks) || !Array.isArray(referenceAudit.transitionalTasks) || !Array.isArray(referenceAudit.taskDefinitions)) throw new Error("Stage B append-only reference audit service/task evidence is missing.");
  const checkReferences = (items, arnKey, name) => {
    const seen = new Set();
    for (const item of items) {
      const observationKey = name === "service" ? item?.serviceName : item?.taskArn;
      if (!item || typeof item !== "object" || typeof item[arnKey] !== "string" || typeof observationKey !== "string") throw new Error(`Stage B append-only reference audit ${name} observation is malformed.`);
      const identity = taskDefinitionArnPattern.exec(item[arnKey]);
      if (!identity || seen.has(observationKey)) throw new Error(`Stage B append-only reference audit ${name} observation is malformed or duplicated.`);
      const expectedStageBScoped = identity[1].startsWith("mscqr-production-");
      if (item.stageBScoped !== expectedStageBScoped) throw new Error(`Stage B append-only reference audit ${name} classification is invalid.`);
      seen.add(observationKey);
      if (expectedStageBScoped && !allowedArnsByFamily.get(identity[1])?.has(identity[0])) {
        throw new Error(`Stage B append-only reference audit ${name} contains an unrecorded task-definition ARN.`);
      }
    }
  };
  checkReferences(referenceAudit.services, "taskDefinition", "service");
  checkReferences(referenceAudit.runningTasks, "taskDefinitionArn", "RUNNING task");
  checkReferences(referenceAudit.pendingTasks, "taskDefinitionArn", "PENDING task");
  checkReferences(referenceAudit.transitionalTasks, "taskDefinitionArn", "transitional task");

  const brokerChange = (plan.resource_changes || []).find((change) => change.address === "aws_lambda_function.broker");
  if (brokerChange && exactActions(brokerChange.change?.actions || [], ["update"])) {
    const broker = referenceAudit.broker;
    if (!broker || !Array.isArray(broker.liveTaskDefinitionMappings)) throw new Error("Stage B append-only reference audit broker mapping evidence is missing.");
    const expectedModes = [...STAGE_B_MODES].sort();
    const actualModes = broker.liveTaskDefinitionMappings.map((entry) => entry?.mode);
    if (actualModes.length !== expectedModes.length
      || new Set(actualModes).size !== actualModes.length
      || JSON.stringify([...actualModes].sort()) !== JSON.stringify(expectedModes)) {
      throw new Error("Stage B append-only reference audit broker mode mapping is incomplete or duplicated.");
    }
    const mappingByMode = new Map();
    for (const mapping of broker.liveTaskDefinitionMappings) {
      const identity = taskDefinitionArnPattern.exec(mapping?.taskDefinitionArn || "");
      if (!identity || identity[1] !== expectedBrokerFamily(mapping.mode) || !allowedArnsByFamily.get(identity[1])?.has(identity[0])) throw new Error("Stage B append-only reference audit broker mapping is outside the exact per-mode current/retained ARN sets.");
      mappingByMode.set(mapping.mode, { ...mapping, arn: identity[0], family: identity[1] });
    }
    if (!Array.isArray(referenceAudit.plannedAtomicBrokerRollovers)) throw new Error("Stage B append-only reference audit broker rollover evidence is missing.");
    const atomicByMode = new Map();
    for (const rollover of referenceAudit.plannedAtomicBrokerRollovers) {
      const currentEntry = current.find((entry) => entry.address === rollover?.taskDefinitionTerraformAddress);
      if (!currentEntry || !["create-only", "no-op"].includes(currentEntry.classification)) throw new Error("Stage B append-only reference audit broker rollover classification is not bound to the current plan.");
      if (mappingByMode.get(rollover.mode)?.arn !== rollover.oldTaskDefinitionArn
        || mappingByMode.get(rollover.mode)?.family !== currentEntry.family
        || expectedBrokerAddress(rollover.mode) !== currentEntry.address
        || atomicByMode.has(rollover.mode)
        || !retainedArnsByFamily.get(currentEntry.family)?.has(rollover.oldTaskDefinitionArn)
        || rollover.taskDefinitionArnReference !== `${currentEntry.address}.arn`
        || rollover.planJsonSha256 !== planJsonSha256) {
        throw new Error("Stage B append-only reference audit broker rollover is not bound to exact per-mode retained/current plan addresses.");
      }
      atomicByMode.set(rollover.mode, rollover);
    }
    for (const mode of expectedModes) {
      const mapping = mappingByMode.get(mode);
      const family = expectedBrokerFamily(mode);
      if (!mapping || mapping.family !== family) throw new Error(`Stage B append-only reference audit broker mode mapping is missing: ${mode}`);
      if (retainedArnsByFamily.get(family)?.has(mapping.arn) && (!atomicByMode.has(mode) || atomicByMode.get(mode).oldTaskDefinitionArn !== mapping.arn)) {
        throw new Error(`Stage B append-only reference audit broker retained mapping lacks atomic rollover evidence: ${mode}`);
      }
    }
  }
}

export function assertStageBPlan(plan, options = {}) {
  const { referenceAudit, referenceAuditBytes, referenceAuditSha256, planJsonBytes, planJsonSha256, trustedCallerArn, now = new Date(), terraformConfiguration, imageEvidence } = options;
  const imageBindings = imageEvidence ? assertStageBPlanImageEvidenceBinding({ plan, imageEvidence }) : undefined;
  const brokerChange = (plan.resource_changes || []).find((change) => change.address === "aws_lambda_function.broker");
  const brokerMutationAddresses = new Set(["aws_lambda_function.broker", "aws_lambda_alias.reviewed", "aws_iam_policy.broker"]);
  const brokerMutation = (plan.resource_changes || []).find((change) => brokerMutationAddresses.has(change.address)
    && !exactActions(change.change?.actions || [], ["no-op"]));
  if (brokerMutation) assertStageBBrokerTaskDefinitionMapping(plan, terraformConfiguration);
  if (brokerChange) {
    const brokerActions = brokerChange.change?.actions;
    if (!Array.isArray(brokerActions) || brokerActions.length === 0) throw new Error("Stage B broker actions are missing or malformed.");
    if (exactActions(brokerActions, ["create"])) assertInitialBrokerCreatePlan(plan, terraformConfiguration);
    else if (exactActions(brokerActions, ["update"])) assertBrokerAuditBinding(plan, brokerChange, referenceAudit, referenceAuditBytes, referenceAuditSha256, planJsonBytes, planJsonSha256, now, terraformConfiguration);
    else if (!exactActions(brokerActions, ["no-op"])) throw new Error(`Stage B broker actions are unsupported: ${JSON.stringify(brokerActions)}`);
  }
  const taskDefinitionChanges = (plan.resource_changes || []).filter((change) => change.type === "aws_ecs_task_definition");
  const taskDefinitionClassification = taskDefinitionChanges.length
    ? assertTaskDefinitionAppendOnlyPlan(plan, terraformConfiguration)
    : null;
  const brokerActions = brokerChange?.change?.actions || [];
  if (taskDefinitionClassification && (referenceAudit || exactActions(brokerActions, ["update"]))) {
    assertAppendOnlyReferenceAuditBinding(plan, taskDefinitionClassification, referenceAudit, { referenceAuditBytes, referenceAuditSha256, planJsonBytes, planJsonSha256, trustedCallerArn, now });
  }
  for (const change of plan.resource_changes || []) {
    const actions = change.change.actions || [];
    if (forbidden.test(change.type) || !allowed.has(change.type)) throw new Error(`Stage B plan rejected: ${change.address}`);
    if (change.type === "aws_ecs_task_definition") {
      if (retainedTaskDefinitionDescriptor(change.address)) {
        assertRetainedTaskDefinition(change);
      } else {
        assertTaskDefinitionScope(change);
        if (!exactActions(actions, ["create"]) && !exactActions(actions, ["no-op"])) throw new Error(`Stage B append-only task-definition plan rejected: ${change.address}`);
      }
    } else if (actions.includes("delete")) {
      throw new Error(`Stage B plan rejected: ${change.address}`);
    }
    const after = JSON.stringify(change.change.after || {});
    if ((after.match(/"image":"([^"@]+):[^"@]+"/) || after.match(/"image"\s*:\s*"[^"@]+:[^"@]+"/)) && !after.includes("@sha256:")) throw new Error(`Stage B image tag rejected: ${change.address}`);
  }
  return { taskDefinitions: taskDefinitionClassification, imageBindings };
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
  let trustedCallerArn;
  try {
    trustedCallerArn = JSON.parse(execFileSync("aws", ["sts", "get-caller-identity", "--output", "json"], { encoding: "utf8" })).Arn;
  } catch {
    throw new Error("Stage B trusted caller attestation failed: aws sts get-caller-identity did not return valid identity JSON.");
  }
  assertStageBPlan(plan, { referenceAudit, referenceAuditBytes, referenceAuditSha256, planJsonBytes: Buffer.from(planJsonText), planJsonSha256, trustedCallerArn, terraformConfiguration });
  process.stdout.write(JSON.stringify({ status: "approved-plan-only", plan: out }) + "\n");
}
