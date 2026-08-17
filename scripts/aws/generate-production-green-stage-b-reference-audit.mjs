#!/usr/bin/env node
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { assertStageBBrokerAliasArn, assertStageBBrokerConfigurationIdentity, STAGE_B, STAGE_B_MODES } from "./production-green-stage-b-contract.mjs";
import {
  assertStageBReferenceAuditFreshness,
  STAGE_B_REFERENCE_AUDIT_SCHEMA_VERSION,
  assertStageBAtomicBrokerPlan,
  assertStageBAtomicBrokerPackagePlan,
  assertStageBCurrentTaskDefinitionNoOp,
  assertStageBTaskDefinitionRotation,
  isStageBTaskDefinitionRotationActionsValue,
  STAGE_B_TASK_DEFINITION_FAMILIES,
  STAGE_B_TASK_DEFINITION_FAMILY_NAMES,
  STAGE_B_BROKER_TASK_DEFINITION_REFERENCE,
} from "./stage-b-reference-audit-contract.mjs";
import { batch, createAwsReader, observeStageBEcs } from "./production-green-stage-b-ecs-observations.mjs";
import { assertStageBImportedBackendMetadataNormalization, classifyStageBPlan, isStageBPartialApplyDeposedTaskDefinitionCleanup, stageBMutationInstanceIdentity, STAGE_B_IMPORTED_BACKEND_CANDIDATE_ADDRESS } from "./stage-b-deployment-contract.mjs";
import { assertStageBDeploymentIdentity } from "./stage-b-deployment-identity.mjs";
import { assertStageBArtifactPath, assertStageBPrivateFile, ensureStageBPrivateDirectory, writeStageBPrivateFileAtomic } from "./stage-b-artifact-contract.mjs";

export { batch, createAwsReader } from "./production-green-stage-b-ecs-observations.mjs";

const sha256 = (value) => crypto.createHash("sha256").update(value).digest("hex");
const taskDefinitionArnPattern = /^arn:aws:ecs:eu-west-2:368992683803:task-definition\/([A-Za-z0-9_-]+):([1-9][0-9]*)$/;
const assumedReleaseRolePattern = /^arn:aws:sts::368992683803:assumed-role\/mscqr-production-release-deployer\/[A-Za-z0-9+=,.@_-]{2,64}$/;
const sorted = (items, key) => [...items].sort((left, right) => String(key(left)).localeCompare(String(key(right))));
const stageBTerraformConfigurationPath = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../infra/aws/terraform/production-green-stage-b/main.tf");
const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");

const familyFromArn = (value, label) => {
  const match = taskDefinitionArnPattern.exec(value || "");
  if (!match) throw new Error(`${label} is not a valid ECS task-definition ARN.`);
  return { arn: value, family: match[1], revision: Number(match[2]) };
};

const expectedBrokerFamily = (mode) => mode === "full-rls-application-canary"
  ? STAGE_B_TASK_DEFINITION_FAMILIES['aws_ecs_task_definition.candidate["canary"]']
  : `mscqr-production-full-rls-green-${mode}`;
const brokerTaskDefinitionAddress = (mode) => mode === "full-rls-application-canary"
  ? 'aws_ecs_task_definition.candidate["canary"]'
  : `aws_ecs_task_definition.executor["${mode}"]`;
const retainedTaskDefinitionAddressPattern = /^aws_ecs_task_definition\.(candidate|executor)_retained\["([^"]+)"\]$/;
const currentAddressForRetained = (address) => {
  const match = retainedTaskDefinitionAddressPattern.exec(address || "");
  if (!match) return undefined;
  for (const currentAddress of Object.keys(STAGE_B_TASK_DEFINITION_FAMILIES)) {
    const currentKey = /\["([^"]+)"\]$/.exec(currentAddress)?.[1];
    if (currentAddress.startsWith(`aws_ecs_task_definition.${match[1]}[`) && new RegExp(`^[a-f0-9]{7,40}-${currentKey}$`).test(match[2])) return currentAddress;
  }
  return null;
};

function parseJson(value, label) {
  if (typeof value !== "string" || value.length === 0) throw new Error(`${label} is missing.`);
  try {
    return JSON.parse(value);
  } catch {
    throw new Error(`${label} is malformed JSON.`);
  }
}

function requireArray(value, label) {
  if (!Array.isArray(value)) throw new Error(`${label} is malformed.`);
  return value;
}

function requireObject(value, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(`${label} is malformed.`);
  return value;
}

function observedFamily(value, label) {
  const { family } = familyFromArn(value, label);
  if (family.startsWith("mscqr-production-") && !STAGE_B_TASK_DEFINITION_FAMILY_NAMES.includes(family)) {
    throw new Error(`${label} contains an unknown Stage B task-definition family.`);
  }
  return family;
}

function normalizeEnvironment(config) {
  const environment = Array.isArray(config?.Environment) ? config.Environment[0] : config?.Environment;
  const variables = environment?.Variables;
  return requireObject(variables, "broker Lambda environment variables");
}

function partitionTaskDefinitionMutationInstances(plan) {
  const changes = requireArray(plan?.resource_changes, "Terraform plan resource_changes")
    .filter((item) => item?.type === "aws_ecs_task_definition");
  const current = [];
  const deposed = [];
  const currentAddresses = new Set();
  const deposedAddresses = new Set();
  const deposedIdentities = new Set();
  for (const change of changes) {
    if (Object.hasOwn(change, "deposed")) {
      if (!isStageBPartialApplyDeposedTaskDefinitionCleanup(change)) {
        throw new Error(`Terraform plan contains an unexpected or malformed deposed task-definition cleanup: ${change.address}`);
      }
      const identity = stageBMutationInstanceIdentity(change);
      if (deposedIdentities.has(identity) || deposedAddresses.has(change.address)) {
        throw new Error(`Terraform plan contains a duplicate deposed task-definition cleanup: ${change.address}`);
      }
      deposedIdentities.add(identity);
      deposedAddresses.add(change.address);
      deposed.push(change);
      continue;
    }
    if (currentAddresses.has(change.address)) {
      throw new Error(`Terraform plan contains a duplicate current task-definition instance: ${change.address}`);
    }
    currentAddresses.add(change.address);
    current.push(change);
  }
  return { current, deposed };
}

function planTaskDefinitions(plan, terraformConfiguration) {
  const { current: currentTaskDefinitionChanges, deposed: deposedTaskDefinitionChanges } = partitionTaskDefinitionMutationInstances(plan);
  const currentPlan = { ...plan, resource_changes: currentTaskDefinitionChanges };
  const seenFamilies = new Set();
  const rolloverByAddress = new Map();
  const createOnlyByAddress = new Map();
  const noOpByAddress = new Map();
  const retainedByAddress = new Map();
  for (const change of currentTaskDefinitionChanges) {
    const address = change.address;
    const before = change.change?.before || {};
    const after = change.change?.after || {};
    const family = after.family || before.family;
    if (typeof family !== "string" || !family) throw new Error(`Terraform plan task-definition family is missing: ${address}`);
    if (!Object.values(STAGE_B_TASK_DEFINITION_FAMILIES).includes(family)) throw new Error(`Terraform plan contains an unknown Stage B task-definition family: ${family}`);
    const currentAddress = currentAddressForRetained(address);
    if (currentAddress !== undefined) {
      if (currentAddress === null) throw new Error(`Terraform plan retained task-definition address must be revision-keyed: ${address}`);
      if (STAGE_B_TASK_DEFINITION_FAMILIES[currentAddress] !== family) throw new Error(`Terraform plan retained task-definition address does not match its exact family: ${address}`);
      const actions = requireArray(change.change?.actions, `Terraform plan actions for ${address}`);
      if (JSON.stringify(actions) !== JSON.stringify(["no-op"]) || !before.arn) throw new Error(`Terraform plan retained task definition must be an exact no-op with a prior ARN: ${address}`);
      const prior = familyFromArn(before.arn, `${address} retained task definition`);
      if (before.family !== family || prior.family !== family) throw new Error(`Terraform plan retained task-definition family mismatch: ${address}`);
      if (retainedByAddress.has(address)) throw new Error(`Terraform plan contains a duplicate retained task-definition address: ${address}`);
      const historyKey = /\["([^"]+)"\]$/.exec(address)?.[1];
      if ([...retainedByAddress.values()].some((entry) => entry.historyKey === historyKey && entry.family === family)) throw new Error(`Terraform plan contains a duplicate retained family in one generation: ${historyKey}`);
      retainedByAddress.set(address, { address, historyKey, family, oldArn: before.arn, proposedFamily: after.family || family });
      continue;
    }
    if (seenFamilies.has(family)) throw new Error(`Terraform plan contains a duplicate Stage B task-definition family: ${family}`);
    seenFamilies.add(family);
    if (STAGE_B_TASK_DEFINITION_FAMILIES[address] !== family) throw new Error(`Terraform plan task-definition address does not match its exact family: ${address}`);
    if (after.family !== family) throw new Error(`Terraform plan proposed task-definition family is unresolved: ${address}`);
    const actions = requireArray(change.change?.actions, `Terraform plan actions for ${address}`);
    const oldArn = before.arn || before.id;
    if (JSON.stringify(actions) === JSON.stringify(["create"])) {
      if (oldArn) throw new Error(`Terraform plan create-only task definition unexpectedly has a prior ARN: ${address}`);
      createOnlyByAddress.set(address, { address, family, proposedFamily: after.family, proposedArn: after.arn });
      continue;
    }
    if (JSON.stringify(actions) === JSON.stringify(["no-op"])) {
      if (!before.arn) throw new Error(`Terraform plan no-op task definition is missing its prior ARN: ${address}`);
      const prior = familyFromArn(before.arn, `${address} no-op task definition`);
      if (before.family !== family || prior.family !== family) throw new Error(`Terraform plan no-op task-definition family mismatch: ${address}`);
      noOpByAddress.set(address, { address, family, priorArn: before.arn, currentArn: after.arn || before.arn, proposedFamily: after.family, change });
      continue;
    }
    if (address === STAGE_B_IMPORTED_BACKEND_CANDIDATE_ADDRESS && JSON.stringify(actions) === JSON.stringify(["update"])) {
      assertStageBImportedBackendMetadataNormalization(change, { terraformConfiguration });
      noOpByAddress.set(address, { address, family, priorArn: before.arn, currentArn: after.arn, proposedFamily: after.family, change, importedMetadata: true });
      continue;
    }
    if (isStageBTaskDefinitionRotationActionsValue(actions)) {
      const rollover = assertStageBTaskDefinitionRotation(change, currentPlan, { strict: true });
      rolloverByAddress.set(address, { ...rollover, proposedFamily: after.family });
      continue;
    }
    throw new Error(`Terraform plan task-definition change must be create-only or rollover: ${address}`);
  }
  if (seenFamilies.size !== STAGE_B_TASK_DEFINITION_FAMILY_NAMES.length) {
    const missing = STAGE_B_TASK_DEFINITION_FAMILY_NAMES.filter((family) => !seenFamilies.has(family));
    throw new Error(`Terraform plan is missing exact Stage B task-definition families: ${missing.join(", ")}`);
  }
  const retainedByFamily = new Map();
  const retainedArns = new Set();
  const retainedFamilyRevisions = new Set();
  for (const entry of retainedByAddress.values()) {
    const identity = familyFromArn(entry.oldArn, `${entry.address} retained task definition`);
    if (retainedArns.has(identity.arn)) throw new Error(`Terraform plan contains a duplicate retained task-definition ARN: ${identity.arn}`);
    const familyRevision = `${identity.family}:${identity.revision}`;
    if (retainedFamilyRevisions.has(familyRevision)) throw new Error(`Terraform plan contains a duplicate retained family and revision: ${familyRevision}`);
    retainedArns.add(identity.arn);
    retainedFamilyRevisions.add(familyRevision);
    retainedByFamily.set(identity.family, [...(retainedByFamily.get(identity.family) || []), { ...entry, revision: identity.revision }]);
  }
  const retainedArnSet = new Set(retainedArns);
  for (const entry of noOpByAddress.values()) {
    if (rolloverByAddress.size === 0 && !entry.importedMetadata) {
      const validated = assertStageBCurrentTaskDefinitionNoOp(entry.change, currentPlan, retainedArnSet);
      entry.priorArn = validated.arn;
      entry.currentArn = validated.currentArn;
    }
  }
  const newestRetainedByFamily = new Map();
  for (const [family, entries] of retainedByFamily) {
    newestRetainedByFamily.set(family, [...entries].sort((left, right) => right.revision - left.revision)[0]);
  }
  return {
    rolloverByAddress,
    createOnlyByAddress,
    noOpByAddress,
    retainedByAddress,
    retainedByFamily,
    newestRetainedByFamily,
    retainedArnSet,
    currentTaskDefinitionChanges,
    currentRuntimeTaskDefinitionChanges: currentTaskDefinitionChanges.filter((change) => currentAddressForRetained(change.address) === undefined),
    deposedTaskDefinitionChanges,
  };
}

function ensurePlanHash(planBytes, expectedPlanSha256) {
  if (!Buffer.isBuffer(planBytes) || planBytes.length === 0) throw new Error("Terraform plan JSON is missing.");
  if (!/^[a-f0-9]{64}$/.test(expectedPlanSha256 || "")) throw new Error("Terraform plan SHA-256 is missing or malformed.");
  const actual = sha256(planBytes);
  if (actual !== expectedPlanSha256) throw new Error("Terraform plan SHA-256 does not match the supplied plan JSON.");
  return actual;
}

function validateCaller(callerArn) {
  if (!assumedReleaseRolePattern.test(callerArn || "")) throw new Error("Caller is not the MFA-backed production release-deployer role.");
  return callerArn;
}

function validateTaskDefinitionResponse(response, expectedFamily, label) {
  const taskDefinition = requireObject(response?.taskDefinition, `${label} response`);
  const identity = familyFromArn(taskDefinition.taskDefinitionArn, `${label} taskDefinitionArn`);
  if (identity.family !== expectedFamily || taskDefinition.family !== expectedFamily || taskDefinition.revision !== identity.revision) {
    throw new Error(`${label} does not match its exact expected task-definition family.`);
  }
  if (typeof taskDefinition.status !== "string" || !taskDefinition.status) throw new Error(`${label} status is missing.`);
  return { family: expectedFamily, arn: identity.arn, revision: identity.revision, status: taskDefinition.status };
}

function validateRetainedTaskDefinitionResponse(response, expectedFamily, label) {
  const status = response?.taskDefinition?.status;
  if (status !== "ACTIVE") {
    throw new Error(`${label} for family ${expectedFamily} has unsupported status ${String(status)}; expected ACTIVE.`);
  }
  return validateTaskDefinitionResponse(response, expectedFamily, label);
}

function currentManagedTaskDefinitionPredecessors(plan) {
  const resources = [];
  const visit = (module) => {
    resources.push(...(module?.resources || []));
    for (const child of module?.child_modules || []) visit(child);
  };
  visit(plan?.prior_state?.values?.root_module);
  return new Map(resources
    .filter((resource) => Object.hasOwn(STAGE_B_TASK_DEFINITION_FAMILIES, resource?.address))
    .map((resource) => [resource.address, { arn: resource.values?.arn, family: resource.values?.family }]));
}

function proveAtomicBrokerReference(plan, mode, rolloverByAddress, planSha256, terraformConfiguration) {
  const taskDefinitionAddress = brokerTaskDefinitionAddress(mode);
  const rollover = rolloverByAddress.get(taskDefinitionAddress);
  if (!rollover) throw new Error(`Broker atomic rollover target is not a planned rollover: ${taskDefinitionAddress}`);
  assertStageBAtomicBrokerPlan(plan, taskDefinitionAddress, mode, terraformConfiguration);
  return {
    brokerTerraformAddress: "aws_lambda_function.broker",
    taskDefinitionTerraformAddress: taskDefinitionAddress,
    mode,
    family: rollover.family,
    oldTaskDefinitionArn: rollover.oldArn,
    brokerEnvironmentReference: STAGE_B_BROKER_TASK_DEFINITION_REFERENCE,
    taskDefinitionArnReference: `${taskDefinitionAddress}.arn`,
    planJsonSha256: planSha256,
  };
}

function proveBrokerPackagePlan(plan, terraformConfiguration, expectedPackageChecksum, livePackageChecksum, planSha256) {
  const packagePath = plan?.variables?.broker_package_path?.value;
  if (typeof packagePath !== "string" || !path.isAbsolute(packagePath)) throw new Error("Broker package path is missing or malformed in the exact plan input.");
  let packageBytes;
  try {
    packageBytes = fs.readFileSync(packagePath);
  } catch {
    throw new Error("Expected broker package file is missing or unreadable.");
  }
  const brokerZipFileSha256 = sha256(packageBytes);
  const plannedBrokerSourceCodeHashBase64 = crypto.createHash("sha256").update(packageBytes).digest("base64");
  const proof = {
    brokerTerraformAddress: "aws_lambda_function.broker",
    brokerEnvironmentReference: "local.broker_approval_expected",
    packageInputReference: "var.package_checksum_sha256",
    packagePath,
    liveReleasePackageChecksumSha256: livePackageChecksum,
    planBeforeReleasePackageChecksumSha256: undefined,
    plannedReleasePackageChecksumSha256: expectedPackageChecksum,
    brokerZipFileSha256,
    plannedBrokerSourceCodeHashBase64,
    planJsonSha256: planSha256,
  };
  const brokerChange = (plan.resource_changes || []).find((change) => change.address === "aws_lambda_function.broker");
  const beforeRaw = brokerChange?.change?.before?.environment?.[0]?.variables?.BROKER_APPROVAL_EXPECTED_JSON;
  try {
    proof.planBeforeReleasePackageChecksumSha256 = JSON.parse(beforeRaw || "").packageChecksumSha256;
  } catch {
    throw new Error("Plan before broker approval JSON is malformed.");
  }
  assertStageBAtomicBrokerPackagePlan(plan, proof, terraformConfiguration);
  return proof;
}

function validateBrokerConfiguration(config, alias, brokerAliasArn, expectedPackageChecksum, oldArns, createOnlyFamilies, currentNoOpByFamily, currentArnSetByFamily, retainedArnSetByFamily, newestRetainedByFamily, plan, rolloverByAddress, planSha256, terraformConfiguration) {
  const brokerIdentity = assertStageBBrokerConfigurationIdentity({ configuration: config, alias });
  const variables = normalizeEnvironment(config);
  const taskDefinitions = requireObject(parseJson(variables.BROKER_TASK_DEFINITIONS_JSON, "BROKER_TASK_DEFINITIONS_JSON"), "BROKER_TASK_DEFINITIONS_JSON");
  const expectedModes = [...STAGE_B_MODES].sort();
  if (JSON.stringify(Object.keys(taskDefinitions).sort()) !== JSON.stringify(expectedModes)) throw new Error("Broker task-definition mode set is not exact.");
  const brokerReferences = new Map();
  const brokerReferencesByFamily = new Map();
  for (const mode of expectedModes) {
    const identity = familyFromArn(taskDefinitions[mode], `broker task definition for ${mode}`);
    if (identity.family !== expectedBrokerFamily(mode)) throw new Error(`Broker task definition family is unexpected for ${mode}.`);
    const retainedArns = retainedArnSetByFamily.get(identity.family) || new Set();
    const currentNoOpArns = currentNoOpByFamily.get(identity.family) || new Set();
    const currentArns = currentArnSetByFamily.get(identity.family) || new Set();
    const currentManagedArns = new Set([...rolloverByAddress.values()]
      .filter((entry) => entry.family === identity.family)
      .map((entry) => entry.oldArn));
    if ((retainedArns.size > 0 || currentNoOpArns.size > 0)
      && !retainedArns.has(identity.arn) && !currentNoOpArns.has(identity.arn) && !currentArns.has(identity.arn) && !currentManagedArns.has(identity.arn)) throw new Error(`Broker task-definition ARN is not an explicitly retained or current no-op revision: ${mode}.`);
    brokerReferences.set(identity.arn, mode);
    brokerReferencesByFamily.set(identity.family, [...(brokerReferencesByFamily.get(identity.family) || []), mode]);
  }
  const atomicByAddress = new Map(rolloverByAddress);
  for (const [address, entry] of [...createOnlyFamilies].flatMap((family) => {
    const current = Object.entries(STAGE_B_TASK_DEFINITION_FAMILIES).find(([, candidateFamily]) => candidateFamily === family)?.[0];
    const newest = newestRetainedByFamily.get(family);
    return current && newest ? [[current, { address: current, family, oldArn: newest.oldArn, proposedFamily: family, classification: "currentCreate" }]] : [];
  })) atomicByAddress.set(address, entry);
  for (const [family, currentArns] of currentNoOpByFamily) {
    const address = Object.entries(STAGE_B_TASK_DEFINITION_FAMILIES).find(([, candidateFamily]) => candidateFamily === family)?.[0];
    const currentArn = [...currentArns][0];
    if (address && currentArn) atomicByAddress.set(address, { address, family, oldArn: currentArn, proposedFamily: family, classification: "currentNoOp" });
  }
  const rolloverByFamily = new Map([...atomicByAddress.values()].map((entry) => [entry.family, entry]));
  const plannedAtomicBrokerRollovers = [];
  for (const [arn, mode] of brokerReferences) {
    const identity = familyFromArn(arn, `broker task definition for ${mode}`);
    const rollover = rolloverByFamily.get(identity.family);
    const retainedArns = retainedArnSetByFamily.get(identity.family) || new Set();
    const currentNoOpArns = currentNoOpByFamily.get(identity.family) || new Set();
    if (!rollover) continue;
    if (retainedArns.has(identity.arn)) {
      try {
        const atomicByLiveArn = new Map(atomicByAddress);
        atomicByLiveArn.set(rollover.address, { ...rollover, oldArn: identity.arn });
        plannedAtomicBrokerRollovers.push(proveAtomicBrokerReference(plan, mode, atomicByLiveArn, planSha256, terraformConfiguration));
      } catch (error) {
        throw new Error(`Broker Lambda still references superseded task definition ${arn}: ${error.message}`);
      }
    } else if (rollover.oldArn === identity.arn) {
      try {
        plannedAtomicBrokerRollovers.push(proveAtomicBrokerReference(plan, mode, atomicByAddress, planSha256, terraformConfiguration));
      } catch (error) {
        throw new Error(`Broker Lambda still references superseded task definition ${arn}: ${error.message}`);
      }
    } else if (currentNoOpArns.size > 0 && !currentNoOpArns.has(identity.arn) && !currentArns.has(identity.arn)) {
      throw new Error(`Broker Lambda task-definition ARN is not an explicitly retained or current no-op revision for ${identity.family}.`);
    }
  }
  for (const oldArn of oldArns) {
    if (brokerReferences.has(oldArn) && !plannedAtomicBrokerRollovers.some((entry) => entry.oldTaskDefinitionArn === oldArn)) {
      throw new Error(`Broker Lambda still references superseded task definition ${oldArn}.`);
    }
  }
  const approvalExpected = requireObject(parseJson(variables.BROKER_APPROVAL_EXPECTED_JSON, "BROKER_APPROVAL_EXPECTED_JSON"), "BROKER_APPROVAL_EXPECTED_JSON");
  const brokerChange = (plan.resource_changes || []).find((change) => change.address === "aws_lambda_function.broker");
  const brokerActions = brokerChange?.change?.actions || [];
  const brokerIsNoOp = JSON.stringify(brokerActions) === JSON.stringify(["no-op"]);
  const brokerProof = brokerChange && !brokerIsNoOp
    ? proveBrokerPackagePlan(plan, terraformConfiguration, expectedPackageChecksum, approvalExpected.packageChecksumSha256, planSha256)
    : null;
  if (brokerIsNoOp && approvalExpected.packageChecksumSha256 !== expectedPackageChecksum) {
    throw new Error("Broker no-op cannot retain a stale release package checksum.");
  }
  if (approvalExpected.packageChecksumSha256 !== expectedPackageChecksum && !brokerProof) {
    throw new Error("Stale broker release checksum requires a planned broker update.");
  }
  const plannedAtomicPackageChecksumTransition = approvalExpected.packageChecksumSha256 === expectedPackageChecksum
    ? null
    : { ...brokerProof, transition: "plannedAtomicPackageChecksumTransition" };
  return {
    summary: {
      functionArn: STAGE_B.brokerFunctionArn,
      functionVersion: brokerIdentity.configurationVersion,
      aliasArn: brokerIdentity.aliasArn,
      aliasVersion: brokerIdentity.aliasFunctionVersion,
      aliasName: brokerIdentity.aliasName,
      aliasFunctionVersion: brokerIdentity.aliasFunctionVersion,
      configurationFunctionArn: brokerIdentity.configurationFunctionArn,
      configurationVersion: brokerIdentity.configurationVersion,
      resolvedVersionArn: brokerIdentity.resolvedVersionArn,
      releasePackageChecksumSha256: approvalExpected.packageChecksumSha256,
      plannedReleasePackageChecksumSha256: expectedPackageChecksum,
      planBeforeReleasePackageChecksumSha256: brokerProof?.planBeforeReleasePackageChecksumSha256,
      brokerZipFileSha256: brokerProof?.brokerZipFileSha256,
      plannedBrokerSourceCodeHashBase64: brokerProof?.plannedBrokerSourceCodeHashBase64,
      brokerPackagePath: brokerProof?.packagePath,
      planJsonSha256: planSha256,
      taskDefinitionModes: expectedModes,
      liveTaskDefinitionMappings: [...brokerReferences.entries()]
        .map(([taskDefinitionArn, mode]) => ({ mode, taskDefinitionArn }))
        .sort((left, right) => left.mode.localeCompare(right.mode)),
    },
    referencesByFamily: brokerReferencesByFamily,
    referencesByArn: brokerReferences,
    plannedAtomicBrokerRollovers: plannedAtomicBrokerRollovers.sort((left, right) => left.taskDefinitionTerraformAddress.localeCompare(right.taskDefinitionTerraformAddress)),
    plannedAtomicPackageChecksumTransition,
  };
}

function referenceNames(items, oldArns, arnKey, nameKey) {
  const references = new Map(oldArns.map((arn) => [arn, []]));
  for (const item of items) {
    const arn = item[arnKey];
    if (references.has(arn)) references.get(arn).push(item[nameKey]);
  }
  return references;
}

function referenceNamesByFamily(items, families, arnKey, nameKey) {
  const references = new Map([...families].map((family) => [family, []]));
  for (const item of items) {
    const family = familyFromArn(item[arnKey], `${nameKey} task definition`).family;
    if (references.has(family)) references.get(family).push(item[nameKey]);
  }
  return references;
}

function generateRecoveryOnlyReferenceAudit({ plan, planBytes, planJsonSha256, reader, callerArn, auditedAt, now, recoveryAttestationSha256 }) {
  if (plan?.variables?.stage_b_recovery_only?.value !== true) throw new Error("Recovery-only reference audit requires the explicit recovery-only plan variable.");
  const changes = requireArray(plan.resource_changes, "Terraform plan resource_changes");
  const alias = changes.find((change) => change?.address === "aws_lambda_alias.reviewed");
  if (!alias || JSON.stringify(alias.change?.actions || []) !== JSON.stringify(["update"])) throw new Error("Recovery-only reference audit requires the reviewed-alias update.");
  const mutations = changes.filter((change) => JSON.stringify(change.change?.actions || []) !== JSON.stringify(["no-op"]));
  if (mutations.length !== 1 || mutations[0] !== alias) throw new Error("Recovery-only reference audit found a non-alias mutation.");
  const aliasVersion = String(alias.change?.before?.function_version || "");
  const targetVersion = String(alias.change?.after?.function_version || "");
  if (!/^[1-9][0-9]*$/.test(aliasVersion) || !/^[1-9][0-9]*$/.test(targetVersion) || alias.change?.after_unknown?.function_version === true) throw new Error("Recovery-only alias target must be a concrete published version.");
  const config = reader.getFunctionConfiguration(STAGE_B.brokerAliasArn);
  const liveAlias = reader.getAlias(STAGE_B.brokerFunctionArn, STAGE_B.brokerAliasQualifier);
  const brokerIdentity = assertStageBBrokerConfigurationIdentity({ configuration: config, alias: liveAlias });
  if (brokerIdentity.aliasFunctionVersion !== aliasVersion) throw new Error("Recovery-only reference audit live alias version does not match the plan.");
  assertStageBReferenceAuditFreshness(auditedAt, now);
  if (recoveryAttestationSha256 !== undefined && !/^[a-f0-9]{64}$/.test(recoveryAttestationSha256)) throw new Error("Recovery attestation SHA256 is malformed.");
  const planSha = ensurePlanHash(planBytes, planJsonSha256);
  const deploymentIdentity = assertStageBDeploymentIdentity({ plan });
  const observedCallerArn = callerArn || reader.getCallerIdentity()?.Arn;
  if (!assumedReleaseRolePattern.test(observedCallerArn || "")) throw new Error("Recovery-only reference audit caller is not the production release-deployer.");
  const noOpResources = changes.filter((change) => change !== alias).map((change) => ({ address: change.address, type: change.type, actions: change.change?.actions || [] }));
  return {
    schemaVersion: STAGE_B_REFERENCE_AUDIT_SCHEMA_VERSION,
    toolingSha: deploymentIdentity.toolingSha,
    imageReleaseSha: deploymentIdentity.imageReleaseSha,
    canonicalImageEvidenceSha256: deploymentIdentity.canonicalImageEvidenceSha256,
    auditedAt,
    callerArn: observedCallerArn,
    clusterArn: STAGE_B.clusterArn,
    recoveryOnly: true,
    recoveryAttestationSha256,
    recoveryAlias: { address: alias.address, liveVersion: aliasVersion, targetVersion, aliasArn: liveAlias.AliasArn, aliasName: liveAlias.Name },
    broker: { ...brokerIdentity, functionArn: STAGE_B.brokerFunctionArn, configurationFunctionArn: brokerIdentity.configurationFunctionArn, configurationVersion: brokerIdentity.configurationVersion, resolvedVersionArn: brokerIdentity.resolvedVersionArn },
    recoveryNoOpResources: noOpResources,
    services: [], runningTasks: [], pendingTasks: [], transitionalTasks: [], taskDefinitions: [],
    oldTaskDefinitions: [], retainedTaskDefinitions: [], newestRetainedTaskDefinitions: [], createOnlyTaskDefinitions: [], noOpTaskDefinitions: noOpResources,
    currentTaskDefinitions: { currentCreates: 0, currentNoOps: noOpResources.filter((entry) => entry.type === "aws_ecs_task_definition").length, total: 0 },
    plannedAtomicBrokerRollovers: [], plannedAtomicPackageChecksumTransition: null,
    allOldRevisionsUnreferenced: true, noServiceDeploymentObserved: true, noTaskExecutionObserved: true,
    planJsonSha256: planSha,
  };
}

function assertStageBLiveReferences(items, allowedByFamily, createOnlyFamilies, arnKey, nameKey) {
  for (const item of items) {
    const family = observedFamily(item[arnKey], `${nameKey} task definition`);
    const allowed = allowedByFamily.get(family);
    if (createOnlyFamilies.has(family) && (!allowed || !allowed.has(item[arnKey]))) {
      throw new Error(`Create-only task-definition family remains referenced: ${item[arnKey]}`);
    }
    if (allowed?.size > 0 && !allowed.has(item[arnKey])) {
      throw new Error(`Superseded task definition remains referenced: ${item[arnKey]} (${nameKey} references an unrecorded task-definition ARN)`);
    }
  }
}

export function generateReferenceAudit({
  plan,
  planBytes,
  planJsonSha256,
  region,
  clusterArn,
  brokerAliasArn,
  expectedPackageChecksumSha256,
  reader,
  callerArn,
  terraformConfiguration,
  recoveryAttestationSha256,
  auditedAt = new Date().toISOString(),
  now = new Date(),
}) {
  if (!reader) throw new Error("Read-only AWS reader is required.");
  if (region !== "eu-west-2") throw new Error("Stage B requires AWS region eu-west-2.");
  if (clusterArn !== STAGE_B.clusterArn) throw new Error("ECS cluster ARN is outside the exact Stage B contract.");
  assertStageBBrokerAliasArn(brokerAliasArn);
  if (!/^[a-f0-9]{64}$/.test(expectedPackageChecksumSha256 || "")) throw new Error("Expected broker package checksum is missing or malformed.");
  if (plan?.variables?.package_checksum_sha256?.value !== expectedPackageChecksumSha256) throw new Error("Expected release package checksum does not match the exact plan input.");
  assertStageBReferenceAuditFreshness(auditedAt, now);
  classifyStageBPlan(plan, { strict: false, validateActions: false, terraformConfiguration });
  const deploymentIdentity = assertStageBDeploymentIdentity({ plan });
  const planSha = ensurePlanHash(planBytes, planJsonSha256);
  if (recoveryAttestationSha256 !== undefined && !/^[a-f0-9]{64}$/.test(recoveryAttestationSha256)) throw new Error("Recovery attestation SHA256 is malformed.");
  if (plan?.variables?.stage_b_recovery_only?.value === true) return generateRecoveryOnlyReferenceAudit({ plan, planBytes, planJsonSha256, reader, callerArn, auditedAt, now, recoveryAttestationSha256 });
  const {
    rolloverByAddress,
    createOnlyByAddress,
    noOpByAddress,
    retainedByAddress,
    retainedByFamily,
    newestRetainedByFamily,
    retainedArnSet,
    currentRuntimeTaskDefinitionChanges,
    deposedTaskDefinitionChanges,
  } = planTaskDefinitions(plan, terraformConfiguration);
  const currentManagedByAddress = currentManagedTaskDefinitionPredecessors(plan);
  for (const rollover of rolloverByAddress.values()) {
    const current = currentManagedByAddress.get(rollover.address);
    if (!current || current.family !== rollover.family || current.arn !== rollover.oldArn) throw new Error(`Terraform plan rollover predecessor is not the exact current managed task definition: ${rollover.address}`);
    if (retainedArnSet.has(current.arn)) throw new Error(`Terraform plan rollover predecessor is also present in retained history: ${rollover.address}`);
  }
  const createOnlyFamilies = new Set([...createOnlyByAddress.values()].map((entry) => entry.family));
  const noOpFamilies = new Set([...noOpByAddress.values()].map((entry) => entry.family));
  const retainedArnSetByFamily = new Map([...retainedByFamily].map(([family, entries]) => [family, new Set(entries.map((entry) => entry.oldArn))]));
  const currentNoOpByFamily = new Map();
  for (const entry of noOpByAddress.values()) currentNoOpByFamily.set(entry.family, new Set([...(currentNoOpByFamily.get(entry.family) || []), entry.currentArn]));
  const currentArnSetByFamily = new Map();
  for (const entry of createOnlyByAddress.values()) {
    if (entry.proposedArn) {
      const identity = familyFromArn(entry.proposedArn, `${entry.address} planned current task definition`);
      if (identity.family !== entry.family) throw new Error(`Planned current task-definition ARN family mismatch: ${entry.address}`);
      currentArnSetByFamily.set(entry.family, new Set([...(currentArnSetByFamily.get(entry.family) || []), identity.arn]));
    }
  }
  for (const entry of noOpByAddress.values()) {
    const identity = familyFromArn(entry.currentArn, `${entry.address} planned current task definition`);
    if (identity.family !== entry.family) throw new Error(`Planned current task-definition ARN family mismatch: ${entry.address}`);
    currentArnSetByFamily.set(entry.family, new Set([...(currentArnSetByFamily.get(entry.family) || []), identity.arn]));
  }
  const allowedLiveArnsByFamily = new Map();
  for (const family of STAGE_B_TASK_DEFINITION_FAMILY_NAMES) {
    allowedLiveArnsByFamily.set(family, new Set([
      ...(retainedArnSetByFamily.get(family) || []),
      ...(currentNoOpByFamily.get(family) || []),
      ...(currentArnSetByFamily.get(family) || []),
    ]));
  }
  const observedCallerArn = validateCaller(callerArn || reader.getCallerIdentity()?.Arn);

  const oldDefinitions = [];
  for (const rollover of [...rolloverByAddress.values()].sort((left, right) => left.address.localeCompare(right.address))) {
    const described = validateTaskDefinitionResponse(reader.describeTaskDefinition(rollover.oldArn), rollover.family, `${rollover.address} old task definition`);
    oldDefinitions.push({ ...rollover, currentStatus: described.status, rollbackArn: described.arn });
  }
  const retainedDefinitions = [];
  for (const retained of [...retainedByAddress.values()].sort((left, right) => left.address.localeCompare(right.address))) {
    const described = validateRetainedTaskDefinitionResponse(reader.describeTaskDefinition(retained.oldArn), retained.family, `${retained.address} retained task definition`);
    retainedDefinitions.push({ ...retained, currentStatus: described.status });
  }
  const oldArns = [...oldDefinitions, ...retainedDefinitions].map((entry) => entry.oldArn);

  const { services, runningTasks, pendingTasks, transitionalTasks, taskDefinitions } = observeStageBEcs({ reader, region, clusterArn });
  const stageBServices = services.filter((service) => service.stageBScoped);
  const stageBRunningTasks = runningTasks.filter((task) => task.stageBScoped);
  const stageBPendingTasks = pendingTasks.filter((task) => task.stageBScoped);
  const {
    summary: broker,
    referencesByFamily: brokerReferencesByFamily,
    referencesByArn: brokerReferencesByArn,
    plannedAtomicBrokerRollovers,
    plannedAtomicPackageChecksumTransition,
  } = validateBrokerConfiguration(reader.getFunctionConfiguration(brokerAliasArn), reader.getAlias(STAGE_B.brokerFunctionArn, STAGE_B.brokerAliasQualifier), brokerAliasArn, expectedPackageChecksumSha256, oldArns, createOnlyFamilies, currentNoOpByFamily, currentArnSetByFamily, retainedArnSetByFamily, newestRetainedByFamily, plan, rolloverByAddress, planSha, terraformConfiguration);
  const serviceReferences = referenceNames(stageBServices, oldArns, "taskDefinition", "serviceName");
  const runningReferences = referenceNames(stageBRunningTasks, oldArns, "taskDefinitionArn", "taskArn");
  const pendingReferences = referenceNames(stageBPendingTasks, oldArns, "taskDefinitionArn", "taskArn");
  const deposedTaskDefinitionCleanups = deposedTaskDefinitionChanges.map((change) => {
    const beforeArn = change.change?.before?.arn;
    const identity = familyFromArn(beforeArn, `${change.address} deposed task definition`);
    return {
      terraformAddress: change.address,
      deposed: change.deposed,
      mutationInstanceIdentity: stageBMutationInstanceIdentity(change),
      family: identity.family,
      beforeTaskDefinitionArn: identity.arn,
      actions: [...change.change.actions],
      classification: "PARTIAL_APPLY_RECOVERY_DEPOSED_TASK_DEFINITION_CLEANUP",
      remoteDeletion: false,
      runtimeReferences: { services: [], runningTasks: [], pendingTasks: [], brokerModes: [] },
    };
  });
  const deposedArns = new Set(deposedTaskDefinitionCleanups.map((entry) => entry.beforeTaskDefinitionArn));
  for (const [items, arnKey, nameKey] of [[stageBServices, "taskDefinition", "serviceName"], [stageBRunningTasks, "taskDefinitionArn", "taskArn"], [stageBPendingTasks, "taskDefinitionArn", "taskArn"]]) {
    for (const item of items) if (deposedArns.has(item[arnKey])) throw new Error(`Deposed task definition remains referenced by ${nameKey}: ${item[arnKey]}`);
  }
  for (const arn of deposedArns) if (brokerReferencesByArn.has(arn)) throw new Error(`Deposed task definition remains referenced by the broker: ${arn}`);
  assertStageBLiveReferences(stageBServices, allowedLiveArnsByFamily, createOnlyFamilies, "taskDefinition", "serviceName");
  assertStageBLiveReferences(stageBRunningTasks, allowedLiveArnsByFamily, createOnlyFamilies, "taskDefinitionArn", "taskArn");
  assertStageBLiveReferences(stageBPendingTasks, allowedLiveArnsByFamily, createOnlyFamilies, "taskDefinitionArn", "taskArn");
  const unretainedCreateOnlyFamilies = new Set([...createOnlyFamilies].filter((family) => !newestRetainedByFamily.has(family)));
  const createOnlyServiceReferences = referenceNamesByFamily(stageBServices, unretainedCreateOnlyFamilies, "taskDefinition", "serviceName");
  const createOnlyRunningReferences = referenceNamesByFamily(stageBRunningTasks, unretainedCreateOnlyFamilies, "taskDefinitionArn", "taskArn");
  const createOnlyPendingReferences = referenceNamesByFamily(stageBPendingTasks, unretainedCreateOnlyFamilies, "taskDefinitionArn", "taskArn");
  const noOpServiceReferences = referenceNamesByFamily(stageBServices, noOpFamilies, "taskDefinition", "serviceName");
  const noOpRunningReferences = referenceNamesByFamily(stageBRunningTasks, noOpFamilies, "taskDefinitionArn", "taskArn");
  const noOpPendingReferences = referenceNamesByFamily(stageBPendingTasks, noOpFamilies, "taskDefinitionArn", "taskArn");
  const auditedOldDefinitions = oldDefinitions.map((entry) => {
    const serviceRefs = [...(serviceReferences.get(entry.oldArn) || [])].sort();
    const runningRefs = [...(runningReferences.get(entry.oldArn) || [])].sort();
    const pendingRefs = [...(pendingReferences.get(entry.oldArn) || [])].sort();
    const brokerRefs = brokerReferencesByArn.has(entry.oldArn) ? [brokerReferencesByArn.get(entry.oldArn)] : [];
    const atomicBrokerRollovers = plannedAtomicBrokerRollovers.filter((rollover) => rollover.oldTaskDefinitionArn === entry.oldArn);
    if (serviceRefs.length || runningRefs.length || pendingRefs.length || (brokerRefs.length && !atomicBrokerRollovers.length)) throw new Error(`Superseded task definition remains referenced: ${entry.address}`);
    return {
      terraformAddress: entry.address,
      oldTaskDefinitionArn: entry.oldArn,
      family: entry.family,
      proposedFamily: entry.proposedFamily,
      classification: entry.classification,
      replacePaths: entry.replacePaths,
      currentStatus: entry.currentStatus,
      serviceReferences: serviceRefs,
      runningTaskReferences: runningRefs,
      pendingTaskReferences: pendingRefs,
      brokerReferenceModes: brokerRefs,
      brokerReferenceStatus: atomicBrokerRollovers.length ? "planned-atomic-broker-rollover-v1" : "not-referenced-by-broker-v1",
      rollbackArn: entry.rollbackArn,
      sameFamilyAsReplacement: entry.family === entry.proposedFamily,
    };
  });

  const createOnlyTaskDefinitions = [...createOnlyByAddress.values()]
    .sort((left, right) => left.address.localeCompare(right.address))
    .map((entry) => {
      const serviceRefs = [...(createOnlyServiceReferences.get(entry.family) || [])].sort();
      const runningRefs = [...(createOnlyRunningReferences.get(entry.family) || [])].sort();
      const pendingRefs = [...(createOnlyPendingReferences.get(entry.family) || [])].sort();
      if (serviceRefs.length || runningRefs.length || pendingRefs.length) throw new Error(`Create-only task-definition family remains referenced: ${entry.address}`);
      return {
        terraformAddress: entry.address,
        family: entry.family,
        proposedFamily: entry.proposedFamily,
        classification: "create-only",
        priorTaskDefinitionArn: null,
        serviceReferences: serviceRefs,
        runningTaskReferences: runningRefs,
        pendingTaskReferences: pendingRefs,
        brokerReferenceModes: [],
      };
    });

  const noOpTaskDefinitions = [...noOpByAddress.values()]
    .sort((left, right) => left.address.localeCompare(right.address))
    .map((entry) => ({
      terraformAddress: entry.address,
      family: entry.family,
      proposedFamily: entry.proposedFamily,
      classification: "no-op",
      priorTaskDefinitionArn: entry.priorArn,
      serviceReferences: [...(noOpServiceReferences.get(entry.family) || [])].sort(),
      runningTaskReferences: [...(noOpRunningReferences.get(entry.family) || [])].sort(),
      pendingTaskReferences: [...(noOpPendingReferences.get(entry.family) || [])].sort(),
      brokerReferenceModes: [...(brokerReferencesByFamily.get(entry.family) || [])].sort(),
    }));

  const retainedAuditEntries = retainedDefinitions.map((entry) => ({
    terraformAddress: entry.address,
    oldTaskDefinitionArn: entry.oldArn,
    family: entry.family,
    classification: "retained-no-op",
    currentStatus: entry.currentStatus,
    serviceReferences: [...(referenceNames(stageBServices, [entry.oldArn], "taskDefinition", "serviceName").get(entry.oldArn) || [])].sort(),
    runningTaskReferences: [...(referenceNames(stageBRunningTasks, [entry.oldArn], "taskDefinitionArn", "taskArn").get(entry.oldArn) || [])].sort(),
    pendingTaskReferences: [...(referenceNames(stageBPendingTasks, [entry.oldArn], "taskDefinitionArn", "taskArn").get(entry.oldArn) || [])].sort(),
    brokerReferenceModes: [...(brokerReferencesByArn.has(entry.oldArn) ? [brokerReferencesByArn.get(entry.oldArn)] : [])].sort(),
    brokerReferenceStatus: plannedAtomicBrokerRollovers.some((rollover) => rollover.oldTaskDefinitionArn === entry.oldArn)
      ? "planned-atomic-broker-rollover-v1"
      : "not-referenced-by-broker-v1",
  }));
  const retainedAuditByAddress = new Map(retainedAuditEntries.map((entry) => [entry.terraformAddress, entry]));
  const currentTaskDefinitionMutationInstances = currentRuntimeTaskDefinitionChanges.map((change) => ({
    terraformAddress: change.address,
    mutationInstanceIdentity: stageBMutationInstanceIdentity(change),
    classification: "CURRENT_RUNTIME_TASK_DEFINITION",
  }));
  const taskDefinitionMutationInstances = [...currentTaskDefinitionMutationInstances, ...deposedTaskDefinitionCleanups.map(({ terraformAddress, mutationInstanceIdentity, classification }) => ({ terraformAddress, mutationInstanceIdentity, classification }))]
    .sort((left, right) => left.mutationInstanceIdentity.localeCompare(right.mutationInstanceIdentity));

  return {
    schemaVersion: STAGE_B_REFERENCE_AUDIT_SCHEMA_VERSION,
    toolingSha: deploymentIdentity.toolingSha,
    imageReleaseSha: deploymentIdentity.imageReleaseSha,
    canonicalImageEvidenceSha256: deploymentIdentity.canonicalImageEvidenceSha256,
    auditedAt,
    callerArn: observedCallerArn,
    clusterArn,
    broker,
    services,
    runningTasks,
    pendingTasks,
    transitionalTasks,
    taskDefinitions,
    allOldRevisionsUnreferenced: plannedAtomicBrokerRollovers.length === 0,
    noServiceDeploymentObserved: true,
    noTaskExecutionObserved: true,
    oldTaskDefinitions: auditedOldDefinitions,
    retainedTaskDefinitions: retainedAuditEntries,
    newestRetainedTaskDefinitions: [...newestRetainedByFamily.values()]
      .sort((left, right) => left.family.localeCompare(right.family))
      .map((entry) => retainedAuditByAddress.get(entry.address)),
    createOnlyTaskDefinitions,
    noOpTaskDefinitions,
    taskDefinitionMutationInstances,
    deposedTaskDefinitionCleanups,
    currentTaskDefinitions: {
      currentCreates: createOnlyTaskDefinitions.length,
      currentNoOps: noOpTaskDefinitions.length,
      total: createOnlyTaskDefinitions.length + noOpTaskDefinitions.length + oldDefinitions.filter((entry) => entry.classification === "rollover").length,
    },
    currentTaskDefinitionReferenceCount: currentTaskDefinitionMutationInstances.length,
    plannedAtomicBrokerRollovers,
    plannedAtomicPackageChecksumTransition,
    planJsonSha256: planSha,
    ...(recoveryAttestationSha256 ? { recoveryAttestationSha256 } : {}),
  };
}

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
  if (argv.includes("--broker-function")) {
    throw new Error("--broker-function is not accepted; Stage B broker identity is canonical.");
  }
  const planJsonPath = requireOption(argv, "--plan-json");
  const planJsonSha256 = requireOption(argv, "--plan-sha256");
  const outputPath = requireOption(argv, "--output");
  const region = requireOption(argv, "--region");
  const clusterArn = requireOption(argv, "--cluster-arn");
  const expectedPackageChecksumSha256 = requireOption(argv, "--expected-package-checksum-sha256");
  if (!path.isAbsolute(planJsonPath) || !path.isAbsolute(outputPath)) throw new Error("Plan and output paths must be absolute.");
  const recoveryAttestationSha256 = readOption(argv, "--recovery-attestation-sha256");
  if (recoveryAttestationSha256 !== undefined && !/^[a-f0-9]{64}$/.test(recoveryAttestationSha256)) throw new Error("Recovery attestation SHA256 is malformed.");
  return { planJsonPath, planJsonSha256, outputPath, region, clusterArn, brokerAliasArn: STAGE_B.brokerAliasArn, expectedPackageChecksumSha256, recoveryAttestationSha256, auditedAt: readOption(argv, "--audited-at") || new Date().toISOString() };
}

export async function runCli(argv = process.argv.slice(2)) {
  const options = parseCli(argv);
  assertStageBPrivateFile({ filePath: options.planJsonPath, repositoryRoot, label: "Stage B plan JSON" });
  const outputPath = assertStageBArtifactPath({ artifactPath: options.outputPath, repositoryRoot, label: "Stage B reference audit", allowExisting: false });
  ensureStageBPrivateDirectory({ directory: path.dirname(outputPath), repositoryRoot, create: true });
  const planBytes = fs.readFileSync(options.planJsonPath);
  const plan = parseJson(planBytes.toString("utf8"), "Terraform plan JSON");
  const reader = createAwsReader(options);
  const terraformConfiguration = fs.readFileSync(stageBTerraformConfigurationPath, "utf8");
  const audit = generateReferenceAudit({ ...options, plan, planBytes, reader, terraformConfiguration });
  writeStageBPrivateFileAtomic({ filePath: outputPath, bytes: Buffer.from(`${JSON.stringify(audit, null, 2)}\n`), repositoryRoot, label: "Stage B reference audit" });
  return { outputPath, auditSha256: sha256(fs.readFileSync(outputPath)), planJsonSha256: audit.planJsonSha256 };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  runCli().then((result) => process.stdout.write(`${JSON.stringify({ status: "generated", ...result })}\n`)).catch((error) => {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 1;
  });
}
