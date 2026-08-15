import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { assertStageBPrivateFile } from "./stage-b-artifact-contract.mjs";
import { assertCanonicalTerraformSerialNumber } from "./stage-b-partial-apply-recovery-contract.mjs";
import { STAGE_B_MODES } from "./production-green-stage-b-contract.mjs";
import { validateCurrentTaskDefinitionState } from "./generate-production-green-stage-b-tfvars.mjs";
import { STAGE_B_TASK_DEFINITION_FAMILIES } from "./stage-b-reference-audit-contract.mjs";

export const STAGE_B_REFRESH_SCHEMA_VERSION = 1;
export const STAGE_B_REFRESH_STATUSES = Object.freeze([
  "NO_CHANGES",
  "REVIEWED_OUTPUT_RECONCILIATION",
  "RESOURCE_DRIFT",
  "OUTPUT_DRIFT",
  "FAILED_CHECK",
  "PROVIDER_OR_BACKEND_FAILURE",
  "MALFORMED_RESULT",
]);
export const STAGE_B_REFRESH_ALLOWED_STATUSES = Object.freeze(["NO_CHANGES", "REVIEWED_OUTPUT_RECONCILIATION"]);
export const STAGE_B_TERRAFORM_PLAN_FORMAT_VERSION = "1.2";
export const STAGE_B_TERRAFORM_MIN_VERSION = "1.6.0";
export const STAGE_B_TERRAFORM_MAX_VERSION_EXCLUSIVE = "2.0.0";
export const STAGE_B_SHARED_BINDING_FIELDS = Object.freeze([
  "toolingSha", "toolingTreeSha256", "imageReleaseSha", "imageEvidenceCanonicalSha256",
  "stageAInputSha256", "stageAStateBackupSha256", "stageAStateObject", "stageAStateLineage", "stageAStateSerial",
  "stateLineage", "stateSerial", "stateBackupSha256", "sourceContractSha256", "migrationSetDigest", "packageChecksumSha256", "images",
]);
export const STAGE_B_REFRESH_ACQUISITION_FAILURES = Object.freeze([
  "PLAN_COMMAND_FAILED",
  "PLAN_FILE_MISSING",
  "PLAN_FILE_EMPTY",
  "SHOW_COMMAND_FAILED",
  "SHOW_OUTPUT_EMPTY",
  "SHOW_OUTPUT_NOT_JSON",
  "TERRAFORM_DIAGNOSTIC_RESULT",
  "TERRAFORM_ERRORED_PLAN",
  "MALFORMED_RESULT",
]);
const TERRAFORM_ROOT_PATH = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../infra/aws/terraform/production-green-stage-b");
const VARIABLES_SOURCE_PATH = path.join(TERRAFORM_ROOT_PATH, "variables.tf");
const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const identifier = /[A-Za-z0-9_-]/;

function skipTerraformTrivia(source, index) {
  let cursor = index;
  while (cursor < source.length) {
    if (/\s/.test(source[cursor])) { cursor += 1; continue; }
    if (source[cursor] === "#") { const end = source.indexOf("\n", cursor); cursor = end < 0 ? source.length : end + 1; continue; }
    if (source.startsWith("//", cursor)) { const end = source.indexOf("\n", cursor); cursor = end < 0 ? source.length : end + 1; continue; }
    if (source.startsWith("/*", cursor)) {
      const end = source.indexOf("*/", cursor + 2);
      if (end < 0) throw new Error("Stage B Terraform source contains an unterminated block comment.");
      cursor = end + 2;
      continue;
    }
    break;
  }
  return cursor;
}

function skipTerraformTemplateExpression(source, index) {
  let cursor = index;
  let depth = 0;
  while (cursor < source.length) {
    const next = skipTerraformTrivia(source, cursor);
    if (next !== cursor) { cursor = next; continue; }
    if (source[cursor] === '"') { cursor = skipTerraformString(source, cursor); continue; }
    if (source.startsWith("<<", cursor)) {
      const heredocEnd = skipTerraformHeredoc(source, cursor);
      if (heredocEnd !== cursor) { cursor = heredocEnd; continue; }
    }
    if (source[cursor] === "{") { depth += 1; cursor += 1; continue; }
    if (source[cursor] === "}") {
      if (depth === 0) return cursor + 1;
      depth -= 1;
      cursor += 1;
      continue;
    }
    cursor += 1;
  }
  throw new Error("Stage B Terraform source contains an unterminated template expression.");
}

function skipTerraformString(source, index) {
  let cursor = index + 1;
  while (cursor < source.length) {
    if (source[cursor] === "\\") { cursor += 2; continue; }
    if (source.startsWith("$${", cursor) || source.startsWith("%%{", cursor)) { cursor += 3; continue; }
    if (source.startsWith("${", cursor) || source.startsWith("%{", cursor)) {
      cursor = skipTerraformTemplateExpression(source, cursor + 2);
      continue;
    }
    if (source[cursor] === '"') return cursor + 1;
    cursor += 1;
  }
  throw new Error("Stage B Terraform source contains an unterminated string.");
}

function skipTerraformHeredoc(source, index) {
  const header = source.slice(index).match(/^<<-?([A-Za-z0-9_]+)[^\n]*\n/);
  if (!header) return index;
  const marker = header[1];
  const bodyStart = index + header[0].length;
  const end = source.slice(bodyStart).search(new RegExp(`^[\\t ]*${marker}[\\t ]*$`, "m"));
  if (end < 0) throw new Error("Stage B Terraform source contains an unterminated heredoc.");
  const lineEnd = source.indexOf("\n", bodyStart + end);
  return lineEnd < 0 ? source.length : lineEnd + 1;
}

export function checkAddressesFromSource(source) {
  if (typeof source !== "string") throw new Error("Stage B Terraform check source must be text.");
  const addresses = [];
  const seen = new Set();
  let cursor = 0;
  let depth = 0;
  while (cursor < source.length) {
    const next = skipTerraformTrivia(source, cursor);
    if (next !== cursor) { cursor = next; continue; }
    if (source[cursor] === '"') { cursor = skipTerraformString(source, cursor); continue; }
    if (source.startsWith("<<", cursor)) {
      const heredocEnd = skipTerraformHeredoc(source, cursor);
      if (heredocEnd !== cursor) { cursor = heredocEnd; continue; }
    }
    if (source[cursor] === "{") { depth += 1; cursor += 1; continue; }
    if (source[cursor] === "}") { if (depth === 0) throw new Error("Stage B Terraform source contains an unmatched closing brace."); depth -= 1; cursor += 1; continue; }
    if (depth === 0 && source.startsWith("check", cursor) && !identifier.test(source[cursor - 1] || "") && !identifier.test(source[cursor + 5] || "")) {
      let probe = skipTerraformTrivia(source, cursor + 5);
      if (source[probe] !== '"') throw new Error("Stage B Terraform check block is malformed.");
      const nameStart = probe + 1;
      probe = skipTerraformString(source, probe);
      const name = source.slice(nameStart, probe - 1);
      if (!/^[A-Za-z0-9_-]+$/.test(name)) throw new Error("Stage B Terraform check block name is malformed.");
      probe = skipTerraformTrivia(source, probe);
      if (source[probe] !== "{") throw new Error("Stage B Terraform check block is missing its body.");
      const address = `check.${name}`;
      if (seen.has(address)) throw new Error(`Duplicate Stage B Terraform check block: ${address}`);
      seen.add(address);
      addresses.push(address);
      cursor = probe + 1;
      depth = 1;
      continue;
    }
    cursor += 1;
  }
  if (depth !== 0) throw new Error("Stage B Terraform source contains an unbalanced block.");
  return addresses.sort();
}

export function collectStageBTerraformCheckAddresses(terraformRoot = TERRAFORM_ROOT_PATH) {
  const root = path.resolve(terraformRoot);
  if (root !== TERRAFORM_ROOT_PATH) throw new Error("Stage B check discovery must use the canonical protected Terraform root.");
  const files = fs.readdirSync(root, { withFileTypes: true }).sort((left, right) => left.name.localeCompare(right.name));
  const addresses = [];
  for (const entry of files) {
    if (!entry.name.endsWith(".tf")) continue;
    if (entry.isSymbolicLink() || !entry.isFile()) throw new Error(`Stage B Terraform source file is not a regular file: ${entry.name}`);
    addresses.push(...checkAddressesFromSource(fs.readFileSync(path.join(root, entry.name), "utf8")));
  }
  const duplicates = addresses.filter((address, index) => addresses.indexOf(address) !== index);
  if (duplicates.length) throw new Error(`Duplicate Stage B Terraform check block: ${duplicates[0]}`);
  return [...new Set(addresses)].sort();
}
const REVIEWED_VARIABLE_VALIDATION_NAMES = Object.freeze(["production_rotation_secret_value_from", "retained_candidate_task_definitions", "retained_executor_task_definitions", "stage_b_recovery_alias_target_version"]);
const variableValidationNamesFromSource = (source) => [...source.matchAll(/variable\s+"([^"]+)"\s*\{/g)]
  .filter((match) => {
    const nextVariable = source.indexOf("\nvariable ", match.index + match[0].length);
    return /\bvalidation\s*\{/.test(source.slice(match.index, nextVariable < 0 ? source.length : nextVariable));
  })
  .map(([, name]) => name)
  .sort();
const variablesSource = fs.readFileSync(VARIABLES_SOURCE_PATH, "utf8");
const sourceVariableValidationNames = variableValidationNamesFromSource(variablesSource);
if (JSON.stringify(sourceVariableValidationNames) !== JSON.stringify([...REVIEWED_VARIABLE_VALIDATION_NAMES].sort())) throw new Error("Stage B Terraform variable-validation inventory requires review.");
export const STAGE_B_EXPECTED_CHECK_ADDRESSES = Object.freeze(collectStageBTerraformCheckAddresses());
export const STAGE_B_EXPECTED_VARIABLE_CHECK_ADDRESSES = Object.freeze(REVIEWED_VARIABLE_VALIDATION_NAMES.map((name) => `var.${name}`).sort());
export const STAGE_B_EXPECTED_CHECK_INVENTORY = Object.freeze([...STAGE_B_EXPECTED_CHECK_ADDRESSES, ...STAGE_B_EXPECTED_VARIABLE_CHECK_ADDRESSES].sort());

const sha256 = (value) => crypto.createHash("sha256").update(value).digest("hex");
const hasUnknown = (value) => value === true || (value && typeof value === "object" && Object.values(value).some(hasUnknown));
const canonicalJson = (value) => {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value && typeof value === "object") return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
  return JSON.stringify(value);
};
const exactJson = (left, right) => canonicalJson(left) === canonicalJson(right);

function requireObject(value, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(`${label} must be an object.`);
  return value;
}

const semver = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$/;
const compareVersion = (left, right) => left.map(Number).map((part, index) => part - right[index]).find((difference) => difference !== 0) || 0;

export function isSupportedStageBTerraformVersion(value) {
  const match = typeof value === "string" ? semver.exec(value) : null;
  if (!match || match[4]) return false;
  const version = match.slice(1, 4);
  return compareVersion(version, STAGE_B_TERRAFORM_MIN_VERSION.split(".")) >= 0 && compareVersion(version, STAGE_B_TERRAFORM_MAX_VERSION_EXCLUSIVE.split(".")) < 0;
}

export function assertSupportedStageBTerraformVersion(value) {
  if (!isSupportedStageBTerraformVersion(value)) throw new Error("Terraform refresh plan terraform_version is outside the supported >= 1.6.0, < 2.0.0 range.");
  return value;
}

export function normalizeStageBRefreshPlan(plan) {
  requireObject(plan, "Terraform refresh plan JSON");
  if (plan.format_version !== STAGE_B_TERRAFORM_PLAN_FORMAT_VERSION) throw new Error("Terraform refresh plan format_version is unsupported.");
  assertSupportedStageBTerraformVersion(plan.terraform_version);
  for (const field of ["planned_values", "configuration"]) requireObject(plan[field], `Terraform refresh plan ${field}`);
  if (plan.prior_state !== undefined) requireObject(plan.prior_state, "Terraform refresh plan prior_state");
  if (plan.errored !== undefined && plan.errored !== false) throw new Error("Terraform refresh plan is errored.");
  if (plan.diagnostics !== undefined) {
    if (!Array.isArray(plan.diagnostics)) throw new Error("Terraform refresh plan diagnostics are malformed.");
    if (plan.diagnostics.length) throw new Error("Terraform refresh plan contains diagnostics.");
  }
  if (plan.resource_changes !== undefined && !Array.isArray(plan.resource_changes)) throw new Error("Terraform refresh plan resource_changes are malformed.");
  if (plan.resource_drift !== undefined && !Array.isArray(plan.resource_drift)) throw new Error("Terraform refresh plan resource_drift is malformed.");
  if (plan.output_changes !== undefined && (!plan.output_changes || typeof plan.output_changes !== "object" || Array.isArray(plan.output_changes))) throw new Error("Terraform refresh plan output_changes are malformed.");
  for (const [name, change] of Object.entries(plan.output_changes || {})) {
    if (!change || typeof change !== "object" || Array.isArray(change) || !Array.isArray(change.actions) || change.actions.length === 0) throw new Error(`Terraform refresh plan output change ${name} is malformed.`);
  }
  return { ...plan, resource_changes: plan.resource_changes || [], resource_drift: plan.resource_drift || [], output_changes: plan.output_changes || {} };
}

function renderedAddress(value) {
  return typeof value === "string" && value.length > 0 && value.trim() === value && /^(?:check|var)\.[A-Za-z0-9_-]+$/.test(value) ? value : undefined;
}

export function checkAddress(value) {
  if (typeof value === "string") return renderedAddress(value);
  if (!value || typeof value !== "object" || Array.isArray(value)) return undefined;
  const toDisplay = value.to_display;
  const toString = value.to_string;
  if (toDisplay !== undefined && typeof toDisplay !== "string") return undefined;
  if (toString !== undefined && typeof toString !== "string") return undefined;
  const display = renderedAddress(toDisplay);
  const string = renderedAddress(toString);
  if ((toDisplay !== undefined && !display) || (toString !== undefined && !string) || (display && string && display !== string)) return undefined;
  const hasStructuredFields = value.kind !== undefined || value.name !== undefined;
  if (hasStructuredFields) {
    if (!["check", "var"].includes(value.kind) || typeof value.name !== "string" || !/^[A-Za-z0-9_-]+$/.test(value.name)) return undefined;
    const structured = `${value.kind}.${value.name}`;
    if (!display && !string) return structured;
    return (!display || display === structured) && (!string || string === structured) ? structured : undefined;
  }
  return display || string;
}

function checkMessage(value) {
  if (typeof value === "string") return value;
  if (value && typeof value.message === "string") return value.message;
  if (value && typeof value.detail === "string") return value.detail;
  return "Terraform check did not provide a usable message.";
}

export function inspectStageBRefreshChecks({ checks, checksSource } = {}) {
  const expectedInfrastructureCheckAddresses = checksSource ? checkAddressesFromSource(checksSource) : STAGE_B_EXPECTED_CHECK_ADDRESSES;
  const expectedVariableCheckAddresses = checksSource ? STAGE_B_EXPECTED_VARIABLE_CHECK_ADDRESSES : STAGE_B_EXPECTED_VARIABLE_CHECK_ADDRESSES;
  const expectedAddresses = [...expectedInfrastructureCheckAddresses, ...expectedVariableCheckAddresses].sort();
  const failedChecks = [];
  const normalized = [];
  const seen = new Set();
  let passedCheckCount = 0;
  let failedCheckCount = 0;
  let malformedCheckCount = 0;
  let missingCheckCount = 0;
  let unknownCheckCount = 0;
  let duplicateCheckCount = 0;
  let emittedInstanceCount = 0;
  let passedInstanceCount = 0;
  let failedInstanceCount = 0;
  let malformedInstanceCount = 0;
  let duplicateInstanceCount = 0;
  let infrastructureCheckCount = 0;
  let variableCheckCount = 0;
  const emptyInstanceInventoryHash = sha256(Buffer.from(canonicalJson([])));
  if (!Array.isArray(checks)) return { checkCount: 0, infrastructureCheckCount: 0, variableCheckCount: 0, passedCheckCount: 0, failedCheckCount: 0, malformedCheckCount: 1, missingCheckCount: expectedAddresses.length, unknownCheckCount: 0, duplicateCheckCount: 0, emittedInstanceCount: 0, passedInstanceCount: 0, failedInstanceCount: 0, malformedInstanceCount: 0, duplicateInstanceCount: 0, checkInventoryHash: emptyInstanceInventoryHash, instanceInventoryHash: emptyInstanceInventoryHash, failedChecks: [{ address: "<checks>", status: "malformed", message: "Terraform refresh JSON is missing the plan.checks array." }], checks: [], expectedInfrastructureCheckAddresses, expectedVariableCheckAddresses, expectedAddresses, valid: false };
  for (const check of checks) {
    const address = checkAddress(check?.address);
    const issues = [];
    let malformed = false;
    let failed = false;
    const category = address?.startsWith("check.") ? "infrastructure" : address?.startsWith("var.") ? "variable" : undefined;
    if (!address) { malformed = true; unknownCheckCount += 1; issues.push({ address: "<unknown>", status: "malformed", message: "Terraform check address is missing or malformed." }); }
    else if (!expectedAddresses.includes(address)) { malformed = true; unknownCheckCount += 1; issues.push({ address, status: "malformed", message: "Terraform check address is not defined by the protected Stage B source." }); }
    else if (seen.has(address)) { malformed = true; duplicateCheckCount += 1; issues.push({ address, status: "malformed", message: "Terraform check address is duplicated." }); }
    else { seen.add(address); if (category === "infrastructure") infrastructureCheckCount += 1; if (category === "variable") variableCheckCount += 1; }
    if (check?.status !== "pass") {
      if (["fail", "error", "unknown"].includes(check?.status)) failed = true;
      else malformed = true;
      if (check?.status === "unknown") unknownCheckCount += 1;
      if (check?.status === undefined || check?.status === null) missingCheckCount += 1;
      issues.push({ address: address || "<unknown>", status: check?.status ?? "missing", message: checkMessage(check?.message || check?.problem) });
    }
    if (!Array.isArray(check?.instances) || check.instances.length === 0) {
      malformed = true;
      issues.push({ address: address || "<unknown>", status: "malformed", message: "Terraform check instances are missing or malformed." });
    }
    const instances = Array.isArray(check?.instances) ? check.instances : [];
    const normalizedInstances = [];
    const seenInstanceAddresses = new Set();
    for (const instance of instances) {
      emittedInstanceCount += 1;
      const instanceAddress = checkAddress(instance?.address, { instance: true });
      const problems = instance?.problems;
      normalizedInstances.push({ address: instanceAddress, status: instance?.status });
      const malformedInstance = !instance || typeof instance !== "object" || Array.isArray(instance) || !instanceAddress || instanceAddress !== address || (problems !== undefined && !Array.isArray(problems));
      if (malformedInstance) {
        malformed = true;
        issues.push({ address: instanceAddress || address || "<unknown>", status: "malformed", message: "Terraform check instance shape is malformed." });
      }
      const duplicateInstance = instanceAddress && seenInstanceAddresses.has(instanceAddress);
      if (duplicateInstance) { malformed = true; duplicateInstanceCount += 1; issues.push({ address: instanceAddress, status: "malformed", message: "Terraform check instance address is duplicated." }); }
      if (instanceAddress) seenInstanceAddresses.add(instanceAddress);
      if (instance?.status !== "pass") {
        if (["fail", "error", "unknown"].includes(instance?.status)) failed = true;
        else malformed = true;
        if (instance?.status === "unknown") unknownCheckCount += 1;
        if (instance?.status === undefined || instance?.status === null) missingCheckCount += 1;
        issues.push({ address: instanceAddress || address || "<unknown>", status: instance?.status ?? "missing", message: checkMessage(instance?.message || instance?.problem) });
      }
      if (Array.isArray(problems) && problems.length) {
        failed = true;
        issues.push(...problems.map((problem) => ({ address: instanceAddress || address || "<unknown>", status: "fail", message: checkMessage(problem) })));
      }
      if (malformedInstance || duplicateInstance) malformedInstanceCount += 1;
      else if (instance?.status === "pass" && (!Array.isArray(problems) || problems.length === 0)) passedInstanceCount += 1;
      else if (["fail", "error", "unknown"].includes(instance?.status) || (Array.isArray(problems) && problems.length > 0)) failedInstanceCount += 1;
      else malformedInstanceCount += 1;
    }
    normalized.push({ address, status: check?.status, instances: normalizedInstances });
    if (malformed) malformedCheckCount += 1;
    else if (failed) failedCheckCount += 1;
    else passedCheckCount += 1;
    failedChecks.push(...issues);
  }
  for (const address of expectedAddresses) if (!seen.has(address)) {
    malformedCheckCount += 1;
    missingCheckCount += 1;
    failedChecks.push({ address, status: "missing", message: "Expected Terraform check is missing from plan.checks." });
  }
  normalized.sort((left, right) => String(left.address).localeCompare(String(right.address)));
  const checkInventoryHash = sha256(Buffer.from(canonicalJson(normalized.map(({ address }) => address).sort())));
  const instanceInventoryHash = sha256(Buffer.from(canonicalJson(normalized.map(({ address, instances }) => ({ address, instances })).sort((left, right) => String(left.address).localeCompare(String(right.address))))));
  return { checkCount: checks.length, infrastructureCheckCount, variableCheckCount, passedCheckCount, failedCheckCount, malformedCheckCount, missingCheckCount, unknownCheckCount, duplicateCheckCount, emittedInstanceCount, passedInstanceCount, failedInstanceCount, malformedInstanceCount, duplicateInstanceCount, checkInventoryHash, instanceInventoryHash, failedChecks, checks: normalized, expectedInfrastructureCheckAddresses, expectedVariableCheckAddresses, expectedAddresses, valid: checks.length === expectedAddresses.length && infrastructureCheckCount === expectedInfrastructureCheckAddresses.length && variableCheckCount === expectedVariableCheckAddresses.length && failedCheckCount === 0 && malformedCheckCount === 0 && missingCheckCount === 0 && unknownCheckCount === 0 && duplicateCheckCount === 0 && emittedInstanceCount === passedInstanceCount && failedInstanceCount === 0 && malformedInstanceCount === 0 && duplicateInstanceCount === 0 && failedChecks.length === 0 };
}

function expectedImages(bindingReport) {
  return Object.fromEntries(Object.values(requireObject(bindingReport.images, "Stage B image bindings"))
    .map((image) => [String(image.terraformVariable).replace(/_image$/, ""), image.imageReference])
    .sort(([left], [right]) => left.localeCompare(right)));
}

function stateTaskDefinitionOutput(state) {
  const output = state.outputs?.task_definition_arns;
  if (output === undefined) return undefined;
  if (!output || typeof output !== "object" || Array.isArray(output) || !Object.hasOwn(output, "value")) throw new Error("Stage B task_definition_arns state output is malformed.");
  return output.value;
}

function currentTaskDefinitionOutputKey(address) {
  const match = /^aws_ecs_task_definition\.(candidate|executor)\["([^\"]+)"\]$/.exec(address);
  if (!match) throw new Error(`Stage B current task-definition address is malformed: ${address}`);
  if (match[1] === "candidate") {
    if (["backend", "worker"].includes(match[2])) return match[2];
    if (match[2] === "canary") return "full-rls-application-canary";
    return undefined;
  }
  return match[2];
}

const taskDefinitionOutputArnPattern = /^arn:aws:ecs:eu-west-2:368992683803:task-definition\/([^:]+):([1-9][0-9]*)$/;

function validateTaskDefinitionOutputPredecessor(value, expectedMapping) {
  if (value === undefined || value === null) return;
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("Stage B task_definition_arns predecessor output is malformed.");
  const expectedKeys = new Set(Object.keys(expectedMapping));
  const seenArns = new Set();
  for (const [key, arn] of Object.entries(value)) {
    if (!expectedKeys.has(key)) throw new Error(`Stage B task_definition_arns predecessor contains an unknown key: ${key}.`);
    const identity = taskDefinitionOutputArnPattern.exec(arn || "");
    const expectedIdentity = taskDefinitionOutputArnPattern.exec(expectedMapping[key] || "");
    if (!identity || !expectedIdentity || identity[1] !== expectedIdentity[1] || seenArns.has(arn)) throw new Error(`Stage B task_definition_arns predecessor is invalid for ${key}.`);
    seenArns.add(arn);
  }
}

function expectedTaskDefinitionArns(state, outputsSource) {
  if (!/output\s+"task_definition_arns"\s*\{/.test(outputsSource)) throw new Error("Stage B task_definition_arns output is not defined in protected main.");
  const resources = Array.isArray(state.resources) ? state.resources : [];
  validateCurrentTaskDefinitionState(resources);
  const current = resources.filter((resource) => resource.type === "aws_ecs_task_definition" && ["candidate", "executor"].includes(resource.name));
  if (!current.length) {
    const output = stateTaskDefinitionOutput(state);
    if (output !== undefined && !exactJson(output, {})) throw new Error("Stage B empty task-definition state has a non-empty task_definition_arns output.");
    return {};
  }
  const expectedAddresses = Object.keys(STAGE_B_TASK_DEFINITION_FAMILIES).sort();
  const entries = current.flatMap((resource) => (resource.instances || []).map((instance) => ({
    address: `aws_ecs_task_definition.${resource.name}["${instance.index_key}"]`,
    arn: instance.attributes?.arn,
  })));
  if (entries.length !== expectedAddresses.length || new Set(entries.map(({ address }) => address)).size !== entries.length
    || new Set(entries.map(({ arn }) => arn)).size !== entries.length
    || JSON.stringify(entries.map(({ address }) => address).sort()) !== JSON.stringify(expectedAddresses)) {
    throw new Error("Stage B current task-definition state does not contain the exact reviewed address set.");
  }
  const mapping = {};
  for (const { address, arn } of entries) {
    const key = currentTaskDefinitionOutputKey(address);
    if (key === undefined) continue;
    if (!STAGE_B_MODES.includes(key) && !["backend", "worker"].includes(key)) throw new Error(`Stage B task-definition output key is not canonical: ${key}`);
    if (Object.hasOwn(mapping, key)) throw new Error(`Stage B task-definition output key is duplicated: ${key}`);
    mapping[key] = arn;
  }
  if (JSON.stringify(Object.keys(mapping).sort()) !== JSON.stringify([...new Set(["backend", "worker", ...STAGE_B_MODES])].sort())) throw new Error("Stage B current task-definition output mapping is incomplete.");
  return Object.fromEntries(Object.entries(mapping).sort(([left], [right]) => left.localeCompare(right)));
}

export function assertStageBRefreshStateBinding({ stateBackupPath, bindingReport } = {}) {
  if (!path.isAbsolute(stateBackupPath || "")) throw new Error("Stage B refresh state backup must be an absolute path.");
  assertStageBPrivateFile({ filePath: stateBackupPath, repositoryRoot, label: "Stage B refresh state backup" });
  const bytes = fs.readFileSync(stateBackupPath);
  const state = JSON.parse(bytes);
  if (sha256(bytes) !== bindingReport.stateBackupSha256) throw new Error("Stage B refresh state backup SHA256 does not match the tfvars binding report.");
  assertCanonicalTerraformSerialNumber(state.serial, "Stage B state serial");
  assertCanonicalTerraformSerialNumber(bindingReport.stateSerial, "Stage B binding state serial");
  if (state.lineage !== bindingReport.stateLineage || state.serial !== bindingReport.stateSerial) throw new Error("Stage B refresh state identity does not match the tfvars binding report.");
  if (!Array.isArray(state.resources)) throw new Error("Stage B refresh state resources are malformed.");
  return { state, sha256: sha256(bytes) };
}

function outputChange(change, name, expected) {
  if (!change || !Array.isArray(change.actions) || change.actions.some((action) => !["create", "update", "no-op"].includes(action))) return { classification: "OUTPUT_DRIFT", reason: `${name} has unsupported output actions.` };
  if (name === "task_definition_arns" && ![["create"], ["update"]].some((actions) => exactJson(change.actions, actions))) return { classification: "OUTPUT_DRIFT", reason: `${name} has an unsupported reconciliation action shape.` };
  if (hasUnknown(change.after_unknown) || change.after_sensitive === true) return { classification: "OUTPUT_DRIFT", reason: `${name} contains unknown or sensitive output values.` };
  if (!exactJson(change.after, expected)) return { classification: "OUTPUT_DRIFT", reason: `${name} does not match authoritative evidence.` };
  return { classification: "reviewed", matchesEvidence: name === "bound_images", actions: change.actions, before: change.before, after: change.after };
}

export function classifyStageBRefreshResult({ plan, terraformExitCode = 0, terraformOutput = "", bindingReport, state, outputsSource } = {}) {
  try {
    if (terraformExitCode !== 0 && terraformExitCode !== 2) return { status: terraformExitCode === 1 ? "FAILED_CHECK" : "PROVIDER_OR_BACKEND_FAILURE", reason: "Terraform refresh-only exited unsuccessfully.", checkCount: 0, passedCheckCount: 0, failedCheckCount: 0, malformedCheckCount: 0, failedChecks: [], checks: [], resourceChanges: { nonNoOp: 0, changes: [] }, outputChanges: [] };
    plan = normalizeStageBRefreshPlan(plan);
    if (terraformExitCode === 2 && (plan.complete === false || plan.errored === true)) return { status: "MALFORMED_RESULT", reason: "Terraform detailed exit code returned an incomplete or errored refresh plan.", checkCount: 0, passedCheckCount: 0, failedCheckCount: 0, malformedCheckCount: 0, failedChecks: [], checks: [], resourceChanges: { nonNoOp: 0, changes: [] }, outputChanges: [] };
    const checkResult = inspectStageBRefreshChecks({ checks: plan.checks });
    if (!checkResult.valid) return { status: "FAILED_CHECK", reason: "Terraform refresh-only contains failed or malformed production checks.", ...checkResult, resourceChanges: { nonNoOp: 0, changes: [] }, outputChanges: [] };
    const resourceChanges = [...plan.resource_changes, ...plan.resource_drift].filter((change) => !Array.isArray(change.change?.actions) || change.change.actions.some((action) => action !== "no-op"));
    if (resourceChanges.length) return { status: "RESOURCE_DRIFT", reason: "Terraform reported managed-resource actions.", ...checkResult, resourceChanges: { nonNoOp: resourceChanges.length, changes: resourceChanges.map(({ address, type, change }) => ({ address, type, actions: change?.actions || [] })) }, outputChanges: [] };
    const taskDefinitionArns = expectedTaskDefinitionArns(state, outputsSource);
    const stateOutput = stateTaskDefinitionOutput(state);
    try {
      validateTaskDefinitionOutputPredecessor(stateOutput, taskDefinitionArns);
    } catch (error) {
      return { status: "OUTPUT_DRIFT", reason: error.message, taskDefinitionOutputClassification: "OUTPUT_RECONCILIATION_INVALID", ...checkResult, resourceChanges: { nonNoOp: 0, changes: [] }, outputChanges: [] };
    }
    const expected = { bound_images: expectedImages(bindingReport), task_definition_arns: taskDefinitionArns };
    const outputChanges = Object.entries(plan.output_changes).filter(([, change]) => change?.actions?.some((action) => action !== "no-op"));
    const taskDefinitionOutputChange = outputChanges.find(([name]) => name === "task_definition_arns")?.[1];
    if (taskDefinitionOutputChange) {
      try {
        validateTaskDefinitionOutputPredecessor(taskDefinitionOutputChange.before, taskDefinitionArns);
      } catch (error) {
        return { status: "OUTPUT_DRIFT", reason: error.message, taskDefinitionOutputClassification: "OUTPUT_RECONCILIATION_INVALID", ...checkResult, resourceChanges: { nonNoOp: 0, changes: [] }, outputChanges: [] };
      }
    } else if (!exactJson(stateOutput ?? {}, taskDefinitionArns)) {
      return { status: "OUTPUT_DRIFT", reason: "Stage B task_definition_arns state output is not converged and Terraform emitted no reviewed correction.", taskDefinitionOutputClassification: "OUTPUT_RECONCILIATION_INVALID", ...checkResult, resourceChanges: { nonNoOp: 0, changes: [] }, outputChanges: [] };
    }
    const classifiedOutputs = [];
    for (const [name, change] of outputChanges) {
      if (!Object.hasOwn(expected, name)) return { status: "OUTPUT_DRIFT", reason: `Unexpected Terraform output changed: ${name}.`, ...checkResult, resourceChanges: { nonNoOp: 0, changes: [] }, outputChanges: classifiedOutputs };
      const result = outputChange(change, name, expected[name]);
      if (result.classification !== "reviewed") return { status: result.classification, reason: result.reason, taskDefinitionOutputClassification: name === "task_definition_arns" ? "OUTPUT_RECONCILIATION_INVALID" : undefined, ...checkResult, resourceChanges: { nonNoOp: 0, changes: [] }, outputChanges: [...classifiedOutputs, { name, ...result }] };
      classifiedOutputs.push({ name, ...result });
    }
    if (terraformExitCode === 2 && !outputChanges.length) return { status: "NO_CHANGES", reason: "Terraform detailed exit code contained no actionable resource, drift, or output changes.", taskDefinitionOutputClassification: "STATE_OUTPUT_ALREADY_CONVERGED", ...checkResult, resourceChanges: { nonNoOp: 0, changes: [] }, outputChanges: [], taskDefinitionArns };
    return { status: outputChanges.length ? "REVIEWED_OUTPUT_RECONCILIATION" : "NO_CHANGES", reason: outputChanges.length ? "Only reviewed output reconciliation was detected." : "No resource or output changes were detected.", taskDefinitionOutputClassification: taskDefinitionOutputChange ? "REVIEWED_OUTPUT_RECONCILIATION" : "STATE_OUTPUT_ALREADY_CONVERGED", ...checkResult, resourceChanges: { nonNoOp: 0, changes: [] }, outputChanges: classifiedOutputs, taskDefinitionArns };
  } catch (error) {
    return { status: "MALFORMED_RESULT", reason: error.message, checkCount: 0, passedCheckCount: 0, failedCheckCount: 0, malformedCheckCount: 0, failedChecks: [], checks: [], resourceChanges: { nonNoOp: 0, changes: [] }, outputChanges: [] };
  }
}

export function assertStageBRefreshEvidence({ refreshReportPath, refreshReportSha256, bindingReport, bindingReportSha256, expectedToolingSha, expectedToolingTreeSha256, expectedTfvarsSha256, expectedImageEvidenceSha256, expectedStateSha256, expectedBackendMetadataSha256, expectedTerraformDataDir, expectedWorkspace = "default", allowReviewedResourceDrift = false } = {}) {
  if (!path.isAbsolute(refreshReportPath || "")) throw new Error("Stage B refresh report path must be absolute.");
  assertStageBPrivateFile({ filePath: refreshReportPath, repositoryRoot, label: "Stage B refresh report" });
  const bytes = fs.readFileSync(refreshReportPath); const report = JSON.parse(bytes);
  if (refreshReportSha256 && sha256(bytes) !== refreshReportSha256) throw new Error("Stage B refresh report SHA256 does not match the approved report.");
  if (report.schemaVersion !== STAGE_B_REFRESH_SCHEMA_VERSION || report.deployablePlan !== false || (!STAGE_B_REFRESH_ALLOWED_STATUSES.includes(report.status) && !(allowReviewedResourceDrift && report.status === "RESOURCE_DRIFT"))) throw new Error("Stage B refresh evidence is not an approved non-deployable refresh result.");
  if (report.acquisitionStatus !== "valid" || ![0, 2].includes(report.planCommandExitCode) || report.showCommandExitCode !== 0 || !path.isAbsolute(report.refreshPlanPath || "") || path.resolve(report.refreshPlanPath || "").startsWith(`${repositoryRoot}${path.sep}`) || !/^[a-f0-9]{64}$/.test(report.refreshPlanSha256 || "") || !/^[a-f0-9]{64}$/.test(report.refreshPlanJsonSha256 || "") || !/^[a-f0-9]{64}$/.test(report.showStdoutSha256 || "") || report.refreshPlanJsonSha256 !== report.showStdoutSha256 || !/^[a-f0-9]{64}$/.test(report.showStderrSha256 || "")) throw new Error("Stage B refresh acquisition evidence is missing or malformed.");
  const checkResult = inspectStageBRefreshChecks({ checks: report.checks });
  if (!checkResult.valid || !isSupportedStageBTerraformVersion(report.terraformVersion) || !/^[a-f0-9]{64}$/.test(report.terraformVersionSha256 || "") || report.terraformVersionSha256 !== sha256(Buffer.from(report.terraformVersion)) || report.formatVersion !== STAGE_B_TERRAFORM_PLAN_FORMAT_VERSION || report.checkCount !== checkResult.checkCount || report.infrastructureCheckCount !== checkResult.infrastructureCheckCount || report.variableCheckCount !== checkResult.variableCheckCount || report.passedCheckCount !== checkResult.passedCheckCount || report.failedCheckCount !== checkResult.failedCheckCount || report.malformedCheckCount !== checkResult.malformedCheckCount || report.missingCheckCount !== checkResult.missingCheckCount || report.unknownCheckCount !== checkResult.unknownCheckCount || report.duplicateCheckCount !== checkResult.duplicateCheckCount || report.checkInventoryHash !== checkResult.checkInventoryHash || report.emittedInstanceCount !== checkResult.emittedInstanceCount || report.passedInstanceCount !== checkResult.passedInstanceCount || report.failedInstanceCount !== checkResult.failedInstanceCount || report.malformedInstanceCount !== checkResult.malformedInstanceCount || report.duplicateInstanceCount !== checkResult.duplicateInstanceCount || report.instanceInventoryHash !== checkResult.instanceInventoryHash || report.failedCheckCount !== 0 || report.malformedCheckCount !== 0 || report.missingCheckCount !== 0 || report.unknownCheckCount !== 0 || report.duplicateCheckCount !== 0 || report.failedInstanceCount !== 0 || report.malformedInstanceCount !== 0 || report.duplicateInstanceCount !== 0 || !Array.isArray(report.failedChecks) || report.failedChecks.length !== 0 || !exactJson(report.checks, checkResult.checks) || !path.isAbsolute(report.terraformDataDir || "") || path.resolve(report.backendMetadataPath || "") !== path.join(path.resolve(report.terraformDataDir), "terraform.tfstate") || report.backendMetadataMode !== "0600" || report.privateModeValidated !== true || report.workspace !== expectedWorkspace || ((!allowReviewedResourceDrift || report.status !== "RESOURCE_DRIFT") && report.resourceChanges?.nonNoOp !== 0) || !Array.isArray(report.outputChanges)) throw new Error("Stage B refresh evidence check or binding structure is malformed.");
  if (report.status === "NO_CHANGES" && report.outputChanges.length !== 0) throw new Error("Stage B NO_CHANGES evidence contains output changes.");
  if (report.status === "REVIEWED_OUTPUT_RECONCILIATION" && report.outputChanges.length === 0) throw new Error("Stage B reviewed reconciliation evidence contains no reviewed output changes.");
  for (const output of report.outputChanges) {
    if (!output || !["bound_images", "task_definition_arns"].includes(output.name) || output.classification !== "reviewed" || hasUnknown(output.after)) throw new Error("Stage B refresh evidence contains an unreviewed output change.");
    if (output.name === "bound_images" && !exactJson(output.after, expectedImages(bindingReport))) throw new Error("Stage B bound_images refresh evidence does not match the tfvars image bindings.");
    if (output.name === "task_definition_arns" && (!report.taskDefinitionArns || !exactJson(output.after, report.taskDefinitionArns))) throw new Error("Stage B task_definition_arns refresh evidence does not match the validated state mapping.");
  }
  const expected = { toolingSha: expectedToolingSha, toolingTreeSha256: expectedToolingTreeSha256, tfvarsSha256: expectedTfvarsSha256 || bindingReport?.tfvarsSha256, imageEvidenceSha256: expectedImageEvidenceSha256 || bindingReport?.imageEvidenceCanonicalSha256, stageAStateSha256: bindingReport?.stageAStateBackupSha256, stageAStateLineage: bindingReport?.stageAStateLineage, stageAStateSerial: bindingReport?.stageAStateSerial, stageBStateSha256: expectedStateSha256 || bindingReport?.stateBackupSha256, stageBStateLineage: bindingReport?.stateLineage, stageBStateSerial: bindingReport?.stateSerial, backendMetadataSha256: expectedBackendMetadataSha256, terraformDataDir: expectedTerraformDataDir, workspace: expectedWorkspace };
  for (const [key, value] of Object.entries(expected)) if (value !== undefined && report[key] !== value) throw new Error(`Stage B refresh evidence ${key} binding differs from the selected deployment.`);
  if (bindingReportSha256 && report.bindingReportSha256 !== bindingReportSha256) throw new Error("Stage B refresh evidence binding-report SHA256 differs from the selected report.");
  return report;
}

export function assertStageBRecoveryProvenance({ refreshReport, refreshReportSha256, observationBindingReport, observationBindingReportSha256, recoveryBindingReport, recoveryClassificationSha256, recoveryAttestationSha256 } = {}) {
  requireObject(refreshReport, "Stage B refresh report");
  requireObject(observationBindingReport, "Stage B observation binding report");
  requireObject(recoveryBindingReport, "Stage B recovery binding report");
  if (observationBindingReport.recoveryOnly !== false) throw new Error("Stage B refresh evidence requires the original non-recovery observation binding.");
  if (recoveryBindingReport.recoveryOnly !== true) throw new Error("Stage B recovery planning requires the recovery binding report.");
  if (!/^[a-f0-9]{64}$/.test(observationBindingReportSha256 || "") || refreshReport.bindingReportSha256 !== observationBindingReportSha256) throw new Error("Stage B refresh evidence is not bound to the selected observation binding report.");
  if (refreshReport.tfvarsSha256 !== observationBindingReport.tfvarsSha256) throw new Error("Stage B refresh evidence is not bound to the selected observation tfvars.");
  if (observationBindingReport.tfvarsSha256 === recoveryBindingReport.tfvarsSha256) throw new Error("Stage B recovery planning requires distinct observation and recovery tfvars bindings.");
  if (recoveryBindingReport.recoveryRefreshReportSha256 !== refreshReportSha256) throw new Error("Stage B recovery binding is bound to a different refresh report.");
  if (recoveryClassificationSha256 !== undefined && recoveryBindingReport.recoveryClassificationSha256 !== recoveryClassificationSha256) throw new Error("Stage B recovery binding is bound to a different recovery classification.");
  if (recoveryAttestationSha256 !== undefined && recoveryBindingReport.recoveryAttestationSha256 !== recoveryAttestationSha256) throw new Error("Stage B recovery binding is bound to a different recovery attestation.");
  for (const field of STAGE_B_SHARED_BINDING_FIELDS) {
    if (!Object.hasOwn(observationBindingReport, field) || !Object.hasOwn(recoveryBindingReport, field) || !exactJson(observationBindingReport[field], recoveryBindingReport[field])) throw new Error(`Stage B observation and recovery binding ${field} differs.`);
  }
  return true;
}
