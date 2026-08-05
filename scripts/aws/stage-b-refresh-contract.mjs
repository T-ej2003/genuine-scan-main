import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { assertStageBPrivateFile } from "./stage-b-artifact-contract.mjs";

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
const VARIABLES_SOURCE_PATH = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../infra/aws/terraform/production-green-stage-b/variables.tf");
const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const checkAddressesFromSource = (source) => [...source.matchAll(/check\s+"([^"]+)"\s*\{/g)].map(([, name]) => `check.${name}`).sort();
const REVIEWED_VARIABLE_VALIDATION_NAMES = Object.freeze(["retained_candidate_task_definitions", "retained_executor_task_definitions"]);
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
export const STAGE_B_EXPECTED_CHECK_ADDRESSES = Object.freeze(checkAddressesFromSource(variablesSource));
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

const semver = /^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-[0-9A-Za-z.-]+)?$/;

export function normalizeStageBRefreshPlan(plan) {
  requireObject(plan, "Terraform refresh plan JSON");
  if (plan.format_version !== STAGE_B_TERRAFORM_PLAN_FORMAT_VERSION) throw new Error("Terraform refresh plan format_version is unsupported.");
  if (typeof plan.terraform_version !== "string" || !semver.test(plan.terraform_version)) throw new Error("Terraform refresh plan terraform_version is malformed.");
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

export function checkAddress(value, { instance = false } = {}) {
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
  return instance ? display || string : undefined;
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
  let infrastructureCheckCount = 0;
  let variableCheckCount = 0;
  if (!Array.isArray(checks)) return { checkCount: 0, infrastructureCheckCount: 0, variableCheckCount: 0, passedCheckCount: 0, failedCheckCount: 0, malformedCheckCount: 1, missingCheckCount: expectedAddresses.length, unknownCheckCount: 0, duplicateCheckCount: 0, checkInventoryHash: sha256(Buffer.from(canonicalJson([]))), failedChecks: [{ address: "<checks>", status: "malformed", message: "Terraform refresh JSON is missing the plan.checks array." }], checks: [], expectedInfrastructureCheckAddresses, expectedVariableCheckAddresses, expectedAddresses, valid: false };
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
      const instanceAddress = checkAddress(instance?.address, { instance: true });
      const problems = instance?.problems;
      normalizedInstances.push({ address: instanceAddress, status: instance?.status, problems });
      if (!instanceAddress || instanceAddress !== address || !Array.isArray(problems)) {
        malformed = true;
        issues.push({ address: instanceAddress || address || "<unknown>", status: "malformed", message: "Terraform check instance shape is malformed." });
      }
      if (instanceAddress && seenInstanceAddresses.has(instanceAddress)) { malformed = true; duplicateCheckCount += 1; issues.push({ address: instanceAddress, status: "malformed", message: "Terraform check instance address is duplicated." }); }
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
  return { checkCount: checks.length, infrastructureCheckCount, variableCheckCount, passedCheckCount, failedCheckCount, malformedCheckCount, missingCheckCount, unknownCheckCount, duplicateCheckCount, checkInventoryHash, failedChecks, checks: normalized, expectedInfrastructureCheckAddresses, expectedVariableCheckAddresses, expectedAddresses, valid: checks.length === expectedAddresses.length && infrastructureCheckCount === expectedInfrastructureCheckAddresses.length && variableCheckCount === expectedVariableCheckAddresses.length && failedCheckCount === 0 && malformedCheckCount === 0 && missingCheckCount === 0 && unknownCheckCount === 0 && duplicateCheckCount === 0 && failedChecks.length === 0 };
}

function expectedImages(bindingReport) {
  return Object.fromEntries(Object.values(requireObject(bindingReport.images, "Stage B image bindings"))
    .map((image) => [String(image.terraformVariable).replace(/_image$/, ""), image.imageReference])
    .sort(([left], [right]) => left.localeCompare(right)));
}

function expectedTaskDefinitionArns(state, outputsSource) {
  if (!/output\s+"task_definition_arns"\s*\{/.test(outputsSource)) throw new Error("Stage B task_definition_arns output is not defined in protected main.");
  const resources = Array.isArray(state.resources) ? state.resources : [];
  const current = resources.filter((resource) => resource.type === "aws_ecs_task_definition" && ["candidate", "executor"].includes(resource.name));
  if (current.length) throw new Error("Stage B state contains current task-definition addresses; output reconciliation is not approved.");
  return {};
}

export function assertStageBRefreshStateBinding({ stateBackupPath, bindingReport } = {}) {
  if (!path.isAbsolute(stateBackupPath || "")) throw new Error("Stage B refresh state backup must be an absolute path.");
  assertStageBPrivateFile({ filePath: stateBackupPath, repositoryRoot, label: "Stage B refresh state backup" });
  const bytes = fs.readFileSync(stateBackupPath);
  const state = JSON.parse(bytes);
  if (sha256(bytes) !== bindingReport.stateBackupSha256) throw new Error("Stage B refresh state backup SHA256 does not match the tfvars binding report.");
  if (state.lineage !== bindingReport.stateLineage || state.serial !== bindingReport.stateSerial) throw new Error("Stage B refresh state identity does not match the tfvars binding report.");
  if (!Array.isArray(state.resources)) throw new Error("Stage B refresh state resources are malformed.");
  return { state, sha256: sha256(bytes) };
}

function outputChange(change, name, expected) {
  if (!change || !Array.isArray(change.actions) || change.actions.some((action) => !["create", "update", "no-op"].includes(action))) return { classification: "OUTPUT_DRIFT", reason: `${name} has unsupported output actions.` };
  if (hasUnknown(change.after_unknown) || change.after_sensitive === true) return { classification: "OUTPUT_DRIFT", reason: `${name} contains unknown or sensitive output values.` };
  if (!exactJson(change.after, expected)) return { classification: "OUTPUT_DRIFT", reason: `${name} does not match authoritative evidence.` };
  return { classification: "reviewed", matchesEvidence: name === "bound_images", actions: change.actions, before: change.before, after: change.after };
}

export function classifyStageBRefreshResult({ plan, terraformExitCode = 0, terraformOutput = "", bindingReport, state, outputsSource } = {}) {
  try {
    if (terraformExitCode !== 0 && terraformExitCode !== 2) return { status: terraformExitCode === 1 ? "FAILED_CHECK" : "PROVIDER_OR_BACKEND_FAILURE", reason: "Terraform refresh-only exited unsuccessfully.", checkCount: 0, passedCheckCount: 0, failedCheckCount: 0, malformedCheckCount: 0, failedChecks: [], checks: [], resourceChanges: { nonNoOp: 0, changes: [] }, outputChanges: [] };
    plan = normalizeStageBRefreshPlan(plan);
    const checkResult = inspectStageBRefreshChecks({ checks: plan.checks });
    if (!checkResult.valid) return { status: "FAILED_CHECK", reason: "Terraform refresh-only contains failed or malformed production checks.", ...checkResult, resourceChanges: { nonNoOp: 0, changes: [] }, outputChanges: [] };
    const resourceChanges = [...plan.resource_changes, ...plan.resource_drift].filter((change) => !Array.isArray(change.change?.actions) || change.change.actions.some((action) => action !== "no-op"));
    if (resourceChanges.length) return { status: "RESOURCE_DRIFT", reason: "Terraform reported managed-resource actions.", ...checkResult, resourceChanges: { nonNoOp: resourceChanges.length, changes: resourceChanges.map(({ address, type, change }) => ({ address, type, actions: change?.actions || [] })) }, outputChanges: [] };
    const expected = { bound_images: expectedImages(bindingReport), task_definition_arns: expectedTaskDefinitionArns(state, outputsSource) };
    const outputChanges = Object.entries(plan.output_changes).filter(([, change]) => change?.actions?.some((action) => action !== "no-op"));
    const classifiedOutputs = [];
    for (const [name, change] of outputChanges) {
      if (!Object.hasOwn(expected, name)) return { status: "OUTPUT_DRIFT", reason: `Unexpected Terraform output changed: ${name}.`, ...checkResult, resourceChanges: { nonNoOp: 0, changes: [] }, outputChanges: classifiedOutputs };
      const result = outputChange(change, name, expected[name]);
      if (result.classification !== "reviewed") return { status: result.classification, reason: result.reason, ...checkResult, resourceChanges: { nonNoOp: 0, changes: [] }, outputChanges: [...classifiedOutputs, { name, ...result }] };
      classifiedOutputs.push({ name, ...result });
    }
    if (terraformExitCode === 2 && !outputChanges.length) return { status: "OUTPUT_DRIFT", reason: "Terraform reported changes without a reviewed output change.", ...checkResult, resourceChanges: { nonNoOp: 0, changes: [] }, outputChanges: [] };
    return { status: outputChanges.length ? "REVIEWED_OUTPUT_RECONCILIATION" : "NO_CHANGES", reason: outputChanges.length ? "Only reviewed output reconciliation was detected." : "No resource or output changes were detected.", ...checkResult, resourceChanges: { nonNoOp: 0, changes: [] }, outputChanges: classifiedOutputs };
  } catch (error) {
    return { status: "MALFORMED_RESULT", reason: error.message, checkCount: 0, passedCheckCount: 0, failedCheckCount: 0, malformedCheckCount: 0, failedChecks: [], checks: [], resourceChanges: { nonNoOp: 0, changes: [] }, outputChanges: [] };
  }
}

export function assertStageBRefreshEvidence({ refreshReportPath, refreshReportSha256, bindingReport, bindingReportSha256, expectedToolingSha, expectedToolingTreeSha256, expectedTfvarsSha256, expectedImageEvidenceSha256, expectedStateSha256, expectedBackendMetadataSha256, expectedTerraformDataDir, expectedWorkspace = "default" } = {}) {
  if (!path.isAbsolute(refreshReportPath || "")) throw new Error("Stage B refresh report path must be absolute.");
  assertStageBPrivateFile({ filePath: refreshReportPath, repositoryRoot, label: "Stage B refresh report" });
  const bytes = fs.readFileSync(refreshReportPath); const report = JSON.parse(bytes);
  if (refreshReportSha256 && sha256(bytes) !== refreshReportSha256) throw new Error("Stage B refresh report SHA256 does not match the approved report.");
  if (report.schemaVersion !== STAGE_B_REFRESH_SCHEMA_VERSION || report.deployablePlan !== false || !STAGE_B_REFRESH_ALLOWED_STATUSES.includes(report.status)) throw new Error("Stage B refresh evidence is not an approved non-deployable refresh result.");
  if (report.acquisitionStatus !== "valid" || ![0, 2].includes(report.planCommandExitCode) || report.showCommandExitCode !== 0 || !path.isAbsolute(report.refreshPlanPath || "") || path.resolve(report.refreshPlanPath || "").startsWith(`${repositoryRoot}${path.sep}`) || !/^[a-f0-9]{64}$/.test(report.refreshPlanSha256 || "") || !/^[a-f0-9]{64}$/.test(report.refreshPlanJsonSha256 || "") || !/^[a-f0-9]{64}$/.test(report.showStdoutSha256 || "") || report.refreshPlanJsonSha256 !== report.showStdoutSha256 || !/^[a-f0-9]{64}$/.test(report.showStderrSha256 || "")) throw new Error("Stage B refresh acquisition evidence is missing or malformed.");
  const checkResult = inspectStageBRefreshChecks({ checks: report.checks });
  if (!checkResult.valid || report.checkCount !== checkResult.checkCount || report.infrastructureCheckCount !== checkResult.infrastructureCheckCount || report.variableCheckCount !== checkResult.variableCheckCount || report.passedCheckCount !== checkResult.passedCheckCount || report.failedCheckCount !== checkResult.failedCheckCount || report.malformedCheckCount !== checkResult.malformedCheckCount || report.missingCheckCount !== checkResult.missingCheckCount || report.unknownCheckCount !== checkResult.unknownCheckCount || report.duplicateCheckCount !== checkResult.duplicateCheckCount || report.checkInventoryHash !== checkResult.checkInventoryHash || report.failedCheckCount !== 0 || report.malformedCheckCount !== 0 || report.missingCheckCount !== 0 || report.unknownCheckCount !== 0 || report.duplicateCheckCount !== 0 || !Array.isArray(report.failedChecks) || report.failedChecks.length !== 0 || !exactJson(report.checks, checkResult.checks) || !path.isAbsolute(report.terraformDataDir || "") || path.resolve(report.backendMetadataPath || "") !== path.join(path.resolve(report.terraformDataDir), "terraform.tfstate") || report.backendMetadataMode !== "0600" || report.privateModeValidated !== true || report.workspace !== expectedWorkspace || report.resourceChanges?.nonNoOp !== 0 || !Array.isArray(report.outputChanges)) throw new Error("Stage B refresh evidence check or binding structure is malformed.");
  if (report.status === "NO_CHANGES" && report.outputChanges.length !== 0) throw new Error("Stage B NO_CHANGES evidence contains output changes.");
  if (report.status === "REVIEWED_OUTPUT_RECONCILIATION" && report.outputChanges.length === 0) throw new Error("Stage B reviewed reconciliation evidence contains no reviewed output changes.");
  for (const output of report.outputChanges) {
    if (!output || !["bound_images", "task_definition_arns"].includes(output.name) || output.classification !== "reviewed" || hasUnknown(output.after)) throw new Error("Stage B refresh evidence contains an unreviewed output change.");
    if (output.name === "bound_images" && !exactJson(output.after, expectedImages(bindingReport))) throw new Error("Stage B bound_images refresh evidence does not match the tfvars image bindings.");
    if (output.name === "task_definition_arns" && !exactJson(output.after, {})) throw new Error("Stage B task_definition_arns refresh evidence is not the proven empty mapping.");
  }
  const expected = { toolingSha: expectedToolingSha, toolingTreeSha256: expectedToolingTreeSha256, tfvarsSha256: expectedTfvarsSha256 || bindingReport?.tfvarsSha256, imageEvidenceSha256: expectedImageEvidenceSha256 || bindingReport?.imageEvidenceCanonicalSha256, stageAStateSha256: bindingReport?.stageAStateBackupSha256, stageAStateLineage: bindingReport?.stageAStateLineage, stageAStateSerial: bindingReport?.stageAStateSerial, stageBStateSha256: expectedStateSha256 || bindingReport?.stateBackupSha256, stageBStateLineage: bindingReport?.stateLineage, stageBStateSerial: bindingReport?.stateSerial, backendMetadataSha256: expectedBackendMetadataSha256, terraformDataDir: expectedTerraformDataDir, workspace: expectedWorkspace };
  for (const [key, value] of Object.entries(expected)) if (value !== undefined && report[key] !== value) throw new Error(`Stage B refresh evidence ${key} binding differs from the selected deployment.`);
  if (bindingReportSha256 && report.bindingReportSha256 !== bindingReportSha256) throw new Error("Stage B refresh evidence binding-report SHA256 differs from the selected report.");
  return report;
}
