#!/usr/bin/env node
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { execFileSync, spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { assertStageBTfvarsBinding } from "./aws/generate-production-green-stage-b-tfvars.mjs";
import { assertStageBTerraformBackendMetadataPrivate, assertStageBTerraformInitializedBackendMetadata } from "./aws/stage-b-terraform-backend-contract.mjs";
import { assertStageBTerraformWorkspace } from "./aws/stage-b-terraform-workspace.mjs";
import { assertStageBProtectedCheckoutMatchesDeploymentIdentity, readStageBProtectedMainCheckout } from "./aws/stage-b-deployment-identity.mjs";
import { assertStageBRefreshStateBinding, classifyStageBRefreshResult, STAGE_B_REFRESH_CAPTURE_STATUSES } from "./aws/stage-b-refresh-contract.mjs";
import { assertStageBArtifactPath, ensureStageBPrivateDirectory, ensureStageBPrivateFile, writeStageBPrivateFileAtomic } from "./aws/stage-b-artifact-contract.mjs";
import { normalizeStageBRefreshPlan } from "./aws/stage-b-refresh-contract.mjs";
import { runStageBTerraformJson } from "./aws/capture-stage-b-terraform-json.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const terraformRoot = "infra/aws/terraform/production-green-stage-b";
const sha256 = (value) => crypto.createHash("sha256").update(value).digest("hex");
export const STAGE_B_REFRESH_DIAGNOSTIC_SCHEMA_VERSION = 1;
export const STAGE_B_REFRESH_DIAGNOSTIC_MAX_EXCERPT_CHARS = 4096;
const STAGE_B_REFRESH_DIAGNOSTIC_COMMAND_PHASES = new Set(["refresh-only-plan", "refresh-only-show"]);
const STAGE_B_REFRESH_RUNTIME_SENSITIVE_ENV_KEYS = Object.freeze([
  "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_SECURITY_TOKEN",
]);

const SECRET_ARN = /arn:aws:(?:secretsmanager|ssm):[^\s,;"']+/gi;
const SENSITIVE_KEYS = new Set([
  "password", "passwd", "secret", "token", "access_key", "access-key", "private_key", "private-key",
  "session_token", "session-token", "aws_access_key_id", "aws_secret_access_key", "aws_session_token",
]);
const SENSITIVE_KEY_SUFFIXES = Object.freeze([
  "aws_access_key_id", "aws_secret_access_key", "aws_session_token", "access_key", "access-key",
  "private_key", "private-key", "session_token", "session-token", "password", "passwd", "secret", "token",
]);
const PEM_BEGIN_PREFIX = "-----BEGIN ";
const PEM_MARKER_SUFFIX = "-----";
const PRIVATE_KEY_SUFFIX = " PRIVATE KEY";
const MAX_PEM_LABEL_CHARS = 128;

const toBytes = (value) => Buffer.isBuffer(value) ? value : Buffer.from(String(value ?? ""));

function isSafePemLabelCharacter(value) {
  return (value >= "A" && value <= "Z") || (value >= "0" && value <= "9") || value === " " || value === "-";
}

function isPrivateKeyLabel(label) {
  if (label === "PRIVATE KEY") return true;
  if (!label.endsWith(PRIVATE_KEY_SUFFIX)) return false;
  const prefix = label.slice(0, -PRIVATE_KEY_SUFFIX.length);
  return prefix.length > 0 && prefix.length <= MAX_PEM_LABEL_CHARS - PRIVATE_KEY_SUFFIX.length
    && prefix[0] !== " " && prefix.at(-1) !== " " && !prefix.includes("  ") && [...prefix].every(isSafePemLabelCharacter);
}

function findBoundedPemMarkerSuffix(text, from) {
  const lastStart = Math.min(text.length - PEM_MARKER_SUFFIX.length, from + MAX_PEM_LABEL_CHARS);
  for (let position = from; position <= lastStart; position += 1) {
    if (text.startsWith(PEM_MARKER_SUFFIX, position)) return position;
  }
  return -1;
}

function findPrivateKeyMarker(text, from) {
  const position = text.indexOf(PEM_BEGIN_PREFIX, from);
  if (position === -1) return null;
  const labelStart = position + PEM_BEGIN_PREFIX.length;
  const nextBegin = text.indexOf(PEM_BEGIN_PREFIX, labelStart);
  const markerEnd = findBoundedPemMarkerSuffix(text, labelStart);
  if (nextBegin !== -1 && (markerEnd === -1 || nextBegin <= markerEnd)) return { nextSearchFrom: nextBegin };
  if (markerEnd === -1) return null;
  const label = text.slice(position + PEM_BEGIN_PREFIX.length, markerEnd);
  if (!isPrivateKeyLabel(label)) return { nextSearchFrom: markerEnd + PEM_MARKER_SUFFIX.length };
  return { position, label, markerEnd: markerEnd + PEM_MARKER_SUFFIX.length };
}

function redactPrivateKeyBlocks(text) {
  let output = "";
  let cursor = 0;
  let searchFrom = 0;
  while (searchFrom < text.length) {
    const next = findPrivateKeyMarker(text, searchFrom);
    if (!next) break;
    if (next.position === undefined) {
      searchFrom = next.nextSearchFrom;
      continue;
    }
    const endMarker = `-----END ${next.label}-----`;
    const endPosition = text.indexOf(endMarker, next.markerEnd);
    const blockEnd = endPosition === -1 ? text.length : endPosition + endMarker.length;
    output += text.slice(cursor, next.position) + "[REDACTED_PRIVATE_KEY]";
    cursor = blockEnd;
    searchFrom = blockEnd;
  }
  return output + text.slice(cursor);
}

const isTokenCharacter = (value) => /[A-Za-z0-9_-]/.test(value);
const isUnquotedValueDelimiter = (value) => /[\s,;}]/.test(value);

function parseSensitiveAssignment(text, start) {
  const initial = text[start];
  const quotedKey = initial === "'" || initial === '"';
  let keyEnd = start;
  let key;
  if (quotedKey) {
    keyEnd += 1;
    const closingQuote = text.indexOf(initial, keyEnd);
    if (closingQuote === -1) return null;
    key = text.slice(keyEnd, closingQuote);
    keyEnd = closingQuote + 1;
  } else {
    if (start > 0 && isTokenCharacter(text[start - 1])) return null;
    while (keyEnd < text.length && isTokenCharacter(text[keyEnd])) keyEnd += 1;
    key = text.slice(start, keyEnd);
  }
  if (!isSensitiveAssignmentKey(key)) return null;
  let valueStart = keyEnd;
  while (/\s/.test(text[valueStart] || "")) valueStart += 1;
  if (text[valueStart] !== "=" && text[valueStart] !== ":") return null;
  valueStart += 1;
  while (/\s/.test(text[valueStart] || "")) valueStart += 1;
  let end = valueStart;
  const quote = text[valueStart];
  if (quote === "'" || quote === '"') {
    end += 1;
    while (end < text.length) {
      if (text[end] === "\\") { end += 2; continue; }
      if (text[end] === quote) { end += 1; break; }
      end += 1;
    }
  } else {
    while (end < text.length && !isUnquotedValueDelimiter(text[end])) end += 1;
  }
  return { start, valueStart, end };
}

function isSensitiveAssignmentKey(key) {
  const normalized = key.toLowerCase();
  if (SENSITIVE_KEYS.has(normalized)) return true;
  return SENSITIVE_KEY_SUFFIXES.some((suffix) => normalized.endsWith(`_${suffix}`) || normalized.endsWith(`-${suffix}`));
}

function redactSensitiveAssignments(text) {
  let output = "";
  let cursor = 0;
  let index = 0;
  while (index < text.length) {
    const parsed = parseSensitiveAssignment(text, index);
    if (!parsed) { index += 1; continue; }
    output += text.slice(cursor, parsed.valueStart) + "[REDACTED]";
    cursor = parsed.end;
    index = parsed.end;
  }
  return output + text.slice(cursor);
}

function findAuthorizationValue(text, from) {
  const lower = text.toLowerCase();
  const names = ["proxy-authorization", "authorization"];
  let position = -1;
  let name;
  for (const candidate of names) {
    const candidatePosition = lower.indexOf(candidate, from);
    if (candidatePosition !== -1 && (position === -1 || candidatePosition < position)) {
      position = candidatePosition;
      name = candidate;
    }
  }
  if (position === -1) return null;
  const nameEnd = position + name.length;
  const preceding = text[position - 1];
  const quotedKey = preceding === "'" || preceding === '"';
  if ((!quotedKey && position > 0 && isTokenCharacter(preceding)) || (quotedKey && text[nameEnd] !== preceding) || (!quotedKey && isTokenCharacter(text[nameEnd] || ""))) {
    return { nextSearchFrom: position + 1 };
  }
  let valueStart = quotedKey ? nameEnd + 1 : nameEnd;
  while (/\s/.test(text[valueStart] || "")) valueStart += 1;
  if (text[valueStart] !== ":") return { nextSearchFrom: position + 1 };
  valueStart += 1;
  while (/\s/.test(text[valueStart] || "")) valueStart += 1;
  const quote = text[valueStart] === "'" || text[valueStart] === '"' ? text[valueStart] : null;
  const schemeStart = quote ? valueStart + 1 : valueStart;
  const scheme = lower.slice(schemeStart, schemeStart + 6);
  const schemeLength = scheme.startsWith("bearer") ? 6 : scheme.startsWith("basic") ? 5 : 0;
  if (!schemeLength || !/\s/.test(text[schemeStart + schemeLength] || "")) return { nextSearchFrom: position + 1 };
  let credentialStart = schemeStart + schemeLength;
  while (/\s/.test(text[credentialStart] || "")) credentialStart += 1;
  if (credentialStart >= text.length || (quote && text[credentialStart] === quote)) return { nextSearchFrom: position + 1 };
  let credentialEnd = credentialStart;
  if (quote) {
    while (credentialEnd < text.length) {
      if (text[credentialEnd] === "\\") { credentialEnd += 2; continue; }
      if (text[credentialEnd] === quote) break;
      credentialEnd += 1;
    }
  } else {
    while (credentialEnd < text.length && !isUnquotedValueDelimiter(text[credentialEnd])) credentialEnd += 1;
  }
  return credentialEnd > credentialStart ? { start: credentialStart, end: credentialEnd } : { nextSearchFrom: position + 1 };
}

function redactAuthorizationValues(text) {
  let output = "";
  let cursor = 0;
  let searchFrom = 0;
  while (searchFrom < text.length) {
    const match = findAuthorizationValue(text, searchFrom);
    if (!match) break;
    if (match.start === undefined) {
      searchFrom = match.nextSearchFrom;
      continue;
    }
    output += text.slice(cursor, match.start) + "[REDACTED]";
    cursor = match.end;
    searchFrom = match.end;
  }
  return output + text.slice(cursor);
}

export function redactStageBRefreshDiagnostic(value, { maxChars = STAGE_B_REFRESH_DIAGNOSTIC_MAX_EXCERPT_CHARS, sensitiveValues = [] } = {}) {
  if (!Number.isInteger(maxChars) || maxChars < 1) throw new Error("Stage B refresh diagnostic excerpt limit is malformed.");
  let text = toBytes(value).toString("utf8").replaceAll("\r\n", "\n").replaceAll("\r", "\n");
  const exactValues = [...new Set(sensitiveValues.filter((candidate) => typeof candidate === "string" && candidate.length > 0))].sort((left, right) => right.length - left.length);
  for (const candidate of exactValues) text = text.split(candidate).join("[REDACTED]");
  const redacted = redactAuthorizationValues(redactSensitiveAssignments(redactPrivateKeyBlocks(text)))
    .replace(SECRET_ARN, "[REDACTED_SECRET_REFERENCE]")
    ;
  return redacted.slice(0, maxChars) + (redacted.length > maxChars ? "\n[TRUNCATED]" : "");
}

export function stageBRefreshRuntimeSensitiveValues(env = process.env) {
  return [...new Set(STAGE_B_REFRESH_RUNTIME_SENSITIVE_ENV_KEYS.map((key) => env?.[key]).filter((value) => typeof value === "string" && value.length > 0))];
}

export function createStageBRefreshDiagnostic({ commandPhase, failureClass, failureReason, planCommandExitCode = null, showCommandExitCode = null, stdout = "", stderr = "", stdoutRaw = stdout, stderrRaw = stderr, terminationSignal = null, commandErrorMessage = "", capturedAt = new Date().toISOString(), sensitiveValues = [] } = {}) {
  if (!STAGE_B_REFRESH_DIAGNOSTIC_COMMAND_PHASES.has(commandPhase)) throw new Error("Stage B refresh diagnostic command phase is unsupported.");
  const stdoutBytes = toBytes(stdoutRaw); const stderrBytes = toBytes(stderrRaw);
  return {
    schemaVersion: STAGE_B_REFRESH_DIAGNOSTIC_SCHEMA_VERSION,
    commandPhase,
    failureClass: String(failureClass || "MALFORMED_RESULT"),
    failureReason: redactStageBRefreshDiagnostic(failureReason || "", { maxChars: 512, sensitiveValues }),
    exitCode: Number.isInteger(planCommandExitCode) ? planCommandExitCode : null,
    showExitCode: Number.isInteger(showCommandExitCode) ? showCommandExitCode : null,
    stdoutSha256: sha256(stdoutBytes),
    stderrSha256: sha256(stderrBytes),
    stdoutExcerptRedacted: redactStageBRefreshDiagnostic(stdoutBytes, { sensitiveValues }),
    stderrExcerptRedacted: redactStageBRefreshDiagnostic(stderrBytes, { sensitiveValues }),
    terminationSignal: terminationSignal ? redactStageBRefreshDiagnostic(terminationSignal, { maxChars: 128, sensitiveValues }) : null,
    commandErrorExcerptRedacted: commandErrorMessage ? redactStageBRefreshDiagnostic(commandErrorMessage, { maxChars: 512, sensitiveValues }) : null,
    capturedAt,
  };
}

function acquisitionFailure(status, reason, extra = {}) {
  return { acquisitionStatus: status, acquisitionReason: reason, plan: undefined, ...extra };
}

function safeDiagnostic(diagnostic = {}) {
  const redact = (value) => redactStageBRefreshDiagnostic(value, { maxChars: 512 });
  return { severity: redact(diagnostic.severity), summary: redact(diagnostic.summary), detail: redact(diagnostic.detail), address: diagnostic.address, range: diagnostic.range };
}

function commandDiagnosticCapture({ result: commandResult, commandName, commandPhase, exitCodeTarget, planCommandExitCode = null, showCommandExitCode = null, error } = {}) {
  const result = commandResult && typeof commandResult === "object" ? commandResult : null;
  const stdout = result?.stdout ?? "";
  const text = (value) => Buffer.isBuffer(value) ? value.toString("utf8") : typeof value === "string" ? value : "";
  const signal = result?.signal || error?.signal;
  const errorMessage = text(result?.error?.message) || text(error?.message);
  const status = Number.isInteger(result?.status) ? result.status : null;
  return {
    stdout: text(stdout),
    stderr: text(result?.stderr),
    stdoutRaw: text(stdout),
    stderrRaw: text(result?.stderr),
    commandPhase,
    terminationSignal: signal || null,
    commandErrorMessage: errorMessage || (!result ? `${commandName} returned no command result.` : ""),
    planCommandExitCode: exitCodeTarget === "plan" ? status : planCommandExitCode,
    showCommandExitCode: exitCodeTarget === "show" ? status : showCommandExitCode,
  };
}

export function acquireStageBRefreshPlan({ planPath, planResult, showPlanJson, showOptions, repositoryRoot = root } = {}) {
  const planCommandDiagnostic = commandDiagnosticCapture({ result: planResult, commandName: "Terraform plan", commandPhase: "refresh-only-plan", exitCodeTarget: "plan" });
  if (![0, 2].includes(planResult?.status)) return acquisitionFailure("PLAN_COMMAND_FAILED", "Terraform refresh-only plan command failed.", { planCommandExitCode: planCommandDiagnostic.planCommandExitCode, showCommandExitCode: planCommandDiagnostic.showCommandExitCode, diagnosticCapture: planCommandDiagnostic });
  const planStat = fs.lstatSync(planPath, { throwIfNoEntry: false });
  if (!planStat) return acquisitionFailure("PLAN_FILE_MISSING", "Terraform refresh-only did not produce its temporary plan.", { planCommandExitCode: planResult.status, diagnosticCapture: planCommandDiagnostic });
  if (!planStat.isFile() || planStat.isSymbolicLink()) return acquisitionFailure("MALFORMED_RESULT", "Terraform refresh-only temporary plan is not a regular non-symlink file.", { planCommandExitCode: planResult.status, diagnosticCapture: planCommandDiagnostic });
  const planBytes = fs.readFileSync(planPath);
  if (planBytes.length === 0) return acquisitionFailure("PLAN_FILE_EMPTY", "Terraform refresh-only temporary plan is empty.", { planCommandExitCode: planResult.status, diagnosticCapture: planCommandDiagnostic });
  const privatePlan = ensureStageBPrivateFile({ filePath: planPath, repositoryRoot, normalize: true, label: "Stage B refresh-only temporary plan" });
  let shown;
  try { shown = showPlanJson(planPath, showOptions); } catch (error) { return acquisitionFailure("SHOW_COMMAND_FAILED", "Terraform show -json failed.", { planCommandExitCode: planResult.status, showCommandExitCode: null, showError: error.message, refreshPlanSha256: privatePlan.sha256, diagnosticCapture: commandDiagnosticCapture({ result: null, commandName: "Terraform show", commandPhase: "refresh-only-show", exitCodeTarget: "show", planCommandExitCode: planResult.status, showCommandExitCode: null, error }) }); }
  const showCapture = commandDiagnosticCapture({ result: shown, commandName: "Terraform show", commandPhase: "refresh-only-show", exitCodeTarget: "show", planCommandExitCode: planResult.status, showCommandExitCode: null });
  if (!shown || typeof shown.status !== "number") return acquisitionFailure("SHOW_COMMAND_FAILED", "Terraform show -json did not return a command result.", { planCommandExitCode: planResult.status, showCommandExitCode: showCapture.showCommandExitCode, refreshPlanSha256: privatePlan.sha256, diagnosticCapture: showCapture });
  const stdout = Buffer.isBuffer(shown.stdout) ? shown.stdout : Buffer.from(shown.stdout || "");
  const stderr = Buffer.isBuffer(shown.stderr) ? shown.stderr : Buffer.from(shown.stderr || "");
  const showDiagnostic = { ...showCapture, stdoutRaw: stdout, stderrRaw: stderr };
  const hashes = { planCommandExitCode: planResult.status, showCommandExitCode: shown.status, refreshPlanSha256: privatePlan.sha256, refreshPlanJsonSha256: sha256(stdout), showStdoutSha256: sha256(stdout), showStderrSha256: sha256(stderr) };
  if (shown.status !== 0) return acquisitionFailure("SHOW_COMMAND_FAILED", "Terraform show -json failed.", { ...hashes, diagnosticCapture: showDiagnostic });
  if (stdout.length === 0) return acquisitionFailure("SHOW_OUTPUT_EMPTY", "Terraform show -json returned empty stdout.", { ...hashes, diagnosticCapture: showDiagnostic });
  let plan;
  try { plan = JSON.parse(stdout.toString("utf8")); } catch { return acquisitionFailure("SHOW_OUTPUT_NOT_JSON", "Terraform show -json returned non-JSON stdout.", { ...hashes, diagnosticCapture: showDiagnostic }); }
  if (plan?.errored === true) return acquisitionFailure("TERRAFORM_ERRORED_PLAN", "Terraform show -json returned an errored plan.", { ...hashes, diagnostics: [], diagnosticCapture: showDiagnostic });
  if (Array.isArray(plan?.diagnostics) && plan.diagnostics.length) return acquisitionFailure("TERRAFORM_DIAGNOSTIC_RESULT", "Terraform show -json returned diagnostics.", { ...hashes, diagnostics: plan.diagnostics.map(safeDiagnostic), diagnosticCapture: showDiagnostic });
  try { plan = normalizeStageBRefreshPlan(plan); } catch (error) { return acquisitionFailure("MALFORMED_RESULT", error.message, { ...hashes, diagnosticCapture: showDiagnostic }); }
  return { acquisitionStatus: "valid", acquisitionReason: "Terraform show -json returned a validated refresh-only plan.", plan, ...hashes };
}

function option(argv, name) {
  const index = argv.indexOf(name);
  const value = index === -1 ? undefined : argv[index + 1];
  if (!value || value.startsWith("--")) throw new Error(`${name} is required.`);
  return value;
}

export function parseCli(argv = process.argv.slice(2)) {
  if (argv.some((value) => value === "-out" || value === "--out" || value.startsWith("-out=") || value.startsWith("--out="))) throw new Error("Stage B refresh-only does not accept a deployable Terraform plan output.");
  const closureMode = option(argv, "--closure-mode");
  if (closureMode !== "production") throw new Error("Stage B refresh-only requires --closure-mode production.");
  return {
    closureMode,
    tfvarsPath: option(argv, "--tfvars"),
    bindingReportPath: option(argv, "--binding-report"),
    bindingReportSha256: option(argv, "--binding-report-sha256"),
    stageBStateBackup: option(argv, "--stage-b-state-backup"),
    toolingSha: option(argv, "--tooling-sha"),
    toolingTreeSha256: option(argv, "--tooling-tree-sha256"),
    terraformDataDir: option(argv, "--terraform-data-dir"),
    backendMetadataPath: option(argv, "--backend-metadata"),
    outputPath: option(argv, "--output"),
  };
}

function assertPrivateNewOutput(outputPath, label = "Stage B refresh-only output") {
  assertStageBArtifactPath({ artifactPath: outputPath, repositoryRoot: root, label, allowExisting: false });
  ensureStageBPrivateDirectory({ directory: path.dirname(outputPath), repositoryRoot: root, create: true });
}

function writeOutput(outputPath, output) {
  return writeStageBPrivateFileAtomic({ filePath: outputPath, bytes: Buffer.from(`${JSON.stringify(output, null, 2)}\n`), repositoryRoot: root, label: "Stage B refresh report" }).path;
}

function writeDiagnostic(outputPath, diagnostic) {
  return writeStageBPrivateFileAtomic({ filePath: outputPath, bytes: Buffer.from(`${JSON.stringify(diagnostic, null, 2)}\n`), repositoryRoot: root, label: "Stage B refresh diagnostic" });
}

export function runRefreshOnly({ argv = process.argv.slice(2), env = process.env, deps = {} } = {}) {
  const artifacts = parseCli(argv);
  if (env.TF_WORKSPACE !== "default") throw new Error("Stage B refresh-only requires TF_WORKSPACE=default.");
  for (const [value, label] of [[artifacts.terraformDataDir, "Terraform data directory"], [artifacts.backendMetadataPath, "Backend metadata"], [artifacts.outputPath, "Refresh-only output"]]) if (!path.isAbsolute(value)) throw new Error(`${label} must be an absolute private path.`);
  const resolvedDataDir = path.resolve(artifacts.terraformDataDir);
  if (env.TF_DATA_DIR !== undefined && path.resolve(env.TF_DATA_DIR) !== resolvedDataDir) throw new Error("Ambient TF_DATA_DIR conflicts with --terraform-data-dir.");
  const backendMetadata = assertStageBTerraformBackendMetadataPrivate({ terraformDataDir: resolvedDataDir, backendMetadataPath: artifacts.backendMetadataPath, repositoryRoot: root });
  const { backendMetadataPath: expectedMetadataPath } = backendMetadata;
  const reportPath = path.resolve(artifacts.outputPath);
  const diagnosticPath = path.resolve(path.join(path.dirname(reportPath), "terraform-plan-diagnostic.json"));
  if (reportPath === diagnosticPath) throw new Error("Stage B refresh report path must differ from diagnostic artifact path.");
  assertPrivateNewOutput(reportPath);
  assertPrivateNewOutput(diagnosticPath, "Stage B refresh diagnostic");
  const validateTfvarsBinding = deps.validateTfvarsBinding || assertStageBTfvarsBinding;
  const bindingReport = validateTfvarsBinding({
    tfvarsPath: artifacts.tfvarsPath,
    bindingReportPath: artifacts.bindingReportPath,
    bindingReportSha256: artifacts.bindingReportSha256,
    expectedToolingSha: artifacts.toolingSha,
    expectedToolingTreeSha256: artifacts.toolingTreeSha256,
  });
  const { state } = assertStageBRefreshStateBinding({ stateBackupPath: artifacts.stageBStateBackup, bindingReport });
  const metadata = JSON.parse(fs.readFileSync(expectedMetadataPath, "utf8"));
  (deps.validateBackendMetadata || ((value) => assertStageBTerraformInitializedBackendMetadata(value)))(metadata.backend);
  const protectedMainCheckout = deps.getProtectedMainCheckout
    ? deps.getProtectedMainCheckout()
    : readStageBProtectedMainCheckout({ cwd: root, fetchOriginMain: true });
  assertStageBProtectedCheckoutMatchesDeploymentIdentity({ protectedMainCheckout, deploymentIdentity: { toolingSha: artifacts.toolingSha } });
  const terraformEnv = { ...env, TF_DATA_DIR: resolvedDataDir };
  const runtimeSensitiveValues = stageBRefreshRuntimeSensitiveValues(terraformEnv);
  const showWorkspace = deps.showWorkspace || ((options) => execFileSync("terraform", [`-chdir=${terraformRoot}`, "workspace", "show"], { ...options, encoding: "utf8" }).trim());
  const observedWorkspace = String(showWorkspace({ cwd: root, env: terraformEnv })).trim();
  assertStageBTerraformWorkspace({ envWorkspace: env.TF_WORKSPACE, observedWorkspace });
  const runTerraform = deps.runTerraform || ((args, options) => spawnSync("terraform", args, { ...options, encoding: "utf8" }));
  const showPlanJson = deps.showPlanJson || ((planPath, options) => runStageBTerraformJson({ terraform: "terraform", args: [`-chdir=${terraformRoot}`, "show", "-json", planPath], cwd: options.cwd, env: options.env }));
  const refreshDirectory = fs.mkdtempSync(path.join(path.dirname(artifacts.outputPath), ".stage-b-refresh-"));
  try {
    fs.chmodSync(refreshDirectory, 0o700);
    const refreshPlanPath = path.join(refreshDirectory, "refresh-only.tfplan");
    const argsForTerraform = [`-chdir=${terraformRoot}`, "plan", "-refresh-only", `-var-file=${artifacts.tfvarsPath}`, `-out=${refreshPlanPath}`, "-input=false", "-lock=true", "-no-color", "-detailed-exitcode"];
    const result = runTerraform(argsForTerraform, { cwd: root, env: terraformEnv });
    const acquisition = acquireStageBRefreshPlan({ planPath: refreshPlanPath, planResult: result, showPlanJson, showOptions: { cwd: root, env: terraformEnv }, repositoryRoot: root });
    const diagnosticArtifact = acquisition.diagnosticCapture
      ? writeDiagnostic(diagnosticPath, createStageBRefreshDiagnostic({
        commandPhase: acquisition.diagnosticCapture.commandPhase,
        failureClass: acquisition.acquisitionStatus,
        failureReason: acquisition.acquisitionReason,
        planCommandExitCode: acquisition.diagnosticCapture.planCommandExitCode,
        showCommandExitCode: acquisition.diagnosticCapture.showCommandExitCode,
        stdoutRaw: acquisition.diagnosticCapture.stdoutRaw,
        stderrRaw: acquisition.diagnosticCapture.stderrRaw,
        terminationSignal: acquisition.diagnosticCapture.terminationSignal,
        commandErrorMessage: acquisition.diagnosticCapture.commandErrorMessage,
        sensitiveValues: runtimeSensitiveValues,
      }))
      : null;
    const classification = acquisition.acquisitionStatus === "valid"
      ? classifyStageBRefreshResult({ plan: acquisition.plan, terraformExitCode: result.status, terraformOutput: result.stdout || "", bindingReport, state, outputsSource: fs.readFileSync(path.join(root, terraformRoot, "outputs.tf"), "utf8") })
      : { status: "MALFORMED_RESULT", reason: acquisition.acquisitionReason, resourceChanges: { nonNoOp: 0, changes: [] }, outputChanges: [] };
    const refreshReport = {
    schemaVersion: 1,
    status: classification.status,
    reason: classification.reason,
    deployablePlan: false,
    toolingSha: artifacts.toolingSha,
    toolingTreeSha256: artifacts.toolingTreeSha256,
    tfvarsSha256: bindingReport.tfvarsSha256,
    bindingReportSha256: artifacts.bindingReportSha256,
    imageEvidenceSha256: bindingReport.imageEvidenceCanonicalSha256,
    stageAStateSha256: bindingReport.stageAStateBackupSha256,
    stageAStateLineage: bindingReport.stageAStateLineage,
    stageAStateSerial: bindingReport.stageAStateSerial,
    stageBStateSha256: bindingReport.stateBackupSha256,
    stageBStateLineage: bindingReport.stateLineage,
    stageBStateSerial: bindingReport.stateSerial,
    backendMetadataSha256: sha256(fs.readFileSync(expectedMetadataPath)),
    backendMetadataMode: backendMetadata.backendMetadataMode,
    privateModeValidated: backendMetadata.privateModeValidated,
    backendMetadataPath: expectedMetadataPath,
    terraformDataDir: resolvedDataDir,
    workspace: observedWorkspace,
    terraformExitCode: result.status,
    terraformOutputSha256: sha256(Buffer.from(result.stdout || "")),
    terraformStderrSha256: sha256(Buffer.from(result.stderr || "")),
    acquisitionStatus: acquisition.acquisitionStatus,
    acquisitionReason: acquisition.acquisitionReason,
    diagnosticArtifactPath: diagnosticArtifact?.path || null,
    diagnosticArtifactSha256: diagnosticArtifact?.sha256 || null,
    terraformVersion: acquisition.plan?.terraform_version || null,
    terraformVersionSha256: acquisition.plan?.terraform_version ? sha256(Buffer.from(acquisition.plan.terraform_version)) : null,
    formatVersion: acquisition.plan?.format_version || null,
    planCommandExitCode: acquisition.planCommandExitCode ?? result.status ?? null,
    showCommandExitCode: acquisition.showCommandExitCode ?? null,
    refreshPlanPath,
    refreshPlanSha256: acquisition.refreshPlanSha256 || null,
    refreshPlanJsonSha256: acquisition.refreshPlanJsonSha256 || null,
    showStdoutSha256: acquisition.showStdoutSha256 || null,
    showStderrSha256: acquisition.showStderrSha256 || null,
    acquisitionDiagnostics: acquisition.diagnostics || [],
    checkCount: classification.checkCount || 0,
    infrastructureCheckCount: classification.infrastructureCheckCount || 0,
    variableCheckCount: classification.variableCheckCount || 0,
    resourcePreconditionCheckCount: classification.resourcePreconditionCheckCount || 0,
    passedCheckCount: classification.passedCheckCount || 0,
    failedCheckCount: classification.failedCheckCount || 0,
    malformedCheckCount: classification.malformedCheckCount || 0,
    missingCheckCount: classification.missingCheckCount || 0,
    unknownCheckCount: classification.unknownCheckCount || 0,
    duplicateCheckCount: classification.duplicateCheckCount || 0,
    checkInventoryHash: classification.checkInventoryHash || null,
    taskDefinitionArns: classification.taskDefinitionArns || null,
    emittedInstanceCount: classification.emittedInstanceCount || 0,
    passedInstanceCount: classification.passedInstanceCount || 0,
    failedInstanceCount: classification.failedInstanceCount || 0,
    malformedInstanceCount: classification.malformedInstanceCount || 0,
    duplicateInstanceCount: classification.duplicateInstanceCount || 0,
    instanceInventoryHash: classification.instanceInventoryHash || null,
    failedChecks: classification.failedChecks || [],
    checks: classification.checks || [],
    resourceChanges: classification.resourceChanges,
    outputChanges: classification.outputChanges,
    };
    writeOutput(artifacts.outputPath, refreshReport);
    if (!STAGE_B_REFRESH_CAPTURE_STATUSES.includes(classification.status)) throw new Error(`Stage B refresh-only ${classification.status}: ${classification.reason}`);
    return { ...refreshReport, outputPath: artifacts.outputPath, terraformArgs: argsForTerraform };
  } finally {
    fs.rmSync(refreshDirectory, { recursive: true, force: true });
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try { process.stdout.write(`${JSON.stringify(runRefreshOnly(), null, 2)}\n`); } catch (error) { console.error(error.message); process.exitCode = 1; }
}
