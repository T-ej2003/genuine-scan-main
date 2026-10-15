#!/usr/bin/env node
import { spawn } from "node:child_process";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { promptProductionHiddenInput } from "../security/production-interactive-mfa-provider.mjs";
import { assertVerifierMfaSerial } from "./establish-production-ecs-exec-verifier-session.mjs";
import { readBoundStageBPrivateJson, readStageBPrivateFileBytes } from "./stage-b-artifact-contract.mjs";
import { assertCompletedInventoryAdoptionPayload } from "./production-completed-inventory-adoption.mjs";
import { canonicalJson, COMPLETED_INVENTORY_PREDECESSOR } from "./production-green-stage-b-contract.mjs";
import { existsSync } from "node:fs";
import { createProductionRotationInfrastructureAdapter } from "./production-cutover-production-adapters.mjs";
import { rotationBindingsToPostPrepareTaskBindings } from "./production-cutover-runtime-bootstrap.mjs";

const SHA1 = /^[a-f0-9]{40}$/;
const SHA256 = /^[a-f0-9]{64}$/;
const INPUTS_BY_MODE = Object.freeze({
  "prepare-overlap": Object.freeze([
    Object.freeze({ name: "MSCQR_VERIFIER_MFA_SERIAL", prompt: "Production verifier MFA serial: ", validate: (value) => { try { assertVerifierMfaSerial(value); return true; } catch { return false; } } }),
  ]),
});
const SAFE_PARENT_ENVIRONMENT = Object.freeze(["HOME", "PATH", "TMPDIR", "TERM", "LANG", "LC_ALL", "LC_CTYPE", "NODE_EXTRA_CA_CERTS"]);
const CHILD_SCRIPT = "scripts/aws/run-production-cutover.mjs";

const inputsForMode = (mode) => {
  const inputs = INPUTS_BY_MODE[mode];
  if (!inputs) throw new Error("Production cutover operator input phase is unsupported.");
  return inputs;
};

export function parseProductionCutoverOperatorArgs(argv = []) {
  const expected = new Set(["--mode", "--config", "--config-sha256", "--source-sha", "--rotation-id"]);
  const values = {};
  if (argv.length !== 10) throw new Error("Production cutover operator launcher requires exactly five non-secret runtime arguments.");
  for (let index = 0; index < argv.length; index += 2) {
    const name = argv[index];
    const value = argv[index + 1];
    if (!expected.has(name) || Object.hasOwn(values, name) || typeof value !== "string" || !value || value.startsWith("--")) throw new Error("Production cutover operator launcher arguments are invalid.");
    values[name] = value;
  }
  if (values["--mode"] !== "prepare-overlap" || !SHA256.test(values["--config-sha256"]) || !SHA1.test(values["--source-sha"]) || !/^rotation-[a-z0-9-]+$/.test(values["--rotation-id"])) throw new Error("Production cutover operator launcher runtime identity is invalid.");
  return Object.freeze(values);
}

export function buildProductionCutoverChildEnvironment({ parentEnvironment = process.env, inputs, mode = "prepare-overlap" } = {}) {
  const requiredInputs = inputsForMode(mode);
  if (!inputs || requiredInputs.some(({ name }) => typeof inputs[name] !== "string" || !inputs[name])) throw new Error("Production cutover operator inputs are incomplete.");
  const environment = Object.fromEntries(SAFE_PARENT_ENVIRONMENT.filter((name) => typeof parentEnvironment[name] === "string" && parentEnvironment[name]).map((name) => [name, parentEnvironment[name]]));
  for (const { name } of requiredInputs) environment[name] = inputs[name];
  return environment;
}

export function assertProductionCutoverOperatorConfig(runtime, { repositoryRoot = process.cwd() } = {}) {
  const configPath = path.resolve(runtime["--config"]);
  const hash = runtime["--config-sha256"];
  const config = readBoundStageBPrivateJson({ filePath: configPath, expectedSha256: hash, repositoryRoot, label: "Production cutover runtime config" });
  const manifestFile = path.join(path.dirname(configPath), "cutover-runtime-manifest.json");
  const manifest = JSON.parse(readStageBPrivateFileBytes({ filePath: manifestFile, repositoryRoot, label: "Cutover runtime manifest" }).bytes);
  if (config.rotationConfigFile !== configPath || path.dirname(config.rotationStateFile || "") !== path.dirname(configPath)
      || manifest.runtimeConfigSha256 !== hash || manifest.readyToConsumeMfa !== true
      || manifest.releaseSourceSha !== runtime["--source-sha"] || config.sourceSha !== runtime["--source-sha"]
      || config.rotationId !== runtime["--rotation-id"] || (config.stageAPlanPath && (!config.endpointSecurityGroupId || !config.runtimeSecurityGroupId))) {
    throw new Error("Production cutover runtime configuration is not bound to its prepared artifact.");
  }
  if (config.newInventoryAfterCompleted && (canonicalJson(config.newInventoryAfterCompleted) !== canonicalJson(COMPLETED_INVENTORY_PREDECESSOR)
      || config.inventoryFailedPredecessor || config.completedInventoryAdoptionRequired || config.sourceSha === COMPLETED_INVENTORY_PREDECESSOR.sourceSha)) throw new Error("Fresh inventory binding is invalid before MFA.");
  const adoptionFile = path.join(path.dirname(configPath), "inventory-completed-adoption-evidence.json");
  if (config.completedInventoryAdoptionRequired === true && !existsSync(adoptionFile)) throw new Error("Completed inventory adoption proof is required before MFA.");
  if (existsSync(adoptionFile)) {
    if (!config.inventoryTaskDefinitionArn) throw new Error("Completed inventory adoption lacks the exact task definition.");
    const evidence = JSON.parse(readStageBPrivateFileBytes({ filePath: adoptionFile, repositoryRoot, label: "Completed inventory adoption evidence" }).bytes);
    assertCompletedInventoryAdoptionPayload(evidence.payload, { config, configSha256: hash });
  }
  return config;
}

export function preflightProductionCutoverRotation({ config, runtime }) {
  const secretBindings = { ...config.overlapTaskInput.secretBindings, ...rotationBindingsToPostPrepareTaskBindings(config) };
  return createProductionRotationInfrastructureAdapter({ config, releaseProfile: config.releaseProfile }).preflight({ sourceSha: runtime["--source-sha"], rotationId: runtime["--rotation-id"], secretBindings });
}

export async function runProductionCutoverOperator({ argv = process.argv.slice(2), stdin = process.stdin, stdout = process.stdout, prompt = promptProductionHiddenInput, spawnChild = spawn, validateConfig = assertProductionCutoverOperatorConfig, preflightRotation = preflightProductionCutoverRotation, parentEnvironment = process.env, cwd = process.cwd(), childExecutable = process.execPath } = {}) {
  if (!stdin?.isTTY || !stdout?.isTTY) throw new Error("Production cutover operator launcher requires an interactive trusted terminal.");
  if (typeof prompt !== "function" || typeof spawnChild !== "function") throw new Error("Production cutover operator launcher dependencies are invalid.");
  const runtime = parseProductionCutoverOperatorArgs(argv);
  const config = validateConfig(runtime, { repositoryRoot: cwd });
  preflightRotation({ config, runtime });
  const requiredInputs = inputsForMode(runtime["--mode"]);
  const inputs = {};
  let childEnvironment;
  try {
    for (const { name, prompt: promptText, validate } of requiredInputs) {
      let supplied;
      try {
        supplied = await prompt({ prompt: promptText, validate, errorMessage: `Interactive ${name} entry failed.` });
      } catch {
        throw new Error(`Interactive ${name} entry failed.`);
      }
      const input = String(supplied).trim();
      if (!validate(input)) throw new Error(`Interactive ${name} entry failed.`);
      inputs[name] = input;
    }
    childEnvironment = buildProductionCutoverChildEnvironment({ parentEnvironment, inputs, mode: runtime["--mode"] });
    const child = spawnChild(childExecutable, [CHILD_SCRIPT, "--mode", runtime["--mode"], "--config", runtime["--config"], "--config-sha256", runtime["--config-sha256"], "--source-sha", runtime["--source-sha"], "--rotation-id", runtime["--rotation-id"]], { cwd, env: childEnvironment, stdio: "inherit" });
    for (const { name } of requiredInputs) {
      delete inputs[name];
      delete childEnvironment[name];
    }
    childEnvironment = undefined;
    if (!child || typeof child.once !== "function") throw new Error("Production cutover child could not be started.");
    const result = await new Promise((resolve, reject) => {
      child.once("error", reject);
      child.once("exit", (code, signal) => resolve({ code, signal }));
    });
    return { exitCode: result.signal ? 1 : Number.isInteger(result.code) ? result.code : 1, signal: result.signal || null };
  } finally {
    for (const { name } of requiredInputs) {
      delete inputs[name];
      if (childEnvironment) delete childEnvironment[name];
    }
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    const result = await runProductionCutoverOperator();
    if (result.signal) process.kill(process.pid, result.signal);
    else process.exitCode = result.exitCode;
  } catch (error) {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 1;
  }
}
