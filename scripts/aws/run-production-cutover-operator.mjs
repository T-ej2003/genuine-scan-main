#!/usr/bin/env node
import { spawn } from "node:child_process";
import { pathToFileURL } from "node:url";
import { promptProductionHiddenInput } from "../security/production-interactive-mfa-provider.mjs";

const SHA1 = /^[a-f0-9]{40}$/;
const SHA256 = /^[a-f0-9]{64}$/;
const REQUIRED_INPUTS = Object.freeze([
  Object.freeze({ name: "MSCQR_VERIFIER_MFA_SERIAL", prompt: "Production verifier MFA serial: ", validate: (value) => Boolean(value) }),
  Object.freeze({ name: "MSCQR_ONBOARDING_EMAIL", prompt: "Production strict-onboarding administrator email: ", validate: (value) => Boolean(value) }),
  Object.freeze({ name: "MSCQR_ONBOARDING_PASSWORD", prompt: "Production strict-onboarding administrator password: ", validate: (value) => Boolean(value) }),
  Object.freeze({ name: "MSCQR_CANARY_ORDINARY_EMAIL", prompt: "Production strict-onboarding tenant-canary email: ", validate: (value) => Boolean(value) }),
  Object.freeze({ name: "MSCQR_CANARY_ORDINARY_PASSWORD", prompt: "Production strict-onboarding tenant-canary password: ", validate: (value) => Boolean(value) }),
]);
const SAFE_PARENT_ENVIRONMENT = Object.freeze(["HOME", "PATH", "TMPDIR", "TERM", "LANG", "LC_ALL", "LC_CTYPE", "AWS_CONFIG_FILE", "AWS_SHARED_CREDENTIALS_FILE", "AWS_SDK_LOAD_CONFIG", "AWS_CA_BUNDLE", "NODE_EXTRA_CA_CERTS"]);
const CHILD_SCRIPT = "scripts/aws/run-production-cutover.mjs";

export function parseProductionCutoverOperatorArgs(argv = []) {
  const expected = new Set(["--config", "--config-sha256", "--source-sha", "--rotation-id"]);
  const values = {};
  if (argv.length !== 8) throw new Error("Production cutover operator launcher requires exactly four non-secret runtime arguments.");
  for (let index = 0; index < argv.length; index += 2) {
    const name = argv[index];
    const value = argv[index + 1];
    if (!expected.has(name) || Object.hasOwn(values, name) || typeof value !== "string" || !value || value.startsWith("--")) throw new Error("Production cutover operator launcher arguments are invalid.");
    values[name] = value;
  }
  if (!SHA256.test(values["--config-sha256"]) || !SHA1.test(values["--source-sha"]) || !/^rotation-[a-z0-9-]+$/.test(values["--rotation-id"])) throw new Error("Production cutover operator launcher runtime identity is invalid.");
  return Object.freeze(values);
}

export function buildProductionCutoverChildEnvironment({ parentEnvironment = process.env, inputs } = {}) {
  if (!inputs || REQUIRED_INPUTS.some(({ name }) => typeof inputs[name] !== "string" || !inputs[name])) throw new Error("Production cutover operator inputs are incomplete.");
  const environment = Object.fromEntries(SAFE_PARENT_ENVIRONMENT.filter((name) => typeof parentEnvironment[name] === "string" && parentEnvironment[name]).map((name) => [name, parentEnvironment[name]]));
  for (const { name } of REQUIRED_INPUTS) environment[name] = inputs[name];
  return environment;
}

export async function runProductionCutoverOperator({ argv = process.argv.slice(2), stdin = process.stdin, stdout = process.stdout, prompt = promptProductionHiddenInput, spawnChild = spawn, parentEnvironment = process.env, cwd = process.cwd(), childExecutable = process.execPath } = {}) {
  if (!stdin?.isTTY || !stdout?.isTTY) throw new Error("Production cutover operator launcher requires an interactive trusted terminal.");
  if (typeof prompt !== "function" || typeof spawnChild !== "function") throw new Error("Production cutover operator launcher dependencies are invalid.");
  const runtime = parseProductionCutoverOperatorArgs(argv);
  const inputs = {};
  let childEnvironment;
  try {
    for (const { name, prompt: promptText, validate } of REQUIRED_INPUTS) {
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
    childEnvironment = buildProductionCutoverChildEnvironment({ parentEnvironment, inputs });
    const child = spawnChild(childExecutable, [CHILD_SCRIPT, "--mode", "production", "--config", runtime["--config"], "--config-sha256", runtime["--config-sha256"], "--source-sha", runtime["--source-sha"], "--rotation-id", runtime["--rotation-id"]], { cwd, env: childEnvironment, stdio: "inherit" });
    for (const { name } of REQUIRED_INPUTS) {
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
    for (const { name } of REQUIRED_INPUTS) {
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
