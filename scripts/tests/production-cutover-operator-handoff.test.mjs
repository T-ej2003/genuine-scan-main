import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { chmodSync, mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { assertProductionCutoverOperatorConfig, buildProductionCutoverChildEnvironment, parseProductionCutoverOperatorArgs, runProductionCutoverOperator as runOperator } from "../aws/run-production-cutover-operator.mjs";
import { promptProductionHiddenInput } from "../security/production-interactive-mfa-provider.mjs";
import { ECS_EXEC_OPERATOR_BOOTSTRAP_MFA_SERIAL_ARN } from "../aws/production-ecs-exec-operator-contract.mjs";
import { COMPLETED_INVENTORY_PREDECESSOR } from "../aws/production-green-stage-b-contract.mjs";
import { readStageBProtectedMainCheckout } from "../aws/stage-b-deployment-identity.mjs";

const sourceSha = "a".repeat(40);
const configSha = "b".repeat(64);
const argv = ["--mode", "prepare-overlap", "--config", "/private/runtime/rotation-config.json", "--config-sha256", configSha, "--source-sha", sourceSha, "--rotation-id", "rotation-20260826060632-b15b3f51"];
const values = Object.freeze({ MSCQR_VERIFIER_MFA_SERIAL: ECS_EXEC_OPERATOR_BOOTSTRAP_MFA_SERIAL_ARN, MSCQR_ONBOARDING_EMAIL: "administration@example.invalid", MSCQR_ONBOARDING_PASSWORD: "fixture-admin-value", MSCQR_CANARY_ORDINARY_EMAIL: "canary@example.invalid", MSCQR_CANARY_ORDINARY_PASSWORD: "fixture-canary-value" });
const runProductionCutoverOperator = options => runOperator({ validateConfig: () => ({}), authenticateCheckout: () => {}, preflightRotation: () => {}, ...options });

test("operator authenticates a clean canonical checkout before Terraform or MFA", async () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "mscqr-operator-checkout-"));
  const checkout = path.join(directory, "checkout");
  const runtimeDirectory = path.join(directory, "runtime");
  mkdirSync(checkout);
  mkdirSync(runtimeDirectory, { mode: 0o700 });
  const git = args => execFileSync("git", args, { cwd: checkout, encoding: "utf8" }).trim();
  git(["init", "-q"]);
  git(["config", "user.email", "operator-test@example.invalid"]);
  git(["config", "user.name", "Operator Test"]);
  writeFileSync(path.join(checkout, "tracked.txt"), "clean\n");
  git(["add", "tracked.txt"]);
  git(["commit", "-qm", "protected source"]);
  const head = git(["rev-parse", "HEAD"]);
  git(["remote", "add", "origin", "https://github.com/T-ej2003/genuine-scan-main.git"]);
  git(["update-ref", "refs/remotes/origin/main", head]);
  git(["symbolic-ref", "refs/remotes/origin/HEAD", "refs/remotes/origin/main"]);
  const configFile = path.join(runtimeDirectory, "rotation-config.json");
  const manifestFile = path.join(runtimeDirectory, "cutover-runtime-manifest.json");
  const rotationId = "rotation-20260913011819-98b062c4";
  const config = { sourceSha: head, rotationId, rotationConfigFile: configFile, rotationStateFile: path.join(runtimeDirectory, "rotation-state.json") };
  const writeConfig = () => {
    const bytes = Buffer.from(`${JSON.stringify(config)}\n`);
    writeFileSync(configFile, bytes, { mode: 0o600 });
    const digest = createHash("sha256").update(bytes).digest("hex");
    writeFileSync(manifestFile, JSON.stringify({ runtimeConfigSha256: digest, readyToConsumeMfa: true, releaseSourceSha: head }), { mode: 0o600 });
    return ["--mode", "prepare-overlap", "--config", configFile, "--config-sha256", digest, "--source-sha", head, "--rotation-id", rotationId];
  };
  const authenticateCheckout = options => readStageBProtectedMainCheckout({ ...options, run: args => args[0] === "fetch" ? "" : args[0] === "rev-parse" && args[1] === "FETCH_HEAD" ? git(["rev-parse", "refs/remotes/origin/main"]) : git(args) });
  let planning = 0;
  let prompts = 0;
  let children = 0;
  const invoke = (args = writeConfig()) => runOperator({ argv: args, cwd: checkout, stdin: { isTTY: true }, stdout: { isTTY: true }, legacyGuard:async()=>{}, authenticateCheckout,
    preflightRotation: ({ cwd }) => { assert.equal(cwd, checkout); planning++; }, prompt: async () => { prompts++; return ECS_EXEC_OPERATOR_BOOTSTRAP_MFA_SERIAL_ARN; }, spawnChild: childThatExits({ capture: () => { children++; } }) });
  try {
    assert.equal((await invoke()).exitCode, 0);
    assert.deepEqual([planning, prompts, children], [1, 1, 1]);
    const invalidConfig = writeConfig();
    invalidConfig[5] = "0".repeat(64);
    await assert.rejects(invoke(invalidConfig), /changed after runtime preparation/);
    assert.deepEqual([planning, prompts, children], [1, 1, 1]);
    writeFileSync(path.join(checkout, "tracked.txt"), "dirty\n");
    await assert.rejects(invoke(), /tracked modifications/);
    assert.deepEqual([planning, prompts, children], [1, 1, 1]);
    git(["checkout", "--", "tracked.txt"]);
    writeFileSync(path.join(checkout, "untracked.txt"), "untracked\n");
    await assert.rejects(invoke(), /untracked file/);
    assert.deepEqual([planning, prompts, children], [1, 1, 1]);
    rmSync(path.join(checkout, "untracked.txt"));
    git(["remote", "set-url", "origin", "https://example.invalid/other.git"]);
    await assert.rejects(invoke(), /canonical production repository/);
    assert.deepEqual([planning, prompts, children], [1, 1, 1]);
    git(["remote", "set-url", "origin", "https://github.com/T-ej2003/genuine-scan-main.git"]);
    config.recoveryTooling = { sourceSha: "f".repeat(40) };
    await assert.rejects(invoke(), /Requested source SHA/);
    assert.deepEqual([planning, prompts, children], [1, 1, 1]);
    delete config.recoveryTooling;
    writeFileSync(path.join(checkout, "tracked.txt"), "successor\n");
    git(["add", "tracked.txt"]);
    git(["commit", "-qm", "main advances"]);
    git(["update-ref", "refs/remotes/origin/main", git(["rev-parse", "HEAD"])]);
    await assert.rejects(invoke(), /Requested source SHA/);
    assert.deepEqual([planning, prompts, children], [1, 1, 1]);
    const wrong = writeConfig();
    wrong[7] = "0".repeat(40);
    await assert.rejects(invoke(wrong), /not bound to its prepared artifact/);
    assert.deepEqual([planning, prompts, children], [1, 1, 1]);
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test("operator authenticates both runtime config reads before MFA", async () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "mscqr-operator-config-"));
  chmodSync(directory, 0o700);
  const file = path.join(directory, "rotation-config.json");
  const manifestFile = path.join(directory, "cutover-runtime-manifest.json");
  const config = { sourceSha, rotationId: argv.at(-1), rotationConfigFile: file, rotationStateFile: path.join(directory, "rotation-state.json"), stageAPlanPath: "/private/stage-a.tfplan", endpointSecurityGroupId: "sg-04d5bf116755ba412", runtimeSecurityGroupId: "sg-0db971332ae625441" };
  const write = () => { writeFileSync(file, `${JSON.stringify(config)}\n`, { mode: 0o600 }); return createHash("sha256").update(`${JSON.stringify(config)}\n`).digest("hex"); };
  try {
    const sha = write();
    writeFileSync(manifestFile, JSON.stringify({ runtimeConfigSha256: sha, readyToConsumeMfa: true, releaseSourceSha: sourceSha }), { mode: 0o600 });
    const valid = [...argv]; valid[3] = file; valid[5] = sha;
    const runtime = parseProductionCutoverOperatorArgs(valid);
    assert.equal(assertProductionCutoverOperatorConfig(runtime).rotationConfigFile, file);
    let prompts = 0;
    config.rotationStateFile = "/private/other/rotation-state.json";
    const wrongStateSha = write();
    writeFileSync(manifestFile, JSON.stringify({ runtimeConfigSha256: wrongStateSha, readyToConsumeMfa: true, releaseSourceSha: sourceSha }), { mode: 0o600 });
    const wrongState = [...valid]; wrongState[5] = wrongStateSha;
    await assert.rejects(() => runOperator({ argv: wrongState, stdin: { isTTY: true }, stdout: { isTTY: true }, prompt: async () => { prompts++; return values.MSCQR_VERIFIER_MFA_SERIAL; } }), /not bound to its prepared artifact/);
    config.rotationStateFile = path.join(directory, "rotation-state.json");
    config.completedInventoryAdoptionRequired = true;
    const adoptionSha = write();
    writeFileSync(manifestFile, JSON.stringify({ runtimeConfigSha256: adoptionSha, readyToConsumeMfa: true, releaseSourceSha: sourceSha }), { mode: 0o600 });
    const adoption = [...valid]; adoption[5] = adoptionSha;
    await assert.rejects(() => runOperator({ argv: adoption, stdin: { isTTY: true }, stdout: { isTTY: true }, prompt: async () => { prompts++; return values.MSCQR_VERIFIER_MFA_SERIAL; } }), /adoption proof is required before MFA/);
    delete config.completedInventoryAdoptionRequired;
    config.newInventoryAfterCompleted = COMPLETED_INVENTORY_PREDECESSOR;
    const freshSha = write();
    writeFileSync(manifestFile, JSON.stringify({ runtimeConfigSha256: freshSha, readyToConsumeMfa: true, releaseSourceSha: sourceSha }), { mode: 0o600 });
    const fresh = [...valid]; fresh[5] = freshSha;
    assert.equal(assertProductionCutoverOperatorConfig(parseProductionCutoverOperatorArgs(fresh)).newInventoryAfterCompleted.operationKey, COMPLETED_INVENTORY_PREDECESSOR.operationKey);
    config.newInventoryAfterCompleted = { ...COMPLETED_INVENTORY_PREDECESSOR, operationKey: "forged" };
    const forgedSha = write();
    writeFileSync(manifestFile, JSON.stringify({ runtimeConfigSha256: forgedSha, readyToConsumeMfa: true, releaseSourceSha: sourceSha }), { mode: 0o600 });
    const forged = [...valid]; forged[5] = forgedSha;
    await assert.rejects(() => runOperator({ argv: forged, stdin: { isTTY: true }, stdout: { isTTY: true }, prompt: async () => { prompts++; return values.MSCQR_VERIFIER_MFA_SERIAL; } }), /Fresh inventory binding is invalid before MFA/);
    delete config.newInventoryAfterCompleted;
    config.rotationConfigFile = path.join(directory, "old-config.json");
    const changed = write();
    writeFileSync(manifestFile, JSON.stringify({ runtimeConfigSha256: changed, readyToConsumeMfa: true, releaseSourceSha: sourceSha }), { mode: 0o600 });
    const wrong = [...valid]; wrong[5] = changed;
    await assert.rejects(() => runOperator({ argv: wrong, stdin: { isTTY: true }, stdout: { isTTY: true }, prompt: async () => { prompts++; return values.MSCQR_VERIFIER_MFA_SERIAL; }, spawnChild: () => { throw new Error("child must not start"); } }), /not bound to its prepared artifact/);
    assert.equal(prompts, 0);
    assert.throws(() => assertProductionCutoverOperatorConfig(runtime), /changed after runtime preparation/);
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test("cross-source successor is authenticated before Terraform planning or MFA", async () => {
  const sequence = [];
  const options = { argv, stdin: { isTTY: true }, stdout: { isTTY: true },
    validateConfig: () => ({ rotationSuccessor: { predecessorSourceSha: "c".repeat(40) }, releaseProfile: "mscqr-production-release-deployer" }),
    authenticateCheckout: () => sequence.push("checkout"), authenticateInventory: () => sequence.push("inventory"),
    authenticateSuccessor: () => { sequence.push("successor"); throw new Error("successor signature invalid"); },
    preflightRotation: () => sequence.push("terraform"), prompt: async () => { sequence.push("MFA"); return values.MSCQR_VERIFIER_MFA_SERIAL; },
    spawnChild: () => { sequence.push("child"); return childThatExits()(); } };
  await assert.rejects(runOperator(options), /successor signature invalid/);
  assert.deepEqual(sequence, ["checkout", "inventory", "successor"]);
  const result = await runOperator({ ...options, authenticateSuccessor: () => sequence.push("successor-ok") });
  assert.equal(result.exitCode, 0);
  assert.deepEqual(sequence.slice(3), ["checkout", "inventory", "successor-ok", "terraform", "MFA", "child"]);
});

const inputFor = (prompt) => values[prompt.includes("verifier MFA serial") ? "MSCQR_VERIFIER_MFA_SERIAL" : prompt.includes("administrator email") ? "MSCQR_ONBOARDING_EMAIL" : prompt.includes("administrator password") ? "MSCQR_ONBOARDING_PASSWORD" : prompt.includes("tenant-canary email") ? "MSCQR_CANARY_ORDINARY_EMAIL" : "MSCQR_CANARY_ORDINARY_PASSWORD"];

const childThatExits = ({ code = 0, signal = null, capture } = {}) => (file, args, options) => {
  capture?.({ file, args, options });
  const child = new EventEmitter();
  queueMicrotask(() => child.emit("exit", code, signal));
  return child;
};

test("operator handoff refuses non-interactive execution before prompting or spawning", async () => {
  let prompts = 0;
  let spawns = 0;
  await assert.rejects(() => runProductionCutoverOperator({ argv, stdin: { isTTY: false }, stdout: { isTTY: true }, prompt: async () => { prompts += 1; return "unexpected"; }, spawnChild: () => { spawns += 1; } }), /interactive trusted terminal/);
  assert.equal(prompts, 0);
  assert.equal(spawns, 0);
});

test("rotation Terraform preflight runs before verifier MFA and fails closed", async () => {
  let prompts = 0;
  let spawns = 0;
  const config = { rotationTerraformPlanFile: "/private/runtime/rotation-infrastructure.tfplan" };
  await assert.rejects(() => runOperator({ argv, stdin: { isTTY: true }, stdout: { isTTY: true }, validateConfig: () => config,
    authenticateCheckout: () => {},
    preflightRotation: ({ config: supplied, runtime }) => { assert.equal(supplied, config); assert.equal(runtime["--source-sha"], sourceSha); throw new Error("Terraform plan checksum changed before MFA."); },
    prompt: async () => { prompts += 1; return values.MSCQR_VERIFIER_MFA_SERIAL; }, spawnChild: () => { spawns += 1; } }), /checksum changed before MFA/);
  assert.equal(prompts, 0);
  assert.equal(spawns, 0);
});

test("prepare-overlap collects only its verifier input and excludes post-deployment credentials", async () => {
  const prompts = [];
  let spawned;
  const output = [];
  const result = await runProductionCutoverOperator({
    argv,
    stdin: { isTTY: true },
    stdout: { isTTY: true, write: (value) => output.push(value) },
    parentEnvironment: { HOME: "/operator", PATH: "/usr/bin", GH_TOKEN: "fixture-gh-token", GITHUB_TOKEN: "fixture-github-token", AWS_CONFIG_FILE: "/hostile/config", AWS_SHARED_CREDENTIALS_FILE: "/hostile/credentials", AWS_SDK_LOAD_CONFIG: "1", AWS_CA_BUNDLE: "/hostile/ca", UNRELATED_SECRET: "must-not-pass", MSCQR_ONBOARDING_PASSWORD: "fixture-old-value" },
    prompt: async (request) => { prompts.push(request); return inputFor(request.prompt); },
    spawnChild: childThatExits({ capture: (value) => { spawned = { ...value, environment: { ...value.options.env } }; } }),
  });
  assert.equal(result.exitCode, 0);
  assert.equal(result.signal, null);
  assert.deepEqual(prompts.map(({ prompt }) => prompt), ["Production verifier MFA serial: "]);
  assert.equal(prompts.some(({ prompt }) => /MFA code|MFA_BOOTSTRAP|onboarding MFA|tenant-canary MFA/.test(prompt)), false);
  assert.deepEqual(spawned.options.stdio, "inherit");
  assert.deepEqual(spawned.args.slice(0, 3), ["scripts/aws/run-production-cutover.mjs", "--mode", "prepare-overlap"]);
  assert.equal(spawned.environment.UNRELATED_SECRET, undefined);
  for (const name of ["AWS_CONFIG_FILE", "AWS_SHARED_CREDENTIALS_FILE", "AWS_SDK_LOAD_CONFIG", "AWS_CA_BUNDLE"]) assert.equal(spawned.environment[name], undefined);
  assert.equal(spawned.environment.MSCQR_VERIFIER_MFA_CODE, undefined);
  assert.equal(spawned.environment.HOME, "/operator");
  assert.equal(spawned.environment.GH_TOKEN, undefined);
  assert.equal(spawned.environment.GITHUB_TOKEN, undefined);
  assert.equal(spawned.environment.MSCQR_VERIFIER_MFA_SERIAL, values.MSCQR_VERIFIER_MFA_SERIAL);
  for (const name of ["MSCQR_ONBOARDING_EMAIL", "MSCQR_ONBOARDING_PASSWORD", "MSCQR_CANARY_ORDINARY_EMAIL", "MSCQR_CANARY_ORDINARY_PASSWORD", "MSCQR_ONBOARDING_MFA_CODE"]) assert.equal(spawned.environment[name], undefined);
  for (const value of Object.values(values).slice(1)) assert.equal(JSON.stringify(spawned).includes(value), false);
  assert.deepEqual(output, []);
});

test("operator handoff fails closed before a child exists for empty or malformed input", async () => {
  let spawns = 0;
  await assert.rejects(() => runProductionCutoverOperator({ argv, stdin: { isTTY: true }, stdout: { isTTY: true }, prompt: async () => "", spawnChild: () => { spawns += 1; } }), /MSCQR_VERIFIER_MFA_SERIAL entry failed/);
  await assert.rejects(() => runProductionCutoverOperator({ argv, stdin: { isTTY: true }, stdout: { isTTY: true }, prompt: async (request) => request.prompt.includes("verifier MFA serial") ? "123456" : inputFor(request.prompt), spawnChild: () => { spawns += 1; } }), /MSCQR_VERIFIER_MFA_SERIAL entry failed/);
  await assert.rejects(() => runProductionCutoverOperator({ argv, stdin: { isTTY: true }, stdout: { isTTY: true }, prompt: async () => { throw new Error("fixture-sensitive-value"); }, spawnChild: () => { spawns += 1; } }), (error) => error.message === "Interactive MSCQR_VERIFIER_MFA_SERIAL entry failed." && !error.message.includes("fixture-sensitive-value"));
  assert.equal(spawns, 0);
});

test("operator handoff preserves the child exit outcome and clears its child-only environment object", async () => {
  let invocation;
  const result = await runProductionCutoverOperator({ argv, stdin: { isTTY: true }, stdout: { isTTY: true }, prompt: async (request) => inputFor(request.prompt), spawnChild: childThatExits({ code: 17, capture: (value) => { invocation = value; } }) });
  assert.deepEqual(result, { exitCode: 17, signal: null });
  assert.equal(invocation.options.env.MSCQR_VERIFIER_MFA_SERIAL, undefined);
});

test("operator handoff reports a child signal for the CLI to propagate", async () => {
  const result = await runProductionCutoverOperator({ argv, stdin: { isTTY: true }, stdout: { isTTY: true }, prompt: async (request) => inputFor(request.prompt), spawnChild: childThatExits({ signal: "SIGTERM" }) });
  assert.deepEqual(result, { exitCode: 1, signal: "SIGTERM" });
});

test("hidden controlling-terminal input disables echo and does not report the entered value", () => {
  const value = "fixture-hidden-value";
  const calls = [];
  assert.equal(promptProductionHiddenInput({ prompt: "Production prompt: ", validate: (input) => input === value, openTerminal: () => 23, closeTerminal: () => {}, spawn: (_file, args, options) => { calls.push({ args, options }); return { status: 0, stdout: Buffer.from(value) }; } }), value);
  assert.match(calls[0].args[1], /stty -echo/);
  assert.equal(JSON.stringify(calls).includes(value), false);
});

test("operator handoff accepts only the exact non-secret runtime argument contract", () => {
  assert.equal(parseProductionCutoverOperatorArgs(argv)["--source-sha"], sourceSha);
  assert.throws(() => parseProductionCutoverOperatorArgs(argv.slice(2)), /exactly five/);
  assert.throws(() => parseProductionCutoverOperatorArgs(["--mode", "production", ...argv.slice(2)]), /runtime identity/);
  assert.throws(() => parseProductionCutoverOperatorArgs(["--mode", "unknown", ...argv.slice(2)]), /runtime identity/);
  assert.throws(() => parseProductionCutoverOperatorArgs([...argv, "--extra", "value"]), /exactly five/);
  assert.throws(() => buildProductionCutoverChildEnvironment({ inputs: { ...values, MSCQR_VERIFIER_MFA_SERIAL: "" } }), /incomplete/);
  const environment = buildProductionCutoverChildEnvironment({ inputs: values });
  for (const name of ["MSCQR_ONBOARDING_EMAIL", "MSCQR_ONBOARDING_PASSWORD", "MSCQR_CANARY_ORDINARY_EMAIL", "MSCQR_CANARY_ORDINARY_PASSWORD"]) assert.equal(environment[name], undefined);
});
