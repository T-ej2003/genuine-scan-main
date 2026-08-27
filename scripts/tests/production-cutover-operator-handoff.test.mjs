import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import test from "node:test";
import { buildProductionCutoverChildEnvironment, parseProductionCutoverOperatorArgs, runProductionCutoverOperator } from "../aws/run-production-cutover-operator.mjs";
import { promptProductionHiddenInput } from "../security/production-interactive-mfa-provider.mjs";
import { ECS_EXEC_OPERATOR_BOOTSTRAP_MFA_SERIAL_ARN } from "../aws/production-ecs-exec-operator-contract.mjs";

const sourceSha = "a".repeat(40);
const configSha = "b".repeat(64);
const argv = ["--config", "/private/runtime/rotation-config.json", "--config-sha256", configSha, "--source-sha", sourceSha, "--rotation-id", "rotation-20260826060632-b15b3f51"];
const values = Object.freeze({ MSCQR_VERIFIER_MFA_SERIAL: ECS_EXEC_OPERATOR_BOOTSTRAP_MFA_SERIAL_ARN, MSCQR_ONBOARDING_EMAIL: "administration@example.invalid", MSCQR_ONBOARDING_PASSWORD: "fixture-admin-value", MSCQR_CANARY_ORDINARY_EMAIL: "canary@example.invalid", MSCQR_CANARY_ORDINARY_PASSWORD: "fixture-canary-value" });

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

test("operator handoff collects exactly five hidden pre-launch inputs and leaves verifier MFA JIT", async () => {
  const prompts = [];
  let spawned;
  const output = [];
  const result = await runProductionCutoverOperator({
    argv,
    stdin: { isTTY: true },
    stdout: { isTTY: true, write: (value) => output.push(value) },
    parentEnvironment: { HOME: "/operator", PATH: "/usr/bin", UNRELATED_SECRET: "must-not-pass", MSCQR_ONBOARDING_PASSWORD: "fixture-old-value" },
    prompt: async (request) => { prompts.push(request); return inputFor(request.prompt); },
    spawnChild: childThatExits({ capture: (value) => { spawned = { ...value, environment: { ...value.options.env } }; } }),
  });
  assert.equal(result.exitCode, 0);
  assert.equal(result.signal, null);
  assert.deepEqual(prompts.map(({ prompt }) => prompt), ["Production verifier MFA serial: ", "Production strict-onboarding administrator email: ", "Production strict-onboarding administrator password: ", "Production strict-onboarding tenant-canary email: ", "Production strict-onboarding tenant-canary password: "]);
  assert.equal(prompts.some(({ prompt }) => /MFA code|MFA_BOOTSTRAP|onboarding MFA|tenant-canary MFA/.test(prompt)), false);
  assert.deepEqual(spawned.options.stdio, "inherit");
  assert.equal(spawned.environment.UNRELATED_SECRET, undefined);
  assert.equal(spawned.environment.MSCQR_VERIFIER_MFA_CODE, undefined);
  assert.equal(spawned.environment.HOME, "/operator");
  for (const [name, value] of Object.entries(values)) assert.equal(spawned.environment[name], value);
  assert.equal(JSON.stringify(spawned.args).includes(values.MSCQR_ONBOARDING_PASSWORD), false);
  assert.deepEqual(output, []);
});

test("operator handoff fails closed before a child exists for empty or malformed input", async () => {
  let spawns = 0;
  await assert.rejects(() => runProductionCutoverOperator({ argv, stdin: { isTTY: true }, stdout: { isTTY: true }, prompt: async () => "", spawnChild: () => { spawns += 1; } }), /MSCQR_VERIFIER_MFA_SERIAL entry failed/);
  await assert.rejects(() => runProductionCutoverOperator({ argv, stdin: { isTTY: true }, stdout: { isTTY: true }, prompt: async (request) => request.prompt.includes("administrator password") ? "" : inputFor(request.prompt), spawnChild: () => { spawns += 1; } }), /MSCQR_ONBOARDING_PASSWORD entry failed/);
  await assert.rejects(() => runProductionCutoverOperator({ argv, stdin: { isTTY: true }, stdout: { isTTY: true }, prompt: async (request) => request.prompt.includes("verifier MFA serial") ? "123456" : inputFor(request.prompt), spawnChild: () => { spawns += 1; } }), /MSCQR_VERIFIER_MFA_SERIAL entry failed/);
  await assert.rejects(() => runProductionCutoverOperator({ argv, stdin: { isTTY: true }, stdout: { isTTY: true }, prompt: async () => { throw new Error("fixture-sensitive-value"); }, spawnChild: () => { spawns += 1; } }), (error) => error.message === "Interactive MSCQR_VERIFIER_MFA_SERIAL entry failed." && !error.message.includes("fixture-sensitive-value"));
  assert.equal(spawns, 0);
});

test("operator handoff preserves the child exit outcome and clears its child-only environment object", async () => {
  let invocation;
  const result = await runProductionCutoverOperator({ argv, stdin: { isTTY: true }, stdout: { isTTY: true }, prompt: async (request) => inputFor(request.prompt), spawnChild: childThatExits({ code: 17, capture: (value) => { invocation = value; } }) });
  assert.deepEqual(result, { exitCode: 17, signal: null });
  for (const name of Object.keys(values)) assert.equal(invocation.options.env[name], undefined);
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
  assert.throws(() => parseProductionCutoverOperatorArgs([...argv, "--extra", "value"]), /exactly four/);
  assert.throws(() => buildProductionCutoverChildEnvironment({ inputs: { ...values, MSCQR_ONBOARDING_PASSWORD: "" } }), /incomplete/);
});
