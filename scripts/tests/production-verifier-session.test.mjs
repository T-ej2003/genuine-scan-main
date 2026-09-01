import assert from "node:assert/strict";
import test from "node:test";
import { createAwsStsRunner, establishInheritedVerifierIdentity, establishVerifierIdentity, VERIFIER_SESSION_MIN_REMAINING_MS } from "../aws/production-identity-adapters.mjs";
import { ECS_EXEC_OPERATOR_BOOTSTRAP_MFA_SERIAL_ARN, ECS_EXEC_OPERATOR_ROLE_ARN } from "../aws/production-ecs-exec-operator-contract.mjs";
import { establishEcsExecVerifierSession } from "../aws/establish-production-ecs-exec-verifier-session.mjs";
import { createProductionVerifierOnlyAdapters } from "../aws/production-cutover-verifier-adapters.mjs";

const bootstrapArn = "arn:aws:iam::368992683803:user/mscqr-production-bootstrap-operator";
const mfaSerial = ECS_EXEC_OPERATOR_BOOTSTRAP_MFA_SERIAL_ARN;
const verifierArn = "arn:aws:sts::368992683803:assumed-role/mscqr-production-ecs-exec-verifier/mscqr-production-ecs-exec-verifier";
const future = () => new Date(Date.now() + VERIFIER_SESSION_MIN_REMAINING_MS + 10 * 60_000).toISOString();

function fixtureRunner({ expiration = future(), now = Date.now } = {}) {
  const calls = [];
  const run = (_file, args, options) => {
    calls.push({ args, options });
    if (args[0] === "sts" && args[1] === "get-caller-identity") {
      return JSON.stringify({ Arn: options.env.AWS_ACCESS_KEY_ID ? verifierArn : bootstrapArn });
    }
    if (args[0] === "sts" && args[1] === "assume-role") {
      return JSON.stringify({ Credentials: { AccessKeyId: "sentinel-access", SecretAccessKey: "sentinel-secret", SessionToken: "sentinel-token", Expiration: expiration } });
    }
    throw new Error(`unexpected AWS call: ${args.join(" ")}`);
  };
  return { runner: createAwsStsRunner({ profile: "fixture", run, now }), calls };
}

test("one MFA challenge establishes one reusable verifier session", async () => {
  const { runner, calls } = fixtureRunner();
  const first = await establishEcsExecVerifierSession({ adapter: runner, mfaSerial, mfaCode: "123456" });
  const session = first.session;
  assert.equal(session.callerArn, verifierArn);
  delete process.env.MSCQR_VERIFIER_MFA_CODE;
  const second = await establishEcsExecVerifierSession({ adapter: runner, mfaSerial, mfaCode: "654321" });
  assert.equal(second.session, session);
  assert.equal(calls.filter(({ args }) => args[1] === "assume-role").length, 1);
  assert.equal(calls.filter(({ args }) => args[1] === "get-caller-identity").length, 3);
  assert.equal(JSON.stringify({ first, second }).includes("sentinel-secret"), false);
});

test("expired verifier sessions fail closed without a second AssumeRole", async () => {
  const expiration = Date.now() + 10 * 60_000;
  let clock = Date.now();
  const { runner, calls } = fixtureRunner({ expiration: new Date(expiration).toISOString(), now: () => clock });
  await establishEcsExecVerifierSession({ adapter: runner, mfaSerial, mfaCode: "123456" });
  clock = expiration - VERIFIER_SESSION_MIN_REMAINING_MS + 1;
  assert.throws(() => runner.getVerifierSession(), (error) => error.code === "VERIFIER_SESSION_EXPIRED" && error.freshMfaRequired === true);
  assert.equal(calls.filter(({ args }) => args[1] === "assume-role").length, 1);
  assert.throws(() => runner.runAsVerifier(["sts", "get-caller-identity"]), /fresh MFA is required/);
  await assert.rejects(() => establishEcsExecVerifierSession({ adapter: runner, mfaSerial, mfaCode: "654321" }), /fresh MFA is required/);
  assert.equal(calls.filter(({ args }) => args[1] === "assume-role").length, 1);
});

test("verifier sessions reject role substitution", async () => {
  const { runner } = fixtureRunner();
  await assert.rejects(() => runner.assumeRole({ roleArn: "arn:aws:iam::368992683803:role/wrong", sessionName: "fixture", mfaSerial: "fixture", mfaCode: "123456" }), /reviewed ECS Exec verifier role/);
  assert.equal(ECS_EXEC_OPERATOR_ROLE_ARN, "arn:aws:iam::368992683803:role/mscqr-production-ecs-exec-verifier");
});

test("verifier MFA is requested only after bootstrap identity validation and immediately before AssumeRole", async () => {
  const calls = [];
  const adapter = {
    getCallerIdentity: async () => { calls.push("caller"); return bootstrapArn; },
    assumeRole: async ({ mfaCode }) => { calls.push(`assume:${mfaCode}`); return { callerArn: verifierArn, expiration: future() }; },
  };
  const result = await establishEcsExecVerifierSession({ adapter, mfaSerial, getMfaCode: async () => { calls.push("prompt"); return "123456"; } });
  assert.equal(result.valid, true);
  assert.deepEqual(calls, ["caller", "prompt", "assume:123456"]);
});

test("production verifier identity forwards its JIT MFA provider to the STS boundary", async () => {
  const calls = [];
  const adapter = {
    getCallerIdentity: async () => { calls.push("caller"); return bootstrapArn; },
    assumeRole: async ({ mfaCode }) => { calls.push(`assume:${mfaCode}`); return { callerArn: verifierArn, expiration: future() }; },
  };
  await establishVerifierIdentity({ adapter, mfaSerial, getMfaCode: async () => { calls.push("prompt"); return "123456"; } });
  assert.deepEqual(calls, ["caller", "prompt", "assume:123456"]);
});

test("verifier MFA fails closed without AssumeRole when identity or JIT input validation fails", async () => {
  let prompts = 0;
  let assumes = 0;
  await assert.rejects(() => establishEcsExecVerifierSession({ adapter: { getCallerIdentity: async () => "arn:aws:iam::368992683803:user/unreviewed", assumeRole: async () => { assumes += 1; } }, mfaSerial, getMfaCode: async () => { prompts += 1; return "123456"; } }), /Only the reviewed bootstrap operator/);
  assert.equal(prompts, 0);
  await assert.rejects(() => establishEcsExecVerifierSession({ adapter: { getCallerIdentity: async () => bootstrapArn, assumeRole: async () => { assumes += 1; } }, mfaSerial, getMfaCode: async () => "bad" }), /MFA serial and code are required/);
  assert.equal(assumes, 0);
});

test("verifier MFA serial is an IAM device ARN, not a one-time code", async () => {
  let callerChecks = 0;
  await assert.rejects(() => establishEcsExecVerifierSession({
    adapter: { getCallerIdentity: async () => { callerChecks += 1; return bootstrapArn; }, assumeRole: async () => { throw new Error("must not assume"); } },
    mfaSerial: "123456",
    getMfaCode: async () => "654321",
  }), /MFA device ARN/);
  assert.equal(callerChecks, 0);
});

test("inherited verifier identity authenticates the current session without MFA or AssumeRole", async () => {
  const calls = [];
  const runner = createAwsStsRunner({
    credentialSource: "inherited-ecs-exec-verifier-session",
    env: { AWS_ACCESS_KEY_ID: "inherited-access", AWS_SECRET_ACCESS_KEY: "inherited-secret", AWS_SESSION_TOKEN: "inherited-token", AWS_PROFILE: "must-not-leak" },
    run: (_file, args, options) => { calls.push({ args, env: options.env }); return JSON.stringify({ Arn: verifierArn }); },
  });
  const result = await establishInheritedVerifierIdentity({ adapter: runner });
  assert.equal(result.valid, true);
  assert.equal(result.callerArn, verifierArn);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].args[1], "get-caller-identity");
  assert.equal(calls[0].env.AWS_PROFILE, undefined);
  assert.equal(result.session.callerArn, verifierArn);
});

test("inherited verifier identity rejects release-deployer and unrelated sessions", async () => {
  for (const callerArn of [
    "arn:aws:sts::368992683803:assumed-role/mscqr-production-release-deployer/run",
    "arn:aws:sts::368992683803:assumed-role/other-role/run",
  ]) {
    const runner = createAwsStsRunner({
      credentialSource: "inherited-ecs-exec-verifier-session",
      env: { AWS_ACCESS_KEY_ID: "access", AWS_SECRET_ACCESS_KEY: "secret", AWS_SESSION_TOKEN: "token" },
      run: () => JSON.stringify({ Arn: callerArn }),
    });
    await assert.rejects(() => establishInheritedVerifierIdentity({ adapter: runner }), /reviewed assumed role/);
  }
});

test("verifier-only composition constructs no release-owned adapter or command runner", async () => {
  const calls = [];
  const session = Object.freeze({ callerArn: verifierArn, run: () => { throw new Error("AWS command must not run during composition"); }, spawn: () => { throw new Error("ECS Exec must not run during composition"); } });
  const adapters = createProductionVerifierOnlyAdapters({
    config: { sourceSha: "a".repeat(40), rotationId: "rotation-20260829015311-765c8a16", rotationCoordinator: "coordinator.mjs", rotationConfigFile: "/private/tmp/config.json", rotationStateFile: "/private/tmp/state.json", rotationFixtureFile: "/private/tmp/fixture.json", overlapRuntimeProofFile: "/private/tmp/proof.json" },
    sourceSha: "a".repeat(40), rotationId: "rotation-20260829015311-765c8a16", runtimeConfigSha256: "b".repeat(64),
    createCommandRunner: (options) => { calls.push(options); return () => ""; },
    createStsRunner: () => ({ getCallerIdentity: async () => verifierArn, getVerifierSession: () => session }),
  });
  assert.deepEqual(Object.keys(adapters).sort(), ["ecsExec", "identities", "postDeploy", "rotationPrepare"]);
  const identity = await adapters.identities.establish();
  assert.equal(identity.verifier.callerArn, verifierArn);
  assert.deepEqual(calls, [{ credentialSource: "inherited-ecs-exec-verifier-session" }]);
});
