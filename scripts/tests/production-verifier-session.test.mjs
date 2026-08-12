import assert from "node:assert/strict";
import test from "node:test";
import { createAwsStsRunner, VERIFIER_SESSION_MIN_REMAINING_MS } from "../aws/production-identity-adapters.mjs";
import { ECS_EXEC_OPERATOR_ROLE_ARN } from "../aws/production-ecs-exec-operator-contract.mjs";
import { establishEcsExecVerifierSession } from "../aws/establish-production-ecs-exec-verifier-session.mjs";

const bootstrapArn = "arn:aws:iam::368992683803:user/mscqr-production-bootstrap-operator";
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
  const first = await establishEcsExecVerifierSession({ adapter: runner, mfaSerial: "arn:aws:iam::368992683803:mfa/fixture", mfaCode: "123456" });
  const session = first.session;
  assert.equal(session.callerArn, verifierArn);
  delete process.env.MSCQR_VERIFIER_MFA_CODE;
  const second = await establishEcsExecVerifierSession({ adapter: runner, mfaSerial: "arn:aws:iam::368992683803:mfa/fixture", mfaCode: "654321" });
  assert.equal(second.session, session);
  assert.equal(calls.filter(({ args }) => args[1] === "assume-role").length, 1);
  assert.equal(calls.filter(({ args }) => args[1] === "get-caller-identity").length, 3);
  assert.equal(JSON.stringify({ first, second }).includes("sentinel-secret"), false);
});

test("expired verifier sessions fail closed without a second AssumeRole", async () => {
  const expiration = Date.now() + 10 * 60_000;
  let clock = Date.now();
  const { runner, calls } = fixtureRunner({ expiration: new Date(expiration).toISOString(), now: () => clock });
  await establishEcsExecVerifierSession({ adapter: runner, mfaSerial: "arn:aws:iam::368992683803:mfa/fixture", mfaCode: "123456" });
  clock = expiration - VERIFIER_SESSION_MIN_REMAINING_MS + 1;
  assert.throws(() => runner.getVerifierSession(), (error) => error.code === "VERIFIER_SESSION_EXPIRED" && error.freshMfaRequired === true);
  assert.equal(calls.filter(({ args }) => args[1] === "assume-role").length, 1);
  assert.throws(() => runner.runAsVerifier(["sts", "get-caller-identity"]), /fresh MFA is required/);
  await assert.rejects(() => establishEcsExecVerifierSession({ adapter: runner, mfaSerial: "arn:aws:iam::368992683803:mfa/fixture", mfaCode: "654321" }), /fresh MFA is required/);
  assert.equal(calls.filter(({ args }) => args[1] === "assume-role").length, 1);
});

test("verifier sessions reject role substitution", async () => {
  const { runner } = fixtureRunner();
  await assert.rejects(() => runner.assumeRole({ roleArn: "arn:aws:iam::368992683803:role/wrong", sessionName: "fixture", mfaSerial: "fixture", mfaCode: "123456" }), /reviewed ECS Exec verifier role/);
  assert.equal(ECS_EXEC_OPERATOR_ROLE_ARN, "arn:aws:iam::368992683803:role/mscqr-production-ecs-exec-verifier");
});
