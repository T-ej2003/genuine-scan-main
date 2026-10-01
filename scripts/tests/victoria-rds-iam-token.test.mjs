import assert from "node:assert/strict";
import test from "node:test";
import { signRdsIamToken } from "../../backend/scripts/victoria-rds-iam-token.mjs";

const input = {
  host: "mscqr-production.abcdefgh.eu-west-2.rds.amazonaws.com",
  username: "mscqr_prod_victoria_recovery",
  credentials: { accessKeyId: "ASIAFIXTURE", secretAccessKey: "fixture-secret", sessionToken: "fixture-session" },
  now: new Date("2026-10-01T12:00:00.000Z"),
};

test("RDS IAM token is deterministic and bound to the fixed database login and region", () => {
  const token = signRdsIamToken(input);
  assert.equal(token, signRdsIamToken(input));
  assert.match(token, /^mscqr-production\.abcdefgh\.eu-west-2\.rds\.amazonaws\.com:5432\//);
  assert.match(token, /DBUser=mscqr_prod_victoria_recovery/);
  assert.match(token, /X-Amz-Security-Token=fixture-session/);
  assert.match(token, /X-Amz-Signature=[a-f0-9]{64}$/);
  for (const invalid of [
    { ...input, host: "other.invalid" },
    { ...input, username: "postgres" },
    { ...input, region: "us-east-1" },
    { ...input, credentials: { accessKeyId: "a", secretAccessKey: "b" } },
  ]) assert.throws(() => signRdsIamToken(invalid));
});
