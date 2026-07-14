import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";
import {
  RUNTIME_IDENTITY_FAILURE_CLASSIFICATIONS,
  compensateEcsCutoverFailure,
  parseRuntimeIdentityProof,
} from "../lib/staging-database-role-credentials-core.mjs";
import { runtimeIdentityParserFixtures } from "../fixtures/staging-ecs-runtime-identity-parser-fixtures.mjs";

for (const fixture of runtimeIdentityParserFixtures) {
  test(`runtime identity parser handles ${fixture.name}`, () => {
    if (fixture.expected === "ok") {
      assert.deepEqual(parseRuntimeIdentityProof(fixture.result), { databaseName: "mscqr_staging", databaseUser: "mscqr_staging_app" });
      return;
    }
    assert.throws(() => parseRuntimeIdentityProof(fixture.result), (error) => {
      const rawStreamsAreSuppressed = [fixture.result.stdout, fixture.result.stderr].filter(Boolean).every((stream) => !error.message.includes(stream));
      return error.code === fixture.expected && rawStreamsAreSuppressed;
    });
  });
}

test("runtime identity parser rejects duplicate delimited payloads as ambiguous", () => {
  const valid = runtimeIdentityParserFixtures.find(({ name }) => name === "crlf").result.stdout;
  assert.throws(() => parseRuntimeIdentityProof({ status: 0, stdout: valid, stderr: valid }), (error) => error.code === "delimiters_missing");
});

test("cutover delegates direct-script output parsing without logging raw streams", () => {
  const source = fs.readFileSync("scripts/aws/staging-database-role-credentials.mjs", "utf8");
  assert.match(source, /"--command", runtimeIdentityCommand\(\)/);
  assert.match(source, /parseRuntimeIdentityProof\(result/);
  assert.match(source, /compensateEcsCutoverFailure\(/);
  assert.doesNotMatch(source, /node\s+-e|SELECT current_database/);
  assert.doesNotMatch(source, /result\.stdout\.match|console\.(?:log|error)\(result\.(?:stdout|stderr)/);
});

for (const classification of RUNTIME_IDENTITY_FAILURE_CLASSIFICATIONS) {
  test(`runtime identity proof failure ${classification} restores the previous task definition`, async () => {
    const fixture = runtimeIdentityParserFixtures.find(({ expected }) => expected === classification);
    let proofError;
    try { parseRuntimeIdentityProof(fixture.result); }
    catch (error) { proofError = error; }
    assert.equal(proofError?.code, classification);
    let rollbackCalls = 0;
    const failure = await compensateEcsCutoverFailure({
      error: proofError,
      serviceUpdated: true,
      rollback: async () => { rollbackCalls += 1; },
    });
    assert.deepEqual(failure, { failureClassification: classification, rollbackResult: "restored" });
    assert.equal(rollbackCalls, 1);
  });
}

test("runtime identity proof reports operator recovery when automatic rollback fails", async () => {
  const failure = await compensateEcsCutoverFailure({
    error: Object.assign(new Error("sanitized"), { code: "invalid_json" }),
    serviceUpdated: true,
    rollback: async () => { throw new Error("suppressed rollback output"); },
  });
  assert.deepEqual(failure, { failureClassification: "invalid_json", rollbackResult: "operator_recovery_required" });
});
