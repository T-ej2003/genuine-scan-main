import assert from "node:assert/strict";
import test from "node:test";
import { componentBrokerArn } from "../aws/component-installation-identity-contract.mjs";
import { fixture } from "./helpers/component-bootstrap-fixture.mjs";

test("first bootstrap creates only fixed code, three versions and source-bound defaults", async () => {
  const f = fixture(); const result = await f.run();
  assert.deepEqual(f.writes, ["CreateFunction", "PutFunctionConcurrency", "PutRuntimeManagementConfig", "PublishVersion", "UpdateFunctionConfiguration", "PublishVersion", "UpdateFunctionConfiguration", "PublishVersion"]);
  assert.equal(result.functionArn, componentBrokerArn);
  assert.deepEqual(Object.keys(result.runtimeVersions), ["1", "2", "3"]);
  const before = f.writes.length;
  assert.deepEqual(await f.run(), result);
  assert.equal(f.writes.length, before, "Exact state must not be rewritten");
});
for (let boundary = 1; boundary <= 8; boundary++) {
  test(`ambiguous accepted bootstrap write ${boundary} reconciles without replay`, async () => {
    const f = fixture();
    f.after = (_operation, count) => { if (count === boundary) throw new Error("Lost response"); };
    await assert.rejects(f.run());
    assert.equal(f.writes.length, boundary);
    f.after = () => {};
    await f.run();
    assert.equal(f.writes.length, 8);
  });
  test(`authorization/source guard failure before bootstrap write ${boundary}`, async () => {
    const f = fixture(); let calls = 0;
    f.guard = () => { if (++calls === boundary + 1) throw new Error("Authorization expired or source moved"); };
    await assert.rejects(f.run());
    assert.equal(f.writes.length, boundary - 1);
  });
}
for (const qualifier of ["$LATEST", "1", "2", "3"]) {
  test(`broker bootstrap rejects resource policy on ${qualifier}`, async () => {
    const f = fixture(); await f.run(); f.policies.add(qualifier);
    const count = f.writes.length;
    await assert.rejects(f.run(), /resource policy/);
    assert.equal(f.writes.length, count);
  });
}
for (const field of ["Role", "CodeSha256", "Environment", "Layers", "KMSKeyArn", "VpcConfig", "Runtime", "Handler", "Architectures", "LoggingConfig", "Description"]) {
  test(`existing broker ${field} drift cannot be repaired by bootstrap`, async () => {
    const f = fixture(); await f.run(); f.versions.$LATEST[field] = "different";
    await assert.rejects(f.run());
    assert.equal(f.writes.length, 8);
  });
}
test("unknown version and package substitution reject before mutation", async () => {
  const f = fixture(); await f.run(); f.versions["4"] = { ...f.versions["3"], Version: "4" };
  await assert.rejects(f.run(), /Unexpected broker version/);
  assert.equal(f.writes.length, 8);
  const g = fixture(); g.packageEvidence.bytes = Buffer.from("replacement");
  await assert.rejects(g.run()); assert.equal(g.writes.length, 0);
});
test("different runtime and concurrency cannot cause partial repair writes", async () => {
  for (const change of [f => { f.runtime.UpdateRuntimeOn = "Manual"; }, f => { f.concurrency.ReservedConcurrentExecutions = 5; }]) {
    const f = fixture(); f.after = (_op, count) => { if (count === 1) throw new Error("crash"); };
    await assert.rejects(f.run()); change(f); f.after = () => {};
    await assert.rejects(f.run()); assert.equal(f.writes.length, 1);
  }
});
