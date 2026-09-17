import assert from "node:assert/strict";
import test from "node:test";
import { createHash } from "node:crypto";
import { bootstrapFixedBroker } from "../aws/component-broker-bootstrap.mjs";
import { componentBrokerPackageManifest } from "../aws/component-broker-package.mjs";
import { brokerConfiguration } from "../aws/component-broker-configuration.mjs";
import { componentBrokerArn } from "../aws/component-installation-identity-contract.mjs";
import { digest, installationIdentity } from "../aws/component-iam-installation-contract.mjs";

function fixture() {
  const manifest = componentBrokerPackageManifest("b".repeat(40));
  const bytes = Buffer.from("offline package transport fixture");
  const packageEvidence = { manifest, manifestSha256: digest(manifest), bytes, packageSha256: createHash("sha256").update(bytes).digest("hex") };
  const state = { versions: {}, concurrency: {}, runtime: { UpdateRuntimeOn: "Auto", RuntimeVersionArn: null }, writes: [], guard: () => {}, after: () => {}, revision: 0, policies: new Set() };
  const absent = () => { throw Object.assign(new Error("absent"), { name: "ResourceNotFoundException" }); };
  const expected = () => brokerConfiguration({ ...packageEvidence, entryPoint: "INSTALL" });
  const lambda = async (operation, input) => {
    assert.equal(input.FunctionName, installationIdentity.functionName);
    const version = input.Qualifier || "$LATEST";
    if (operation === "GetFunction") return state.versions[version] ? { Configuration: structuredClone(state.versions[version]) } : absent();
    if (operation === "GetPolicy") return state.policies.has(version) ? { Policy: "unexpected" } : absent();
    if (operation === "ListVersionsByFunction") return { Versions: Object.keys(state.versions).map(Version => ({ Version })) };
    if (operation === "GetFunctionConcurrency") return structuredClone(state.concurrency);
    if (operation === "GetFunctionCodeSigningConfig") return { FunctionName: installationIdentity.functionName, ...state.signing };
    if (operation === "GetRuntimeManagementConfig") return structuredClone(state.runtime);
    if (operation === "CreateFunction") {
      assert.equal(state.versions.$LATEST, undefined);
      assert.deepEqual(input.Code.ZipFile, bytes);
      assert.equal(input.Publish, false);
      const base = expected();
      for (const key of Object.keys(input).filter(key => !["Code", "Publish"].includes(key))) assert.deepEqual(input[key], base[key]);
      state.versions.$LATEST = { ...base, Version: "$LATEST", FunctionArn: componentBrokerArn, State: "Active", LastUpdateStatus: "Successful", CodeSize: bytes.length,
        RuntimeVersionConfig: { RuntimeVersionArn: `arn:aws:lambda:eu-west-2::runtime:${"c".repeat(64)}` }, RevisionId: String(++state.revision) };
    } else if (operation === "PutFunctionConcurrency") state.concurrency = { ReservedConcurrentExecutions: input.ReservedConcurrentExecutions };
    else if (operation === "PutRuntimeManagementConfig") state.runtime.UpdateRuntimeOn = input.UpdateRuntimeOn;
    else if (operation === "UpdateFunctionConfiguration") {
      assert.deepEqual(Object.keys(input).sort(), ["Description", "FunctionName", "RevisionId"]);
      assert.equal(input.RevisionId, state.versions.$LATEST.RevisionId);
      Object.assign(state.versions.$LATEST, { Description: input.Description, RevisionId: String(++state.revision) });
    } else if (operation === "PublishVersion") {
      assert.equal(input.RevisionId, state.versions.$LATEST.RevisionId);
      assert.equal(input.CodeSha256, state.versions.$LATEST.CodeSha256);
      const next = String(Object.keys(state.versions).length);
      assert(Number(next) <= 3);
      state.versions[next] = { ...structuredClone(state.versions.$LATEST), Version: next, FunctionArn: `${componentBrokerArn}:${next}` };
    } else assert.fail(`Unexpected AWS operation ${operation}`);
    state.writes.push(operation);
    state.after(operation, state.writes.length);
    return {};
  };
  state.run = () => bootstrapFixedBroker(packageEvidence, { lambda, authorize: async () => state.guard(), sleep: async () => {} });
  state.packageEvidence = packageEvidence;
  return state;
}

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
