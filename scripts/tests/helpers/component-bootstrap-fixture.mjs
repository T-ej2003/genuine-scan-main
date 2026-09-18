import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { bootstrapFixedBroker } from "../../aws/component-broker-bootstrap.mjs";
import { componentBrokerPackageManifest } from "../../aws/component-broker-package.mjs";
import { brokerConfiguration } from "../../aws/component-broker-configuration.mjs";
import { componentBrokerArn } from "../../aws/component-installation-identity-contract.mjs";
import { digest, installationIdentity } from "../../aws/component-iam-installation-contract.mjs";

export function fixture() {
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
  state.lambda = lambda;
  state.run = () => bootstrapFixedBroker(packageEvidence, { lambda, authorize: async () => state.guard(), sleep: async () => {} });
  state.packageEvidence = packageEvidence;
  return state;
}
