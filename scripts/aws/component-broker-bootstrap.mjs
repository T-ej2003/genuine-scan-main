import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { setTimeout as delay } from "node:timers/promises";
import { brokerConfiguration, assertBrokerConfiguration, brokerEntryPoints } from "./component-broker-configuration.mjs";
import { componentBrokerArn } from "./component-installation-identity-contract.mjs";
import { componentBrokerPackageManifest } from "./component-broker-package.mjs";
import { digest, installationIdentity } from "./component-iam-installation-contract.mjs";

// Internal first-bootstrap transaction; no CLI accepts a package, role or
// configuration override. The bootstrap composition root supplies its clean
// source package and freshly authenticated authorization guard.
export async function bootstrapFixedBroker(packageEvidence, { lambda, authorize, sleep = delay }) {
  const { manifest, manifestSha256, packageSha256 } = packageEvidence;
  const bytes = Buffer.from(packageEvidence.bytes);
  assert.equal(createHash("sha256").update(bytes).digest("hex"), packageSha256);
  assert.equal(digest(manifest), manifestSha256);
  assert.equal(digest(componentBrokerPackageManifest(manifest.sourceSha)), manifestSha256);
  const name = installationIdentity.functionName;
  const input = { FunctionName: name };
  const expected = (entryPoint, latest = false) => {
    const config = brokerConfiguration({ packageSha256, manifestSha256, entryPoint });
    return latest ? { ...config, FunctionArn: componentBrokerArn, Version: "$LATEST" } : config;
  };
  const read = async (qualifier) => {
    try { return await lambda("GetFunction", { ...input, ...(qualifier ? { Qualifier: qualifier } : {}) }); }
    catch (error) { if (error.name === "ResourceNotFoundException") return null; throw error; }
  };
  const mutate = async (operation, fields) => {
    await authorize();
    assert.equal(digest(componentBrokerPackageManifest(manifest.sourceSha)), manifestSha256, "Bootstrap source changed");
    // No automatic mutation retries. A caller must reconcile live state after
    // any uncertain response; it must not replay this operation blindly.
    return lambda(operation, { ...input, ...fields });
  };
  const ready = async (qualifier) => {
    for (let attempt = 0; attempt < 12; attempt++) {
      const value = await read(qualifier);
      assert(value, "Broker disappeared during bootstrap");
      const { State, LastUpdateStatus } = value.Configuration;
      if (State === "Active" && LastUpdateStatus === "Successful") return value;
      assert(["Pending", "Active"].includes(State) && [undefined, "InProgress", "Successful"].includes(LastUpdateStatus), "Broker cannot converge");
      await sleep(1000);
    }
    throw new Error("Broker propagation did not converge; inspect before resuming");
  };
  const noResourcePolicies = async () => {
    for (const qualifier of [null, ...Object.values(brokerEntryPoints)]) {
      try { await lambda("GetPolicy", { ...input, ...(qualifier ? { Qualifier: qualifier } : {}) }); }
      catch (error) { if (error.name === "ResourceNotFoundException") continue; throw error; }
      throw new Error("Unexpected broker resource policy");
    }
  };
  const versions = async () => {
    const result = [];
    const seen = new Set();
    let marker;
    do {
      const page = await lambda("ListVersionsByFunction", { ...input, ...(marker ? { Marker: marker } : {}) });
      assert(Array.isArray(page.Versions));
      result.push(...page.Versions.map(value => value.Version));
      marker = page.NextMarker;
      if (marker) {
        assert(typeof marker === "string" && !seen.has(marker) && seen.size < 20, "Incomplete broker version inventory");
        seen.add(marker);
      }
    } while (marker);
    assert.equal(new Set(result).size, result.length);
    assert(result.includes("$LATEST"));
    assert(result.every(value => ["$LATEST", "1", "2", "3"].includes(value)), "Unexpected broker version");
    const numbers = result.filter(value => value !== "$LATEST").sort();
    assert.deepEqual(numbers, ["1", "2", "3"].slice(0, numbers.length), "Non-contiguous broker versions");
    return numbers;
  };
  const controls = async (qualifier) => ({
    concurrency: await lambda("GetFunctionConcurrency", input),
    signing: await lambda("GetFunctionCodeSigningConfig", input),
    runtime: await lambda("GetRuntimeManagementConfig", { ...input, ...(qualifier ? { Qualifier: qualifier } : {}) }),
  });
  await authorize();
  let latest = await read();
  if (!latest) {
    const config = expected("INSTALL", true);
    // Only API request fields; readback-only/default material is authenticated
    // separately. No caller can insert a layer, environment or alternate role.
    const fields = Object.fromEntries(["Role", "Runtime", "Handler", "Description", "Timeout", "MemorySize", "Architectures", "PackageType", "Layers", "Environment", "TracingConfig", "EphemeralStorage", "FileSystemConfigs", "LoggingConfig"].map(key => [key, config[key]]));
    await mutate("CreateFunction", { ...fields, Code: { ZipFile: bytes }, Publish: false });
    latest = await ready();
  }
  await noResourcePolicies();
  let published = await versions();
  let settings = await controls();
  // On a partial create only the known AWS defaults may be completed. Validate
  // every other field before the first configuration write.
  const entry = ["INSTALL", "CLEANUP", "AUTHORIZE"].find(value => latest.Configuration.Description === expected(value, true).Description);
  assert(entry, "Different broker description/source");
  assert(([['INSTALL'], ['INSTALL', 'CLEANUP'], ['CLEANUP', 'AUTHORIZE'], ['AUTHORIZE']][published.length]).includes(entry), "Different bootstrap publication phase");
  assert([undefined, 1].includes(settings.concurrency.ReservedConcurrentExecutions), "Different broker concurrency");
  assert(["Auto", "FunctionUpdate"].includes(settings.runtime.UpdateRuntimeOn) && settings.runtime.RuntimeVersionArn == null, "Different broker runtime management");
  if (published.length) {
    assert.equal(settings.concurrency.ReservedConcurrentExecutions, 1);
    assert.equal(settings.runtime.UpdateRuntimeOn, "FunctionUpdate");
  }
  const runtime = latest.Configuration.RuntimeVersionConfig?.RuntimeVersionArn;
  assertBrokerConfiguration(latest, expected(entry, true), { ...settings,
    concurrency: { ReservedConcurrentExecutions: 1 }, runtime: { UpdateRuntimeOn: "FunctionUpdate", RuntimeVersionArn: null } });
  assert(runtime, "Missing resolved runtime");
  if (settings.concurrency.ReservedConcurrentExecutions !== 1) {
    assert.equal(settings.concurrency.ReservedConcurrentExecutions, undefined, "Different broker concurrency");
    assert.equal(published.length, 0, "Published broker lacks reviewed concurrency");
    await mutate("PutFunctionConcurrency", { ReservedConcurrentExecutions: 1 });
  }
  if (settings.runtime.UpdateRuntimeOn !== "FunctionUpdate") {
    assert.equal(settings.runtime.UpdateRuntimeOn, "Auto");
    assert.equal(published.length, 0, "Published broker has different runtime policy");
    await mutate("PutRuntimeManagementConfig", { UpdateRuntimeOn: "FunctionUpdate" });
  }
  const runtimeVersions = {};
  for (const [entryPoint, version] of Object.entries(brokerEntryPoints)) {
    let fn = await read(version);
    if (!fn) {
      published = await versions();
      assert.equal(published.length, Number(version) - 1, "Broker publication moved");
      latest = await ready();
      settings = await controls();
      const previous = Number(version) === 1 ? "INSTALL" : Object.keys(brokerEntryPoints)[Number(version) - 2];
      const alreadyPrepared = latest.Configuration.Description === expected(entryPoint, true).Description;
      assertBrokerConfiguration(latest, expected(alreadyPrepared ? entryPoint : previous, true), settings);
      if (!alreadyPrepared) {
        assert(typeof latest.Configuration.RevisionId === "string" && latest.Configuration.RevisionId);
        await mutate("UpdateFunctionConfiguration", { Description: expected(entryPoint, true).Description, RevisionId: latest.Configuration.RevisionId });
        latest = await ready();
        assertBrokerConfiguration(latest, expected(entryPoint, true), await controls());
      }
      assert(typeof latest.Configuration.RevisionId === "string" && latest.Configuration.RevisionId);
      await mutate("PublishVersion", { Description: expected(entryPoint).Description, CodeSha256: expected(entryPoint).CodeSha256, RevisionId: latest.Configuration.RevisionId });
      fn = await ready(version);
    }
    assertBrokerConfiguration(fn, expected(entryPoint), await controls(version));
    runtimeVersions[version] = fn.Configuration.RuntimeVersionConfig.RuntimeVersionArn;
  }
  assert.deepEqual(await versions(), ["1", "2", "3"]);
  assertBrokerConfiguration(await ready(), expected("AUTHORIZE", true), await controls());
  await noResourcePolicies();
  await authorize();
  return { functionArn: componentBrokerArn, packageSha256, manifestSha256, runtimeVersions };
}
