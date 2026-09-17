import assert from "node:assert/strict";
import { installationIdentity, digest, canonical } from "./component-iam-installation-contract.mjs";
import { componentBrokerArn, componentRoleArn } from "./component-installation-identity-contract.mjs";

export const brokerEntryPoints = Object.freeze({ INSTALL: "1", CLEANUP: "2", AUTHORIZE: "3" });
export function brokerConfiguration({ packageSha256, manifestSha256, entryPoint }) {
  assert.match(packageSha256 || "", /^[a-f0-9]{64}$/);
  assert.match(manifestSha256 || "", /^[a-f0-9]{64}$/);
  assert(Object.hasOwn(brokerEntryPoints, entryPoint));
  const version = brokerEntryPoints[entryPoint];
  return {
    FunctionName: installationIdentity.functionName, FunctionArn: `${componentBrokerArn}:${version}`,
    Version: version, CodeSha256: Buffer.from(packageSha256, "hex").toString("base64"),
    Description: `Component installation ${entryPoint} ${manifestSha256}`,
    Role: componentRoleArn(installationIdentity.provisionerRole), Runtime: "nodejs22.x", Handler: "index.handler",
    Timeout: 60, MemorySize: 256, Architectures: ["x86_64"], PackageType: "Zip",
    Layers: [], Environment: { Variables: {} }, KMSKeyArn: "", TracingConfig: { Mode: "PassThrough" },
    VpcConfig: { SubnetIds: [], SecurityGroupIds: [], VpcId: "", Ipv6AllowedForDualStack: false },
    DeadLetterConfig: {}, EphemeralStorage: { Size: 512 }, FileSystemConfigs: [],
    SnapStart: { ApplyOn: "None", OptimizationStatus: "Off" },
    LoggingConfig: { LogFormat: "Text", LogGroup: `/aws/lambda/${installationIdentity.functionName}` },
  };
}

// Only documented empty/default forms are normalized. Unknown configuration
// fields stop execution so an API expansion cannot silently weaken the boundary.
export function assertBrokerConfiguration(response, expected, { concurrency, signing, runtime } = {}) {
  assert(response && expected);
  const config = structuredClone(response.Configuration);
  const operational = new Set(["CodeSize", "LastModified", "RevisionId", "State", "LastUpdateStatus", "RuntimeVersionConfig", "ConfigSha256"]);
  for (const key of Object.keys(config)) assert(Object.hasOwn(expected, key) || operational.has(key), `Unknown broker field: ${key}`);
  const empty = {
    Layers: [], Environment: { Variables: {} }, KMSKeyArn: "", DeadLetterConfig: {}, FileSystemConfigs: [],
    VpcConfig: { SubnetIds: [], SecurityGroupIds: [], VpcId: "", Ipv6AllowedForDualStack: false },
  };
  for (const [key, value] of Object.entries(empty)) {
    if (config[key] === undefined) config[key] = value;
  }
  for (const key of ["Environment", "VpcConfig"]) assert(config[key] && typeof config[key] === "object" && !Array.isArray(config[key]), `Malformed broker ${key}`);
  if (Object.keys(config.Environment).length === 0) config.Environment = { Variables: {} };
  if (Object.keys(config.VpcConfig).length === 0) config.VpcConfig = empty.VpcConfig;
  else if (config.VpcConfig.Ipv6AllowedForDualStack === undefined) config.VpcConfig.Ipv6AllowedForDualStack = false;
  // Never include unexpected environment/config values in exception diagnostics.
  for (const [key, value] of Object.entries(expected)) assert(canonical(config[key]) === canonical(value), `Unexpected broker ${key}`);
  assert.equal(config.State, "Active");
  assert.equal(config.LastUpdateStatus, "Successful");
  assert(Number.isSafeInteger(config.CodeSize) && config.CodeSize > 0);
  assert.equal(concurrency?.ReservedConcurrentExecutions, 1);
  assert.equal(signing?.FunctionName, installationIdentity.functionName);
  assert(!signing.CodeSigningConfigArn, "Unreviewed signing configuration");
  assert.equal(runtime?.UpdateRuntimeOn, "FunctionUpdate");
  // GetRuntimeManagementConfig returns null in FunctionUpdate mode. The
  // resolved runtime identity is supplied by GetFunction, not this control API.
  assert(runtime.RuntimeVersionArn == null, "Unexpected manual runtime binding");
  assert.match(config.RuntimeVersionConfig?.RuntimeVersionArn || "", /^arn:aws:lambda:eu-west-2::runtime:[a-f0-9]{64}$/);
  assert.deepEqual(Object.keys(config.RuntimeVersionConfig), ["RuntimeVersionArn"]);
  return digest(expected);
}

export function assertBrokerEntryPoint(context, operation) {
  const version = { INSTALL: "1", INSPECT: "1", PROVE_INSTALL_SESSION: "1", PROVE_TERRAFORM_SESSION: "1", CLOSE: "2", CLEANUP_CONTEXT: "2", PROVE_CLEANUP_SESSION: "2", AUTHORIZE: "3" }[operation];
  assert(version, "Unsupported broker operation");
  assert.equal(context.functionVersion, version, "Operation not authorized on this immutable entry point");
  assert.equal(context.invokedFunctionArn, `${componentBrokerArn}:${version}`, "Unqualified/alias invocation forbidden");
  return version;
}
