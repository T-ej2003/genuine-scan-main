import assert from "node:assert/strict";
import { installationIdentity, digest, canonical } from "./component-iam-installation-contract.mjs";
import { componentBrokerArn, componentRoleArn } from "./component-installation-identity-contract.mjs";

export const brokerEntryPoints = Object.freeze({ INSTALL: "1", CLEANUP: "2", AUTHORIZE: "3" });
// A broker change publishes another immutable three-entry set.  This is not
// configurable input: these are the only three source-owned entry layouts.
export const brokerChangeEntryPoints = Object.freeze({ INSTALL: "4", CLEANUP: "5", AUTHORIZE: "6" });
export const brokerPolicySuccessorEntryPoints = Object.freeze({ INSTALL: "7", CLEANUP: "8", AUTHORIZE: "9" });
function assertEntryPoints(value) {
  assert(value === brokerEntryPoints || value === brokerChangeEntryPoints || value === brokerPolicySuccessorEntryPoints, "Unreviewed broker entry-point set");
  return value;
}

// Routing is not authority: the invoked broker still authenticates the full
// journal lineage before a semantic operation. Callers try the predecessor
// first and may reach the successor only after AWS denies that exact version.
export function brokerEntryPointCandidates(entryPoint) {
  assert(["INSTALL", "CLEANUP", "AUTHORIZE"].includes(entryPoint), "Unsupported broker entry point");
  return [...new Set([brokerEntryPoints[entryPoint], brokerChangeEntryPoints[entryPoint], brokerPolicySuccessorEntryPoints[entryPoint]])];
}
export function brokerConfiguration({ packageSha256, manifestSha256, entryPoint, entryPoints = brokerEntryPoints }) {
  assert.match(packageSha256 || "", /^[a-f0-9]{64}$/);
  assert.match(manifestSha256 || "", /^[a-f0-9]{64}$/);
  assertEntryPoints(entryPoints); assert(Object.hasOwn(entryPoints, entryPoint));
  const version = entryPoints[entryPoint];
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
  assert(signing && typeof signing === "object" && !Array.isArray(signing), "Malformed signing configuration");
  for (const key of Object.keys(signing)) assert(["$metadata", "FunctionName", "CodeSigningConfigArn"].includes(key), `Unknown signing field: ${key}`);
  if (signing.FunctionName !== undefined) assert.equal(signing.FunctionName, installationIdentity.functionName);
  assert.equal(signing.CodeSigningConfigArn, undefined, "Unreviewed signing configuration");
  assert.equal(runtime?.UpdateRuntimeOn, "FunctionUpdate");
  // GetRuntimeManagementConfig returns null in FunctionUpdate mode. The
  // resolved runtime identity is supplied by GetFunction, not this control API.
  assert(runtime.RuntimeVersionArn == null, "Unexpected manual runtime binding");
  assert.match(config.RuntimeVersionConfig?.RuntimeVersionArn || "", /^arn:aws:lambda:eu-west-2::runtime:[a-f0-9]{64}$/);
  assert.deepEqual(Object.keys(config.RuntimeVersionConfig), ["RuntimeVersionArn"]);
  return digest(expected);
}

// AWS GetFunction includes a short-lived presigned package URL. Diagnostics
// retain only non-secret structure and can never serialize that URL or signing
// query material.
export function redactBrokerDiagnostic(value) {
  if (Array.isArray(value)) return value.map(redactBrokerDiagnostic);
  if (!value || typeof value !== "object") {
    if (typeof value === "string" && (/https?:\/\/[^\s]*X-Amz-(?:Credential|Signature|Security-Token)/i.test(value) || /X-Amz-(?:Credential|Signature|Security-Token)=/i.test(value))) return "[REDACTED_PRESIGNED_URL]";
    return value;
  }
  return Object.fromEntries(Object.entries(value)
    .filter(([key]) => key !== "Location" && !/(?:SecretAccessKey|SessionToken|AccessKeyId|MfaCode)/i.test(key))
    .map(([key, item]) => [key, redactBrokerDiagnostic(item)]));
}

export function assertBrokerEntryPoint(context, operation, entryPoints = brokerEntryPoints) {
  assertEntryPoints(entryPoints);
  const entry = { INSTALL: "INSTALL", INSPECT: "INSTALL", PROVE_INSTALL_SESSION: "INSTALL", TERRAFORM_CONTEXT: "INSTALL", PROVE_TERRAFORM_SESSION: "INSTALL", CLOSE: "CLEANUP", CLEANUP_CONTEXT: "CLEANUP", PROVE_CLEANUP_SESSION: "CLEANUP", AUTHORIZE: "AUTHORIZE" }[operation];
  const version = entry && entryPoints[entry];
  assert(version, "Unsupported broker operation");
  assert.equal(context.functionVersion, version, "Operation not authorized on this immutable entry point");
  assert.equal(context.invokedFunctionArn, `${componentBrokerArn}:${version}`, "Unqualified/alias invocation forbidden");
  return version;
}
