import test from "node:test";
import assert from "node:assert/strict";
import { brokerConfiguration, assertBrokerConfiguration, assertBrokerEntryPoint, brokerPolicySuccessorEntryPoints, brokerRecoverySuccessorEntryPoints, redactBrokerDiagnostic } from "../aws/component-broker-configuration.mjs";
import { componentBrokerArn } from "../aws/component-installation-identity-contract.mjs";
import { installationIdentity } from "../aws/component-iam-installation-contract.mjs";

const expected = brokerConfiguration({ packageSha256: "a".repeat(64), manifestSha256: "b".repeat(64), entryPoint: "INSTALL" });
const runtime = { UpdateRuntimeOn: "FunctionUpdate", RuntimeVersionArn: null };
const controls = { concurrency: { ReservedConcurrentExecutions: 1 }, signing: { FunctionName: installationIdentity.functionName }, runtime };
const response = () => ({ Configuration: { ...structuredClone(expected), CodeSize: 1000, State: "Active", LastUpdateStatus: "Successful", RuntimeVersionConfig: { RuntimeVersionArn: `arn:aws:lambda:eu-west-2::runtime:${"c".repeat(64)}` } } });

test("exact qualified package and full configuration accepted", () => {
  assert.match(assertBrokerConfiguration(response(), expected, controls), /^[a-f0-9]{64}$/);
  assertBrokerConfiguration(response(), expected, { ...controls, runtime: { UpdateRuntimeOn: "FunctionUpdate" } });
  const missing = response(); delete missing.Configuration.RuntimeVersionConfig;
  assert.throws(() => assertBrokerConfiguration(missing, expected, controls));
});
for (const field of Object.keys(expected)) {
  test(`reject broker configuration drift: ${field}`, () => {
    const value = response(); value.Configuration[field] = "different";
    assert.throws(() => assertBrokerConfiguration(value, expected, controls));
  });
}
for (const field of ["ImageConfigResponse", "SigningJobArn", "SigningProfileVersionArn", "CapacityProviderConfig", "DurableConfig", "TenancyConfig", "MasterArn", "FutureExecutableSetting"]) {
  test(`unknown/unsupported executable configuration rejected: ${field}`, () => {
    const value = response(); value.Configuration[field] = {};
    assert.throws(() => assertBrokerConfiguration(value, expected, controls));
  });
}
test("defaults normalize narrowly without accepting injected settings", () => {
  const value = response();
  for (const field of ["Layers", "Environment", "KMSKeyArn", "DeadLetterConfig", "FileSystemConfigs", "VpcConfig"]) delete value.Configuration[field];
  assertBrokerConfiguration(value, expected, controls);
  value.Configuration.Environment = { Error: { Message: "Unreadable environment" } };
  assert.throws(() => assertBrokerConfiguration(value, expected, controls));
});
test("signing, runtime and concurrency are independently bound", () => {
  for (const changed of [
    { ...controls, concurrency: { ReservedConcurrentExecutions: 2 } },
    { ...controls, signing: { ...controls.signing, CodeSigningConfigArn: "unexpected" } },
    { ...controls, runtime: { ...runtime, UpdateRuntimeOn: "Auto" } },
    { ...controls, runtime: { ...runtime, RuntimeVersionArn: `arn:aws:lambda:eu-west-2::runtime:${"d".repeat(64)}` } },
  ]) assert.throws(() => assertBrokerConfiguration(response(), expected, changed));
});
test("production no-code-signing response omits FunctionName without weakening the authenticated function", () => {
  assertBrokerConfiguration(response(), expected, { ...controls, signing: { $metadata: { httpStatusCode: 200 } } });
  assertBrokerConfiguration(response(), expected, { ...controls, signing: { FunctionName: installationIdentity.functionName } });
  for (const signing of [null, [], { FunctionName: "other" }, { CodeSigningConfigArn: "arn:unexpected" }, { FutureSecurityState: true }]) {
    assert.throws(() => assertBrokerConfiguration(response(), expected, { ...controls, signing }));
  }
});
test("broker diagnostics drop package locations and presigned credential material recursively", () => {
  const url = "https://awslambda.example/code?X-Amz-Credential=credential&X-Amz-Signature=signature&X-Amz-Security-Token=token";
  const safe = redactBrokerDiagnostic({ Code: { RepositoryType: "S3", Location: url }, nested: { value: url }, SessionToken: "secret", Configuration: { FunctionName: installationIdentity.functionName } });
  assert.deepEqual(safe, { Code: { RepositoryType: "S3" }, nested: { value: "[REDACTED_PRESIGNED_URL]" }, Configuration: { FunctionName: installationIdentity.functionName } });
  assert.doesNotMatch(JSON.stringify(safe), /Location|X-Amz-Credential|X-Amz-Signature|X-Amz-Security-Token|secret/);
});
test("AWS-supplied version, not request operation, separates cleanup and install", () => {
  for (const [operation, version] of Object.entries({ INSTALL: "1", INSPECT: "1", CLOSE: "2", CLEANUP_CONTEXT: "2", AUTHORIZE: "3" })) {
    const context = { functionVersion: version, invokedFunctionArn: `${componentBrokerArn}:${version}` };
    assert.equal(assertBrokerEntryPoint(context, operation), version);
    for (const wrong of ["$LATEST", "reviewed", "99"]) assert.throws(() => assertBrokerEntryPoint({ functionVersion: wrong, invokedFunctionArn: `${componentBrokerArn}:${wrong}` }, operation));
    assert.throws(() => assertBrokerEntryPoint({ ...context, invokedFunctionArn: componentBrokerArn }, operation));
  }
  assert.throws(() => assertBrokerEntryPoint({ functionVersion: "2", invokedFunctionArn: `${componentBrokerArn}:2` }, "INSTALL"));
  assert.throws(() => assertBrokerEntryPoint({ functionVersion: "1", invokedFunctionArn: `${componentBrokerArn}:1` }, "AUTHORIZE"));
});

test("successor package routes install, cleanup and authorization only through immutable versions 7-9", () => {
  for (const [operation, version] of Object.entries({ TERRAFORM_CONTEXT: "7", PROVE_TERRAFORM_SESSION: "7", CLOSE: "8", CLEANUP_CONTEXT: "8", AUTHORIZE: "9" })) {
    const context = { functionVersion: version, invokedFunctionArn: `${componentBrokerArn}:${version}` };
    assert.equal(assertBrokerEntryPoint(context, operation, brokerPolicySuccessorEntryPoints), version);
    for (const predecessor of ["4", "5", "6"]) assert.throws(() => assertBrokerEntryPoint({ functionVersion: predecessor, invokedFunctionArn: `${componentBrokerArn}:${predecessor}` }, operation, brokerPolicySuccessorEntryPoints));
  }
});
test("recovery successor package routes Terraform only through immutable version 10", () => {
  assert.equal(assertBrokerEntryPoint({ functionVersion: "10", invokedFunctionArn: `${componentBrokerArn}:10` }, "TERRAFORM_CONTEXT", brokerRecoverySuccessorEntryPoints), "10");
  for (const version of ["7", "8", "9", "11", "12"]) assert.throws(() => assertBrokerEntryPoint({ functionVersion: version, invokedFunctionArn: `${componentBrokerArn}:${version}` }, "TERRAFORM_CONTEXT", brokerRecoverySuccessorEntryPoints));
});
