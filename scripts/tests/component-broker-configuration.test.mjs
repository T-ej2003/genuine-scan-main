import test from "node:test";
import assert from "node:assert/strict";
import { brokerConfiguration, assertBrokerConfiguration, assertBrokerEntryPoint } from "../aws/component-broker-configuration.mjs";
import { componentBrokerArn } from "../aws/component-installation-identity-contract.mjs";
import { installationIdentity } from "../aws/component-iam-installation-contract.mjs";

const expected = brokerConfiguration({ packageSha256: "a".repeat(64), manifestSha256: "b".repeat(64), entryPoint: "INSTALL" });
const runtime = { UpdateRuntimeOn: "FunctionUpdate", RuntimeVersionArn: `arn:aws:lambda:eu-west-2::runtime:${"c".repeat(64)}` };
const controls = { concurrency: { ReservedConcurrentExecutions: 1 }, signing: { FunctionName: installationIdentity.functionName }, runtime };
const response = () => ({ Configuration: { ...structuredClone(expected), CodeSize: 1000, State: "Active", LastUpdateStatus: "Successful", RuntimeVersionConfig: { RuntimeVersionArn: runtime.RuntimeVersionArn } } });

test("exact qualified package and full configuration accepted", () => {
  assert.match(assertBrokerConfiguration(response(), expected, controls), /^[a-f0-9]{64}$/);
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
