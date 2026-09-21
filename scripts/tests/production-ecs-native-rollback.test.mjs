import assert from "node:assert/strict";
import test from "node:test";
import { NORMAL_DEPLOYMENT_ROLLBACK, assertNormalDeploymentNativeRollback } from "../aws/production-ecs-native-rollback.mjs";

const response = () => ({ failures: [], services: Object.entries(NORMAL_DEPLOYMENT_ROLLBACK).map(([serviceName, alarmNames]) => ({
  serviceName,
  deploymentConfiguration: {
    deploymentCircuitBreaker: { enable: true, rollback: true },
    alarms: { enable: true, rollback: true, alarmNames: [...alarmNames] },
  },
})) });

test("backend and frontend require exact ECS-native rollback alarms", () => {
  assert.doesNotThrow(() => assertNormalDeploymentNativeRollback(response()));
  for (const serviceName of Object.keys(NORMAL_DEPLOYMENT_ROLLBACK)) {
    for (const mutation of [
      (value) => { value.deploymentConfiguration.deploymentCircuitBreaker.enable = false; },
      (value) => { value.deploymentConfiguration.deploymentCircuitBreaker.rollback = false; },
      (value) => { value.deploymentConfiguration.alarms.enable = false; },
      (value) => { value.deploymentConfiguration.alarms.rollback = false; },
      (value) => { value.deploymentConfiguration.alarms.alarmNames.pop(); },
      (value) => { value.deploymentConfiguration.alarms.alarmNames.push("unreviewed-alarm"); },
    ]) {
      const changed = response();
      mutation(changed.services.find((service) => service.serviceName === serviceName));
      assert.throws(() => assertNormalDeploymentNativeRollback(changed));
    }
  }
});

test("native rollback contract rejects missing, duplicate, and unrelated services", () => {
  const missing = response(); missing.services.pop();
  assert.throws(() => assertNormalDeploymentNativeRollback(missing));
  const duplicate = response(); duplicate.services[1] = duplicate.services[0];
  assert.throws(() => assertNormalDeploymentNativeRollback(duplicate));
  const unrelated = response(); unrelated.services[0].serviceName = "other";
  assert.throws(() => assertNormalDeploymentNativeRollback(unrelated));
});
