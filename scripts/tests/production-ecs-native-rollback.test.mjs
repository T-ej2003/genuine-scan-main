import assert from "node:assert/strict";
import test from "node:test";
import { NORMAL_DEPLOYMENT_ALARMS, NORMAL_DEPLOYMENT_ROLLBACK, assertNormalDeploymentAlarms, assertNormalDeploymentNativeRollback } from "../aws/production-ecs-native-rollback.mjs";

const response = () => ({ failures: [], services: Object.entries(NORMAL_DEPLOYMENT_ROLLBACK).map(([serviceName, alarmNames]) => ({
  serviceName,
  loadBalancers: [{ targetGroupArn: serviceName.includes("backend")
    ? "arn:aws:elasticloadbalancing:eu-west-2:368992683803:targetgroup/mscqr-backend-tg-euw2-v2/f6673ff776f6e2ec"
    : "arn:aws:elasticloadbalancing:eu-west-2:368992683803:targetgroup/mscqr-frontend-ecs-tg-euw2/ddafd2fc00ed732e" }],
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
      (value) => { value.loadBalancers[0].targetGroupArn = value.loadBalancers[0].targetGroupArn.replace(/[^/]+$/, "other"); },
    ]) {
      const changed = response();
      mutation(changed.services.find((service) => service.serviceName === serviceName));
      assert.throws(() => assertNormalDeploymentNativeRollback(changed));
    }
  }
});

test("backend and frontend accept expanded ECS circuit-breaker readback without weakening rollback", () => {
  for (const serviceName of Object.keys(NORMAL_DEPLOYMENT_ROLLBACK)) {
    for (const circuitBreaker of [
      { enable: true, rollback: true },
      { enable: true, rollback: true, resetOnHealthyTask: true, thresholdConfiguration: { type: "BOUNDED_PERCENT", value: 50 } },
      { enable: true, rollback: true, resetOnUnhealthyTask: true, thresholdConfiguration: { type: "BOUNDED_PERCENT", value: 50 } },
      { enable: true, rollback: true, futureAwsField: "value" },
    ]) {
      const changed = response();
      changed.services.find((service) => service.serviceName === serviceName).deploymentConfiguration.deploymentCircuitBreaker = circuitBreaker;
      assert.doesNotThrow(() => assertNormalDeploymentNativeRollback(changed));
    }
  }
});

test("native rollback rejects malformed or weakened circuit-breaker readback", () => {
  for (const circuitBreaker of [
    { enable: false, rollback: true }, { enable: true, rollback: false },
    { rollback: true }, { enable: true }, {}, null, [], "invalid", 1,
  ]) {
    const changed = response();
    changed.services[0].deploymentConfiguration.deploymentCircuitBreaker = circuitBreaker;
    assert.throws(() => assertNormalDeploymentNativeRollback(changed));
  }
  const missing = response();
  delete missing.services[0].deploymentConfiguration.deploymentCircuitBreaker;
  assert.throws(() => assertNormalDeploymentNativeRollback(missing));
});

test("native rollback contract rejects missing, duplicate, and unrelated services", () => {
  const missing = response(); missing.services.pop();
  assert.throws(() => assertNormalDeploymentNativeRollback(missing));
  const duplicate = response(); duplicate.services[1] = duplicate.services[0];
  assert.throws(() => assertNormalDeploymentNativeRollback(duplicate));
  const unrelated = response(); unrelated.services[0].serviceName = "other";
  assert.throws(() => assertNormalDeploymentNativeRollback(unrelated));
});

const alarms = () => ({ CompositeAlarms: [], MetricAlarms: NORMAL_DEPLOYMENT_ALARMS.map((value) => structuredClone(value)) });

test("four exact ALB target-failure alarms protect backend and frontend deployments", () => {
  assert.equal(NORMAL_DEPLOYMENT_ALARMS.length, 4);
  assert.doesNotThrow(() => assertNormalDeploymentAlarms(alarms()));
  for (const mutate of [
    (value) => value.MetricAlarms.pop(),
    (value) => value.MetricAlarms.push({ ...value.MetricAlarms[0], AlarmName: "unreviewed" }),
    (value) => { value.MetricAlarms[0].MetricName = "HTTPCode_ELB_5XX_Count"; },
    (value) => { value.MetricAlarms[0].Threshold = 5; },
    (value) => { value.MetricAlarms[0].Dimensions[1].Value = "targetgroup/other/123"; },
    (value) => { value.MetricAlarms[0].TreatMissingData = "breaching"; },
    (value) => { value.MetricAlarms[0].Unit = "Seconds"; },
    (value) => { value.MetricAlarms[0].AlarmActions = ["arn:aws:sns:eu-west-2:368992683803:other"]; },
    (value) => { value.CompositeAlarms = [{ AlarmName: "other" }]; },
  ]) {
    const changed = alarms(); mutate(changed);
    assert.throws(() => assertNormalDeploymentAlarms(changed));
  }
});
