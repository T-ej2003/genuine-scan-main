import assert from "node:assert/strict";
import fs from "node:fs";
import { pathToFileURL } from "node:url";

const loadBalancer = "app/mscqr-alb-euw2/cda0292be6e39608";
const dimensions = (targetGroup) => Object.freeze([
  Object.freeze({ Name: "LoadBalancer", Value: loadBalancer }),
  Object.freeze({ Name: "TargetGroup", Value: targetGroup }),
]);
const alarm = (AlarmName, MetricName, Statistic, TargetGroup) => Object.freeze({
  AlarmName,
  Namespace: "AWS/ApplicationELB",
  MetricName,
  Statistic,
  Period: 60,
  EvaluationPeriods: 2,
  DatapointsToAlarm: 2,
  Threshold: 0,
  ComparisonOperator: "GreaterThanThreshold",
  TreatMissingData: "notBreaching",
  Dimensions: dimensions(TargetGroup),
});

export const NORMAL_DEPLOYMENT_ALARMS = Object.freeze([
  alarm("mscqr-production-backend-target-5xx", "HTTPCode_Target_5XX_Count", "Sum", "targetgroup/mscqr-backend-tg-euw2-v2/f6673ff776f6e2ec"),
  alarm("mscqr-production-backend-unhealthy-hosts", "UnHealthyHostCount", "Maximum", "targetgroup/mscqr-backend-tg-euw2-v2/f6673ff776f6e2ec"),
  alarm("mscqr-production-frontend-target-5xx", "HTTPCode_Target_5XX_Count", "Sum", "targetgroup/mscqr-frontend-ecs-tg-euw2/ddafd2fc00ed732e"),
  alarm("mscqr-production-frontend-unhealthy-hosts", "UnHealthyHostCount", "Maximum", "targetgroup/mscqr-frontend-ecs-tg-euw2/ddafd2fc00ed732e"),
]);

export const NORMAL_DEPLOYMENT_ROLLBACK = Object.freeze({
  "mscqr-backend-servi-euw2": Object.freeze(NORMAL_DEPLOYMENT_ALARMS.slice(0, 2).map(({ AlarmName }) => AlarmName)),
  "mscqr-frontend-servi-euw2": Object.freeze(NORMAL_DEPLOYMENT_ALARMS.slice(2).map(({ AlarmName }) => AlarmName)),
});
const serviceTargetGroups = Object.freeze({
  "mscqr-backend-servi-euw2": "targetgroup/mscqr-backend-tg-euw2-v2/f6673ff776f6e2ec",
  "mscqr-frontend-servi-euw2": "targetgroup/mscqr-frontend-ecs-tg-euw2/ddafd2fc00ed732e",
});

export function assertNormalDeploymentNativeRollback(response) {
  assert.deepEqual(response?.failures, []);
  assert.equal(response?.services?.length, 2, "Production ECS services are missing.");
  const seen = new Set();
  for (const service of response.services) {
    const alarms = NORMAL_DEPLOYMENT_ROLLBACK[service?.serviceName];
    assert.ok(alarms && !seen.has(service.serviceName), "Unexpected or duplicate production ECS service.");
    seen.add(service.serviceName);
    const circuitBreaker = service.deploymentConfiguration?.deploymentCircuitBreaker;
    // AWS may add readback fields; the two required rollback properties remain authoritative.
    assert.ok(circuitBreaker !== null && typeof circuitBreaker === "object" && !Array.isArray(circuitBreaker) && Object.getPrototypeOf(circuitBreaker) === Object.prototype, `${service.serviceName} must have a valid ECS circuit-breaker configuration.`);
    assert.equal(circuitBreaker.enable, true, `${service.serviceName} must enable the ECS circuit breaker.`);
    assert.equal(circuitBreaker.rollback, true, `${service.serviceName} must enable ECS circuit-breaker rollback.`);
    assert.equal(service.deploymentConfiguration?.alarms?.enable, true, `${service.serviceName} must enable ECS deployment alarms.`);
    assert.equal(service.deploymentConfiguration?.alarms?.rollback, true, `${service.serviceName} alarms must roll back failed deployments.`);
    assert.deepEqual([...(service.deploymentConfiguration?.alarms?.alarmNames || [])].sort(), [...alarms].sort(), `${service.serviceName} deployment alarms do not match the reviewed contract.`);
    assert.deepEqual(service.loadBalancers?.map(({ targetGroupArn }) => String(targetGroupArn).split(":").at(-1)), [serviceTargetGroups[service.serviceName]], `${service.serviceName} target group does not match its deployment alarms.`);
  }
  assert.deepEqual([...seen].sort(), Object.keys(NORMAL_DEPLOYMENT_ROLLBACK).sort());
}

export function assertNormalDeploymentAlarms(response) {
  assert.deepEqual(response?.CompositeAlarms || [], [], "Composite deployment alarms are not reviewed.");
  assert.equal(response?.MetricAlarms?.length, NORMAL_DEPLOYMENT_ALARMS.length, "Production deployment alarms are missing or unexpected.");
  const actual = new Map(response.MetricAlarms.map((value) => [value.AlarmName, value]));
  assert.equal(actual.size, NORMAL_DEPLOYMENT_ALARMS.length, "Production deployment alarms are duplicated.");
  for (const expected of NORMAL_DEPLOYMENT_ALARMS) {
    const value = actual.get(expected.AlarmName);
    assert.ok(value, `Missing production deployment alarm: ${expected.AlarmName}`);
    for (const key of ["Namespace", "MetricName", "Statistic", "Period", "EvaluationPeriods", "DatapointsToAlarm", "Threshold", "ComparisonOperator", "TreatMissingData"])
      assert.deepEqual(value[key], expected[key], `${expected.AlarmName} ${key} does not match the reviewed contract.`);
    assert.deepEqual([...(value.Dimensions || [])].sort((a, b) => a.Name.localeCompare(b.Name)), [...expected.Dimensions].sort((a, b) => a.Name.localeCompare(b.Name)), `${expected.AlarmName} dimensions do not match the reviewed target.`);
    assert.deepEqual(value.AlarmActions || [], [], `${expected.AlarmName} must not invoke alarm actions.`);
    assert.deepEqual(value.OKActions || [], [], `${expected.AlarmName} must not invoke OK actions.`);
    assert.deepEqual(value.InsufficientDataActions || [], [], `${expected.AlarmName} must not invoke insufficient-data actions.`);
    assert.equal(value.Metrics, undefined, `${expected.AlarmName} must use the reviewed single metric.`);
    assert.equal(value.Unit, undefined, `${expected.AlarmName} must not set a metric unit.`);
  }
}

if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  const inputs = Object.fromEntries(process.argv.slice(2).map((value) => {
    const match = /^--(services|alarms)=(.+)$/.exec(value);
    assert.ok(match, "Usage: production-ecs-native-rollback.mjs --services=<describe-services.json> --alarms=<describe-alarms.json>");
    return [match[1], match[2]];
  }));
  assert.deepEqual(Object.keys(inputs).sort(), ["alarms", "services"]);
  assertNormalDeploymentNativeRollback(JSON.parse(fs.readFileSync(inputs.services, "utf8")));
  assertNormalDeploymentAlarms(JSON.parse(fs.readFileSync(inputs.alarms, "utf8")));
}
