import assert from "node:assert/strict";
import fs from "node:fs";
import { pathToFileURL } from "node:url";

export const NORMAL_DEPLOYMENT_ROLLBACK = Object.freeze({
  "mscqr-backend-servi-euw2": Object.freeze([
    "mscqr-production-backend-target-5xx",
    "mscqr-production-backend-unhealthy-hosts",
  ]),
  "mscqr-frontend-servi-euw2": Object.freeze([
    "mscqr-production-frontend-target-5xx",
    "mscqr-production-frontend-unhealthy-hosts",
  ]),
});

export function assertNormalDeploymentNativeRollback(response) {
  assert.deepEqual(response?.failures, []);
  assert.equal(response?.services?.length, 2, "Production ECS services are missing.");
  const seen = new Set();
  for (const service of response.services) {
    const alarms = NORMAL_DEPLOYMENT_ROLLBACK[service?.serviceName];
    assert.ok(alarms && !seen.has(service.serviceName), "Unexpected or duplicate production ECS service.");
    seen.add(service.serviceName);
    assert.deepEqual(service.deploymentConfiguration?.deploymentCircuitBreaker, { enable: true, rollback: true }, `${service.serviceName} must enable ECS circuit-breaker rollback.`);
    assert.equal(service.deploymentConfiguration?.alarms?.enable, true, `${service.serviceName} must enable ECS deployment alarms.`);
    assert.equal(service.deploymentConfiguration?.alarms?.rollback, true, `${service.serviceName} alarms must roll back failed deployments.`);
    assert.deepEqual([...(service.deploymentConfiguration?.alarms?.alarmNames || [])].sort(), [...alarms].sort(), `${service.serviceName} deployment alarms do not match the reviewed contract.`);
  }
  assert.deepEqual([...seen].sort(), Object.keys(NORMAL_DEPLOYMENT_ROLLBACK).sort());
}

if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  const match = /^--services=(.+)$/.exec(process.argv[2] || "");
  assert.ok(match && process.argv.length === 3, "Usage: production-ecs-native-rollback.mjs --services=<describe-services.json>");
  assertNormalDeploymentNativeRollback(JSON.parse(fs.readFileSync(match[1], "utf8")));
}
