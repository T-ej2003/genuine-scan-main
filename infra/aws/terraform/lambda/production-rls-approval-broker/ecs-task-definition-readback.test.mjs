import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { assertEcsTaskDefinitionReadback, canonicalizeEcsTaskDefinition, normalizeEcsTaskDefinitionReadback } from "./ecs-task-definition-readback.mjs";

const fixture = JSON.parse(readFileSync(new URL("../../../../../scripts/tests/fixtures/mscqr-backend-47.task-definition.json", import.meta.url)));
const productionCapture = readFileSync(new URL("../../../../../documents/ops/evidence/aws-elasticache-rightsize-inventory-20260603T184059Z/07-ecs-services-and-taskdefs.txt", import.meta.url), "utf8");
const base = () => ({ family: "reviewed", containerDefinitions: [{ name: "reviewed", image: "example@sha256:abc", logConfiguration: { logDriver: "awslogs", options: { "awslogs-group": "/ecs/reviewed" } } }] });
const equivalent = (expected, readback) => canonicalizeEcsTaskDefinition(expected) === canonicalizeEcsTaskDefinition(readback);
const revision17EnvironmentNames = Object.freeze([
  "PUBLIC_APP_URL", "WEBAUTHN_ALLOWED_ORIGINS", "WEB_APP_BASE_URL", "SMTP_USER", "PRINT_AGENT_REQUIRE_MTLS", "WEBAUTHN_RP_ID",
  "SMTP_REQUIRE_TLS", "OBJECT_STORAGE_REGION", "SMTP_SECURE", "SUPERADMIN_ALERT_EMAILS", "WEBAUTHN_ORIGIN", "SMTP_PORT", "COOKIE_SECURE",
  "AUTH_MFA_CHALLENGE_TTL_MINUTES", "SUPER_ADMIN_EMAIL", "APP_URL", "MSCQR_FULL_RLS_SOURCE_CONTRACT_SHA256", "QR_TOKEN_EXP_DAYS",
  "CUSTOMER_WEBAUTHN_CHALLENGE_TTL_MINUTES", "SCAN_RATE_LIMIT_PER_MIN", "PORT", "AUTH_RISK_STEPUP_THRESHOLD", "PRINT_JOB_MAX_RUN_LABELS",
  "SMTP_FROM", "SMTP_HOST", "OBJECT_STORAGE_BUCKET", "PRINT_AGENT_REQUIRE_SIGNATURE", "AUTH_EMAIL_FROM", "SENTRY_ENVIRONMENT",
  "PRINT_AGENT_MTLS_TRUSTED_PROXY_IPS", "CORS_ORIGIN", "PUBLIC_SCAN_WEB_BASE_URL", "FRONTEND_URL", "PUBLIC_VERIFY_WEB_BASE_URL",
  "RUN_DB_MIGRATIONS_ON_START", "RUN_BACKGROUND_WORKERS", "MSCQR_FULL_RLS_MIGRATION_SET_DIGEST", "PRINT_AGENT_SESSION_MODE", "NODE_ENV",
  "OBJECT_STORAGE_FORCE_PATH_STYLE", "PUBLIC_ADMIN_WEB_BASE_URL", "WEBAUTHN_RP_NAME", "GIT_SHA", "RELEASE_GIT_SHA", "CLIENT_IP_TRUST_MODE",
  "CLIENT_IP_TRUSTED_ALB_CIDRS", "CLIENT_IP_TRUSTED_CLOUDFRONT_CIDRS",
]);
const revision17ReadbackOrder = Object.freeze([
  "PUBLIC_APP_URL", "WEBAUTHN_ALLOWED_ORIGINS", "WEB_APP_BASE_URL", "GIT_SHA", "SMTP_USER", "PRINT_AGENT_REQUIRE_MTLS", "WEBAUTHN_RP_ID",
  "SMTP_REQUIRE_TLS", "OBJECT_STORAGE_REGION", "SMTP_SECURE", "SUPERADMIN_ALERT_EMAILS", "WEBAUTHN_ORIGIN", "SMTP_PORT", "COOKIE_SECURE",
  "AUTH_MFA_CHALLENGE_TTL_MINUTES", "RELEASE_GIT_SHA", "SUPER_ADMIN_EMAIL", "CLIENT_IP_TRUSTED_ALB_CIDRS", "APP_URL", "CLIENT_IP_TRUST_MODE",
  "MSCQR_FULL_RLS_SOURCE_CONTRACT_SHA256", "QR_TOKEN_EXP_DAYS", "CUSTOMER_WEBAUTHN_CHALLENGE_TTL_MINUTES", "CLIENT_IP_TRUSTED_CLOUDFRONT_CIDRS",
  "SCAN_RATE_LIMIT_PER_MIN", "PORT", "AUTH_RISK_STEPUP_THRESHOLD", "PRINT_JOB_MAX_RUN_LABELS", "SMTP_FROM", "SMTP_HOST", "OBJECT_STORAGE_BUCKET",
  "PRINT_AGENT_REQUIRE_SIGNATURE", "AUTH_EMAIL_FROM", "SENTRY_ENVIRONMENT", "PRINT_AGENT_MTLS_TRUSTED_PROXY_IPS", "CORS_ORIGIN",
  "PUBLIC_SCAN_WEB_BASE_URL", "FRONTEND_URL", "PUBLIC_VERIFY_WEB_BASE_URL", "RUN_DB_MIGRATIONS_ON_START", "RUN_BACKGROUND_WORKERS",
  "MSCQR_FULL_RLS_MIGRATION_SET_DIGEST", "PRINT_AGENT_SESSION_MODE", "NODE_ENV", "OBJECT_STORAGE_FORCE_PATH_STYLE", "PUBLIC_ADMIN_WEB_BASE_URL",
  "WEBAUTHN_RP_NAME",
]);

const revision17Pair = () => {
  const values = new Map(revision17EnvironmentNames.map((name, index) => [name, `sanitized-${index}`]));
  const expected = base();
  expected.containerDefinitions[0].environment = revision17EnvironmentNames.map((name) => ({ name, value: values.get(name) }));
  const taskDefinitionArn = "arn:aws:ecs:eu-west-2:111122223333:task-definition/reviewed:17";
  const readback = { ...structuredClone(expected), taskDefinitionArn, revision: 17, status: "ACTIVE" };
  readback.containerDefinitions[0].environment = revision17ReadbackOrder.map((name) => ({ name, value: values.get(name) }));
  return { expected, readback, taskDefinitionArn };
};

test("canonical ECS readback normalizes only the proven AWS default materializations", () => {
  const defaults = [
    ["task enableFaultInjection false", (definition) => { definition.enableFaultInjection = false; }],
    ["container cpu zero", (definition) => { definition.containerDefinitions[0].cpu = 0; }],
    ["empty environment", (definition) => { definition.containerDefinitions[0].environment = []; }],
    ["empty environmentFiles", (definition) => { definition.containerDefinitions[0].environmentFiles = []; }],
    ["empty mountPoints", (definition) => { definition.containerDefinitions[0].mountPoints = []; }],
    ["empty portMappings", (definition) => { definition.containerDefinitions[0].portMappings = []; }],
    ["empty systemControls", (definition) => { definition.containerDefinitions[0].systemControls = []; }],
    ["empty ulimits", (definition) => { definition.containerDefinitions[0].ulimits = []; }],
    ["empty volumesFrom", (definition) => { definition.containerDefinitions[0].volumesFrom = []; }],
    ["empty log secretOptions", (definition) => { definition.containerDefinitions[0].logConfiguration.secretOptions = []; }],
    ["empty placementConstraints", (definition) => { definition.placementConstraints = []; }],
    ["empty volumes", (definition) => { definition.volumes = []; }],
  ];
  for (const [label, materialize] of defaults) {
    const expected = base();
    const readback = base();
    materialize(readback);
    assert.equal(equivalent(expected, readback), true, label);
  }
});

test("fault-injection normalization is symmetric for false and preserves true", () => {
  const omitted = base();
  const falseValue = base(); falseValue.enableFaultInjection = false;
  const trueValue = base(); trueValue.enableFaultInjection = true;
  assert.equal(equivalent(omitted, falseValue), true);
  assert.equal(equivalent(falseValue, omitted), true);
  assert.equal(equivalent(falseValue, falseValue), true);
  assert.equal(equivalent(omitted, trueValue), false);
  assert.equal(equivalent(falseValue, trueValue), false);
  assert.equal(equivalent(trueValue, falseValue), false);
  assert.equal(equivalent(trueValue, omitted), false);
});

test("canonical ECS readback accepts only the empty awslogs secretOptions default", () => {
  const omitted = base();
  const empty = base();
  empty.containerDefinitions[0].logConfiguration.secretOptions = [];
  assert.equal(equivalent(omitted, empty), true);
  assert.equal(equivalent(empty, omitted), true);
  assert.equal(equivalent(omitted, omitted), true);
  assert.equal(equivalent(empty, empty), true);
});

test("exact readback accepts the revision-17 environment set in AWS readback order", () => {
  const { expected, readback, taskDefinitionArn } = revision17Pair();
  assert.notDeepEqual(expected.containerDefinitions[0].environment, readback.containerDefinitions[0].environment);
  assert.equal(assertEcsTaskDefinitionReadback({ definition: readback, taskDefinitionArn, expected }), true);

  for (const mutate of [
    (environment) => { environment[0].value += "-changed"; },
    (environment) => { environment.pop(); },
    (environment) => { environment.push({ name: "ADDITIONAL", value: "sanitized" }); },
  ]) {
    const changed = structuredClone(readback);
    mutate(changed.containerDefinitions[0].environment);
    assert.throws(() => assertEcsTaskDefinitionReadback({ definition: changed, taskDefinitionArn, expected }), /exact approved execution contract/);
  }
});

test("environment normalization rejects ambiguous or malformed entries", () => {
  const invalidEnvironments = [
    [{ name: "DUPLICATE", value: "first" }, { name: "DUPLICATE", value: "second" }],
    [{ name: "", value: "value" }],
    [{ name: 1, value: "value" }],
    [{ name: "NAME", value: 1 }],
    [null],
    [{ name: "NAME", value: "value", unexpected: true }],
    { name: "NAME", value: "value" },
  ];
  for (const environment of invalidEnvironments) {
    const definition = base();
    definition.containerDefinitions[0].environment = environment;
    assert.throws(() => normalizeEcsTaskDefinitionReadback(definition), /ECS container environment/);
  }
});

test("environment remains optional and only its entry ordering is normalized", () => {
  const omitted = base();
  const empty = base(); empty.containerDefinitions[0].environment = [];
  assert.equal(equivalent(omitted, empty), true);

  const expected = base();
  expected.containerDefinitions[0].secrets = [{ name: "FIRST", valueFrom: "first" }, { name: "SECOND", valueFrom: "second" }];
  expected.containerDefinitions[0].mountPoints = [{ sourceVolume: "first", containerPath: "/first" }, { sourceVolume: "second", containerPath: "/second" }];
  const reorderedSecrets = structuredClone(expected); reorderedSecrets.containerDefinitions[0].secrets.reverse();
  const reorderedMounts = structuredClone(expected); reorderedMounts.containerDefinitions[0].mountPoints.reverse();
  assert.equal(equivalent(expected, reorderedSecrets), false);
  assert.equal(equivalent(expected, reorderedMounts), false);
});

test("canonical ECS readback normalizes only an empty host volume configuration", () => {
  const omitted = { ...base(), volumes: [{ name: "tmp" }] };
  const empty = structuredClone(omitted); empty.volumes[0].host = {};
  assert.equal(equivalent(omitted, empty), true);
  assert.equal(equivalent(empty, omitted), true);

  for (const host of [{ sourcePath: "/tmp" }, null, [], "", { unexpected: "value" }]) {
    const changed = structuredClone(omitted); changed.volumes[0].host = host;
    assert.equal(equivalent(omitted, changed), false);
    assert.equal(equivalent(empty, changed), false);
  }
  for (const configuration of [
    { efsVolumeConfiguration: { fileSystemId: "fs-reviewed" } },
    { dockerVolumeConfiguration: { scope: "task" } },
    { fsxWindowsFileServerVolumeConfiguration: { fileSystemId: "fs-reviewed" } },
    { unknownVolumeConfiguration: {} },
  ]) {
    const changed = structuredClone(omitted); Object.assign(changed.volumes[0], configuration);
    assert.equal(equivalent(omitted, changed), false);
  }

  const multiple = { ...base(), volumes: [{ name: "first" }, { name: "second" }] };
  const materialized = structuredClone(multiple); materialized.volumes[0].host = {};
  assert.equal(equivalent(multiple, materialized), true);
  materialized.volumes.reverse();
  assert.equal(equivalent(multiple, materialized), false);
});

test("exact task-definition readback accepts empty host materialization and rejects material host drift", () => {
  const expected = { ...base(), volumes: [{ name: "tmp" }] };
  const taskDefinitionArn = "arn:aws:ecs:eu-west-2:111122223333:task-definition/reviewed:1";
  const readback = { ...structuredClone(expected), taskDefinitionArn, revision: 1, status: "ACTIVE" };
  readback.volumes[0].host = {};
  assert.equal(assertEcsTaskDefinitionReadback({ definition: readback, taskDefinitionArn, expected }), true);
  readback.volumes[0].host = { sourcePath: "/tmp" };
  assert.throws(() => assertEcsTaskDefinitionReadback({ definition: readback, taskDefinitionArn, expected }), /exact approved execution contract/);
});

test("independent production-shaped ECS evidence contains and normalizes AWS defaults", () => {
  const readback = fixture.taskDefinition;
  const reviewed = structuredClone(readback);
  delete reviewed.containerDefinitions[0].logConfiguration.secretOptions;
  delete reviewed.enableFaultInjection;
  assert.match(productionCapture, /"enableFaultInjection": false/);
  assert.equal(readback.containerDefinitions[0].logConfiguration.secretOptions.length, 0);
  assert.equal(readback.enableFaultInjection, false);
  assert.equal(equivalent(reviewed, readback), true);
});

test("canonical ECS readback preserves non-empty awslogs secretOptions", () => {
  const omitted = base();
  const expected = base();
  expected.containerDefinitions[0].logConfiguration.secretOptions = [{ name: "token", valueFrom: "arn:aws:secretsmanager:eu-west-2:111122223333:secret:reviewed" }];
  const differentValue = structuredClone(expected);
  differentValue.containerDefinitions[0].logConfiguration.secretOptions[0].valueFrom += "-changed";
  const differentName = structuredClone(expected);
  differentName.containerDefinitions[0].logConfiguration.secretOptions[0].name = "other";
  const additionalOption = structuredClone(expected);
  additionalOption.containerDefinitions[0].logConfiguration.secretOptions.push({ name: "second", valueFrom: "arn:aws:secretsmanager:eu-west-2:111122223333:secret:second" });
  const reversed = structuredClone(additionalOption);
  reversed.containerDefinitions[0].logConfiguration.secretOptions.reverse();
  assert.deepEqual(normalizeEcsTaskDefinitionReadback(expected).containerDefinitions[0].logConfiguration.secretOptions, expected.containerDefinitions[0].logConfiguration.secretOptions);
  assert.equal(equivalent(omitted, expected), false);
  assert.equal(equivalent(expected, omitted), false);
  assert.equal(equivalent(expected, differentValue), false);
  assert.equal(equivalent(expected, differentName), false);
  assert.equal(equivalent(expected, additionalOption), false);
  assert.equal(equivalent(additionalOption, reversed), false);
});

test("canonical ECS readback rejects every non-default executable drift", () => {
  const expected = {
    ...base(),
    networkMode: "awsvpc",
    taskRoleArn: "arn:aws:iam::111122223333:role/task",
    executionRoleArn: "arn:aws:iam::111122223333:role/execution",
    runtimePlatform: { operatingSystemFamily: "LINUX", cpuArchitecture: "X86_64" },
  };
  expected.containerDefinitions[0].command = ["node", "reviewed.mjs"];
  expected.containerDefinitions[0].environment = [{ name: "RELEASE_GIT_SHA", value: "reviewed" }];
  expected.containerDefinitions[0].secrets = [{ name: "DATABASE_URL", valueFrom: "arn:aws:secretsmanager:eu-west-2:111122223333:secret:reviewed" }];
  const changes = [
    ["fault injection true", (definition) => { definition.enableFaultInjection = true; }],
    ["non-empty secretOptions", (definition) => { definition.containerDefinitions[0].logConfiguration.secretOptions = [{ name: "token", valueFrom: "arn:aws:secretsmanager:eu-west-2:111122223333:secret:reviewed" }]; }],
    ["runtime platform", (definition) => { definition.runtimePlatform.cpuArchitecture = "ARM64"; }],
    ["task role", (definition) => { definition.taskRoleArn += "-changed"; }],
    ["execution role", (definition) => { definition.executionRoleArn += "-changed"; }],
    ["image", (definition) => { definition.containerDefinitions[0].image = "example@sha256:changed"; }],
    ["command", (definition) => { definition.containerDefinitions[0].command = ["node", "changed.mjs"]; }],
    ["environment", (definition) => { definition.containerDefinitions[0].environment[0].value = "changed"; }],
    ["secrets", (definition) => { definition.containerDefinitions[0].secrets[0].valueFrom += "-changed"; }],
    ["network mode", (definition) => { definition.networkMode = "bridge"; }],
  ];
  for (const [label, change] of changes) {
    const readback = structuredClone(expected);
    change(readback);
    assert.equal(equivalent(expected, readback), false, label);
  }
});
