import assert from "node:assert/strict";
import test from "node:test";
import { generateKeyPairSync } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { verifyArtifactSigningDomain } from "../aws/production-artifact-signing-domain.mjs";
import { createProductionRuntimeInventoryAdapter, PRODUCTION_RUNTIME_INVENTORY_COMMAND } from "../aws/production-runtime-inventory-adapter.mjs";
import { createProductionCommandRunner, createProductionOverlapDeploymentAdapter } from "../aws/production-cutover-production-adapters.mjs";
import { loadApprovedArtifactSigningBindings } from "../aws/production-artifact-signing-secrets-adapter.mjs";
import { assertNoOnboardingEvidenceLeak } from "../security/production-strict-onboarding.mjs";
import { createProductionInteractiveEcsExecRunner } from "../aws/production-ecs-exec-command.mjs";
import { executeProductionRotationInventory, buildRotationInventorySql } from "../security/production-rotation-state-inventory.mjs";
import { createCookieAuthenticatedRequest, createStrictHttpOnboardingAdapter, parseSetCookieHeaders } from "../security/production-strict-onboarding-http.mjs";
import { PRODUCTION_ONBOARDING_PATHS } from "../security/production-onboarding-contract.mjs";

const digest = `sha256:${"b".repeat(64)}`;
const taskArn = "arn:aws:ecs:eu-west-2:368992683803:task/mscqr-prod-euw2-main/one";
const expected = { expectedClusterArn: "arn:aws:ecs:eu-west-2:368992683803:cluster/mscqr-prod-euw2-main", expectedTaskDefinitionArn: "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-production-rls-green-backend-candidate:1", expectedImageDigest: digest, serviceName: "mscqr-backend-servi-euw2", containerName: "backend" };

test("runtime inventory uses one exact tagged task and fixed aggregate command", async () => {
  let finalDescribe;
  let executed;
  const task = { taskArn, clusterArn: expected.expectedClusterArn, taskDefinitionArn: expected.expectedTaskDefinitionArn, lastStatus: "RUNNING", group: "service:mscqr-backend-servi-euw2", containers: [{ name: "backend", imageDigest: digest }], tags: [{ key: "MSCQRExecTarget", value: "production-backend" }], managedAgents: [{ name: "ExecuteCommandAgent", lastStatus: "RUNNING" }] };
  const adapter = createProductionRuntimeInventoryAdapter({ expected, ecs: {
    describeService: async () => ({ enableExecuteCommand: true }),
    listTasks: async () => ({ taskArns: [taskArn] }),
    describeTasks: async ({ taskArns }) => { finalDescribe = taskArns; return { tasks: [task] }; },
    executeCommand: async (value) => { executed = value; return JSON.stringify({ refreshSessions: { count: 0 }, adminSessions: { count: 0 }, customerSessions: { count: 0 }, customerVerificationState: { count: 0 }, activeInvites: { count: 0 }, resetTokens: { count: 0 }, emailVerification: { count: 0 }, qrArtifacts: { count: 0 }, printerTestQrArtifacts: { status: "NOT_APPLICABLE", reason: "fixture" }, artifactRecords: { count: 0 }, legacyComplianceArtifacts: { count: 0 }, legacyImmutableAuditArtifacts: { status: "NOT_APPLICABLE", reason: "fixture" }, oauthState: { status: "NOT_APPLICABLE", reason: "fixture" }, oauthExchange: { status: "NOT_APPLICABLE", reason: "fixture" }, printedQrCompatibility: { status: "NOT_APPLICABLE", reason: "fixture" } }); },
  } });
  const result = await adapter({ taskDefinitionArn: expected.expectedTaskDefinitionArn });
  const value = result.inventory;
  assert.equal(value.refreshSessions.count, 0);
  assert.equal(result.taskArn, taskArn);
  assert.deepEqual(finalDescribe, [taskArn]);
  assert.deepEqual(executed, { taskArn, container: "backend", command: PRODUCTION_RUNTIME_INVENTORY_COMMAND });
});

test("artifact signing rejects mismatched pair and never accepts sensitive evidence", async () => {
  const current = generateKeyPairSync("ed25519", { privateKeyEncoding: { format: "pem", type: "pkcs8" }, publicKeyEncoding: { format: "pem", type: "spki" } });
  const other = generateKeyPairSync("ed25519", { privateKeyEncoding: { format: "pem", type: "pkcs8" }, publicKeyEncoding: { format: "pem", type: "spki" } });
  const bindings = Object.fromEntries(["ARTIFACT_SIGN_PRIVATE_KEY_CURRENT", "ARTIFACT_SIGN_PUBLIC_KEY_CURRENT", "ARTIFACT_SIGN_ACTIVE_KEY_VERSION", "ARTIFACT_SIGN_PUBLIC_KEYS_JSON"].map((name) => [name, name]));
  const values = { ARTIFACT_SIGN_PRIVATE_KEY_CURRENT: current.privateKey, ARTIFACT_SIGN_PUBLIC_KEY_CURRENT: other.publicKey, ARTIFACT_SIGN_ACTIVE_KEY_VERSION: "v1", ARTIFACT_SIGN_PUBLIC_KEYS_JSON: JSON.stringify({ v1: current.publicKey }) };
  await assert.rejects(() => verifyArtifactSigningDomain({ bindings, readSecret: async (ref) => values[ref] }), /inconsistent|match/i);
  assert.throws(() => assertNoOnboardingEvidenceLeak({ token: "x" }), /sensitive/);
});

test("artifact secret bindings are loaded only from reviewed IAM configuration", () => {
  assert.throws(() => loadApprovedArtifactSigningBindings("/tmp/unreviewed-artifact-bindings.json"), /repository-reviewed IAM configuration/);
});

test("production AWS command runner executes service operations through aws", () => {
  const calls = [];
  const run = createProductionCommandRunner({ profile: "mscqr-test", region: "eu-west-2", exec: (file, args, options) => {
    calls.push({ file, args, options });
    return "{}";
  } });
  run(["secretsmanager", "get-secret-value", "--secret-id", "reviewed"]);
  run(["ecs", "describe-services", "--cluster", "cluster", "--region", "eu-west-2"]);
  run(["aws", "iam", "get-role", "--role-name", "role"]);
  run(["node", "fixture.mjs"]);
  assert.deepEqual(calls.map(({ file }) => file), ["aws", "aws", "aws", "node"]);
  assert.equal(calls[0].args.at(-1), "eu-west-2");
  assert.equal(calls[1].args.filter((arg) => arg === "--region").length, 1);
  assert.equal(calls[2].args[0], "iam");
  assert.equal(calls[0].options.env.AWS_PROFILE, "mscqr-test");
  assert.equal(calls[0].options.env.AWS_DEFAULT_REGION, "eu-west-2");
  assert.deepEqual(calls[0].options.stdio, ["ignore", "pipe", "pipe"]);
});

test("production inventory targets the stable backend, not the pending overlap revision", () => {
  const source = fs.readFileSync("scripts/aws/production-cutover-production-adapters.mjs", "utf8");
  assert.match(source, /expectedTaskDefinitionArn: config\.inventoryTaskDefinitionArn \|\| config\.expectedCurrentTaskDefinitionArn/);
});

test("interactive ECS Exec adapter uses the exact revalidated ARN and process runner", async () => {
  let invocation;
  const run = createProductionInteractiveEcsExecRunner({ spawn: (command, args) => {
    invocation = { command, args };
    return { status: 0, stdout: "MSCQR_FIXTURE_READY\r\n{" + "\"ok\":true}" };
  } });
  const transcript = await run({ cluster: "mscqr-prod-euw2-main", taskArn, container: "backend", command: "node /app/scripts/production-rotation-state-inventory.mjs" });
  assert.match(transcript, /\"ok\":true/);
  assert.equal(invocation.command, "python3");
  assert.equal(invocation.args[invocation.args.indexOf("--task") + 1], taskArn);
  assert.equal(invocation.args[invocation.args.indexOf("--command") + 1], "sh -c 'printf MSCQR_FIXTURE_READY; node /app/scripts/production-rotation-state-inventory.mjs'");
});

test("production overlap adapter invokes the governed deploy wrapper with exact mutation bindings", async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-overlap-adapter-test-"));
  const readinessFile = path.join(directory, "readiness.json");
  const taskDefinitionArn = "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-production-rls-green-backend-candidate:9";
  let invocation;
  try {
    const adapter = createProductionOverlapDeploymentAdapter({
      deployScript: path.join(directory, "deploy-ecs-service.sh"),
      readinessFile,
      sourceSha: "a".repeat(40),
      rotationId: "rotation-test-1",
      rotationStateSha256: "f".repeat(64),
      readinessSha256: "d".repeat(64),
      imageDigest: digest,
      expectedCurrentTaskDefinitionArn: "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-backend:47",
      runScript: (_script, _args, options) => {
        invocation = options;
        fs.writeFileSync(options.env.METADATA_FILE, JSON.stringify({ newTaskDefinitionArn: taskDefinitionArn }));
      },
    });
    const result = await adapter.run({ taskDefinitionArn, rotationStateSha256: "c".repeat(64) });
    assert.equal(result.updateServiceCount, 1);
    assert.equal(invocation.env.MSCQR_GOVERNED_ORCHESTRATOR, "1");
    assert.equal(invocation.env.PROPAGATE_TAGS, "TASK_DEFINITION");
    assert.equal(invocation.env.ENABLE_EXECUTE_COMMAND, "true");
    assert.equal(invocation.env.EXISTING_TASK_DEFINITION_ARN, taskDefinitionArn);
    assert.equal(invocation.env.OVERLAP_READINESS_EVIDENCE_SHA256, "d".repeat(64));
    assert.equal(invocation.env.ROTATION_STATE_SHA256, "c".repeat(64));
    assert.equal(result.rotationStateSha256, "c".repeat(64));
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("production inventory executes the corrected SQL through the psql boundary", () => {
  let invocation;
  const inventory = { refreshSessions: { count: 0 }, qrArtifacts: { count: 0 }, artifactRecords: { count: 0 } };
  const result = executeProductionRotationInventory({
    env: { DATABASE_URL: "postgresql://fixture.invalid/fixture", ROTATION_INVENTORY_APPROVED: "true", ROTATION_INVENTORY_RLS_ROLE: "mscqr_prod_rls" },
    spawn: (file, args, options) => {
      invocation = { file, args, options };
      assert.match(args[args.indexOf("--command") + 1], /max\(max_expiry\)/);
      assert.match(args[args.indexOf("--command") + 1], /max\(max_finished_at\)/);
      return { status: 0, stdout: `${JSON.stringify(inventory)}\n` };
    },
  });
  assert.deepEqual(result, inventory);
  assert.equal(invocation.file, "psql");
  assert.equal(invocation.options.env.PGAPPNAME, "mscqr-production-rotation-read-only-inventory");
  assert.match(buildRotationInventorySql("mscqr_prod_rls"), /SET TRANSACTION READ ONLY/);
});

test("cookie-authenticated onboarding retains all cookies and replays the CSRF token", async () => {
  const requests = [];
  const response = (status, payload, setCookie = []) => ({ status, ok: status >= 200 && status < 300, headers: { getSetCookie: () => setCookie }, json: async () => payload });
  const fetchImpl = async (url, options) => {
    requests.push({ url, options });
    if (url.endsWith("/login")) return response(200, { data: { auth: { sessionStage: "MFA_BOOTSTRAP" } } }, ["aq_access=access; Path=/", "aq_refresh=refresh; Path=/", "aq_db_session=session; Path=/", "aq_csrf=csrf; Path=/"]);
    if (url.endsWith("/mfa/challenge/begin")) return response(200, { data: { ticket: "ticket" } });
    if (url.endsWith("/mfa/challenge/complete")) return response(200, {});
    if (url.endsWith("/api/auth/refresh")) return options.headers["x-csrf-token"] === "csrf" && options.headers.Cookie.includes("aq_access=access") && options.headers.Cookie.includes("aq_refresh=refresh") && options.headers.Cookie.includes("aq_db_session=session") ? response(200, {}) : response(403, {});
    return response(200, {});
  };
  const client = createCookieAuthenticatedRequest({ baseUrl: "https://fixture.example", fetchImpl });
  assert.deepEqual(parseSetCookieHeaders(["aq_access=access; Path=/", "aq_refresh=refresh; Path=/"]), [{ name: "aq_access", value: "access", attributes: ["path=/"] }, { name: "aq_refresh", value: "refresh", attributes: ["path=/"] }]);
  await client.request("/login", { method: "POST", body: {} });
  await client.request("/mfa/challenge/begin", { method: "POST", body: {} });
  await client.request("/mfa/challenge/complete", { method: "POST", body: { ticket: "ticket", code: "123456" } });
  assert.equal((await client.request("/api/auth/refresh", { method: "POST", body: {} })).response.status, 200);
  client.cookieJar.delete("aq_csrf");
  assert.equal((await client.request("/api/auth/refresh", { method: "POST", body: {} })).response.status, 403);
  client.cookieJar.set("aq_csrf", "wrong");
  assert.equal((await client.request("/api/auth/refresh", { method: "POST", body: {} })).response.status, 403);
  assert.equal(requests[3].options.headers["x-csrf-token"], "csrf");
  assert.equal(requests[4].options.headers["x-csrf-token"], undefined);
  assert.equal(requests[5].options.headers["x-csrf-token"], "wrong");
});

test("strict onboarding adapter uses the cookie and CSRF boundary on its real probe graph", async () => {
  const requests = [];
  let mfaReads = 0;
  let currentMfaCode = "123456";
  const proof = { jwtCurrentRuntimeVerify: true, jwtPreviousRuntimeVerify: true, jwtInvalidRuntimeRejected: true, qrCurrentRuntimeVerify: true, qrPreviousRuntimeVerify: true, qrTamperMatchingKeyTest: true, qrUnknownKeyRejected: true, artifactCurrentRuntimeVerify: true, artifactHistoricalRuntimeVerify: true };
  const response = (status, payload, setCookie = []) => ({ status, ok: status >= 200 && status < 300, headers: { getSetCookie: () => setCookie }, json: async () => payload });
  const rotationFixtureFile = path.join(os.tmpdir(), `mscqr-onboarding-qr-fixture-${process.pid}.json`);
  fs.writeFileSync(rotationFixtureFile, JSON.stringify({ token: "synthetic-qr-fixture-token" }));
  let tenantLoginObserved = false;
  const fetchImpl = async (url, options) => {
    requests.push({ url, options });
    if (url.endsWith("/api/auth/login")) {
      const tenant = options.body?.includes("tenant@example.invalid");
      if (tenant) tenantLoginObserved = true;
      return response(200, { data: { auth: { sessionStage: "MFA_BOOTSTRAP" }, user: tenant ? { role: "LICENSEE_ADMIN", licenseeId: "tenant-licensee" } : { role: "PLATFORM_SUPER_ADMIN", licenseeId: null } } }, ["aq_access=access; Path=/", "aq_refresh=refresh; Path=/", "aq_db_session=session; Path=/", "aq_csrf=csrf; Path=/"]);
    }
    if (url.endsWith("/api/auth/mfa/challenge/begin")) return response(200, { data: { ticket: "ticket" } });
    if (url.endsWith("/api/auth/mfa/challenge/complete")) return response(200, {});
    if (url.endsWith("/api/auth/refresh") && options.headers["x-csrf-token"] !== "csrf") return response(403, {});
    if (url.endsWith("/version")) return response(200, { releaseGitSha: "a".repeat(40) });
    if (url.endsWith("/api/health/ready")) return response(200, { status: "ready", dependencies: { database: { ready: true }, redis: { ready: true }, objectStorage: { ready: true } } });
    if (url.includes("/api/licensees/")) return tenantLoginObserved ? response(403, {}) : response(500, {});
    if (url.endsWith("/api/manufacturer/printer-agent/status")) return response(403, {});
    if (url.endsWith("/api/verify/ROTATION-SYNTHETIC")) return response(options.headers["x-mscqr-verification-token"] === "synthetic-qr-fixture-token" ? 200 : 400, {});
    return response(200, {});
  };
  const paths = PRODUCTION_ONBOARDING_PATHS;
  const run = createStrictHttpOnboardingAdapter({
    baseUrl: "https://fixture.example",
    paths,
    credentials: { email: "admin@example.invalid", password: "fixture-password", mfaCode: "000000" },
    getMfaCode: () => { mfaReads += 1; return currentMfaCode; },
    tenantCredentials: { email: "tenant@example.invalid", password: "tenant-fixture-password" },
    getTenantMfaCode: () => "654321",
    runtimeReadback: async () => ({ imageDigest: digest, serviceStable: true, taskDefinitionArn: expected.expectedTaskDefinitionArn, taskMarker: true }),
    ecsExecEvidence: async () => ({ valid: true, proof }),
    rotationStateReadback: async () => ({ rotationId: "rotation-test-1", phase: "overlap-deploy-required" }),
    rotationFixtureFile,
    fetchImpl,
  });
  assert.equal(mfaReads, 0);
  const evidence = await run({ sourceSha: "a".repeat(40), imageDigest: digest, taskDefinitionArn: expected.expectedTaskDefinitionArn, taskArn, rotationId: "rotation-test-1" });
  assert.equal(evidence.valid, true);
  assert.equal(mfaReads, 1);
  assert.ok(requests.findIndex(({ url }) => url.endsWith("/mfa/challenge/begin")) > requests.findIndex(({ url }) => url.endsWith("/login")));
  assert.ok(requests.findIndex(({ url }) => url.endsWith("/mfa/challenge/complete")) > requests.findIndex(({ url }) => url.endsWith("/mfa/challenge/begin")));
  const refresh = requests.find(({ url }) => url.endsWith("/api/auth/refresh"));
  assert.equal(refresh.options.headers["x-csrf-token"], "csrf");
  assert.match(refresh.options.headers.Cookie, /aq_access=access/);
  assert.match(refresh.options.headers.Cookie, /aq_refresh=refresh/);
  assert.match(refresh.options.headers.Cookie, /aq_db_session=session/);
  const qrRequests = requests.filter(({ url }) => url.endsWith("/api/verify/ROTATION-SYNTHETIC"));
  assert.equal(qrRequests.length, 2);
  assert.ok(qrRequests.every(({ url }) => !url.includes("synthetic-qr-fixture-token") && !url.includes("?t=")));
  assert.equal(qrRequests[0].options.headers["x-mscqr-verification-token"], "synthetic-qr-fixture-token");
  assert.notEqual(qrRequests[0].options.headers["x-mscqr-verification-token"], qrRequests[1].options.headers["x-mscqr-verification-token"]);
  assert.ok(requests.some(({ url, options }) => url.includes("/api/licensees/") && tenantLoginObserved && options.headers.Cookie.includes("aq_access=access")));

  currentMfaCode = undefined;
  const missing = createStrictHttpOnboardingAdapter({
    baseUrl: "https://fixture.example",
    paths,
    credentials: { email: "admin@example.invalid", password: "fixture-password" },
    getMfaCode: () => currentMfaCode,
    runtimeReadback: async () => ({ imageDigest: digest, serviceStable: true, taskDefinitionArn: expected.expectedTaskDefinitionArn, taskMarker: true }),
    ecsExecEvidence: async () => ({ valid: true, proof }),
    rotationStateReadback: async () => ({ rotationId: "rotation-test-1", phase: "overlap-deploy-required" }),
    rotationFixtureFile,
    fetchImpl,
  });
  await assert.rejects(() => missing({ sourceSha: "a".repeat(40), imageDigest: digest, taskDefinitionArn: expected.expectedTaskDefinitionArn, taskArn, rotationId: "rotation-test-1" }), /Mandatory onboarding check failed: superAdminLogin/);
  fs.rmSync(rotationFixtureFile, { force: true });
});
