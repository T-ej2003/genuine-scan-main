import test from "node:test";
import assert from "node:assert/strict";
import { createAppOnlyActivationAdapters, createAppOnlyEcsReaders, registerAppOnlyVerifier, executeAppOnlyVerifierTask, readAppOnlyVerifierResult } from "../aws/production-app-only-adapters.mjs";
import { APP_ONLY } from "../aws/production-app-only-contract.mjs";
import { APP_ONLY_VERIFIER, APP_ONLY_PROVISIONING, appOnlyVerifierNetwork } from "../aws/production-app-only-policy.mjs";
import { createAppOnlyRequirements } from "../aws/production-app-only-requirements.mjs";
import { buildAppOnlyVerifierDefinition } from "../aws/production-app-only-verifier-command.mjs";
import { canonicalSha256 } from "../aws/production-green-stage-b-contract.mjs";

const predecessorArn = `arn:aws:ecs:${APP_ONLY.region}:${APP_ONLY.account}:task-definition/${APP_ONLY.family}:14`;
const taskArn = `arn:aws:ecs:${APP_ONLY.region}:${APP_ONLY.account}:task/${APP_ONLY.cluster}/${"1".repeat(32)}`;
const verifierArn = `arn:aws:ecs:${APP_ONLY.region}:${APP_ONLY.account}:task-definition/${APP_ONLY_VERIFIER.family}:1`;
const token = "a".repeat(64);
const identity = { sourceSha: "a".repeat(40), candidateSourceSha: "b".repeat(40), account: APP_ONLY.account, region: APP_ONLY.region,
  clusterArn: APP_ONLY.clusterArn, serviceArn: APP_ONLY.serviceArn, predecessorTaskDefinition: predecessorArn,
  predecessorBackendDigest: `sha256:${"1".repeat(64)}`, candidateDigest: `sha256:${"2".repeat(64)}`,
  verifierImageDigest: `sha256:${"3".repeat(64)}`, databaseHostname: "reviewed.eu-west-2.rds.amazonaws.com" };
const requirements = createAppOnlyRequirements({ repositoryRoot: process.cwd(), ...identity, packageChecksums: { fixture: true },
  catalogue: { routines: [{ schema: "app_auth", name: "fixed", arguments: "" }], tables: [{ name: "Example" }],
    policies: [{ table: "Example", name: "isolation" }], schemas: [{ name: "app_auth" }], roles: [{ name: "mscqr_prod_rls_canary_read" }] } });
const verifier = { requirements, identity, repositoryRoot: process.cwd(),
  databaseSecretArn: `arn:aws:secretsmanager:${APP_ONLY.region}:${APP_ONLY.account}:secret:mscqr/production/rls-green/phase4/read-only-canary-database-url-ABC123` };
const built = buildAppOnlyVerifierDefinition(verifier);
const readback = { taskDefinition: { ...built.definition, taskDefinitionArn: verifierArn, revision: 1, status: "ACTIVE" } };
const request = () => ({ cluster: APP_ONLY.clusterArn, taskDefinition: verifierArn, launchType: "FARGATE", count: 1,
  enableExecuteCommand: false, clientToken: token, networkConfiguration: appOnlyVerifierNetwork() });
const authorization = { authenticate: async () => {}, writeEvidence: async () => {} };
test("activation rechecks candidate and predecessor ECR viability without tags or mutation", async () => {
  const preparation = { candidateDigest: identity.candidateDigest, predecessor: { backendDigest: identity.predecessorBackendDigest } };
  for (const missing of [undefined, identity.candidateDigest, identity.predecessorBackendDigest]) {
    const calls = [];
    const adapters = createAppOnlyActivationAdapters({ ...authorization, preparation, run: (args) => {
      calls.push(args); assert.deepEqual(args.slice(0, 4), ["ecr", "describe-images", "--repository-name", "mscqr-backend"]);
      const digest = args[args.indexOf("--image-ids") + 1].replace("imageDigest=", "");
      return { imageDetails: digest === missing ? [] : [{ imageDigest: digest }] };
    } });
    if (missing) await assert.rejects(adapters.authenticate(preparation));
    else { await adapters.authenticate(preparation); assert.equal(calls.length, 2); }
  }
});
test("separate provisioner registers only source-derived verifier and requires independent exact readback", async () => {
  const now = Date.now();
  const body = { schemaVersion: 1, kind: "APP_ONLY_VERIFIER_PREPARATION", eligible: false,
    sourceSha: identity.sourceSha, identity, databaseSecretArn: verifier.databaseSecretArn, generatedAt: new Date(now).toISOString(),
    evidence: { requirements: requirements.requirementsSha256 }, networkSha256: canonicalSha256(appOnlyVerifierNetwork()),
    definitionSha256: canonicalSha256(built.definition), verificationContractSha256: built.verificationContractSha256 };
  const preparation = { ...body, preparationSha256: canonicalSha256(body) };
  const calls = [], evidence = [];
  const run = (args) => {
    calls.push(args);
    if (args[1] === "get-caller-identity") return { Account: APP_ONLY.account, Arn: `arn:aws:sts::${APP_ONLY.account}:assumed-role/${APP_ONLY_PROVISIONING.roleName}/test` };
    if (args[1] === "register-task-definition") assert.deepEqual(JSON.parse(args[3]), built.definition);
    else assert.equal(args[1], "describe-task-definition");
    return readback;
  };
  const options = { ...authorization, run, preparation, verifier, now: () => now, writeEvidence: async (value) => evidence.push(value) };
  assert.equal((await registerAppOnlyVerifier(options)).taskDefinitionArn, verifierArn);
  assert.deepEqual(calls.map((c) => c[1]), ["get-caller-identity", "register-task-definition", "describe-task-definition"]);
  assert.deepEqual(evidence.map((e) => e.status), ["REGISTRATION_INTENT", "REGISTERED_READBACK_PENDING", "REGISTERED_VERIFIED"]);
  for (const attack of ["role", "readback", "ambiguous"]) {
    const events = []; let mutations = 0;
    await assert.rejects(registerAppOnlyVerifier({ ...options, writeEvidence: async (e) => events.push(e), run: (args) => {
      if (args[1] === "register-task-definition") { mutations++; if (attack === "ambiguous") throw new Error("Lost registration response"); }
      const result = structuredClone(run(args));
      if (args[1] === "get-caller-identity" && attack === "role") result.Arn = APP_ONLY.roleArn;
      if (args[1] === "describe-task-definition" && attack === "readback") result.taskDefinition.taskRoleArn = APP_ONLY.taskRoleArn;
      return result;
    } }));
    assert.equal(mutations, attack === "role" ? 0 : 1);
    if (attack !== "role") assert.equal(events.at(-1).status, attack === "readback" ? "REGISTRATION_READBACK_REQUIRED" : "REGISTRATION_OUTCOME_UNCERTAIN");
  }
});
test("verifier adapters run once with exact request then bound completion to exact task", async () => {
  const calls = [];
  const task = { taskArn, clusterArn: APP_ONLY.clusterArn, taskDefinitionArn: verifierArn, enableExecuteCommand: false,
    lastStatus: "STOPPED", stopCode: "EssentialContainerExited", containers: [{ exitCode: 0, name: "production-green-read-only-rls-canary", imageDigest: identity.verifierImageDigest }] };
  const run = (args) => { calls.push(args); return args[1] === "describe-task-definition" ? readback : { tasks: [task], failures: [] }; };
  const evidence = [];
  assert.equal((await executeAppOnlyVerifierTask({ ...authorization, writeEvidence: async (value) => evidence.push(value), run, verifier, taskDefinitionArn: verifierArn, clientToken: token, request: request() })).task.taskArn, taskArn);
  assert.deepEqual(evidence.map((e) => e.status), ["LAUNCH_INTENT", "LAUNCHED", "TASK_SUCCEEDED_EVIDENCE_PENDING"]);
  assert.equal(evidence[1].taskArn, taskArn);
  assert.deepEqual(calls.map((c) => c[1]), ["describe-task-definition", "run-task", "describe-tasks"]);
  assert.deepEqual(JSON.parse(calls[1][3]), request());
});
test("verifier override rejected before RunTask", async () => {
  let calls = 0;
  await assert.rejects(executeAppOnlyVerifierTask({ run: () => calls++, taskDefinitionArn: verifierArn, clientToken: token,
    request: { ...request(), overrides: { containerOverrides: [{ command: ["sh"] }] } } }));
  assert.equal(calls, 0);
});
test("verifier timeout is bounded and never retries RunTask", async () => {
  let launches = 0, descriptions = 0;
  const run = (args) => {
    if (args[1] === "describe-task-definition") return readback;
    if (args[1] === "run-task") launches++; else descriptions++;
    return { tasks: [{ taskArn, clusterArn: APP_ONLY.clusterArn, taskDefinitionArn: verifierArn, enableExecuteCommand: false, lastStatus: "RUNNING" }] };
  };
  await assert.rejects(executeAppOnlyVerifierTask({ ...authorization, run, verifier, taskDefinitionArn: verifierArn, clientToken: token, request: request(), now: () => 0, wait: async () => {} }), /timed out/);
  assert.equal(launches, 1); assert.equal(descriptions, 60);
});
test("verifier task-definition substitution is rejected before any launch", async () => {
  const bad = structuredClone(readback); bad.taskDefinition.containerDefinitions[0].command = ["sh"];
  const calls = [];
  await assert.rejects(executeAppOnlyVerifierTask({ ...authorization, run: (args) => { calls.push(args[1]); return bad; }, verifier,
    taskDefinitionArn: verifierArn, clientToken: token, request: request() }));
  assert.deepEqual(calls, ["describe-task-definition"]);
});
test("verifier durable intent survives ambiguous launch and failed approval prevents launch", async () => {
  const evidence = []; let launches = 0;
  const run = (args) => {
    if (args[1] === "describe-task-definition") return readback;
    assert.equal(args[1], "run-task"); launches++; throw new Error("Transport lost after AWS accepted launch");
  };
  const options = { ...authorization, run, verifier, taskDefinitionArn: verifierArn, clientToken: token, request: request(),
    writeEvidence: async (value) => evidence.push(value) };
  await assert.rejects(executeAppOnlyVerifierTask(options), /do not relaunch/);
  assert.equal(launches, 1);
  assert.deepEqual(evidence.map((e) => e.status), ["LAUNCH_INTENT", "LAUNCH_OUTCOME_UNCERTAIN"]);
  await assert.rejects(executeAppOnlyVerifierTask({ ...options, authenticate: async () => { throw new Error("Approval or CAS invalid"); } }));
  assert.equal(launches, 1);
  await assert.rejects(executeAppOnlyVerifierTask({ ...options, writeEvidence: async () => { throw new Error("Evidence unavailable"); } }));
  assert.equal(launches, 1);
});
test("verifier output comes from exact task stream and rejects duplicate/substituted results", async () => {
  const now = Date.now();
  const execution = { verificationContractSha256: built.verificationContractSha256, task: { taskArn, clusterArn: APP_ONLY.clusterArn,
    lastStatus: "STOPPED", stopCode: "EssentialContainerExited", enableExecuteCommand: false,
    containers: [{ name: "production-green-read-only-rls-canary", imageDigest: identity.verifierImageDigest, exitCode: 0 }] } };
  const body = { schemaVersion: 1, kind: "APP_ONLY_DATABASE_COMPATIBILITY", identity, generatedAt: new Date(now).toISOString(),
    requirementsSha256: requirements.requirementsSha256, verificationContractSha256: built.verificationContractSha256,
    domains: Object.fromEntries(["DATABASE_SCHEMA", "RLS_FUNCTIONS", "RLS_POLICIES", "RLS_GRANTS", "RLS_FORCE_STATUS", "GENERATED_RLS_CONTRACT"].map((key) => [key, "COMPATIBLE"])) };
  const event = { message: JSON.stringify({ ...body, evidenceSha256: canonicalSha256(body) }) };
  const run = (args) => {
    assert.equal(args[args.indexOf("--log-stream-name") + 1], `app-only/production-green-read-only-rls-canary/${"1".repeat(32)}`);
    return { events: [event] };
  };
  assert.equal((await readAppOnlyVerifierResult({ run, execution, verifier, now: () => now })).evidenceSha256, canonicalSha256(body));
  await assert.rejects(readAppOnlyVerifierResult({ run: () => ({ events: [event, event] }), execution, verifier, now: () => now }), /exactly one/);
  await assert.rejects(readAppOnlyVerifierResult({ run, execution, verifier: { ...verifier, identity: { ...identity, candidateDigest: `sha256:${"4".repeat(64)}` } }, now: () => now }));
  for (const mutate of [
    (task) => { task.stopCode = "TaskFailedToStart"; },
    (task) => { task.enableExecuteCommand = true; },
    (task) => { task.containers[0].exitCode = 1; },
  ]) {
    const changed = structuredClone(execution); mutate(changed.task);
    await assert.rejects(readAppOnlyVerifierResult({ run: () => { assert.fail("Invalid task must not consume logs"); }, execution: changed, verifier, now: () => now }));
  }
});
test("foreign definition read and arbitrary rollback request never reach AWS", () => {
  let calls = 0;
  const adapters = createAppOnlyActivationAdapters({ run: () => calls++, preparation: { predecessor: { taskDefinitionArn: predecessorArn } } });
  assert.throws(() => adapters.readDefinition("arn:aws:ecs:eu-west-2:368992683803:task-definition/other:1"));
  assert.throws(() => adapters.updateService({ cluster: APP_ONLY.clusterArn, service: APP_ONLY.serviceArn, taskDefinition: predecessorArn }));
  assert.equal(calls, 0);
});
test("HTTP adapters use fixed canonical origins, reject redirects and require bounded JSON", async () => {
  const calls = [];
  const adapters = createAppOnlyActivationAdapters({ preparation: {}, run: () => { throw Error("Unexpected AWS"); }, fetchImpl: async (url, options) => {
    calls.push(url); assert.equal(options.redirect, "error"); assert.ok(options.signal);
    return new Response(url.endsWith("/ready") ? JSON.stringify({ success: true }) : "ok", { status: 200 });
  } });
  const health = await adapters.readHealth();
  assert.deepEqual(calls, ["https://www.mscqr.com/api/health", "https://www.mscqr.com/api/health/ready", "https://www.mscqr.com/login"]);
  assert.equal(health.frontendStatus, 200);
  const tooLarge = createAppOnlyActivationAdapters({ preparation: {}, run: () => {}, fetchImpl: async (url) => new Response(url.endsWith("/ready") ? "x".repeat(262145) : "ok") });
  await assert.rejects(tooLarge.readHealth(), /Oversized/);
});
test("ECS reader rejects service substitution and AWS partial failures", () => {
  for (const response of [{ failures: [{ reason: "MISSING" }] }, { services: [{ serviceArn: "other", clusterArn: APP_ONLY.clusterArn }] }]) {
    assert.throws(() => createAppOnlyEcsReaders(() => response).readService());
  }
});
test("configuration-only service races invalidate the entire live snapshot", () => {
  let reads = 0;
  const service = { clusterArn: APP_ONLY.clusterArn, serviceArn: APP_ONLY.serviceArn, taskDefinition: predecessorArn,
    desiredCount: 2, deployments: [], networkConfiguration: appOnlyVerifierNetwork() };
  const run = (args) => {
    if (args[1] === "describe-services") {
      const copy = structuredClone(service);
      if (++reads === 2) copy.networkConfiguration.awsvpcConfiguration.securityGroups = ["sg-substituted"];
      return { services: [copy] };
    }
    if (args[1] === "describe-task-definition") return { taskDefinition: { taskDefinitionArn: predecessorArn } };
    if (args[1] === "list-tasks") return { taskArns: [] };
    throw new Error("Unexpected API");
  };
  assert.throws(() => createAppOnlyEcsReaders(run).readLive(), /configuration change/);
});
