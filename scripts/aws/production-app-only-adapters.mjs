import assert from "node:assert/strict";
import { setTimeout as sleep } from "node:timers/promises";
import { APP_ONLY, captureAppOnlyPredecessor, assertAppOnlyCas, assertAppOnlyCandidate, appOnlyServiceConfigurationSha256 } from "./production-app-only-contract.mjs";
import { CANONICAL_PRODUCTION_ORIGIN, CANONICAL_PRODUCTION_READINESS_URL } from "./production-backend-readiness-contract.mjs";
import { APP_ONLY_VERIFIER, APP_ONLY_PROVISIONING, appOnlyVerifierNetwork, assertAppOnlyVerifierLaunch } from "./production-app-only-policy.mjs";
import { buildAppOnlyVerifierDefinition, assertRegisteredAppOnlyVerifier, authenticateAppOnlyVerifierResult } from "./production-app-only-verifier-command.mjs";
import { canonicalSha256 } from "./production-green-stage-b-contract.mjs";
import { assertRollbackImageAvailable } from "./production-normal-backend-activation.mjs";

const family = new RegExp(`^arn:aws:ecs:${APP_ONLY.region}:${APP_ONLY.account}:task-definition/${APP_ONLY.family}:[1-9][0-9]*$`);
const taskArn = new RegExp(`^arn:aws:ecs:${APP_ONLY.region}:${APP_ONLY.account}:task/${APP_ONLY.cluster}/[a-f0-9]{32}$`);
const parse = (value) => typeof value === "string" ? JSON.parse(value) : value;
const noFailures = (value) => { assert.equal((value.failures || []).length, 0, "ECS readback returned failures"); return value; };

// Internal fixed adapters, not a CLI. The protected workflow supplies the
// credential-scoped runner; no dispatch input supplies AWS argument arrays.
export function createAppOnlyEcsReaders(run) {
  const aws = (args) => parse(run([...args, "--output", "json", "--no-cli-pager"]));
  const readService = () => {
    const response = noFailures(aws(["ecs", "describe-services", "--cluster", APP_ONLY.clusterArn, "--services", APP_ONLY.serviceArn, "--include", "TAGS"]));
    assert.equal(response.services?.length, 1);
    const service = response.services[0];
    assert.equal(service.clusterArn, APP_ONLY.clusterArn); assert.equal(service.serviceArn, APP_ONLY.serviceArn);
    return service;
  };
  const readDefinition = (arn) => {
    assert.match(arn || "", family);
    const response = aws(["ecs", "describe-task-definition", "--task-definition", arn, "--include", "TAGS"]);
    assert.equal(response.taskDefinition?.taskDefinitionArn, arn);
    return { ...response.taskDefinition, tags: response.tags || [] };
  };
  const readLive = () => {
    const service = readService();
    const definition = readDefinition(service.taskDefinition);
    const response = aws(["ecs", "list-tasks", "--cluster", APP_ONLY.clusterArn, "--service-name", APP_ONLY.service, "--desired-status", "RUNNING"]);
    assert.ok(Array.isArray(response.taskArns) && response.taskArns.length <= 100 && !response.nextToken, "Unbounded task listing");
    for (const arn of response.taskArns) assert.match(arn, taskArn);
    const tasks = response.taskArns.length ? noFailures(aws(["ecs", "describe-tasks", "--cluster", APP_ONLY.clusterArn, "--tasks", ...response.taskArns])).tasks : [];
    assert.equal(tasks?.length, response.taskArns.length);
    assert.deepEqual([...tasks.map((task) => task.taskArn)].sort(), [...response.taskArns].sort());
    // Close the read window: deployment state changing during the observations
    // cannot be converted into an internally inconsistent preparation snapshot.
    const after = readService();
    assert.deepEqual(after.deployments, service.deployments, "Concurrent deployment during readback");
    assert.equal(after.taskDefinition, service.taskDefinition);
    assert.equal(after.desiredCount, service.desiredCount);
    assert.equal(appOnlyServiceConfigurationSha256(after), appOnlyServiceConfigurationSha256(service), "Concurrent service configuration change during readback");
    return { service, definition, tasks };
  };
  return { readService, readDefinition, readLive };
}

export function createAppOnlyActivationAdapters({ run, preparation, authenticate, writeEvidence, fetchImpl = fetch, wait = sleep, now = Date.now }) {
  const readers = createAppOnlyEcsReaders(run);
  let registeredArn;
  // Reuse the existing exact-digest validator; running predecessor tasks alone
  // do not prove that a rollback can still pull their image.
  const verifyImage = (digest) => assertRollbackImageAvailable((args) => {
    const value = run(args); return typeof value === "string" ? value : JSON.stringify(value);
  }, digest);
  return {
    ...readers, writeEvidence,
    authenticate: async (value) => {
      await authenticate(value);
      verifyImage(preparation.predecessor.backendDigest); verifyImage(preparation.candidateDigest);
    },
    register: (definition) => {
      // Re-derive the sole acceptable registration request from the authenticated
      // predecessor immediately before invoking the API.
      const live = readers.readLive();
      assertAppOnlyCas(preparation.predecessor, captureAppOnlyPredecessor(live));
      assertAppOnlyCandidate(live.definition, definition, preparation.candidateDigest);
      const response = parse(run(["ecs", "register-task-definition", "--cli-input-json", JSON.stringify(definition), "--output", "json", "--no-cli-pager"]));
      assert.match(response.taskDefinition?.taskDefinitionArn || "", family);
      registeredArn = response.taskDefinition.taskDefinitionArn;
      return response.taskDefinition;
    },
    updateService: (request) => {
      assert.equal(request.cluster, APP_ONLY.clusterArn); assert.equal(request.service, APP_ONLY.serviceArn);
      assert.deepEqual(Object.keys(request).sort(), ["cluster", "service", "taskDefinition"]);
      assert.ok(registeredArn && [registeredArn, preparation.predecessor.taskDefinitionArn].includes(request.taskDefinition), "Unowned activation or rollback target");
      verifyImage(request.taskDefinition === registeredArn ? preparation.candidateDigest : preparation.predecessor.backendDigest);
      return parse(run(["ecs", "update-service", "--cluster", APP_ONLY.clusterArn, "--service", APP_ONLY.serviceArn,
        "--task-definition", request.taskDefinition, "--output", "json", "--no-cli-pager"])).service;
    },
    waitStable: async (expectedArn) => {
      assert.ok([registeredArn, preparation.predecessor.taskDefinitionArn].includes(expectedArn));
      const deadline = now() + 10 * 60 * 1000;
      for (let attempt = 0; attempt < 60 && now() < deadline; attempt++) {
        const service = readers.readService();
        assert.equal(service.taskDefinition, expectedArn, "Competing deployment replaced ownership");
        const primary = service.deployments?.find((d) => d.status === "PRIMARY");
        assert.notEqual(primary?.rolloutState, "FAILED", "ECS rollout failed");
        if (service.deployments?.length === 1 && primary?.rolloutState === "COMPLETED"
          && service.desiredCount === 2 && service.runningCount === 2 && service.pendingCount === 0) return;
        await wait(10000);
      }
      throw new Error("ECS stability timeout");
    },
    readHealth: async () => {
      const get = async (url, json = false) => {
        const response = await fetchImpl(url, { redirect: "error", signal: AbortSignal.timeout(15000), cache: "no-store" });
        assert.equal(response.status, 200, "Public health endpoint failed");
        if (!json) { await response.body?.cancel(); return response.status; }
        let bytes = 0; const chunks = [];
        for await (const chunk of response.body) { bytes += chunk.length; assert.ok(bytes <= 262144, "Oversized health response"); chunks.push(chunk); }
        return { httpStatus: response.status, body: JSON.parse(Buffer.concat(chunks).toString("utf8")) };
      };
      await get(`${CANONICAL_PRODUCTION_ORIGIN}/api/health`);
      return { backend: await get(CANONICAL_PRODUCTION_READINESS_URL, true), frontendStatus: await get(`${CANONICAL_PRODUCTION_ORIGIN}/login`) };
    },
  };
}

// Only the separate provisioner registers verifier definitions. The launcher
// receives permission for the independently read-back revision, never a family
// supplied by dispatch. No automatic retry after ambiguous registration.
export async function registerAppOnlyVerifier({ run, preparation, verifier, authenticate, writeEvidence, now = Date.now }) {
  assert.equal(typeof authenticate, "function"); assert.equal(typeof writeEvidence, "function");
  const { preparationSha256, ...body } = preparation;
  assert.equal(preparationSha256, canonicalSha256(body));
  assert.equal(body.schemaVersion, 1); assert.equal(body.kind, "APP_ONLY_VERIFIER_PREPARATION"); assert.equal(body.eligible, false);
  assert.equal(body.sourceSha, verifier.identity.sourceSha);
  assert.deepEqual(body.identity, verifier.identity); assert.equal(body.databaseSecretArn, verifier.databaseSecretArn);
  assert.equal(body.evidence.requirements, verifier.requirements.requirementsSha256);
  assert.equal(body.networkSha256, canonicalSha256(appOnlyVerifierNetwork()));
  const expected = buildAppOnlyVerifierDefinition(verifier);
  assert.equal(body.definitionSha256, canonicalSha256(expected.definition));
  assert.equal(body.verificationContractSha256, expected.verificationContractSha256);
  const verify = async () => {
    const age = now() - Date.parse(body.generatedAt);
    assert.ok(Number.isFinite(age) && age >= 0 && age <= APP_ONLY.maxEvidenceAgeMs, "Stale verifier preparation");
    await authenticate(preparation);
  };
  await verify();
  const caller = parse(run(["sts", "get-caller-identity", "--output", "json", "--no-cli-pager"]));
  assert.equal(caller.Account, APP_ONLY.account);
  assert.match(caller.Arn || "", new RegExp(`^arn:aws:sts::${APP_ONLY.account}:assumed-role/${APP_ONLY_PROVISIONING.roleName}/[^/]+$`));
  const record = async (status, fields = {}) => writeEvidence({ schemaVersion: 1, kind: "APP_ONLY_VERIFIER_REGISTRATION",
    preparationSha256, sourceSha: body.sourceSha, status, ...fields });
  await verify(); await record("REGISTRATION_INTENT");
  let taskDefinitionArn;
  try {
    const response = parse(run(["ecs", "register-task-definition", "--cli-input-json", JSON.stringify(expected.definition), "--output", "json", "--no-cli-pager"]));
    taskDefinitionArn = response.taskDefinition?.taskDefinitionArn;
    assert.match(taskDefinitionArn || "", new RegExp(`^arn:aws:ecs:${APP_ONLY.region}:${APP_ONLY.account}:task-definition/${APP_ONLY_VERIFIER.family}:[1-9][0-9]*$`));
    await record("REGISTERED_READBACK_PENDING", { taskDefinitionArn });
    const readback = parse(run(["ecs", "describe-task-definition", "--task-definition", taskDefinitionArn, "--include", "TAGS", "--output", "json", "--no-cli-pager"]));
    assertRegisteredAppOnlyVerifier({ ...verifier, taskDefinitionArn, definition: { ...readback.taskDefinition, tags: readback.tags || [] } });
    await verify();
    const result = { taskDefinitionArn, preparationSha256, definitionSha256: body.definitionSha256,
      verificationContractSha256: expected.verificationContractSha256 };
    await record("REGISTERED_VERIFIED", result);
    return result;
  } catch (cause) {
    await record(taskDefinitionArn ? "REGISTRATION_READBACK_REQUIRED" : "REGISTRATION_OUTCOME_UNCERTAIN", { ...(taskDefinitionArn ? { taskDefinitionArn } : {}) });
    throw new Error("Verifier registration not authenticated; preserve evidence and do not retry automatically", { cause });
  }
}

export async function executeAppOnlyVerifierTask({ run, taskDefinitionArn, clientToken, request, verifier,
  authenticate, writeEvidence, wait = sleep, now = Date.now }) {
  assertAppOnlyVerifierLaunch(request, { taskDefinitionArn, clientToken });
  assert.equal(typeof authenticate, "function"); assert.equal(typeof writeEvidence, "function");
  await authenticate(); // Fixed producer: protected source, approval, evidence freshness and ECS CAS.
  const readback = parse(run(["ecs", "describe-task-definition", "--task-definition", taskDefinitionArn, "--include", "TAGS", "--output", "json", "--no-cli-pager"]));
  const { verificationContractSha256 } = assertRegisteredAppOnlyVerifier({ ...verifier,
    definition: { ...readback.taskDefinition, tags: readback.tags || [] }, taskDefinitionArn });
  await authenticate();
  let arn;
  const record = async (status) => writeEvidence({ schemaVersion: 1, kind: "APP_ONLY_VERIFIER_EXECUTION",
    status, taskDefinitionArn, clientToken, verificationContractSha256, ...(arn ? { taskArn: arn } : {}) });
  await record("LAUNCH_INTENT");
  try {
    const response = noFailures(parse(run(["ecs", "run-task", "--cli-input-json", JSON.stringify(request), "--output", "json", "--no-cli-pager"])));
    assert.equal(response.tasks?.length, 1);
    arn = response.tasks[0].taskArn; assert.match(arn || "", taskArn);
    await record("LAUNCHED");
    const deadline = now() + 5 * 60 * 1000;
    for (let attempt = 0; attempt < 60 && now() < deadline; attempt++) {
      const observed = noFailures(parse(run(["ecs", "describe-tasks", "--cluster", APP_ONLY.clusterArn, "--tasks", arn, "--output", "json", "--no-cli-pager"])));
      assert.equal(observed.tasks?.length, 1); const task = observed.tasks[0];
      assert.equal(task.taskArn, arn); assert.equal(task.clusterArn, APP_ONLY.clusterArn); assert.equal(task.taskDefinitionArn, taskDefinitionArn);
      assert.equal(task.enableExecuteCommand, false);
      if (task.lastStatus === "STOPPED") {
        assert.equal(task.stopCode, "EssentialContainerExited");
        assert.equal(task.containers?.length, 1); assert.equal(task.containers[0].exitCode, 0, "Compatibility verifier failed");
        assert.equal(task.containers[0].name, readback.taskDefinition.containerDefinitions[0].name);
        assert.equal(task.containers[0].imageDigest, verifier.identity.verifierImageDigest);
        await authenticate(); // A changed predecessor cannot receive compatibility authority.
        await record("TASK_SUCCEEDED_EVIDENCE_PENDING");
        return { task, verificationContractSha256 }; // Exact task output is authenticated separately below.
      }
      await wait(5000);
    }
    throw new Error("Compatibility verifier completion timeout; do not relaunch an ambiguous task");
  } catch (cause) {
    await record(arn ? "TASK_OUTCOME_REQUIRES_READBACK" : "LAUNCH_OUTCOME_UNCERTAIN");
    throw new Error("Compatibility verifier failed or timed out; preserve evidence and do not relaunch automatically", { cause });
  }
}

// Only the stream derived from the returned task ARN and source-fixed container
// is read. Never select the newest log stream or accept a caller stream name.
export async function readAppOnlyVerifierResult({ run, execution, verifier, wait = sleep, now = Date.now }) {
  const { task, verificationContractSha256 } = execution;
  assert.match(task.taskArn || "", taskArn);
  assert.equal(task.clusterArn, APP_ONLY.clusterArn);
  assert.equal(task.lastStatus, "STOPPED");
  assert.equal(task.stopCode, "EssentialContainerExited");
  assert.equal(task.enableExecuteCommand, false);
  assert.equal(task.containers?.length, 1);
  assert.equal(task.containers[0].exitCode, 0);
  assert.equal(task.containers[0].name, "production-green-read-only-rls-canary");
  assert.equal(task.containers[0].imageDigest, verifier.identity.verifierImageDigest);
  const stream = `app-only/production-green-read-only-rls-canary/${task.taskArn.split("/").at(-1)}`;
  const deadline = now() + 60000;
  for (let attempt = 0; attempt < 12 && now() < deadline; attempt++) {
    const events = []; let token;
    for (let page = 0; page < 10; page++) {
      const response = parse(run(["logs", "get-log-events", "--log-group-name", APP_ONLY_VERIFIER.logGroup,
        "--log-stream-name", stream, "--start-from-head", "--limit", "100", ...(token ? ["--next-token", token] : []), "--output", "json", "--no-cli-pager"]));
      assert.ok(Array.isArray(response.events));
      events.push(...response.events);
      assert.ok(events.length <= 100 && events.reduce((sum, event) => sum + Buffer.byteLength(event.message || ""), 0) <= 32768, "Unexpected verifier output volume");
      if (!response.nextForwardToken || response.nextForwardToken === token) break;
      assert.ok(page < 9, "Unbounded verifier log pagination"); token = response.nextForwardToken;
    }
    if (events.length) {
      assert.equal(events.length, 1, "Verifier must emit exactly one non-secret result");
      return authenticateAppOnlyVerifierResult({ message: events[0].message, identity: verifier.identity,
        requirementsSha256: verifier.requirements.requirementsSha256, verificationContractSha256, now: now() });
    }
    await wait(5000);
  }
  throw new Error("Verifier evidence unavailable; preserve task identity without relaunch");
}
