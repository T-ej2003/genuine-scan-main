import test from "node:test";
import assert from "node:assert/strict";
import { executeAppOnlyActivation } from "../aws/production-app-only-activation.mjs";
import { APP_ONLY, captureAppOnlyPredecessor, assertAppOnlySessionRiskConfiguration } from "../aws/production-app-only-contract.mjs";
import { canonicalSha256 } from "../aws/production-green-stage-b-contract.mjs";

const oldDigest = `sha256:${"1".repeat(64)}`, candidateDigest = `sha256:${"2".repeat(64)}`;
const arn = (n) => `arn:aws:ecs:${APP_ONLY.region}:${APP_ONLY.account}:task-definition/${APP_ONLY.family}:${n}`;
function harness({ unhealthy = false, competing = false, corruptReadback = false, stale = false, uncertainUpdate = false, fixedRuntimeMetadata = false, initialDeploymentId = "ecs-svc/100", activatedDeploymentId = "ecs-svc/200" } = {}) {
  const prior = { family: APP_ONLY.family, taskDefinitionArn: arn(14), revision: 14, status: "ACTIVE",
    taskRoleArn: APP_ONLY.taskRoleArn, executionRoleArn: APP_ONLY.executionRoleArn, networkMode: "awsvpc",
    runtimePlatform: { cpuArchitecture: "X86_64", operatingSystemFamily: "LINUX" },
    containerDefinitions: [{ name: "backend", image: `${APP_ONLY.backendRepository}@${oldDigest}`,
      environment: fixedRuntimeMetadata ? [{ name: "RELEASE_GIT_SHA", value: "b".repeat(40) }, { name: "GIT_SHA", value: "b".repeat(40) }] : [], secrets: [] }] };
  let current = prior, deploymentId = initialDeploymentId, registered, reads = 0;
  const records = [], mutations = [];
  const live = () => ({ definition: structuredClone(current), service: { clusterArn: APP_ONLY.clusterArn, serviceArn: APP_ONLY.serviceArn, serviceName: APP_ONLY.service,
    status: "ACTIVE", taskDefinition: current.taskDefinitionArn, desiredCount: 2, runningCount: 2, pendingCount: 0,
    deployments: [{ id: deploymentId, taskDefinition: current.taskDefinitionArn, status: "PRIMARY", rolloutState: "COMPLETED" }] },
  tasks: ["a", "b"].map((taskArn) => ({ taskArn, taskDefinitionArn: current.taskDefinitionArn, clusterArn: APP_ONLY.clusterArn, group: `service:${APP_ONLY.service}`,
    lastStatus: "RUNNING", healthStatus: "HEALTHY", startedBy: deploymentId, containers: [{ name: "backend", imageDigest: current.containerDefinitions[0].image.split("@")[1] }] })) });
  const body = { predecessor: captureAppOnlyPredecessor(live()), candidateDigest, candidateSourceSha: "a".repeat(40), predecessorSourceSha: "b".repeat(40) };
  const preparation = { ...body, preparationSha256: canonicalSha256(body) };
  const adapters = {
    authenticate: async () => {},
    readLive: async () => { if (stale && ++reads > 1) deploymentId = "ecs-svc/400"; return live(); },
    register: async (definition) => { mutations.push("register"); registered = { ...definition, taskDefinitionArn: arn(23), revision: 23, status: "ACTIVE" }; return registered; },
    readDefinition: async (target) => { const value = structuredClone(target === arn(14) ? prior : registered); if (corruptReadback && target !== arn(14)) value.cpu = "8192"; return value; },
    updateService: async ({ taskDefinition }) => { mutations.push(taskDefinition); current = taskDefinition === arn(14) ? prior : registered; deploymentId = taskDefinition === arn(14) ? "ecs-svc/300" : activatedDeploymentId; if (uncertainUpdate) throw new Error("lost response"); return live().service; },
    waitStable: async () => {},
    readHealth: async () => { if (unhealthy && current.taskDefinitionArn === arn(23)) { if (competing) deploymentId = "ecs-svc/400"; throw new Error("unhealthy"); } return { frontendStatus: 200, backend: { httpStatus: 200, body: { success: true, status: "ready", timestamp: new Date().toISOString(), release: { gitSha: !fixedRuntimeMetadata && current.taskDefinitionArn === arn(23) ? body.candidateSourceSha : body.predecessorSourceSha }, dependencies: { database: { ready: true }, redis: { configured: true, ready: true }, objectStorage: { configured: true, ready: true } } } } }; },
    writeEvidence: async (value) => records.push(value),
  };
  return { preparation, adapters, records, mutations, prior };
}
test("authenticated healthy activation registers, reads back and updates only exact candidate", async () => {
  const h = harness(); const result = await executeAppOnlyActivation(h.preparation, h.adapters);
  assert.equal(result.status, "HEALTHY");
  assert.deepEqual(h.mutations, ["register", arn(23)]);
  assert.deepEqual(h.records.map(({ status }) => status), ["PRE_MUTATION", "REGISTRATION_INTENT", "CANDIDATE_REGISTERED", "ACTIVATION_INTENT", "ACTIVATING", "HEALTHY"]);
});
for (const id of ["ecs-svc/0559890711032160707", "ecs-svc/1234567890123456789"]) {
  test(`activation and exact-predecessor rollback preserve opaque ID ${id}`, async () => {
    for (const unhealthy of [false, true]) {
      const h = harness({ initialDeploymentId: id, activatedDeploymentId: id, unhealthy });
      const preparation = JSON.parse(JSON.stringify(h.preparation));
      assert.equal(preparation.predecessor.deploymentId, id);
      if (unhealthy) await assert.rejects(executeAppOnlyActivation(preparation, h.adapters));
      else assert.equal((await executeAppOnlyActivation(preparation, h.adapters)).status, "HEALTHY");
      assert.equal(h.records.find(({ status }) => status === "ACTIVATING").candidateDeploymentId, id);
      assert.equal(h.records.at(-1).status, unhealthy ? "ROLLED_BACK" : "HEALTHY");
    }
  });
}
test("malformed activation IDs cannot authorize rollback", async () => {
  for (const id of ["ecs-svc/", "ecs-svc/-1", "ecs-svc/+1", "ecs-svc/1.0", "ecs-svc/abc", "ecs-svc/123abc", "ecs-svc/ 123", "ecs-svc/123 ", "ecs-svc//123", "svc/123", "ecs-svc/123\n"]) {
    const h = harness({ activatedDeploymentId: id });
    await assert.rejects(executeAppOnlyActivation(h.preparation, h.adapters));
    assert.deepEqual(h.mutations, ["register", arn(23)]);
    assert.equal(h.records.at(-1).status, "ACTIVATION_FAILED_RECOVERY_REQUIRED");
  }
});
test("image-only activation preserves fixed release metadata without confusing it with image provenance", async () => {
  const h = harness({ fixedRuntimeMetadata: true });
  const result = await executeAppOnlyActivation(h.preparation, h.adapters);
  assert.equal(result.status, "HEALTHY");
  assert.equal(result.deployedBackendDigest, candidateDigest);
  assert.equal(result.deployedImageSourceSha, h.preparation.candidateSourceSha);
  assert.equal(result.healthMetadataSourceSha, h.preparation.predecessorSourceSha);
});
test("stale CAS stops before registration", async () => {
  const h = harness({ stale: true }); await assert.rejects(executeAppOnlyActivation(h.preparation, h.adapters));
  assert.deepEqual(h.mutations, []);
});
test("candidate readback mutation stops before UpdateService", async () => {
  const h = harness({ corruptReadback: true }); await assert.rejects(executeAppOnlyActivation(h.preparation, h.adapters));
  assert.deepEqual(h.mutations, ["register"]);
  assert.equal(h.records.at(-1).status, "FAILED_BEFORE_ACTIVATION");
});
test("health failure rolls back to exact predecessor, never candidate revision minus one", async () => {
  const h = harness({ unhealthy: true }); await assert.rejects(executeAppOnlyActivation(h.preparation, h.adapters));
  assert.deepEqual(h.mutations, ["register", arn(23), arn(14)]);
  assert.equal(h.records.at(-1).status, "ROLLED_BACK"); assert.equal(h.records.at(-1).rollbackVerified, true);
});
test("competing deployment prevents rollback", async () => {
  const h = harness({ unhealthy: true, competing: true }); await assert.rejects(executeAppOnlyActivation(h.preparation, h.adapters));
  assert.deepEqual(h.mutations, ["register", arn(23)]);
  assert.equal(h.records.at(-1).status, "ACTIVATION_FAILED_RECOVERY_REQUIRED");
});
test("ambiguous UpdateService result records uncertainty without guessing ownership", async () => {
  const h = harness({ uncertainUpdate: true }); await assert.rejects(executeAppOnlyActivation(h.preparation, h.adapters));
  assert.deepEqual(h.mutations, ["register", arn(23)]);
  assert.equal(h.records.at(-1).status, "ACTIVATION_FAILED_RECOVERY_REQUIRED");
});
test("session risk is verified without accessing DB or other secret values", () => {
  const h = harness(); assert.equal(assertAppOnlySessionRiskConfiguration(h.prior).effectiveThreshold, 85);
  for (const value of ["0", "1", "100", "invalid"]) {
    const bad = structuredClone(h.prior); bad.containerDefinitions[0].environment = [{ name: "AUTH_RISK_BLOCK_THRESHOLD", value }];
    assert.throws(() => assertAppOnlySessionRiskConfiguration(bad));
  }
  const secret = structuredClone(h.prior); secret.containerDefinitions[0].secrets = [{ name: "AUTH_RISK_BLOCK_THRESHOLD", valueFrom: "private" }];
  assert.throws(() => assertAppOnlySessionRiskConfiguration(secret));
});
