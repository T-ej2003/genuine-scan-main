import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import { APP_ONLY, APP_ONLY_DOMAINS, buildAppOnlyCandidate, assertAppOnlyCandidate, assertRegisteredAppOnlyCandidate, captureAppOnlyPredecessor, assertAppOnlyCas, assertAppOnlyEvidenceIdentity, evaluateAppOnlyDomains, assertAppOnlyRollbackOwnership, appOnlyExpectedHealthSourceSha } from "../aws/production-app-only-contract.mjs";
import { canonicalSha256 } from "../aws/production-green-stage-b-contract.mjs";

const oldDigest = `sha256:${"1".repeat(64)}`;
const newDigest = `sha256:${"2".repeat(64)}`;
const arn = (revision) => `arn:aws:ecs:${APP_ONLY.region}:${APP_ONLY.account}:task-definition/${APP_ONLY.family}:${revision}`;

test("health metadata precedence matches backend source while image identity remains separate", () => {
  const source = fs.readFileSync("backend/src/observability/release.ts", "utf8");
  const expression = source.match(/const gitSha = firstKnownValue\(([\s\S]*?)\);/)[1];
  assert.deepEqual([...expression.matchAll(/process\.env\.([A-Z_]+)/g)].map((match) => match[1]),
    ["RELEASE_GIT_SHA", "GITHUB_SHA", "COMMIT_SHA", "GIT_SHA", "RENDER_GIT_COMMIT", "VERCEL_GIT_COMMIT_SHA"]);
  const definition = fixture().definition, imageSource = "a".repeat(40), configured = "b".repeat(40);
  const backend = definition.containerDefinitions.find((container) => container.name === "backend");
  backend.environment = [{ name: "GIT_SHA", value: configured }];
  assert.equal(appOnlyExpectedHealthSourceSha(definition, imageSource), imageSource, "Image RELEASE_GIT_SHA takes priority over GIT_SHA override");
  backend.environment.push({ name: "RELEASE_GIT_SHA", value: configured });
  assert.equal(appOnlyExpectedHealthSourceSha(definition, imageSource), configured);
  backend.environment.push({ name: "RELEASE_GIT_SHA", value: imageSource });
  assert.throws(() => appOnlyExpectedHealthSourceSha(definition, imageSource));
  backend.environment = []; backend.secrets = [{ name: "RELEASE_GIT_SHA", valueFrom: "unproven" }];
  assert.throws(() => appOnlyExpectedHealthSourceSha(definition, imageSource));
});
function fixture() {
  const definition = { taskDefinitionArn: arn(14), revision: 14, status: "ACTIVE", family: APP_ONLY.family,
    taskRoleArn: APP_ONLY.taskRoleArn, executionRoleArn: APP_ONLY.executionRoleArn, networkMode: "awsvpc",
    runtimePlatform: { cpuArchitecture: "X86_64", operatingSystemFamily: "LINUX" }, cpu: "1024", memory: "2048",
    containerDefinitions: [{ name: "backend", image: `${APP_ONLY.backendRepository}@${oldDigest}`, environment: [{ name: "NODE_ENV", value: "production" }], secrets: [], portMappings: [{ containerPort: 4000 }], logConfiguration: { logDriver: "awslogs" } }],
    tags: [{ key: "Environment", value: "production" }],
  };
  const service = { clusterArn: APP_ONLY.clusterArn, serviceArn: APP_ONLY.serviceArn, serviceName: APP_ONLY.service,
    status: "ACTIVE", taskDefinition: arn(14), desiredCount: 2, runningCount: 2, pendingCount: 0,
    deployments: [{ id: "ecs-svc/100", status: "PRIMARY", rolloutState: "COMPLETED", taskDefinition: arn(14) }],
    networkConfiguration: { awsvpcConfiguration: { assignPublicIp: "DISABLED", subnets: ["private"] } },
  };
  const tasks = ["a", "b"].map((id) => ({ taskArn: id, clusterArn: APP_ONLY.clusterArn, group: `service:${APP_ONLY.service}`,
    taskDefinitionArn: arn(14), lastStatus: "RUNNING", healthStatus: "HEALTHY", startedBy: "ecs-svc/100", containers: [{ name: "backend", imageDigest: oldDigest }] }));
  return { definition, service, tasks };
}
test("only the backend image changes, and AWS defaults are normalized on readback", () => {
  const { definition } = fixture();
  const original = structuredClone(definition);
  const candidate = buildAppOnlyCandidate(definition, newDigest);
  assert.equal(assertAppOnlyCandidate(definition, candidate, newDigest), true);
  assert.deepEqual(definition, original);
  Object.assign(candidate, { taskDefinitionArn: arn(15), revision: 15, status: "ACTIVE", enableFaultInjection: false, volumes: [] });
  candidate.containerDefinitions[0].cpu = 0;
  candidate.containerDefinitions[0].logConfiguration.secretOptions = [];
  assert.equal(assertRegisteredAppOnlyCandidate(definition, candidate, newDigest), true);
});
for (const field of ["taskRoleArn", "executionRoleArn", "networkMode", "family", "runtimePlatform", "cpu", "memory", "volumes", "ephemeralStorage", "pidMode", "ipcMode", "proxyConfiguration", "inferenceAccelerators", "placementConstraints", "requiresCompatibilities", "enableFaultInjection", "tags"]) {
  test(`rejects root task-definition change: ${field}`, () => {
    const { definition } = fixture();
    const candidate = buildAppOnlyCandidate(definition, newDigest);
    candidate[field] = "changed";
    assert.throws(() => assertAppOnlyCandidate(definition, candidate, newDigest));
  });
}
for (const field of ["name", "environment", "secrets", "command", "entryPoint", "portMappings", "mountPoints", "volumesFrom", "linuxParameters", "logConfiguration", "healthCheck", "memory", "memoryReservation", "ulimits", "systemControls", "privileged"]) {
  test(`rejects container change: ${field}`, () => {
    const { definition } = fixture();
    const candidate = buildAppOnlyCandidate(definition, newDigest);
    candidate.containerDefinitions[0][field] = "changed";
    assert.throws(() => assertAppOnlyCandidate(definition, candidate, newDigest));
  });
}
test("sidecar identity, tag images and mismatched readback are rejected", () => {
  const { definition } = fixture();
  definition.containerDefinitions.push({ name: "sidecar", image: `other@${oldDigest}` });
  const candidate = buildAppOnlyCandidate(definition, newDigest);
  candidate.containerDefinitions[1].image = `other@${newDigest}`;
  assert.throws(() => assertAppOnlyCandidate(definition, candidate, newDigest));
  assert.throws(() => buildAppOnlyCandidate(definition, "latest"));
  assert.throws(() => assertRegisteredAppOnlyCandidate(definition, buildAppOnlyCandidate(definition, newDigest), newDigest));
});
test("preparation and immediate pre-mutation CAS reject concurrent deployments", () => {
  const live = fixture();
  const prior = captureAppOnlyPredecessor(live);
  assert.doesNotThrow(() => assertAppOnlyCas(prior, captureAppOnlyPredecessor(live)));
  for (const field of Object.keys(prior)) assert.throws(() => assertAppOnlyCas(prior, { ...prior, [field]: "changed" }));
  live.service.deployments.push({ id: "ecs-svc/400" });
  assert.throws(() => captureAppOnlyPredecessor(live));
});
test("rollback is only the recorded predecessor while deployment ownership remains", () => {
  const live = fixture();
  const predecessor = captureAppOnlyPredecessor(live);
  live.service.taskDefinition = arn(23);
  live.service.deployments = [{ id: "ecs-svc/200", status: "PRIMARY", taskDefinition: arn(23) }];
  const input = { service: live.service, predecessor, candidateArn: arn(23), candidateDeploymentId: "ecs-svc/200" };
  assert.equal(assertAppOnlyRollbackOwnership(input), arn(14)); // Never revision-1.
  const changedConfiguration = structuredClone(input);
  changedConfiguration.service.enableExecuteCommand = true;
  assert.throws(() => assertAppOnlyRollbackOwnership(changedConfiguration), /configuration changed/);
  live.service.deployments.push({ id: "ecs-svc/400", status: "ACTIVE", taskDefinition: arn(22) });
  assert.throws(() => assertAppOnlyRollbackOwnership(input));
  live.service.deployments = [{ id: "other-candidate", status: "PRIMARY", taskDefinition: arn(23) }];
  assert.throws(() => assertAppOnlyRollbackOwnership(input));
});

test("all mutable service settings including unknown future fields bind activation and rollback CAS", () => {
  for (const [field, value] of Object.entries({ healthCheckGracePeriodSeconds: 90, propagateTags: "SERVICE",
    enableECSManagedTags: true, serviceConnectConfiguration: { enabled: true }, availabilityZoneRebalancing: "DISABLED",
    volumeConfigurations: [{ name: "changed" }], vpcLatticeConfigurations: [{ targetGroupArn: "changed" }],
    tags: [{ key: "authority", value: "changed" }], futureMutableSetting: { changed: true } })) {
    const live = fixture(), predecessor = captureAppOnlyPredecessor(live);
    live.service[field] = value;
    assert.throws(() => assertAppOnlyCas(predecessor, captureAppOnlyPredecessor(live)), field);
    live.service.taskDefinition = arn(23);
    live.service.deployments = [{ id: "ecs-svc/200", status: "PRIMARY", taskDefinition: arn(23) }];
    assert.throws(() => assertAppOnlyRollbackOwnership({ service: live.service, predecessor, candidateArn: arn(23), candidateDeploymentId: "ecs-svc/200" }), field);
  }
});

test("missing or non-AWS deployment identity cannot become a predecessor even when tasks omit it too", () => {
  for (const id of [undefined, "", "ecs-svc/original", "svc/123", "ecs-svc/0"]) {
    const live = fixture(); live.service.deployments[0].id = id;
    for (const task of live.tasks) task.startedBy = id;
    assert.throws(() => captureAppOnlyPredecessor(live));
  }
});
test("historical changes require positive compatibility; state drift is not an input", () => {
  const domains = Object.fromEntries(APP_ONLY_DOMAINS.map((domain) => [domain, { changed: true, status: "COMPATIBLE" }]));
  assert.equal(evaluateAppOnlyDomains(domains).eligible, true);
  for (const domain of APP_ONLY_DOMAINS) {
    assert.equal(evaluateAppOnlyDomains({ ...domains, [domain]: { changed: true, status: "UNPROVEN" } }).eligible, false);
    assert.equal(evaluateAppOnlyDomains({ ...domains, [domain]: { changed: true, status: "INCOMPATIBLE" } }).eligible, false);
    assert.equal(evaluateAppOnlyDomains({ ...domains, [domain]: { changed: false } }).domains[domain], "UNCHANGED");
  }
  delete domains.RLS;
  assert.throws(() => evaluateAppOnlyDomains(domains));
});
test("evidence identity, every context field, freshness and content hash are bound", () => {
  const identity = { sourceSha: "a".repeat(40), candidateSourceSha: "b".repeat(40), account: APP_ONLY.account, region: APP_ONLY.region,
    clusterArn: APP_ONLY.clusterArn, serviceArn: APP_ONLY.serviceArn, predecessorTaskDefinition: arn(14), predecessorBackendDigest: oldDigest, candidateDigest: newDigest };
  const now = Date.now();
  const payload = { identity, generatedAt: new Date(now).toISOString(), results: {} };
  const evidence = { ...payload, evidenceSha256: canonicalSha256(payload) };
  assert.equal(assertAppOnlyEvidenceIdentity(evidence, identity, now), true);
  for (const field of Object.keys(identity)) assert.throws(() => assertAppOnlyEvidenceIdentity({ ...evidence, identity: { ...identity, [field]: "other" } }, identity, now));
  assert.throws(() => assertAppOnlyEvidenceIdentity(evidence, identity, now + APP_ONLY.maxEvidenceAgeMs + 1));
  assert.throws(() => assertAppOnlyEvidenceIdentity(evidence, identity, now - 1));
  assert.throws(() => assertAppOnlyEvidenceIdentity({ ...evidence, results: { pass: true } }, identity, now));
});
