import { packReleaseEvidenceTransport, unpackReleaseEvidenceTransport } from "../aws/production-release-dispatch-contract.mjs";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import test from "node:test";
import { canonicalSha256, canonicalJson, canonicalStageBApproval } from "../aws/production-green-stage-b-contract.mjs";
import { historicalWorkerTasks, classifyHistoricalWorkerWorkload, prepareHistoricalRuntimeReference, assertHistoricalRuntimeReference, verifyHistoricalRuntimeLive, assertHistoricalRuntimeRetention } from "../aws/production-historical-runtime-contract.mjs";
import { authenticateHistoricalRuntimeEvidence, authenticateRetainedHistoricalRuntime, historicalRuntimeRetention, verifyHistoricalRuntimeInventory } from "../aws/production-historical-runtime-evidence.mjs";
import { verifyHistoricalRuntimeHandoff, verifyStageBHistoricalRuntime, readHistoricalRuntimeTransport } from "../aws/verify-production-historical-runtime-handoff.mjs";
import { stateHash, componentStateCasRequest, advanceProductionComponentDeploymentState, assertProductionComponentDeploymentState } from "../aws/production-component-deployment-state.mjs";
import { commitSecurityComponentState } from "../aws/commit-production-component-security-state.mjs";
import { executeNormalComponentTransaction, buildNormalReleasePlan } from "../aws/production-normal-release.mjs";
import { NORMAL_RECEIPT_WORKFLOW } from "../aws/production-normal-receipt-contract.mjs";
import { historicalRuntimeFixture, rehashReference } from "./fixtures/historical-runtime.mjs";

const retained = (f) => historicalRuntimeRetention({ evidence: f.evidence, sourceSha: f.release, current: f.state, componentStateSha256: stateHash(f.state), reader: f.reader, verify: f.verify, writerContext: f.writerContext, now: f.now });
const committed = (f) => advanceProductionComponentDeploymentState({ current: f.state, expectedGeneration: 1, lane: "SECURITY_INFRASTRUCTURE", changes: { security: { sourceSha: f.release, releaseIdentity: "reviewed-release" } }, historicalRuntimeRetention: retained(f), ...f.writerContext });

test("one canonical exact-object reference preserves truthful historical provenance", () => {
  const f = historicalRuntimeFixture();
  assert.equal(f.reference.kind, "EXACT_HISTORICAL_RUNTIME_BASELINE");
  assert.equal(f.reference.historicalGovernedDeploymentProvenance, false); assert.equal(f.reference.historicalNormalDeploymentReceipt, false);
  assert.equal(verifyHistoricalRuntimeLive({ reference: f.reference, reader: f.reader }), true);
  const reordered = Object.fromEntries(Object.entries(f.reference).reverse()); assert.equal(canonicalSha256(reordered), canonicalSha256(f.reference));
  assert.equal(verifyHistoricalRuntimeHandoff({ evidence: f.evidence, state: f.state, reader: f.reader, sourceSha: f.release, verify: f.verify, now: f.now }).referenceSha256, f.reference.referenceSha256);
});

const identityAttacks = {
  "different task ARN": (f) => { f.task.taskArn = f.taskArn.replace(/1$/, "2"); },
  "same family another revision": (f) => { f.task.taskDefinitionArn = f.definitionArn.replace(/:7$/, ":8"); },
  "same source wrong running image": (f) => { f.task.containers[0].imageDigest = `sha256:${"9".repeat(64)}`; },
  "different task-definition content": (f) => { f.definition.cpu = "2048"; },
  "changed task role": (f) => { f.definition.taskRoleArn += "-other"; },
  "changed execution role": (f) => { f.definition.executionRoleArn += "-other"; },
  "changed environment": (f) => { f.definition.containerDefinitions[0].environment.push({ name: "MODE", value: "changed" }); },
  "changed override": (f) => { f.task.overrides.containerOverrides[0].environment = [{ name: "MODE", value: "changed" }]; },
  "changed secret reference": (f) => { f.definition.containerDefinitions[0].secrets[0].valueFrom += "-other"; },
  "changed network": (f) => { f.eni.Groups = [{ GroupId: "sg-123456" }]; },
  "changed cluster": (f) => { f.task.clusterArn += "-other"; },
  "task STOPPED": (f) => { f.task.lastStatus = "STOPPED"; },
  "desired STOPPED": (f) => { f.task.desiredStatus = "STOPPED"; },
  "task disappears": (f) => { f.tasks.length = 0; },
  "overridden source": (f) => { f.task.overrides.containerOverrides[0].environment = [{ name: "RELEASE_GIT_SHA", value: "e".repeat(40) }]; },
  "overridden command": (f) => { f.task.overrides.containerOverrides[0].command = ["node", "attack.js"]; },
};
for (const [name, attack] of Object.entries(identityAttacks)) test(`live immutable readback rejects ${name}`, () => {
  const f = historicalRuntimeFixture(); attack(f);
  assert.throws(() => verifyHistoricalRuntimeLive({ reference: f.reference, reader: f.reader }));
});

const authorityAttacks = {
  "reference hash changed": (f) => { f.evidence.reference.referenceSha256 = "0".repeat(64); },
  "reference body changed and self-rehashed": (f) => { f.evidence.reference.runtime.taskArn = f.taskArn.replace(/1$/, "2"); rehashReference(f.evidence.reference); f.evidence.binding.historicalRuntimeAuthority.referenceSha256 = f.evidence.reference.referenceSha256; },
  "approval binds another hash": (f) => { f.evidence.binding.historicalRuntimeAuthority.referenceSha256 = "0".repeat(64); },
  "unsigned reference": (f) => { delete f.evidence.signatureBase64; },
  "forged signature": (f) => { f.evidence.signatureBase64 = "AA=="; },
  "stale approval": (f) => { f.now = "2026-09-30T11:00:00.000Z"; },
  "wrong protected release": (f) => { f.release = "0".repeat(40); },
  "wrong component generation": (f) => { f.state = { ...f.state, generation: 2 }; },
  "component-state substitution": (f) => { f.state = { ...f.state, components: { ...f.state.components, backend: { ...f.state.components.backend, desiredCount: 3 } } }; },
  "bootstrap hash substitution": (f) => { f.evidence.reference.bootstrap.componentStateSha256 = "0".repeat(64); rehashReference(f.evidence.reference); f.evidence.binding.historicalRuntimeAuthority.referenceSha256 = f.evidence.reference.referenceSha256; },
  "false governed provenance": (f) => { f.evidence.reference.historicalGovernedDeploymentProvenance = true; rehashReference(f.evidence.reference); },
  "wrong AWS account": (f) => { f.evidence.reference.runtime.account = "000000000000"; rehashReference(f.evidence.reference); },
  "wrong AWS region": (f) => { f.evidence.reference.runtime.region = "eu-west-1"; rehashReference(f.evidence.reference); },
  "different recovery tree": (f) => { f.evidence.reference.recoveryTreeSha256 = "0".repeat(64); rehashReference(f.evidence.reference); f.evidence.binding.historicalRuntimeAuthority.referenceSha256 = f.evidence.reference.referenceSha256; },
  "another Stage B evidence kind": (f) => { f.evidence.binding.evidenceKind = "INITIAL_ADMINISTRATOR_CAPABILITY"; },
};
for (const [name, attack] of Object.entries(authorityAttacks)) test(`authenticated handoff rejects ${name}`, () => {
  const f = historicalRuntimeFixture(); attack(f);
  assert.throws(() => verifyHistoricalRuntimeHandoff({ evidence: f.evidence, state: f.state, reader: f.reader, sourceSha: f.release, verify: f.verify, now: f.now }));
});

for (const scenario of ["arbitrary root actor", "no MFA", "unrelated registration", "stale registration", "unrelated launch", "stale launch", "future worker", "unprotected source"]) test(`initial baseline rejects ${scenario}`, () => {
  const f = historicalRuntimeFixture();
  if (scenario === "arbitrary root actor") f.registration.userIdentity = { ...f.registration.userIdentity, arn: "arn:aws:iam::368992683803:user/other" };
  if (scenario === "no MFA") f.launch.userIdentity = { ...f.launch.userIdentity, sessionContext: { attributes: { mfaAuthenticated: "false" } } };
  if (scenario === "unrelated registration") f.registration.responseElements.taskDefinition.taskDefinitionArn += "-other";
  if (scenario === "stale registration") f.registration.eventTime = "2026-09-01T10:00:00.000Z";
  if (scenario === "unrelated launch") f.launch.responseElements.tasks[0].taskArn += "-other";
  if (scenario === "stale launch") f.launch.eventTime = "2026-09-01T10:00:00.000Z";
  if (scenario === "future worker") f.task.createdAt = "2026-10-01T10:00:00.000Z";
  assert.throws(() => prepareHistoricalRuntimeReference({ reader: f.reader, taskArn: f.taskArn, componentState: f.state, componentStateSha256: stateHash(f.state), recoverySourceSha: f.release, recoveryTreeSha256: "f".repeat(64), isProtectedSource: () => scenario !== "unprotected source" }));
});

test("second standalone worker, missing handoff, and missing retention fail closed", () => {
  const f = historicalRuntimeFixture();
  assert.throws(() => verifyHistoricalRuntimeHandoff({ state: f.state, reader: f.reader, sourceSha: f.release }), /requires/);
  const state = structuredClone(committed(f)); delete state.historicalRuntimeRetention;
  assert.throws(() => verifyHistoricalRuntimeHandoff({ state, reader: f.reader }), /requires/);
  f.tasks.push({ ...structuredClone(f.task), taskArn: f.taskArn.replace(/1$/, "2") });
  assert.throws(() => verifyHistoricalRuntimeInventory({ reference: f.reference, reader: f.reader }), /second worker/);
});

test("terminal CAS persists authenticated reference and unknown-outcome retry is idempotent", () => {
  const f = historicalRuntimeFixture(); let state = f.state, writes = 0;
  const body = { sourceSha: f.release, valid: true }, authorization = { ...body, authorizationSha256: canonicalSha256(body) };
  const client = { read: () => state, advance: (current, next) => { componentStateCasRequest({ current, next }); state = next; writes++; } };
  const options = { sourceSha: f.release, authorization, client, historicalRuntimeEvidence: f.evidence, runtimeReader: f.reader, verifyRuntimeSignature: f.verify, writerContext: f.writerContext, now: f.now };
  const first = commitSecurityComponentState(options); assert.equal(first.state.generation, 2); assert.equal(writes, 1);
  assert.equal(authenticateRetainedHistoricalRuntime({ state, reader: f.reader, verify: f.verify }).referenceSha256, f.reference.referenceSha256);
  const second = commitSecurityComponentState({ ...options, now: "2026-10-01T11:00:00.000Z" }); assert.equal(second.alreadyCurrent, true); assert.equal(writes, 1);
});

test("initial retention cannot CAS against a changed bootstrap or retry generation drift", () => {
  const f = historicalRuntimeFixture(); const next = committed(f);
  const drifted = { ...f.state, generation: 2 };
  assert.throws(() => componentStateCasRequest({ current: drifted, next: { ...next, generation: 3 } }));
  const substituted = structuredClone(next); substituted.historicalRuntimeRetention.reference.runtime.privateIp = "10.0.2.1";
  assert.throws(() => assertProductionComponentDeploymentState(substituted));
});

for (const proof of ["INVENTORY_RECEIPT", "RLS_RECEIPT", "TASK_DEFINITION_REGISTRATION", "CLOUDTRAIL_LAUNCH", "NEW_RUNNING_WORKER", "GENERIC_RECEIPT", "FUTURE_SUCCESSOR_WITHOUT_CONTRACT"]) test(`${proof} cannot supersede historical retention`, () => {
  const f = historicalRuntimeFixture(), current = committed(f);
  const retention = structuredClone(current.historicalRuntimeRetention); retention.status = "SUPERSEDED"; retention.successorProof = { kind: proof };
  assert.throws(() => assertHistoricalRuntimeRetention(retention));
  const removed = { ...current, generation: current.generation + 1 }; delete removed.historicalRuntimeRetention;
  assert.throws(() => componentStateCasRequest({ current, next: removed }), /cannot remove/);
});

test("Stage B apply/closure rejects omission and revalidates the exact live object", () => {
  const f = historicalRuntimeFixture();
  assert.equal(verifyStageBHistoricalRuntime({ reference: f.reference, permissionReport: f.report, state: f.state, reader: f.reader }), true);
  assert.throws(() => verifyStageBHistoricalRuntime({ permissionReport: f.report, state: committed(f), reader: f.reader, verify: f.verify }), /omitted/);
  f.task.lastStatus = "STOPPED";
  assert.throws(() => verifyStageBHistoricalRuntime({ reference: f.reference, permissionReport: f.report, state: f.state, reader: f.reader }));
});

test("transport rejects changed bytes; existing Stage B checker signature includes runtime hash", () => {
  const f = historicalRuntimeFixture(), bytes = Buffer.from(JSON.stringify(f.evidence));
  assert.equal(readHistoricalRuntimeTransport({ bytes, expectedSha256: crypto.createHash("sha256").update(bytes).digest("hex") }).schemaVersion, 1);
  assert.throws(() => readHistoricalRuntimeTransport({ bytes: Buffer.concat([bytes, Buffer.from(" ")]), expectedSha256: crypto.createHash("sha256").update(bytes).digest("hex") }));
  const approval = { historicalRuntimeReferenceSha256: f.reference.referenceSha256 };
  assert.ok(canonicalStageBApproval(approval).includes(f.reference.referenceSha256));
  assert.notEqual(canonicalStageBApproval(approval), canonicalStageBApproval({ historicalRuntimeReferenceSha256: "0".repeat(64) }));
});

test("backend then frontend canonical normal transactions preserve retained runtime without new authorization", async () => {
  const f = historicalRuntimeFixture(); let state = committed(f);
  const original = canonicalJson(state.historicalRuntimeRetention);
  const client = { read: () => structuredClone(state), advance: (current, next) => { componentStateCasRequest({ current, next }); assert.equal(current.generation, state.generation); state = structuredClone(next); } };
  for (const [name, sourceSha, file] of [["backend", "c".repeat(40), "backend/src/services/batchService.ts"], ["frontend", "e".repeat(40), "src/App.tsx"]]) {
    const imageRef = `368992683803.dkr.ecr.eu-west-2.amazonaws.com/${name === "backend" ? "mscqr-backend" : "mscqr-web"}@sha256:${"f".repeat(64)}`;
    const plan = buildNormalReleasePlan({ sourceSha, componentFiles: { backendFiles: name === "backend" ? [file] : [], frontendFiles: name === "frontend" ? [file] : [], databaseFiles: [], securityFiles: [] }, images: { [name]: imageRef } });
    const candidateArn = state.components[name].taskDefinitionArn.replace(/:[0-9]+$/, ":8");
    const adapter = { deploy: async (_, { recordCandidate }) => { await recordCandidate(candidateArn); return { result: name === "backend" ? { candidateTaskDefinition: candidateArn, candidateDeploymentId: "ecs-svc/8", deployedBackendDigest: imageRef.split("@")[1] } : { candidateTaskDefinitionArn: candidateArn, imageRef }, rollback: async () => {} }; }, rollback: async () => {} };
    const result = await executeNormalComponentTransaction({ plan, sourceSha, state: structuredClone(state), stateClient: client, [name]: adapter, smoke: async () => true, verifyCandidates: async () => { authenticateRetainedHistoricalRuntime({ state, reader: f.reader, verify: f.verify }); }, isAncestor: () => true, writerContext: { updatedByWorkflow: NORMAL_RECEIPT_WORKFLOW, githubRunId: "303" } });
    assert.equal(result.componentState.components[name].sourceSha, sourceSha);
    assert.equal(canonicalJson(state.historicalRuntimeRetention), original);
    assert.equal(state.normalDeploymentReceipt, undefined);
    assert.equal(authenticateRetainedHistoricalRuntime({ state, reader: f.reader, verify: f.verify }).runtime.taskArn, f.taskArn);
  }
});

test("machine contract: same canonical reference travels through both existing terminal writers", () => {
  const train = fs.readFileSync(".github/workflows/release-train.yml", "utf8"), gate = fs.readFileSync(".github/workflows/release-gate.yml", "utf8");
  assert.ok(train.includes("packReleaseEvidenceTransport")); assert.ok(train.includes("[\"normal_image_authorization_json\", transport.json]")); assert.ok(gate.includes("unpackReleaseEvidenceTransport"));
  for (const input of ["HISTORICAL_RUNTIME_EVIDENCE_JSON", "HISTORICAL_RUNTIME_EVIDENCE_SHA256"]) { assert.ok(train.includes(`process.env.${input}`)); assert.ok(gate.includes(`env.${input}`)); }
  const authenticate = gate.indexOf("Authenticate historical runtime evidence handoff");
  assert.ok(authenticate < gate.indexOf("Activate exact Stage-B backend candidate"));
  for (const file of ["commit-production-component-security-state.mjs", "commit-production-component-rotation-state.mjs"]) {
    const source = fs.readFileSync(`scripts/aws/${file}`, "utf8");
    assert.ok(source.includes("createHistoricalRuntimeRetention({")); assert.ok(source.includes("historicalRuntimeRetention: retention")); assert.ok(source.includes("verifyHistoricalRuntimeInventory({"));
  }
  const apply = fs.readFileSync("scripts/apply-production-green-stage-b.mjs", "utf8"); assert.ok(apply.indexOf("revalidateHistoricalRuntime();") < apply.indexOf("effectiveDeps.apply(artifacts.planPath)"));
  assert.ok(!/stop-task|run-task|StopTask|RunTask/.test(fs.readFileSync("scripts/aws/production-historical-runtime-evidence.mjs", "utf8")));
});


test("existing release transport preserves both signed byte sequences and rejects body/hash substitution", () => {
  const f = historicalRuntimeFixture(), authorizationJson = JSON.stringify({ schemaVersion: 1, authorization: "fixture" }), historicalRuntimeJson = JSON.stringify(f.evidence);
  const digest = (json) => crypto.createHash("sha256").update(json).digest("hex");
  const inputs = { authorizationJson, authorizationSha256: digest(authorizationJson), historicalRuntimeJson, historicalRuntimeSha256: digest(historicalRuntimeJson) };
  const transport = packReleaseEvidenceTransport(inputs);
  assert.deepEqual(unpackReleaseEvidenceTransport(transport), inputs);
  assert.deepEqual(unpackReleaseEvidenceTransport(packReleaseEvidenceTransport({ authorizationJson, authorizationSha256: digest(authorizationJson) })), { authorizationJson, authorizationSha256: digest(authorizationJson) });
  assert.throws(() => unpackReleaseEvidenceTransport({ ...transport, json: transport.json + " " }));
  for (const field of ["imageAuthorizationJson", "imageAuthorizationSha256", "historicalRuntimeJson", "historicalRuntimeSha256", "schemaVersion"]) {
    const value = JSON.parse(transport.json); value[field] = "tampered";
    const json = JSON.stringify(value); assert.throws(() => unpackReleaseEvidenceTransport({ json, sha256: digest(json) }));
  }
});

for (const operation of ["describeTasks", "describeTaskDefinition", "describeNetworkInterfaces", "listTasks"]) test(`closure ${operation} failure keeps bootstrap and never publishes retention`, () => {
  const f = historicalRuntimeFixture(); let writes = 0;
  f.reader[operation] = () => { throw new Error("injected read failure"); };
  const body = { sourceSha: f.release, valid: true }, authorization = { ...body, authorizationSha256: canonicalSha256(body) };
  assert.throws(() => commitSecurityComponentState({ sourceSha: f.release, authorization, client: { read: () => f.state, advance: () => { writes++; } }, historicalRuntimeEvidence: f.evidence, runtimeReader: f.reader, verifyRuntimeSignature: f.verify, writerContext: f.writerContext, now: f.now }), /injected/);
  assert.equal(writes, 0); assert.equal(f.state.generation, 1);
});

for (const outcome of ["before-write", "response-lost-after-write", "worker-drift-during-CAS", "CAS-loses-race"]) test(`closure ${outcome} fails safely and re-authenticates on retry`, () => {
  const f = historicalRuntimeFixture(); let durable = f.state, writes = 0;
  const body = { sourceSha: f.release, valid: true }, authorization = { ...body, authorizationSha256: canonicalSha256(body) };
  const client = { read: () => durable, advance: (current, next) => {
    componentStateCasRequest({ current, next }); writes++;
    if (outcome === "before-write") throw new Error("before write");
    if (outcome === "CAS-loses-race") { durable = { ...durable, generation: 2 }; throw new Error("ConditionalCheckFailedException"); }
    durable = next;
    if (outcome === "worker-drift-during-CAS") f.task.lastStatus = "STOPPED";
    else throw new Error("response lost");
  } };
  const options = { sourceSha: f.release, authorization, client, historicalRuntimeEvidence: f.evidence, runtimeReader: f.reader, verifyRuntimeSignature: f.verify, writerContext: f.writerContext, now: f.now };
  assert.throws(() => commitSecurityComponentState(options)); assert.equal(writes, 1);
  if (outcome === "response-lost-after-write") {
    assert.equal(commitSecurityComponentState(options).alreadyCurrent, true); assert.equal(writes, 1);
  } else if (outcome !== "before-write") {
    assert.throws(() => commitSecurityComponentState(options)); assert.equal(writes, 1);
  } else assert.equal(durable.historicalRuntimeRetention, undefined);
});


test("retained immutable image authority does not depend on later mutable ECR metadata or grants", () => {
  const f = historicalRuntimeFixture(), state = committed(f);
  f.reader.describeRepositories = f.reader.describeImages = () => { throw new Error("ECR metadata is not authoritative after signed retention"); };
  assert.equal(authenticateRetainedHistoricalRuntime({ state, reader: f.reader, verify: f.verify }).runtime.imageDigest, f.imageDigest);
  f.task.containers[0].imageDigest = `sha256:${"0".repeat(64)}`;
  assert.throws(() => authenticateRetainedHistoricalRuntime({ state, reader: f.reader, verify: f.verify }));
});


test("a renamed standalone family cannot hide another worker or bypass omitted retention", () => {
  const f = historicalRuntimeFixture();
  const foreign = { ...structuredClone(f.task), taskArn: f.taskArn.replace(/1$/, "2"), taskDefinitionArn: f.definitionArn.replace("mscqr-production-rls-green-worker-candidate", "legacy-renamed-task") };
  f.tasks.push(foreign);
  const readDefinition = f.reader.describeTaskDefinition;
  f.reader.describeTaskDefinition = (arn) => arn === foreign.taskDefinitionArn ? { taskDefinition: { ...f.definition, taskDefinitionArn: arn, family: "legacy-renamed-task" } } : readDefinition(arn);
  assert.throws(() => verifyHistoricalRuntimeInventory({ reference: f.reference, reader: f.reader }), /second worker/);
  f.tasks.shift();
  assert.throws(() => verifyHistoricalRuntimeHandoff({ state: f.state, reader: f.reader }), /requires/);
});


for (const field of ["updatedByLane", "updatedByWorkflow", "githubRunId"]) test(`raw CAS cannot install historical retention with wrong ${field}`, () => {
  const f = historicalRuntimeFixture(), next = structuredClone(committed(f));
  next[field] = field === "updatedByLane" ? "NORMAL_APPLICATION" : field === "githubRunId" ? "999" : "unrelated-workflow";
  assert.throws(() => componentStateCasRequest({ current: f.state, next }));
});

const additionalWorkloads = [
  ["service worker role", "service:renamed-service", "WORKER", definition => { definition.taskRoleArn = "arn:aws:iam::368992683803:role/mscqr-production-rls-green-worker-task"; }],
  ["service worker image", "service:renamed-service", "WORKER", (definition, task, f) => { definition.containerDefinitions[0].image = f.definition.containerDefinitions[0].image; }],
  ["service worker entrypoint", "service:renamed-service", "WORKER", definition => { definition.containerDefinitions[0].entryPoint = ["node", "dist/worker.js"]; }],
  ["service worker command", "service:renamed-service", "WORKER", definition => { definition.containerDefinitions[0].command = ["node", "dist/worker.js"]; }],
  ["service multiple worker signals", "service:renamed-service", "WORKER", (definition, task, f) => { Object.assign(definition, structuredClone(f.definition), { taskDefinitionArn: task.taskDefinitionArn, family: "renamed-family" }); }],
  ["backend service", "service:backend", "DEFINITELY_NON_WORKER", () => {}],
  ["frontend service", "service:frontend", "DEFINITELY_NON_WORKER", definition => { definition.taskRoleArn = "arn:aws:iam::368992683803:role/mscqr-ecs-task-role"; definition.containerDefinitions[0] = { name: "frontend", image: `368992683803.dkr.ecr.eu-west-2.amazonaws.com/mscqr-web@sha256:${"d".repeat(64)}`, entryPoint: ["nginx"] }; }],
  ["display service named worker", "service:worker", "DEFINITELY_NON_WORKER", () => {}],
  ["renamed non-worker service", "service:unrelated", "DEFINITELY_NON_WORKER", () => {}],
  ["ambiguous worker container", "service:renamed-service", "AMBIGUOUS_WORKER_IDENTITY", definition => { definition.containerDefinitions[0].name = "worker"; }],
  ["mutable worker image", "service:renamed-service", "AMBIGUOUS_WORKER_IDENTITY", definition => { definition.containerDefinitions[0].image = "368992683803.dkr.ecr.eu-west-2.amazonaws.com/mscqr-worker:latest"; }],
  ["foreign worker image", "service:renamed-service", "AMBIGUOUS_WORKER_IDENTITY", definition => { definition.containerDefinitions[0].image = `000000000000.dkr.ecr.eu-west-2.amazonaws.com/mscqr-worker@sha256:${"d".repeat(64)}`; }],
  ["invalid definition in worker family", "service:unrelated", "AMBIGUOUS_WORKER_IDENTITY", (definition, task, f) => { task.taskDefinitionArn = f.definitionArn.replace(/:7$/, ":8"); definition.taskDefinitionArn = task.taskDefinitionArn; }],
  ["standalone renamed worker", "family:renamed-family", "WORKER", definition => { definition.containerDefinitions[0].entryPoint = ["node", "dist/worker.js"]; }],
  ["service role override", "service:renamed-service", "WORKER", (definition, task, f) => { task.overrides = { taskRoleArn: f.definition.taskRoleArn }; }],
  ["service command override", "service:renamed-service", "WORKER", (definition, task) => { task.overrides = { containerOverrides: [{ name: "backend", command: ["node", "dist/worker.js"] }] }; }],
  ["ambiguous override identity", "service:renamed-service", "AMBIGUOUS_WORKER_IDENTITY", (definition, task) => { task.overrides = { containerOverrides: [{ name: "worker" }] }; }],
];
for (const [name, group, expected, configure] of additionalWorkloads) test(`complete workload census: ${name}`, () => {
  const f = historicalRuntimeFixture(), extra = { taskArn: f.taskArn.replace(/1$/, "2"), taskDefinitionArn: f.definitionArn.replace("mscqr-production-rls-green-worker-candidate", "renamed-family").replace(/:7$/, ":8"), group, lastStatus: "RUNNING", desiredStatus: "RUNNING" };
  const definition = { taskDefinitionArn: extra.taskDefinitionArn, family: "renamed-family", taskRoleArn: "arn:aws:iam::368992683803:role/mscqr-production-rls-green-backend-task", containerDefinitions: [{ name: "backend", image: `368992683803.dkr.ecr.eu-west-2.amazonaws.com/mscqr-backend@sha256:${"d".repeat(64)}`, entryPoint: ["node", "dist/server.js"] }] };
  configure(definition, extra, f); f.tasks.push(extra);
  const original = f.reader.describeTaskDefinition; let extraReads = 0;
  f.reader.describeTaskDefinition = arn => { if (arn !== extra.taskDefinitionArn) return original(arn); extraReads++; return { taskDefinition: definition }; };
  assert.equal(classifyHistoricalWorkerWorkload({ task: extra, definition }), expected);
  if (expected === "DEFINITELY_NON_WORKER") assert.equal(verifyHistoricalRuntimeInventory({ reference: f.reference, reader: f.reader }), true);
  else {
    if (expected === "WORKER") assert.equal(historicalWorkerTasks({ tasks: f.tasks, reader: f.reader }).length, 2);
    assert.throws(() => verifyHistoricalRuntimeInventory({ reference: f.reference, reader: f.reader }), /second worker|Ambiguous worker/);
  }
  assert.ok(extraReads > 0, "Service membership must never skip definition inspection");
});

test("retained exact task cannot acquire service membership", () => {
  const f = historicalRuntimeFixture(); f.task.group = "service:renamed-service";
  assert.throws(() => verifyHistoricalRuntimeInventory({ reference: f.reference, reader: f.reader }));
});

test("an unreadable or incomplete additional service definition fails closed", () => {
  const f = historicalRuntimeFixture(); const extra = { ...f.task, taskArn: f.taskArn.replace(/1$/, "2"), taskDefinitionArn: f.definitionArn.replace(/:7$/, ":8"), group: "service:unrelated" }; f.tasks.push(extra);
  const original = f.reader.describeTaskDefinition;
  f.reader.describeTaskDefinition = arn => { if (arn === extra.taskDefinitionArn) throw new Error("read denied"); return original(arn); };
  assert.throws(() => verifyHistoricalRuntimeInventory({ reference: f.reference, reader: f.reader }), /read denied/);
  f.reader.describeTaskDefinition = arn => arn === extra.taskDefinitionArn ? { taskDefinition: { taskDefinitionArn: arn } } : original(arn);
  assert.throws(() => verifyHistoricalRuntimeInventory({ reference: f.reference, reader: f.reader }), /incomplete/);
});

// Exercise the actual projection, not a reconstructed task passed to the census.
for (const [name, group, overrides, expected] of [
  ["standalone role override", "family:unrelated", { taskRoleArn: "arn:aws:iam::368992683803:role/mscqr-production-rls-green-worker-task" }, "WORKER"],
  ["standalone command override", "family:unrelated", { containerOverrides: [{ name: "backend", command: ["node", "dist/worker.js"] }] }, "WORKER"],
  ["service role override", "service:unrelated", { taskRoleArn: "arn:aws:iam::368992683803:role/mscqr-production-rls-green-worker-task" }, "WORKER"],
  ["service command override", "service:unrelated", { containerOverrides: [{ name: "backend", command: ["node", "dist/worker.js"] }] }, "WORKER"],
  ["entrypoint override", "service:unrelated", { containerOverrides: [{ name: "backend", entryPoint: ["node", "dist/worker.js"] }] }, "WORKER"],
  ["ambiguous container override", "service:unrelated", { containerOverrides: [{ name: "worker" }] }, "AMBIGUOUS_WORKER_IDENTITY"],
  ["unrelated override", "family:unrelated", { containerOverrides: [{ name: "backend", environment: [{ name: "MODE", value: "normal" }] }] }, "DEFINITELY_NON_WORKER"],
  ["backend command override", "service:backend", { containerOverrides: [{ name: "backend", command: ["node", "dist/server.js"] }] }, "DEFINITELY_NON_WORKER"],
  ["frontend override", "service:frontend", { containerOverrides: [{ name: "frontend", command: ["nginx"] }] }, "DEFINITELY_NON_WORKER"],
  ["no overrides", "service:unrelated", undefined, "DEFINITELY_NON_WORKER"],
  ["empty overrides", "service:unrelated", {}, "DEFINITELY_NON_WORKER"],
  ["empty container overrides", "service:unrelated", { containerOverrides: [] }, "DEFINITELY_NON_WORKER"],
]) test(`projection preserves census semantics: ${name}`, async () => {
  const { observeStageBEcs } = await import("../aws/production-green-stage-b-ecs-observations.mjs");
  const f = historicalRuntimeFixture();
  const definition = { ...f.definition, family: "unrelated", taskDefinitionArn: f.definitionArn.replace("mscqr-production-rls-green-worker-candidate", "unrelated"), taskRoleArn: "arn:aws:iam::368992683803:role/backend", containerDefinitions: [{ name: "backend", image: "example/non-worker", command: ["node", "dist/server.js"] }] };
  const task = { ...f.task, group, taskDefinitionArn: definition.taskDefinitionArn };
  if (overrides === undefined) delete task.overrides; else task.overrides = structuredClone(overrides);
  const reader = { listServices: () => [], listTasks: () => [task.taskArn], describeTasks: () => ({ tasks: [task], failures: [] }), describeTaskDefinition: () => ({ taskDefinition: definition }) };
  const observed = observeStageBEcs({ reader }).runningTasks[0];
  for (const field of ["taskArn", "taskDefinitionArn", "group", "lastStatus", "desiredStatus", "overrides"]) assert.deepEqual(observed[field], task[field]);
  assert.equal(classifyHistoricalWorkerWorkload({ task, definition }), expected);
  assert.equal(classifyHistoricalWorkerWorkload({ task: observed, definition }), expected);
  if (task.overrides) {
    observed.overrides.containerOverrides = [{ name: "tampered" }];
    assert.deepEqual(task.overrides, overrides, "Observation must not mutate the raw identity");
  }
});

test("projected overrides cannot substitute or mutate the retained exact identity", async () => {
  const { observeStageBEcs } = await import("../aws/production-green-stage-b-ecs-observations.mjs");
  const f = historicalRuntimeFixture();
  const observed = observeStageBEcs({ reader: { ...f.reader, listServices: () => [] } }).runningTasks[0];
  observed.overrides.taskRoleArn = "arn:aws:iam::368992683803:role/other";
  assert.equal(verifyHistoricalRuntimeLive({ reference: f.reference, reader: f.reader }), true);
  f.task.overrides = observed.overrides;
  assert.throws(() => verifyHistoricalRuntimeLive({ reference: f.reference, reader: f.reader }));
});
