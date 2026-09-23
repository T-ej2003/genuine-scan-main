import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import { createRequire } from "node:module";
import { B01_PREREQUISITE, assertB01ExecutorAwsEvidence, assertB01LivePredecessor, assertB01PrerequisiteReceipt, assertB01ReceiptExecutorContract,
  assertB01RunTaskRequestEvidence, assertSemanticallyEmptyB01TaskOverrides, attestBridgeDiff, buildB01ExecutorDefinition, buildB01PrerequisiteReceipt,
  buildB01ReadOnlyDefinition, buildB01RunTaskRequest, canonicalSha256, classifyBridgeFiles } from "../aws/production-b01-prerequisite-contract.mjs";
import { authenticateB01RunTaskCloudTrail, b01CatalogueRuntimeSource, buildB01ExecutorInput, buildB01ReadOnlyInput,
  canonicalB01Prerequisite, executeB01Transaction } from "../aws/apply-production-b01-prerequisite.mjs";
import { authenticateB01ReadOnlyResult } from "../aws/probe-production-b01-prerequisite.mjs";

const require = createRequire(import.meta.url), runtime = require("../aws/production-b01-prerequisite-executor.cjs");
const readOnlyRuntime = require("../aws/production-b01-prerequisite-readonly.cjs");
const deploymentSourceSha = "1".repeat(40), now = new Date("2026-09-23T12:00:00.000Z");
const bridgeEntry = { file: "scripts/aws/production-b01-prerequisite-contract.mjs", classification: "BRIDGE_DEPLOYMENT_TOOLING", hunkCount: 1 };
const bridgeDiffAttestation = { schemaVersion: 2, rlsDeltaOriginSha: B01_PREREQUISITE.rlsDeltaOriginSha, bridgeOriginSha: B01_PREREQUISITE.bridgeOriginSha, deploymentSourceSha,
  bridge: { base: B01_PREREQUISITE.rlsDeltaOriginSha, target: B01_PREREQUISITE.bridgeOriginSha, entries: [bridgeEntry], patchSha256: "2".repeat(64) },
  predecessorCorrection: { base: B01_PREREQUISITE.bridgeOriginSha, target: B01_PREREQUISITE.correctionBaseSha, entries: [bridgeEntry], patchSha256: "3".repeat(64) },
  correction: { base: B01_PREREQUISITE.correctionBaseSha, target: deploymentSourceSha, entries: [bridgeEntry], patchSha256: "4".repeat(64) } };
bridgeDiffAttestation.attestationSha256 = canonicalSha256(bridgeDiffAttestation);
const executor = fs.readFileSync("scripts/aws/production-b01-prerequisite-executor.cjs", "utf8"), executorSourceSha256 = crypto.createHash("sha256").update(executor).digest("hex");
const taskArn = "arn:aws:ecs:eu-west-2:368992683803:task/mscqr-prod-euw2-main/" + "a".repeat(32);
const taskDefinitionArn = "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-production-b01-prerequisite:1";
const runTaskRequest = buildB01RunTaskRequest({ taskDefinitionArn, deploymentSourceSha });
const runTaskRequestBody = { eventId: "12345678-1234-1234-1234-123456789abc", eventTime: new Date(now.getTime() - 20_000).toISOString(), taskArn, taskDefinitionArn,
  cluster: "arn:aws:ecs:eu-west-2:368992683803:cluster/mscqr-prod-euw2-main", launchType: "FARGATE", count: 1, enableExecuteCommand: false, overridesPresent: false };
const runTaskRequestEvidence = { ...runTaskRequestBody, requestSha256: canonicalSha256(runTaskRequest) };

const receipt = (changes = {}) => buildB01PrerequisiteReceipt({ deploymentSourceSha, predecessorRlsIdentity: "3".repeat(64), successorRlsIdentity: "4".repeat(64),
  liveRlsIdentity: "4".repeat(64), executorSourceSha256, executorContractSha256: "5".repeat(64), executorCommandSha256: "6".repeat(64),
  executionResult: "APPLIED", writeCount: 7, taskArn, taskDefinitionArn, runTaskRequestEvidence, bridgeDiffAttestation,
  executedAt: now.toISOString(), expiresAt: new Date(now.getTime() + B01_PREREQUISITE.maxReceiptAgeMs).toISOString(), ...changes });
const reseal = (value, changes) => { const body = { ...value, ...changes }; delete body.receiptSha256; return { ...body, receiptSha256: canonicalSha256(body) }; };

test("bridge diff accepts only the reviewed bridge inventory and binds exact patch bytes", () => {
  const files = [".github/workflows/production-deploy.yml", "scripts/aws/production-b01-prerequisite-contract.mjs", "scripts/tests/production-b01-prerequisite.test.mjs"];
  const patch = files.map((file) => `diff --git a/${file} b/${file}\n@@ -1 +1 @@\n-old\n+new`).join("\n");
  const calls = [], attestation = attestBridgeDiff({ deploymentSourceSha, git: (args) => { calls.push(args); if (args[0] === "merge-base") return "";
    if (args[0] === "rev-parse") return args[1] === `${B01_PREREQUISITE.bridgeOriginSha}^1` ? B01_PREREQUISITE.rlsDeltaOriginSha
      : args[1] === `${B01_PREREQUISITE.correctionBaseSha}^1` ? B01_PREREQUISITE.bridgeOriginSha : B01_PREREQUISITE.correctionBaseSha;
    if (args.includes("--name-only")) return files.join("\n"); return patch; } });
  assert.equal(attestation.rlsDeltaOriginSha, B01_PREREQUISITE.rlsDeltaOriginSha); assert.equal(attestation.deploymentSourceSha, deploymentSourceSha);
  assert.equal(attestation.bridgeOriginSha, B01_PREREQUISITE.bridgeOriginSha); assert.equal(attestation.bridge.entries.length, 3);
  assert.equal(attestation.predecessorCorrection.entries.length, 3); assert.equal(attestation.correction.entries.length, 3);
  assert.ok([...attestation.bridge.entries, ...attestation.predecessorCorrection.entries, ...attestation.correction.entries].every(({ hunkCount }) => hunkCount === 1));
  assert.match(attestation.bridge.patchSha256, /^[a-f0-9]{64}$/); assert.match(attestation.predecessorCorrection.patchSha256, /^[a-f0-9]{64}$/);
  assert.match(attestation.correction.patchSha256, /^[a-f0-9]{64}$/);
  assert.deepEqual(calls.filter(([name]) => name === "merge-base").map((args) => args.slice(2)), [[B01_PREREQUISITE.rlsDeltaOriginSha, B01_PREREQUISITE.bridgeOriginSha],
    [B01_PREREQUISITE.bridgeOriginSha, B01_PREREQUISITE.correctionBaseSha], [B01_PREREQUISITE.correctionBaseSha, deploymentSourceSha]]);
});

test("bridge attestation accepts only the immediate reviewed correction successor", () => {
  assert.throws(() => attestBridgeDiff({ deploymentSourceSha, git: (args) => args[0] === "merge-base" ? "" : args[0] === "rev-parse" ? "f".repeat(40) : "" }),
    /Reviewed bridge origin|immediate protected-main prerequisite-correction successor/);
  assert.throws(() => attestBridgeDiff({ deploymentSourceSha, git: (args) => args[0] === "merge-base" ? "" : args[0] === "rev-parse"
    ? args[1] === `${B01_PREREQUISITE.bridgeOriginSha}^1` ? B01_PREREQUISITE.rlsDeltaOriginSha
      : args[1] === `${B01_PREREQUISITE.correctionBaseSha}^1` ? B01_PREREQUISITE.bridgeOriginSha : "f".repeat(40) : "" }),
  /immediate protected-main runtime-evidence successor/);
});

test("application, auth, RLS, schema, and unclassified bridge changes fail closed", () => {
  for (const file of ["backend/src/index.ts", "backend/src/services/auth/refreshTokenService.ts", "backend/src/rls-waves/session-b/b01/b01RefreshRotationFunctions.sql",
    "backend/prisma/schema.prisma", "src/business.ts", "README.md"]) assert.throws(() => classifyBridgeFiles([file]), /unclassified or semantic/);
  assert.throws(() => classifyBridgeFiles(["scripts/aws/production-b01-prerequisite-contract.mjs", "scripts/aws/production-b01-prerequisite-contract.mjs"]), /duplicate/);
});

test("live B01 executor predecessor is exact revision 19, immutable image, and source", () => {
  const service = { serviceArn: B01_PREREQUISITE.predecessorServiceArn, serviceName: "mscqr-backend-servi-euw2",
    clusterArn: `arn:aws:ecs:${B01_PREREQUISITE.region}:${B01_PREREQUISITE.account}:cluster/${B01_PREREQUISITE.cluster}`,
    status: "ACTIVE", taskDefinition: B01_PREREQUISITE.predecessorTaskDefinitionArn, desiredCount: 2, runningCount: 2, pendingCount: 0,
    enableExecuteCommand: true, propagateTags: "TASK_DEFINITION", deploymentConfiguration: { deploymentCircuitBreaker: { enable: true, rollback: true },
      alarms: { alarmNames: ["mscqr-production-backend-unhealthy-hosts", "mscqr-production-backend-target-5xx"], rollback: true, enable: true } },
    deployments: [{ status: "PRIMARY", taskDefinition: B01_PREREQUISITE.predecessorTaskDefinitionArn, desiredCount: 2, runningCount: 2, pendingCount: 0, failedTasks: 0, rolloutState: "COMPLETED" }] };
  const taskDefinition = { taskDefinitionArn: B01_PREREQUISITE.predecessorTaskDefinitionArn, family: "mscqr-production-rls-green-backend-candidate", revision: 19,
    status: "ACTIVE", networkMode: "awsvpc", requiresCompatibilities: ["FARGATE"], cpu: "2048", memory: "4096",
    executionRoleArn: "arn:aws:iam::368992683803:role/mscqr-production-rls-green-backend-execution",
    taskRoleArn: "arn:aws:iam::368992683803:role/mscqr-production-rls-green-backend-task", runtimePlatform: B01_PREREQUISITE.runtimePlatform,
    containerDefinitions: [{ name: "backend", image: B01_PREREQUISITE.executorImage, essential: true, entryPoint: [], command: [], readonlyRootFilesystem: true, privileged: false }] };
  const repository = { repositoryArn: "arn:aws:ecr:eu-west-2:368992683803:repository/mscqr-backend", repositoryName: "mscqr-backend", registryId: B01_PREREQUISITE.account, imageTagMutability: "IMMUTABLE" };
  const imageDetails = [{ imageDigest: B01_PREREQUISITE.executorImage.split("@")[1], imageTags: [B01_PREREQUISITE.predecessorSourceSha, "production"] }];
  assert.equal(assertB01LivePredecessor({ service, taskDefinition, repository, imageDetails }), true);
  const historical = structuredClone(taskDefinition); historical.containerDefinitions[0].image = "368992683803.dkr.ecr.eu-west-2.amazonaws.com/mscqr-backend@sha256:d2a6f641f44e27454a80d502914a9e168c61cdace1201f9d7af9d85a87ea208c";
  assert.throws(() => assertB01LivePredecessor({ service, taskDefinition: historical, repository, imageDetails }));
  assert.throws(() => assertB01LivePredecessor({ service, taskDefinition, repository, imageDetails: [{ ...imageDetails[0], imageDigest: `sha256:${"0".repeat(64)}` }] }));
  assert.throws(() => assertB01LivePredecessor({ service, taskDefinition, repository, imageDetails: [{ ...imageDetails[0], imageTags: ["0".repeat(40)] }] }));
  assert.throws(() => assertB01LivePredecessor({ service: { ...service, taskDefinition: service.taskDefinition.replace(":19", ":18") }, taskDefinition, repository, imageDetails }));
  assert.throws(() => assertB01LivePredecessor({ service, taskDefinition, repository: { ...repository, imageTagMutability: "MUTABLE" }, imageDetails }));
});

test("revision 19 backend runtime contains the fixed inline executor dependencies", () => {
  const dockerfile = fs.readFileSync("backend/Dockerfile", "utf8"), runtimeStage = dockerfile.split("FROM node:24-bookworm-slim AS production-rls-executor")[0];
  const backendPackage = JSON.parse(fs.readFileSync("backend/package.json", "utf8"));
  assert.match(runtimeStage, /FROM node:24-bookworm-slim AS runtime/); assert.match(runtimeStage, /COPY --from=builder[^\n]+node_modules \.\/node_modules/);
  assert.ok(backendPackage.dependencies["@prisma/client"]); assert.deepEqual(buildB01ExecutorDefinition(["-e", "source"]).containerDefinitions[0].entryPoint, ["node"]);
});

test("receipt binds different RLS origin and current deployment source and rejects tampering or staleness", () => {
  const value = receipt(); assert.notEqual(value.rlsDeltaOriginSha, value.deploymentSourceSha);
  assert.equal(assertB01PrerequisiteReceipt(value, { deploymentSourceSha, bridgeDiffAttestation, now: now.getTime() }).receiptSha256, value.receiptSha256);
  for (const changed of [{ rlsDeltaOriginSha: "0".repeat(40) }, { deploymentSourceSha: "9".repeat(40) }, { environment: "staging" },
    { successorRlsIdentity: "8".repeat(64) }, { migrationSetDigest: "8".repeat(64) }, { bridgeDiffAttestation: { ...bridgeDiffAttestation,
      correction: { ...bridgeDiffAttestation.correction, patchSha256: "8".repeat(64) } } }]) {
    assert.throws(() => assertB01PrerequisiteReceipt({ ...value, ...changed }, { deploymentSourceSha, bridgeDiffAttestation, now: now.getTime() }));
  }
  assert.throws(() => assertB01PrerequisiteReceipt(value, { deploymentSourceSha, bridgeDiffAttestation, now: now.getTime() + B01_PREREQUISITE.maxReceiptAgeMs }));
});

test("executor command contains only the seven source-fixed #567 mutations", async () => {
  const delta = canonicalB01Prerequisite(); assert.equal(delta.mutations.length, 7); assert.equal(delta.predecessor.policies.length + 1, delta.successor.policies.length);
  assert.equal(delta.predecessor.functions.length + 1, delta.successor.functions.length); assert.equal(delta.predecessor.catalogue.payload_column_select, true);
  assert.equal(delta.successor.catalogue.payload_column_select, true);
  const built = buildB01ExecutorInput({ deploymentSourceSha, databaseHostname: "db.synthetic.invalid" });
  assert.equal(built.contract.rlsDeltaOriginSha, B01_PREREQUISITE.rlsDeltaOriginSha); assert.equal(built.contract.deploymentSourceSha, deploymentSourceSha);
  const attacked = structuredClone(built); attacked.contract.mutations[0].sql += "\nDELETE FROM public.\"User\"";
  const state = stateFixture(delta.predecessor); const harness = transactionHarness([state]);
  await assert.rejects(executeB01Transaction({ tx: harness.tx, input: attacked, collect: harness.collect })); assert.equal(harness.writes.length, 0);
});

test("read-only command reuses the exact mutation catalogue collector and cannot reach mutation code", () => {
  const built = buildB01ReadOnlyInput({ deploymentSourceSha, databaseHostname: "db.synthetic.invalid" });
  const source = built.command[1], shared = b01CatalogueRuntimeSource();
  assert.ok(source.includes(shared));
  assert.match(source, /SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY/);
  assert.doesNotMatch(shared, /EXPECTED_MUTATIONS|CREATE POLICY|GRANT EXECUTE|executeB01Transaction|AUTHORIZED_MUTATION/);
  assert.doesNotMatch(source, /executeB01Transaction|mutation\.sql|SET LOCAL ROLE/);
  const definition = buildB01ReadOnlyDefinition(built.command);
  assert.equal(definition.family, B01_PREREQUISITE.readOnlyFamily);
  assert.equal(definition.containerDefinitions[0].name, B01_PREREQUISITE.readOnlyContainer);
  assert.deepEqual(definition.containerDefinitions[0].entryPoint, ["node"]);
  assert.deepEqual(definition.containerDefinitions[0].command, built.command);
  assert.throws(() => buildB01ReadOnlyInput({ deploymentSourceSha: "main", databaseHostname: "db.synthetic.invalid" }));
  assert.throws(() => buildB01ReadOnlyInput({ deploymentSourceSha, databaseHostname: "db.invalid/other" }));
});

test("read-only collector classifies exact predecessor, successor, partial, and unknown safely", async () => {
  const delta = canonicalB01Prerequisite(), contract = buildB01ReadOnlyInput({ deploymentSourceSha, databaseHostname: "db.synthetic.invalid" }).contract;
  const execute = async (state) => readOnlyRuntime.executeB01ReadOnlyTransaction({
    client: { $transaction: async (callback) => callback({ $executeRawUnsafe: async (sql) => assert.equal(sql, "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY") }) },
    input: { contract }, collect: async () => state, inspect: runtime.inspectB01State,
  });
  assert.equal((await execute(stateFixture(delta.predecessor, { identity: { ...identity, read_only: "on" } }))).classification, "PREDECESSOR");
  assert.equal((await execute(stateFixture(delta.successor, { identity: { ...identity, read_only: "on" } }))).classification, "SUCCESSOR");
  const partial = await execute(stateFixture(delta.predecessor, { identity: { ...identity, read_only: "on" }, functions: [] }));
  assert.deepEqual({ classification: partial.classification, unauthorizedCatalogueDelta: partial.unauthorizedCatalogueDelta,
    mismatchIdentifiers: partial.mismatchIdentifiers }, { classification: "PARTIAL", unauthorizedCatalogueDelta: true, mismatchIdentifiers: ["CATALOGUE_IDENTITY"] });
  await assert.rejects(() => execute(stateFixture(delta.predecessor)), /read_only/);
  const unknownBody = { schemaVersion: 1, kind: "PRODUCTION_B01_READONLY_RESULT", mode: "READ_ONLY", classification: "UNKNOWN",
    stage: "DATABASE_CONNECTIVITY", code: "UNEXPECTED_FAILURE" };
  assert.equal(authenticateB01ReadOnlyResult(JSON.stringify({ ...unknownBody, evidenceSha256: canonicalSha256(unknownBody) }), contract).classification, "UNKNOWN");
});

test("structured executor telemetry exposes only allowlisted stages and sanitized codes", () => {
  assert.deepEqual(runtime.FAILURE_STAGES, ["BOOTSTRAP","INPUT_AUTHENTICATION","SECRET_ACCESS","DATABASE_CONNECTIVITY","PREDECESSOR_COLLECTION",
    "PREDECESSOR_CLASSIFICATION","TRANSACTION_BEGIN","AUTHORIZED_MUTATION","SUCCESSOR_COLLECTION","SUCCESSOR_CLASSIFICATION","COMMIT","RECEIPT_PRECONDITION"]);
  const secret = "synthetic-sensitive-canary-value";
  for (const stage of runtime.FAILURE_STAGES) {
    const evidence = runtime.safeFailure(stage, Object.assign(new Error(secret), { code: "P1001" }));
    assert.deepEqual(evidence, { status: "PRODUCTION_B01_PREREQUISITE_FAILED", stage, code: "P1001" });
    assert.doesNotMatch(JSON.stringify(evidence), /synthetic-sensitive-canary-value/);
  }
  assert.equal(runtime.safeFailure("BOOTSTRAP", Object.assign(new Error(secret), { code: "SENSITIVE_CUSTOM_CODE" })).code, "UNEXPECTED_FAILURE");
  assert.throws(() => runtime.safeFailure("NOT_A_STAGE", new Error(secret)));
  const executed = spawnSync(process.execPath, ["-e", executor], { encoding: "utf8", env: { MSCQR_B01_PREREQUISITE_ADMIN_PASSWORD: secret } });
  assert.equal(executed.status, 1); const emitted = JSON.parse(executed.stderr);
  assert.deepEqual(emitted, { status: "PRODUCTION_B01_PREREQUISITE_FAILED", stage: "INPUT_AUTHENTICATION", code: "CONTRACT_REJECTED" });
  assert.doesNotMatch(executed.stderr, /admin:secret|private-db|user-data/); assert.equal(executed.stdout, "");
});

test("receipt RLS identities must match the reconstructed source-fixed executor contract", () => {
  const built = buildB01ExecutorInput({ deploymentSourceSha, databaseHostname: "db.synthetic.invalid" });
  const value = receipt({ predecessorRlsIdentity: built.contract.predecessorRlsIdentity, successorRlsIdentity: built.contract.successorRlsIdentity,
    liveRlsIdentity: built.contract.successorRlsIdentity, executorSourceSha256: built.contract.executorSourceSha256,
    executorContractSha256: built.contractSha256, executorCommandSha256: built.commandSha256 });
  assert.equal(assertB01ReceiptExecutorContract(value, built.contract), true);
  const wrong = receipt({ predecessorRlsIdentity: built.contract.predecessorRlsIdentity, successorRlsIdentity: "8".repeat(64), liveRlsIdentity: "8".repeat(64),
    executorSourceSha256: built.contract.executorSourceSha256, executorContractSha256: built.contractSha256, executorCommandSha256: built.commandSha256 });
  assert.throws(() => assertB01ReceiptExecutorContract(wrong, built.contract));
  for (const change of [{ rlsDeltaOriginSha: "8".repeat(40) }, { deploymentSourceSha: "8".repeat(40) }, { predecessorRlsIdentity: "8".repeat(64) },
    { successorRlsIdentity: "8".repeat(64), liveRlsIdentity: "8".repeat(64) }, { liveRlsIdentity: "8".repeat(64) },
    { sourceContractSha256: "8".repeat(64) }, { migrationSetDigest: "8".repeat(64) }, { executorSourceSha256: "8".repeat(64) },
    { executorContractSha256: "8".repeat(64) }]) assert.throws(() => assertB01ReceiptExecutorContract(reseal(value, change), built.contract));
});

const identity = { role: "mscqr_prod_admin", session_role: "mscqr_prod_admin", database: "mscqr_production_rls_green_phase2", read_only: "off",
  server_major: 18, rolcanlogin: true, rolsuper: false, rolinherit: false, rolcreaterole: true, rolcreatedb: true, rolreplication: false, rolbypassrls: false };
const stateFixture = (value, changes = {}) => ({ identity, roles: value.roles, functions: value.functions, policies: value.policies, catalogue: value.catalogue, ...changes });
const transactionHarness = (states, failOn = "") => {
  const writes = [], tx = { async $executeRawUnsafe(sql) { writes.push(sql); if (sql.includes(failOn) && failOn) throw new Error("injected failure"); } };
  return { tx, writes, collect: async () => states.shift() };
};

test("exact predecessor converges atomically and exact successor is idempotent", async () => {
  const delta = canonicalB01Prerequisite(), built = buildB01ExecutorInput({ deploymentSourceSha, databaseHostname: "db.synthetic.invalid" });
  const applied = transactionHarness([stateFixture(delta.predecessor), stateFixture(delta.successor)]);
  assert.deepEqual(await executeB01Transaction({ tx: applied.tx, input: { contract: built.contract }, collect: applied.collect }), {
    status: "APPLIED", writeCount: 7, predecessorRlsIdentity: delta.predecessorRlsIdentity, successorRlsIdentity: delta.successorRlsIdentity, liveRlsIdentity: delta.successorRlsIdentity });
  assert.equal(applied.writes.filter((sql) => built.contract.mutations.some((mutation) => mutation.sql === sql)).length, 7);
  const converged = transactionHarness([stateFixture(delta.successor)]);
  assert.equal((await executeB01Transaction({ tx: converged.tx, input: { contract: built.contract }, collect: converged.collect })).writeCount, 0);
  assert.equal(converged.writes.filter((sql) => built.contract.mutations.some((mutation) => mutation.sql === sql)).length, 0);
});

test("wrong function, policy, grant, missing object, and conflicting object fail before mutation", async () => {
  const delta = canonicalB01Prerequisite(), built = buildB01ExecutorInput({ deploymentSourceSha, databaseHostname: "db.synthetic.invalid" });
  const attacks = [
    { ...stateFixture(delta.predecessor), functions: [{ ...delta.predecessor.functions[0], body: "wrong" }] },
    { ...stateFixture(delta.predecessor), policies: delta.predecessor.policies.slice(1) },
    { ...stateFixture(delta.predecessor), catalogue: { ...delta.predecessor.catalogue, payload_column_select: false } },
    { ...stateFixture(delta.predecessor), catalogue: { ...delta.predecessor.catalogue, payload_column_acl: [...delta.predecessor.catalogue.payload_column_acl, "mscqr_prd_rls_phase2_preauth|mscqr_prd_rls_phase2_owner|SELECT|f"] } },
    { ...stateFixture(delta.predecessor), catalogue: { ...delta.predecessor.catalogue, table_acl: [...delta.predecessor.catalogue.table_acl, "PUBLIC|mscqr_prd_rls_phase2_owner|SELECT|f"] } },
    { ...stateFixture(delta.predecessor), functions: [{ ...delta.predecessor.functions[0], acl: [...delta.predecessor.functions[0].acl, "mscqr_prd_rls_phase2_preauth|mscqr_prd_rls_phase2_auth_owner|EXECUTE|f"] }] },
    { ...stateFixture(delta.predecessor), functions: [] },
    { ...stateFixture(delta.predecessor), roles: delta.predecessor.roles.map((role, index) => index ? role : { ...role, bypass_rls: true }) },
    { ...stateFixture(delta.predecessor), policies: [...delta.predecessor.policies, { schema: "public", table: "User", name: "b01_conflict", command: "r",
      permissive: true, roles: [], comment: null, using_sha256: "0".repeat(64), with_check_sha256: null }] },
  ];
  for (const state of attacks) { const harness = transactionHarness([state]); await assert.rejects(executeB01Transaction({ tx: harness.tx, input: { contract: built.contract }, collect: harness.collect }));
    assert.equal(harness.writes.some((sql) => built.contract.mutations.some((mutation) => mutation.sql === sql)), false); }
});

test("every B01 policy security field and both predicate expressions are exact", async () => {
  const delta = canonicalB01Prerequisite(), built = buildB01ExecutorInput({ deploymentSourceSha, databaseHostname: "db.synthetic.invalid" });
  const selected = delta.predecessor.policies.find(({ name }) => name === "b01_refreshtoken_select");
  const updated = delta.predecessor.policies.find(({ name }) => name === "b01_refreshtoken_update");
  assert.ok(selected && updated && selected.name !== "b01_auditlogoutbox_select");
  const attacks = [
    [selected.name, { using_sha256: "0".repeat(64) }],
    [updated.name, { with_check_sha256: "0".repeat(64) }],
    [selected.name, { roles: ["PUBLIC"] }],
    [selected.name, { command: "d" }],
    [selected.name, { permissive: false }],
  ];
  for (const [name, change] of attacks) {
    const policies = delta.predecessor.policies.map((policy) => policy.name === name ? { ...policy, ...change } : policy);
    const harness = transactionHarness([stateFixture(delta.predecessor, { policies })]);
    await assert.rejects(executeB01Transaction({ tx: harness.tx, input: { contract: built.contract }, collect: harness.collect }), /neither the exact predecessor nor successor/);
    assert.equal(harness.writes.some((sql) => built.contract.mutations.some((mutation) => mutation.sql === sql)), false);
  }
  const successorPolicies = delta.successor.policies.map((policy) => policy.name === selected.name ? { ...policy, using_sha256: "0".repeat(64) } : policy);
  const successor = transactionHarness([stateFixture(delta.successor, { policies: successorPolicies })]);
  await assert.rejects(executeB01Transaction({ tx: successor.tx, input: { contract: built.contract }, collect: successor.collect }), /neither the exact predecessor nor successor/);
  assert.equal(successor.writes.some((sql) => built.contract.mutations.some((mutation) => mutation.sql === sql)), false);
});

test("every authenticated function property and grant is exact", async () => {
  const delta = canonicalB01Prerequisite(), built = buildB01ExecutorInput({ deploymentSourceSha, databaseHostname: "db.synthetic.invalid" });
  const original = delta.predecessor.functions[0];
  for (const change of [{ body: "wrong" }, { owner: "mscqr_prd_rls_phase2_owner" }, { language: "sql" }, { result: "text" },
    { security_definer: false }, { leakproof: true }, { strict: true }, { volatility: "s" }, { parallel: "s" }, { proconfig: null },
    { public_execute: true }, { preauth_execute: true }, { acl: [] }]) {
    const harness = transactionHarness([stateFixture(delta.predecessor, { functions: [{ ...original, ...change }] })]);
    await assert.rejects(executeB01Transaction({ tx: harness.tx, input: { contract: built.contract }, collect: harness.collect }), /neither the exact predecessor nor successor/);
    assert.equal(harness.writes.some((sql) => built.contract.mutations.some((mutation) => mutation.sql === sql)), false);
  }
});

test("transaction failure prevents successor authentication and is surfaced", async () => {
  const delta = canonicalB01Prerequisite(), built = buildB01ExecutorInput({ deploymentSourceSha, databaseHostname: "db.synthetic.invalid" });
  const harness = transactionHarness([stateFixture(delta.predecessor)], "CREATE POLICY");
  await assert.rejects(executeB01Transaction({ tx: harness.tx, input: { contract: built.contract }, collect: harness.collect }), /injected/);
});

const exactExecutorEvidence = () => {
  let value = { ...receipt() }; const command = ["node-command"];
  const task = { taskArn, taskDefinitionArn, clusterArn: "arn:aws:ecs:eu-west-2:368992683803:cluster/mscqr-prod-euw2-main", lastStatus: "STOPPED", stopCode: "EssentialContainerExited",
    enableExecuteCommand: false, startedAt: new Date(now.getTime() - 10_000).toISOString(), stoppedAt: new Date(now.getTime() + 10_000).toISOString(),
    overrides: { containerOverrides: [{ name: B01_PREREQUISITE.executorContainer }], inferenceAcceleratorOverrides: [] },
    containers: [{ name: B01_PREREQUISITE.executorContainer, exitCode: 0 }] };
  const taskDefinition = { ...buildB01ExecutorDefinition(command), taskDefinitionArn, status: "ACTIVE" };
  // Use an executor command whose inline source is the real executor bytes.
  command.splice(0, 1, "-e", executor); value = { ...value, executorCommandSha256: canonicalSha256(command) }; const payload = { ...value }; delete payload.receiptSha256; value.receiptSha256 = canonicalSha256(payload);
  return { value, task, taskDefinition };
};

test("handoff authenticates stopped exact executor task and rejects definition command substitution", () => {
  const { value, task, taskDefinition } = exactExecutorEvidence();
  assert.equal(assertB01ExecutorAwsEvidence({ receipt: value, task, taskDefinition, expectedExecutorSourceSha256: executorSourceSha256 }), true);
  assert.throws(() => assertB01ExecutorAwsEvidence({ receipt: value, task, taskDefinition: { ...taskDefinition, containerDefinitions: [{ ...taskDefinition.containerDefinitions[0], command: ["-e", "substituted"] }] }, expectedExecutorSourceSha256: executorSourceSha256 }));
  const oldRequest = { ...value.runTaskRequestEvidence, eventTime: new Date(now.getTime() - 10 * 60 * 1000).toISOString() };
  const stale = reseal(value, { runTaskRequestEvidence: oldRequest });
  assert.throws(() => assertB01ExecutorAwsEvidence({ receipt: stale, task, taskDefinition, expectedExecutorSourceSha256: executorSourceSha256 }));
});

test("task-definition evidence accepts only reviewed ECS materialized defaults", () => {
  const { value, task, taskDefinition } = exactExecutorEvidence(), observed = structuredClone(taskDefinition);
  Object.assign(observed, { revision: 1, placementConstraints: [], enableFaultInjection: false, requiresAttributes: [], compatibilities: ["EC2", "FARGATE"] });
  observed.volumes[0].host = {}; Object.assign(observed.containerDefinitions[0], { cpu: 0, environmentFiles: [], portMappings: [], systemControls: [],
    ulimits: [], volumesFrom: [] }); observed.containerDefinitions[0].logConfiguration.secretOptions = [];
  assert.equal(assertB01ExecutorAwsEvidence({ receipt: value, task, taskDefinition: observed, expectedExecutorSourceSha256: executorSourceSha256 }), true);
  assert.throws(() => assertB01ExecutorAwsEvidence({ receipt: value, task, taskDefinition: { ...observed, ipcMode: "host" }, expectedExecutorSourceSha256: executorSourceSha256 }));
  assert.throws(() => assertB01ExecutorAwsEvidence({ receipt: value, task, taskDefinition: { ...observed, enableFaultInjection: true }, expectedExecutorSourceSha256: executorSourceSha256 }));
});

test("CloudTrail proves the RunTask request supplied no runtime overrides", () => {
  const cloudTrail = [{ EventId: runTaskRequestBody.eventId, CloudTrailEvent: JSON.stringify({ eventID: runTaskRequestBody.eventId,
    eventTime: runTaskRequestBody.eventTime, eventSource: "ecs.amazonaws.com", eventName: "RunTask",
    requestParameters: { ...runTaskRequest, dryrun: false, enableECSManagedTags: false },
    responseElements: { tasks: [{ taskArn }] } }) }];
  assert.deepEqual(authenticateB01RunTaskCloudTrail(cloudTrail, { taskArn, taskDefinitionArn, deploymentSourceSha }), runTaskRequestEvidence);
  const contradictory = structuredClone(cloudTrail);
  const event = JSON.parse(contradictory[0].CloudTrailEvent); event.requestParameters.overrides = { containerOverrides: [{ name: B01_PREREQUISITE.executorContainer, command: ["true"] }] };
  contradictory[0].CloudTrailEvent = JSON.stringify(event);
  assert.throws(() => authenticateB01RunTaskCloudTrail(contradictory, { taskArn, taskDefinitionArn, deploymentSourceSha }));
  assert.throws(() => assertB01RunTaskRequestEvidence({ ...runTaskRequestEvidence, overridesPresent: true }, { taskArn, taskDefinitionArn, deploymentSourceSha }));
  const extra = structuredClone(cloudTrail), tagged = JSON.parse(extra[0].CloudTrailEvent); tagged.requestParameters.tags = [{ key: "mode", value: "other" }];
  extra[0].CloudTrailEvent = JSON.stringify(tagged);
  assert.throws(() => authenticateB01RunTaskCloudTrail(extra, { taskArn, taskDefinitionArn, deploymentSourceSha }));
  const activeDefault = structuredClone(cloudTrail), changedDefault = JSON.parse(activeDefault[0].CloudTrailEvent); changedDefault.requestParameters.enableECSManagedTags = true;
  activeDefault[0].CloudTrailEvent = JSON.stringify(changedDefault);
  assert.throws(() => authenticateB01RunTaskCloudTrail(activeDefault, { taskArn, taskDefinitionArn, deploymentSourceSha }));
});

test("handoff accepts only observed inert DescribeTasks materialization and rejects all real overrides", () => {
  const { value, task, taskDefinition } = exactExecutorEvidence();
  const verify = (overrides) => assertB01ExecutorAwsEvidence({ receipt: value, task: overrides === undefined ? task : { ...task, overrides }, taskDefinition, expectedExecutorSourceSha256: executorSourceSha256 });
  for (const empty of [{}, { containerOverrides: [] }, { inferenceAcceleratorOverrides: [] },
    { containerOverrides: [{ name: B01_PREREQUISITE.executorContainer }] },
    { containerOverrides: [{ name: B01_PREREQUISITE.executorContainer }], inferenceAcceleratorOverrides: [] }]) assert.equal(verify(empty), true);
  const rejected = [
    { containerOverrides: [{ name: B01_PREREQUISITE.executorContainer, command: ["sh", "-c", "exit 0"] }] },
    { containerOverrides: [{ name: B01_PREREQUISITE.executorContainer, environment: [{ name: "NODE_OPTIONS", value: "--require=/tmp/noop" }] }] },
    { containerOverrides: [{ name: B01_PREREQUISITE.executorContainer, environmentFiles: [{ type: "s3", value: "arn:aws:s3:::synthetic/env" }] }] },
    { taskRoleArn: "arn:aws:iam::368992683803:role/other" }, { executionRoleArn: "arn:aws:iam::368992683803:role/other" },
    { cpu: "2048" }, { memory: "4096" }, { ephemeralStorage: { sizeInGiB: 40 } },
    { inferenceAcceleratorOverrides: [{ deviceName: "device", deviceType: "synthetic" }] },
    { containerOverrides: [{ name: B01_PREREQUISITE.executorContainer, cpu: 2 }] },
    { containerOverrides: [{ name: B01_PREREQUISITE.executorContainer, memory: 4 }] },
    { containerOverrides: [{ name: B01_PREREQUISITE.executorContainer, memoryReservation: 2 }] },
    { containerOverrides: [{ name: B01_PREREQUISITE.executorContainer, resourceRequirements: [{ type: "GPU", value: "1" }] }] },
    { unknownOverride: true }, { containerOverrides: [{ name: "wrong" }] },
    { containerOverrides: [{ name: B01_PREREQUISITE.executorContainer }, { name: B01_PREREQUISITE.executorContainer }] },
    null, [], { containerOverrides: {} }, { containerOverrides: undefined },
  ];
  for (const overrides of rejected) assert.throws(() => verify(overrides));
  assert.throws(() => assertSemanticallyEmptyB01TaskOverrides({ containerOverrides: [{ name: B01_PREREQUISITE.executorContainer, command: ["sh", "-c", "exit 0"] }] }));
});

test("workflow keeps security classification and reuses the existing backend-only deploy job", () => {
  const workflow = fs.readFileSync(".github/workflows/production-deploy.yml", "utf8");
  assert.match(workflow, /PRIVILEGED_PREREQUISITE_BACKEND/); assert.match(workflow, /verify-production-b01-prerequisite-handoff\.mjs/);
  assert.match(workflow, /frontend=false/); assert.match(workflow, /\.\/scripts\/aws\/deploy-ecs-service\.sh/);
  assert.doesNotMatch(workflow, /terraform apply|DynamoDB|transition UUID/i);
});

test("#567 RLS successor is additive and remains compatible with the deployed predecessor backend", () => {
  const diff = fs.readFileSync("backend/src/rls-waves/session-b/b01/b01RefreshRotationFunctions.sql", "utf8");
  assert.match(diff, /finalize_refresh_token_rotation/); assert.match(diff, /finalize-successor/);
  assert.doesNotMatch(diff, /DROP FUNCTION|DROP POLICY|ALTER TABLE/);
});
