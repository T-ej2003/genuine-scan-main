import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import { createRequire } from "node:module";
import { B01_PREREQUISITE, assertB01ExecutorAwsEvidence, assertB01PrerequisiteReceipt, assertB01ReceiptExecutorContract, attestBridgeDiff, buildB01ExecutorDefinition, buildB01PrerequisiteReceipt,
  canonicalSha256, classifyBridgeFiles } from "../aws/production-b01-prerequisite-contract.mjs";
import { buildB01ExecutorInput, canonicalB01Prerequisite, executeB01Transaction } from "../aws/apply-production-b01-prerequisite.mjs";

const require = createRequire(import.meta.url), runtime = require("../aws/production-b01-prerequisite-executor.cjs");
const deploymentSourceSha = "1".repeat(40), now = new Date("2026-09-23T12:00:00.000Z");
const bridgeDiffAttestation = { schemaVersion: 1, rlsDeltaOriginSha: B01_PREREQUISITE.rlsDeltaOriginSha, deploymentSourceSha,
  entries: [{ file: "scripts/aws/production-b01-prerequisite-contract.mjs", classification: "BRIDGE_DEPLOYMENT_TOOLING" }], patchSha256: "2".repeat(64) };
bridgeDiffAttestation.attestationSha256 = canonicalSha256(bridgeDiffAttestation);
const executor = fs.readFileSync("scripts/aws/production-b01-prerequisite-executor.cjs", "utf8"), executorSourceSha256 = crypto.createHash("sha256").update(executor).digest("hex");
const taskArn = "arn:aws:ecs:eu-west-2:368992683803:task/mscqr-prod-euw2-main/" + "a".repeat(32);
const taskDefinitionArn = "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-production-b01-prerequisite:1";

const receipt = (changes = {}) => buildB01PrerequisiteReceipt({ deploymentSourceSha, predecessorRlsIdentity: "3".repeat(64), successorRlsIdentity: "4".repeat(64),
  liveRlsIdentity: "4".repeat(64), executorSourceSha256, executorContractSha256: "5".repeat(64), executorCommandSha256: "6".repeat(64),
  executionResult: "APPLIED", writeCount: 7, taskArn, taskDefinitionArn, bridgeDiffAttestation,
  executedAt: now.toISOString(), expiresAt: new Date(now.getTime() + B01_PREREQUISITE.maxReceiptAgeMs).toISOString(), ...changes });
const reseal = (value, changes) => { const body = { ...value, ...changes }; delete body.receiptSha256; return { ...body, receiptSha256: canonicalSha256(body) }; };

test("bridge diff accepts only the reviewed bridge inventory and binds exact patch bytes", () => {
  const files = [".github/workflows/production-deploy.yml", "scripts/aws/production-b01-prerequisite-contract.mjs", "scripts/tests/production-b01-prerequisite.test.mjs"];
  const patch = files.map((file) => `diff --git a/${file} b/${file}\n@@ -1 +1 @@\n-old\n+new`).join("\n");
  const calls = [], attestation = attestBridgeDiff({ deploymentSourceSha, git: (args) => { calls.push(args); if (args[0] === "merge-base") return "";
    if (args[0] === "rev-parse") return B01_PREREQUISITE.rlsDeltaOriginSha; if (args.includes("--name-only")) return files.join("\n"); return patch; } });
  assert.equal(attestation.rlsDeltaOriginSha, B01_PREREQUISITE.rlsDeltaOriginSha); assert.equal(attestation.deploymentSourceSha, deploymentSourceSha);
  assert.equal(attestation.entries.length, 3); assert.ok(attestation.entries.every(({ hunkCount }) => hunkCount === 1));
  assert.match(attestation.patchSha256, /^[a-f0-9]{64}$/); assert.equal(calls[0][2], B01_PREREQUISITE.rlsDeltaOriginSha);
});

test("bridge attestation rejects every protected-main advance after the bridge commit", () => {
  assert.throws(() => attestBridgeDiff({ deploymentSourceSha, git: (args) => args[0] === "merge-base" ? "" : args[0] === "rev-parse" ? "f".repeat(40) : "" }),
    /immediate protected-main bridge successor/);
});

test("application, auth, RLS, schema, and unclassified bridge changes fail closed", () => {
  for (const file of ["backend/src/index.ts", "backend/src/services/auth/refreshTokenService.ts", "backend/src/rls-waves/session-b/b01/b01RefreshRotationFunctions.sql",
    "backend/prisma/schema.prisma", "src/business.ts", "README.md"]) assert.throws(() => classifyBridgeFiles([file]), /unclassified or semantic/);
  assert.throws(() => classifyBridgeFiles(["scripts/aws/production-b01-prerequisite-contract.mjs", "scripts/aws/production-b01-prerequisite-contract.mjs"]), /duplicate/);
});

test("receipt binds different RLS origin and current deployment source and rejects tampering or staleness", () => {
  const value = receipt(); assert.notEqual(value.rlsDeltaOriginSha, value.deploymentSourceSha);
  assert.equal(assertB01PrerequisiteReceipt(value, { deploymentSourceSha, bridgeDiffAttestation, now: now.getTime() }).receiptSha256, value.receiptSha256);
  for (const changed of [{ rlsDeltaOriginSha: "0".repeat(40) }, { deploymentSourceSha: "9".repeat(40) }, { environment: "staging" },
    { successorRlsIdentity: "8".repeat(64) }, { migrationSetDigest: "8".repeat(64) }, { bridgeDiffAttestation: { ...bridgeDiffAttestation, patchSha256: "8".repeat(64) } }]) {
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

test("handoff authenticates stopped exact executor task and rejects definition command substitution", () => {
  let value = { ...receipt() }; const command = ["node-command"];
  const task = { taskArn, taskDefinitionArn, clusterArn: "arn:aws:ecs:eu-west-2:368992683803:cluster/mscqr-prod-euw2-main", lastStatus: "STOPPED", stopCode: "EssentialContainerExited",
    enableExecuteCommand: false, startedAt: new Date(now.getTime() - 10_000).toISOString(), stoppedAt: new Date(now.getTime() + 10_000).toISOString(),
    containers: [{ name: B01_PREREQUISITE.executorContainer, exitCode: 0 }] };
  const taskDefinition = { ...buildB01ExecutorDefinition(command), taskDefinitionArn, status: "ACTIVE" };
  // Use an executor command whose inline source is the real executor bytes.
  command.splice(0, 1, "-e", executor); value = { ...value, executorCommandSha256: canonicalSha256(command) }; const payload = { ...value }; delete payload.receiptSha256; value.receiptSha256 = canonicalSha256(payload);
  assert.equal(assertB01ExecutorAwsEvidence({ receipt: value, task, taskDefinition, expectedExecutorSourceSha256: executorSourceSha256 }), true);
  assert.throws(() => assertB01ExecutorAwsEvidence({ receipt: value, task, taskDefinition: { ...taskDefinition, containerDefinitions: [{ ...taskDefinition.containerDefinitions[0], command: ["-e", "substituted"] }] }, expectedExecutorSourceSha256: executorSourceSha256 }));
});

test("handoff rejects every executable or security-relevant RunTask override", () => {
  let value = { ...receipt() }; const command = ["-e", executor];
  value = { ...value, executorCommandSha256: canonicalSha256(command) }; const payload = { ...value }; delete payload.receiptSha256; value.receiptSha256 = canonicalSha256(payload);
  const task = { taskArn, taskDefinitionArn, clusterArn: "arn:aws:ecs:eu-west-2:368992683803:cluster/mscqr-prod-euw2-main", lastStatus: "STOPPED", stopCode: "EssentialContainerExited",
    enableExecuteCommand: false, startedAt: new Date(now.getTime() - 10_000).toISOString(), stoppedAt: new Date(now.getTime() + 10_000).toISOString(),
    containers: [{ name: B01_PREREQUISITE.executorContainer, exitCode: 0 }] };
  const taskDefinition = { ...buildB01ExecutorDefinition(command), taskDefinitionArn, status: "ACTIVE" };
  const verify = (overrides) => assertB01ExecutorAwsEvidence({ receipt: value, task: overrides === undefined ? task : { ...task, overrides }, taskDefinition, expectedExecutorSourceSha256: executorSourceSha256 });
  for (const empty of [undefined, {}, { containerOverrides: [] }]) assert.equal(verify(empty), true);
  const rejected = [
    { containerOverrides: [{ name: B01_PREREQUISITE.executorContainer, command: ["sh", "-c", "exit 0"] }] },
    { containerOverrides: [{ name: B01_PREREQUISITE.executorContainer, environment: [{ name: "NODE_OPTIONS", value: "--require=/tmp/noop" }] }] },
    { containerOverrides: [{ name: B01_PREREQUISITE.executorContainer, environmentFiles: [{ type: "s3", value: "arn:aws:s3:::synthetic/env" }] }] },
    { taskRoleArn: "arn:aws:iam::368992683803:role/other" }, { executionRoleArn: "arn:aws:iam::368992683803:role/other" },
    { cpu: "2048" }, { memory: "4096" }, { ephemeralStorage: { sizeInGiB: 40 } },
    { inferenceAcceleratorOverrides: [{ deviceName: "device", deviceType: "synthetic" }] },
    { containerOverrides: [{ name: B01_PREREQUISITE.executorContainer, cpu: 2, memory: 4, memoryReservation: 2,
      resourceRequirements: [{ type: "GPU", value: "1" }] }] },
    { unknownOverride: true }, { containerOverrides: [{ name: "wrong" }] },
    { containerOverrides: [{ name: B01_PREREQUISITE.executorContainer }, { name: B01_PREREQUISITE.executorContainer }] },
    null, [], { containerOverrides: {} }, { containerOverrides: undefined },
  ];
  for (const overrides of rejected) assert.throws(() => verify(overrides));
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
