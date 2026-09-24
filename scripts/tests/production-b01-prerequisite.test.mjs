import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import { createRequire } from "node:module";
import { B01_PREREQUISITE, assertB01ExecutorAwsEvidence, assertB01ExpiredMutationTaskQuiescent, assertB01LivePredecessor, assertB01PrerequisiteReceipt, assertB01ReceiptExecutorContract,
  assertB01RunTaskRequestEvidence, assertSemanticallyEmptyB01TaskOverrides, attestBridgeDiff, buildB01ExecutorDefinition, buildB01PrerequisiteReceipt,
  buildB01ReadOnlyDefinition, buildB01RunTaskRequest, canonicalSha256, classifyBridgeFiles, assertB01EcsEventCapture,
  authenticateB01TerminalTaskEvents, collectB01TerminalTaskEvents } from "../aws/production-b01-prerequisite-contract.mjs";
import { B01_CLASSIFICATION_INVARIANTS, authenticateB01RunTaskCloudTrail, b01CatalogueRuntimeSource, buildB01ExecutorInput, buildB01ReadOnlyInput,
  canonicalB01Prerequisite, executeB01Transaction } from "../aws/apply-production-b01-prerequisite.mjs";
import { authenticateB01AmbiguousMutationTask, authenticateB01ExpiredMutationTask, authenticateB01MissingTask,
  authenticateB01MutationLaunchHistory, authenticateB01MutationTaskListing, authenticateB01ReadOnlyResult, collectB01RecoveryPostflight,
  collectB01MutationCensus, collectB01MutationTaskArns, collectB01RunTaskEvents, findNonTerminalB01MutationTasks } from "../aws/probe-production-b01-prerequisite.mjs";

const require = createRequire(import.meta.url), runtime = require("../aws/production-b01-prerequisite-executor.cjs");
const readOnlyRuntime = require("../aws/production-b01-prerequisite-readonly.cjs");
const deploymentSourceSha = "1".repeat(40), now = new Date("2026-09-23T12:00:00.000Z");
const bridgeEntry = { file: "scripts/aws/production-b01-prerequisite-contract.mjs", classification: "BRIDGE_DEPLOYMENT_TOOLING", hunkCount: 1 };
const bridgeDiffAttestation = { schemaVersion: 5, rlsDeltaOriginSha: B01_PREREQUISITE.rlsDeltaOriginSha, bridgeOriginSha: B01_PREREQUISITE.bridgeOriginSha, deploymentSourceSha,
  bridge: { base: B01_PREREQUISITE.rlsDeltaOriginSha, target: B01_PREREQUISITE.bridgeOriginSha, entries: [bridgeEntry], patchSha256: "2".repeat(64) },
  predecessorCorrection: { base: B01_PREREQUISITE.bridgeOriginSha, target: B01_PREREQUISITE.correctionBaseSha, entries: [bridgeEntry], patchSha256: "3".repeat(64) },
  runtimeEvidence: { base: B01_PREREQUISITE.correctionBaseSha, target: B01_PREREQUISITE.recoveryBaseSha, entries: [bridgeEntry], patchSha256: "4".repeat(64) },
  expiredTaskRecovery: { base: B01_PREREQUISITE.recoveryBaseSha, target: B01_PREREQUISITE.expiredTaskRecoverySha, entries: [bridgeEntry], patchSha256: "5".repeat(64) },
  terminalEventRecovery: { base: B01_PREREQUISITE.expiredTaskRecoverySha, target: B01_PREREQUISITE.terminalEventRecoverySha, entries: [bridgeEntry], patchSha256: "6".repeat(64) },
  provenanceCorrection: { base: B01_PREREQUISITE.terminalEventRecoverySha, target: B01_PREREQUISITE.provenanceBaseSha, entries: [bridgeEntry], patchSha256: "7".repeat(64) },
  classificationTelemetry: { base: B01_PREREQUISITE.provenanceBaseSha, target: deploymentSourceSha, entries: [bridgeEntry], patchSha256: "8".repeat(64) } };
bridgeDiffAttestation.attestationSha256 = canonicalSha256(bridgeDiffAttestation);
const executor = fs.readFileSync("scripts/aws/production-b01-prerequisite-executor.cjs", "utf8"), executorSourceSha256 = crypto.createHash("sha256").update(executor).digest("hex");
const taskArn = "arn:aws:ecs:eu-west-2:368992683803:task/mscqr-prod-euw2-main/" + "a".repeat(32);
const taskDefinitionArn = "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-production-b01-prerequisite:1";
const ambiguousMutationTaskEvidenceSha256 = "7".repeat(64);
const runTaskRequest = buildB01RunTaskRequest({ taskDefinitionArn, deploymentSourceSha });
const runTaskRequestBody = { eventId: "12345678-1234-1234-1234-123456789abc", eventTime: new Date(now.getTime() - 20_000).toISOString(), taskArn, taskDefinitionArn,
  cluster: "arn:aws:ecs:eu-west-2:368992683803:cluster/mscqr-prod-euw2-main", launchType: "FARGATE", count: 1, enableExecuteCommand: false, overridesPresent: false };
const runTaskRequestEvidence = { ...runTaskRequestBody, requestSha256: canonicalSha256(runTaskRequest) };
const terminalTaskEvidenceBody = { schemaVersion: 1, kind: "PRODUCTION_B01_TERMINAL_TASK_EVIDENCE",
  eventId: "32345678-1234-1234-1234-123456789abc", eventTime: now.toISOString(), taskArn, taskDefinitionArn, taskVersion: 4, containerExitCode: 0 };
const terminalTaskEvidence = { ...terminalTaskEvidenceBody, evidenceSha256: canonicalSha256(terminalTaskEvidenceBody) };

const receipt = (changes = {}) => buildB01PrerequisiteReceipt({ deploymentSourceSha, predecessorRlsIdentity: "3".repeat(64), successorRlsIdentity: "4".repeat(64),
  liveRlsIdentity: "4".repeat(64), executorSourceSha256, executorContractSha256: "5".repeat(64), executorCommandSha256: "6".repeat(64),
  executionResult: "APPLIED", writeCount: 7, taskArn, taskDefinitionArn, runTaskRequestEvidence, terminalTaskEvidence, bridgeDiffAttestation,
  executedAt: now.toISOString(), expiresAt: new Date(now.getTime() + B01_PREREQUISITE.maxReceiptAgeMs).toISOString(), ...changes });
const reseal = (value, changes) => { const body = { ...value, ...changes }; delete body.receiptSha256; return { ...body, receiptSha256: canonicalSha256(body) }; };

test("bridge diff accepts only the reviewed bridge inventory and binds exact patch bytes", () => {
  const files = ["documents/security/rls-program/production-b01-prerequisite-bridge.md", "scripts/aws/production-b01-prerequisite-contract.mjs", "scripts/tests/production-b01-prerequisite.test.mjs"];
  const patch = files.map((file) => `diff --git a/${file} b/${file}\n@@ -1 +1 @@\n-old\n+new`).join("\n");
  const calls = [], attestation = attestBridgeDiff({ deploymentSourceSha, git: (args) => { calls.push(args); if (args[0] === "merge-base") return "";
    if (args[0] === "rev-parse") return args[1] === `${B01_PREREQUISITE.bridgeOriginSha}^1` ? B01_PREREQUISITE.rlsDeltaOriginSha
      : args[1] === `${B01_PREREQUISITE.correctionBaseSha}^1` ? B01_PREREQUISITE.bridgeOriginSha
        : args[1] === `${B01_PREREQUISITE.recoveryBaseSha}^1` ? B01_PREREQUISITE.correctionBaseSha
          : args[1] === `${B01_PREREQUISITE.expiredTaskRecoverySha}^1` ? B01_PREREQUISITE.recoveryBaseSha
            : args[1] === `${B01_PREREQUISITE.terminalEventRecoverySha}^1` ? B01_PREREQUISITE.expiredTaskRecoverySha
              : args[1] === `${B01_PREREQUISITE.provenanceBaseSha}^1` ? B01_PREREQUISITE.terminalEventRecoverySha : B01_PREREQUISITE.provenanceBaseSha;
    if (args.includes("--name-only")) return files.join("\n"); return patch; } });
  assert.equal(attestation.rlsDeltaOriginSha, B01_PREREQUISITE.rlsDeltaOriginSha); assert.equal(attestation.deploymentSourceSha, deploymentSourceSha);
  assert.equal(attestation.bridgeOriginSha, B01_PREREQUISITE.bridgeOriginSha); assert.equal(attestation.bridge.entries.length, 3);
  assert.equal(attestation.predecessorCorrection.entries.length, 3); assert.equal(attestation.runtimeEvidence.entries.length, 3); assert.equal(attestation.expiredTaskRecovery.entries.length, 3);
  assert.equal(attestation.terminalEventRecovery.entries.length, 3); assert.equal(attestation.provenanceCorrection.entries.length, 3); assert.equal(attestation.classificationTelemetry.entries.length, 3);
  assert.ok([...attestation.bridge.entries, ...attestation.predecessorCorrection.entries, ...attestation.runtimeEvidence.entries,
    ...attestation.expiredTaskRecovery.entries, ...attestation.terminalEventRecovery.entries, ...attestation.provenanceCorrection.entries,
    ...attestation.classificationTelemetry.entries].every(({ hunkCount }) => hunkCount === 1));
  assert.match(attestation.bridge.patchSha256, /^[a-f0-9]{64}$/); assert.match(attestation.predecessorCorrection.patchSha256, /^[a-f0-9]{64}$/);
  assert.match(attestation.runtimeEvidence.patchSha256, /^[a-f0-9]{64}$/); assert.match(attestation.expiredTaskRecovery.patchSha256, /^[a-f0-9]{64}$/);
  assert.match(attestation.terminalEventRecovery.patchSha256, /^[a-f0-9]{64}$/); assert.match(attestation.provenanceCorrection.patchSha256, /^[a-f0-9]{64}$/);
  assert.match(attestation.classificationTelemetry.patchSha256, /^[a-f0-9]{64}$/);
  assert.deepEqual(calls.filter(([name]) => name === "merge-base").map((args) => args.slice(2)), [[B01_PREREQUISITE.rlsDeltaOriginSha, B01_PREREQUISITE.bridgeOriginSha],
    [B01_PREREQUISITE.bridgeOriginSha, B01_PREREQUISITE.correctionBaseSha], [B01_PREREQUISITE.correctionBaseSha, B01_PREREQUISITE.recoveryBaseSha],
    [B01_PREREQUISITE.recoveryBaseSha, B01_PREREQUISITE.expiredTaskRecoverySha], [B01_PREREQUISITE.expiredTaskRecoverySha, B01_PREREQUISITE.terminalEventRecoverySha],
    [B01_PREREQUISITE.terminalEventRecoverySha, B01_PREREQUISITE.provenanceBaseSha], [B01_PREREQUISITE.provenanceBaseSha, deploymentSourceSha]]);
});

test("bridge attestation accepts only the complete reviewed recovery lineage and its immediate correction successor", () => {
  assert.throws(() => attestBridgeDiff({ deploymentSourceSha, git: (args) => args[0] === "merge-base" ? "" : args[0] === "rev-parse" ? "f".repeat(40) : "" }),
    /Reviewed bridge origin|immediate protected-main prerequisite-correction successor/);
  assert.throws(() => attestBridgeDiff({ deploymentSourceSha, git: (args) => args[0] === "merge-base" ? "" : args[0] === "rev-parse"
    ? args[1] === `${B01_PREREQUISITE.bridgeOriginSha}^1` ? B01_PREREQUISITE.rlsDeltaOriginSha
      : args[1] === `${B01_PREREQUISITE.correctionBaseSha}^1` ? B01_PREREQUISITE.bridgeOriginSha
        : args[1] === `${B01_PREREQUISITE.recoveryBaseSha}^1` ? B01_PREREQUISITE.correctionBaseSha
          : args[1] === `${B01_PREREQUISITE.expiredTaskRecoverySha}^1` ? B01_PREREQUISITE.recoveryBaseSha
            : args[1] === `${B01_PREREQUISITE.terminalEventRecoverySha}^1` ? B01_PREREQUISITE.expiredTaskRecoverySha
              : args[1] === `${B01_PREREQUISITE.provenanceBaseSha}^1` ? B01_PREREQUISITE.terminalEventRecoverySha : "f".repeat(40) : "" }),
  /immediate protected-main classification-telemetry successor/);
});

test("reviewed #571 and #572 merge lineage is immutable and every substitution fails closed", () => {
  const parents = new Map([
    [`${B01_PREREQUISITE.bridgeOriginSha}^1`, B01_PREREQUISITE.rlsDeltaOriginSha],
    [`${B01_PREREQUISITE.correctionBaseSha}^1`, B01_PREREQUISITE.bridgeOriginSha],
    [`${B01_PREREQUISITE.recoveryBaseSha}^1`, B01_PREREQUISITE.correctionBaseSha],
    [`${B01_PREREQUISITE.expiredTaskRecoverySha}^1`, B01_PREREQUISITE.recoveryBaseSha],
    [`${B01_PREREQUISITE.terminalEventRecoverySha}^1`, B01_PREREQUISITE.expiredTaskRecoverySha],
    [`${B01_PREREQUISITE.provenanceBaseSha}^1`, B01_PREREQUISITE.terminalEventRecoverySha],
    [`${deploymentSourceSha}^1`, B01_PREREQUISITE.provenanceBaseSha],
  ]);
  const files = "scripts/aws/production-b01-prerequisite-contract.mjs";
  const patch = `diff --git a/${files} b/${files}\n@@ -1 +1 @@\n-old\n+new`;
  const git = (changes = new Map()) => (args) => args[0] === "merge-base" ? "" : args[0] === "rev-parse" ? changes.get(args[1]) || parents.get(args[1])
    : args.includes("--name-only") ? files : patch;
  for (const [ref, expected] of [[`${B01_PREREQUISITE.expiredTaskRecoverySha}^1`, B01_PREREQUISITE.recoveryBaseSha],
    [`${B01_PREREQUISITE.terminalEventRecoverySha}^1`, B01_PREREQUISITE.expiredTaskRecoverySha],
    [`${B01_PREREQUISITE.provenanceBaseSha}^1`, B01_PREREQUISITE.terminalEventRecoverySha]]) {
    assert.equal(spawnSync("git", ["rev-parse", ref], { encoding: "utf8" }).stdout.trim(), expected);
  }
  assert.equal(attestBridgeDiff({ deploymentSourceSha, git: git() }).terminalEventRecovery.target, B01_PREREQUISITE.terminalEventRecoverySha);
  for (const [ref, message] of [[`${B01_PREREQUISITE.expiredTaskRecoverySha}^1`, /expired-task recovery/],
    [`${B01_PREREQUISITE.terminalEventRecoverySha}^1`, /terminal-event recovery/], [`${B01_PREREQUISITE.provenanceBaseSha}^1`, /provenance correction/],
    [`${deploymentSourceSha}^1`, /classification-telemetry successor/]]) {
    assert.throws(() => attestBridgeDiff({ deploymentSourceSha, git: git(new Map([[ref, "f".repeat(40)]])) }), message);
  }
  const alteredRecoveryFile = ".github/workflows/production-deploy.yml";
  assert.throws(() => attestBridgeDiff({ deploymentSourceSha, git: (args) => {
    if (args[0] === "merge-base") return ""; if (args[0] === "rev-parse") return parents.get(args[1]);
    const finalRange = args.includes(`${B01_PREREQUISITE.provenanceBaseSha}..${deploymentSourceSha}`);
    if (args.includes("--name-only")) return finalRange ? alteredRecoveryFile : files;
    const file = finalRange ? alteredRecoveryFile : files; return `diff --git a/${file} b/${file}\n@@ -1 +1 @@\n-old\n+new`;
  } }), /outside its reviewed scope/);
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
      provenanceCorrection: { ...bridgeDiffAttestation.provenanceCorrection, patchSha256: "8".repeat(64) } } }]) {
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
  const built = buildB01ReadOnlyInput({ deploymentSourceSha, databaseHostname: "db.synthetic.invalid", ambiguousMutationTaskEvidenceSha256 });
  const source = built.command[1], shared = b01CatalogueRuntimeSource();
  assert.ok(source.includes(shared));
  assert.match(source, /SET TRANSACTION ISOLATION LEVEL READ COMMITTED, READ ONLY/);
  assert.ok(source.includes(runtime.B01_MUTATION_ADVISORY_LOCK_SQL));
  assert.doesNotMatch(shared, /EXPECTED_MUTATIONS|CREATE POLICY|GRANT EXECUTE|executeB01Transaction|AUTHORIZED_MUTATION/);
  assert.doesNotMatch(source, /executeB01Transaction|mutation\.sql|SET LOCAL ROLE/);
  assert.equal((source.match(/\.\$transaction\(/g) || []).length, 1);
  assert.doesNotMatch(source, /\bCOMMIT\b|SET TRANSACTION READ WRITE|SET LOCAL ROLE/);
  const definition = buildB01ReadOnlyDefinition(built.command);
  assert.equal(definition.family, B01_PREREQUISITE.readOnlyFamily);
  assert.equal(definition.containerDefinitions[0].name, B01_PREREQUISITE.readOnlyContainer);
  assert.deepEqual(definition.containerDefinitions[0].entryPoint, ["node"]);
  assert.deepEqual(definition.containerDefinitions[0].command, built.command);
  assert.throws(() => buildB01ReadOnlyInput({ deploymentSourceSha: "main", databaseHostname: "db.synthetic.invalid" }));
  assert.throws(() => buildB01ReadOnlyInput({ deploymentSourceSha, databaseHostname: "db.invalid/other" }));
  assert.throws(() => buildB01ReadOnlyInput({ deploymentSourceSha, databaseHostname: "db.synthetic.invalid", ambiguousMutationTaskEvidenceSha256: "bad" }));
});

test("read-only collector classifies exact predecessor, successor, partial, and unknown safely", async () => {
  const delta = canonicalB01Prerequisite(), contract = buildB01ReadOnlyInput({ deploymentSourceSha, databaseHostname: "db.synthetic.invalid", ambiguousMutationTaskEvidenceSha256 }).contract;
  const statements = [];
  const execute = async (state) => readOnlyRuntime.executeB01ReadOnlyTransaction({
    client: { $transaction: async (callback) => callback({ $executeRawUnsafe: async (sql) => { statements.push(sql); } }) },
    input: { contract }, collect: async () => state, inspect: runtime.inspectB01State, lockSql: runtime.B01_MUTATION_ADVISORY_LOCK_SQL,
  });
  assert.equal((await execute(stateFixture(delta.predecessor, { identity: { ...identity, read_only: "on" } }))).classification, "PREDECESSOR");
  assert.deepEqual(statements.slice(0, 4), ["SET TRANSACTION ISOLATION LEVEL READ COMMITTED, READ ONLY",
    "SET LOCAL statement_timeout = '10000ms'", runtime.B01_MUTATION_ADVISORY_LOCK_SQL, "SET LOCAL statement_timeout = '0'"]);
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

test("read-only classification rejection telemetry exposes only closed invariant identifiers", () => {
  assert.deepEqual(B01_CLASSIFICATION_INVARIANTS, ["B01_EXECUTION_IDENTITY","B01_AUDIT_OUTBOX_RLS_ENABLED","B01_AUDIT_OUTBOX_FORCE_RLS_ENABLED",
    "B01_AUDIT_OUTBOX_TABLE_OWNER","B01_AUTH_SCHEMA_OWNER","B01_AUTH_OWNER_SET_CAPABILITY","B01_SCHEMA_OWNER_SET_CAPABILITY"]);
  const delta = canonicalB01Prerequisite(), contract = buildB01ReadOnlyInput({ deploymentSourceSha, databaseHostname: "db.synthetic.invalid", ambiguousMutationTaskEvidenceSha256 }).contract;
  const secret = ["postgresql", "://", "secret-user", ":", "secret-password", "@", "private-db.invalid/secret"].join("");
  const cases = [
    ["B01_EXECUTION_IDENTITY", (state) => { state.identity.database = secret; }],
    ["B01_AUDIT_OUTBOX_RLS_ENABLED", (state) => { state.catalogue.rls = false; }],
    ["B01_AUDIT_OUTBOX_FORCE_RLS_ENABLED", (state) => { state.catalogue.forced = false; }],
    ["B01_AUDIT_OUTBOX_TABLE_OWNER", (state) => { state.catalogue.table_owner = secret; }],
    ["B01_AUTH_SCHEMA_OWNER", (state) => { state.catalogue.schema_owner = secret; }],
    ["B01_AUTH_OWNER_SET_CAPABILITY", (state) => { state.catalogue.owner_set = false; }],
    ["B01_SCHEMA_OWNER_SET_CAPABILITY", (state) => { state.catalogue.schema_owner_set = false; }],
  ];
  for (const [identifier, mutate] of cases) {
    const state = structuredClone(stateFixture(delta.predecessor, { identity: { ...identity, read_only: "on" } })); mutate(state);
    let rejection; try { runtime.inspectB01State(state, contract, "on"); } catch (error) { rejection = error; }
    assert.ok(rejection); const body = readOnlyRuntime.safeB01ReadOnlyFailure("PREDECESSOR_CLASSIFICATION", rejection, B01_CLASSIFICATION_INVARIANTS);
    assert.equal(body.classificationInvariant, identifier); assert.doesNotMatch(JSON.stringify(body), /secret|private-db|postgresql|SELECT|POLICY/i);
    assert.equal(authenticateB01ReadOnlyResult(JSON.stringify({ ...body, evidenceSha256: canonicalSha256(body) }), contract).classificationInvariant, identifier);
    assert.deepEqual(runtime.safeFailure("PREDECESSOR_CLASSIFICATION", rejection),
      { status: "PRODUCTION_B01_PREREQUISITE_FAILED", stage: "PREDECESSOR_CLASSIFICATION", code: "CONTRACT_REJECTED" });
  }
  const malicious = Object.assign(new assert.AssertionError({ message: secret }), { b01ClassificationInvariant: secret });
  const generic = readOnlyRuntime.safeB01ReadOnlyFailure("PREDECESSOR_CLASSIFICATION", malicious, B01_CLASSIFICATION_INVARIANTS);
  assert.deepEqual(generic, { schemaVersion: 1, kind: "PRODUCTION_B01_READONLY_RESULT", mode: "READ_ONLY", classification: "UNKNOWN",
    stage: "PREDECESSOR_CLASSIFICATION", code: "CONTRACT_REJECTED" });
  assert.doesNotMatch(JSON.stringify(generic), /secret|private-db|postgresql/i);
  const forged = { ...generic, classificationInvariant: "B01_DYNAMIC_DATABASE_VALUE" };
  assert.throws(() => authenticateB01ReadOnlyResult(JSON.stringify({ ...forged, evidenceSha256: canonicalSha256(forged) }), contract));
});

test("receipt RLS identities must match the reconstructed source-fixed executor contract", () => {
  const built = buildB01ExecutorInput({ deploymentSourceSha, databaseHostname: "db.synthetic.invalid" });
  assert.equal(built.contract.successorRlsIdentity, "24b8389a47b2c120e88a080db3e751fa52577fb684356860d183499327275577");
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

const historicalRunTaskEvent = ({ arn = taskArn, definition = taskDefinitionArn, sourceSha = deploymentSourceSha,
  eventId = runTaskRequestBody.eventId, eventTime = runTaskRequestBody.eventTime, request = {}, task = {}, account = B01_PREREQUISITE.account } = {}) => {
  const exactRequest = buildB01RunTaskRequest({ taskDefinitionArn: definition, deploymentSourceSha: sourceSha });
  const responseTask = { taskArn: arn, taskDefinitionArn: definition,
    clusterArn: `arn:aws:ecs:${B01_PREREQUISITE.region}:${B01_PREREQUISITE.account}:cluster/${B01_PREREQUISITE.cluster}`,
    group: `family:${B01_PREREQUISITE.executorFamily}`, launchType: "FARGATE", enableExecuteCommand: false,
    desiredStatus: "RUNNING", lastStatus: "PROVISIONING",
    overrides: { containerOverrides: [{ name: B01_PREREQUISITE.executorContainer }], inferenceAcceleratorOverrides: [] },
    containers: [{ name: B01_PREREQUISITE.executorContainer, image: B01_PREREQUISITE.executorImage }], ...task };
  return { EventId: eventId, EventName: "RunTask", EventSource: "ecs.amazonaws.com", EventTime: eventTime, ReadOnly: "false", Username: "root",
    CloudTrailEvent: JSON.stringify({ eventID: eventId, eventTime, eventSource: "ecs.amazonaws.com", eventName: "RunTask",
      awsRegion: B01_PREREQUISITE.region, recipientAccountId: account,
      userIdentity: { accountId: account, arn: `arn:aws:iam::${account}:root` },
      requestParameters: { ...exactRequest, dryrun: false, enableECSManagedTags: false, ...request },
      responseElements: { failures: [], tasks: [responseTask] } }) };
};

test("expired mutation task requires exact durable launch history and fixed definition", () => {
  const events = [historicalRunTaskEvent()];
  const history = authenticateB01MutationLaunchHistory(events, { expectedTaskArn: taskArn, taskDefinitionArn, deploymentSourceSha });
  assert.match(history.evidenceSha256, /^[a-f0-9]{64}$/); assert.equal(history.requestEvidence.overridesPresent, false);
  const command = buildB01ExecutorInput({ deploymentSourceSha, databaseHostname: "db.synthetic.invalid" }).command;
  const definition = { ...buildB01ExecutorDefinition(command), taskDefinitionArn, revision: 1, status: "ACTIVE", tags: [] };
  const authenticate = (changes = {}) => authenticateB01ExpiredMutationTask({ expectedTaskArn: taskArn,
    taskDefinitionArn: changes.taskDefinitionArn || taskDefinitionArn, taskDefinition: changes.taskDefinition || definition,
    taskDefinitionTags: [], events: changes.events || events, launchHistoryEvidenceSha256: changes.launchHistoryEvidenceSha256 || history.evidenceSha256,
    terminalTaskEvidence: changes.terminalTaskEvidence || terminalTaskEvidence,
    activeMutationTaskArns: changes.activeMutationTaskArns || [], ambiguousDeploymentSourceSha: changes.sourceSha || deploymentSourceSha,
    deploymentSourceSha, readExecutorSource: () => executor });
  assert.equal(authenticate().kind, "PRODUCTION_B01_EXPIRED_TASK_QUIESCENCE");
  assert.equal(authenticateB01MissingTask({ tasks: [], failures: [{ arn: taskArn, reason: "MISSING" }] }, taskArn), true);
  assert.throws(() => authenticateB01MissingTask({ tasks: [], failures: [] }, taskArn));
  assert.throws(() => authenticate({ activeMutationTaskArns: [taskArn] }));
  const unrelatedBody = { ...terminalTaskEvidenceBody, taskArn: taskArn.replace(/a$/, "b") };
  assert.throws(() => authenticate({ terminalTaskEvidence: { ...unrelatedBody, evidenceSha256: canonicalSha256(unrelatedBody) } }));
  assert.throws(() => authenticate({ taskDefinitionArn: taskDefinitionArn.replace(":1", ":2") }));
  assert.throws(() => authenticate({ sourceSha: "8".repeat(40) }));
  const overridden = historicalRunTaskEvent({ request: { overrides: { containerOverrides: [{ name: B01_PREREQUISITE.executorContainer, command: ["true"] }] } } });
  assert.throws(() => authenticateB01MutationLaunchHistory([overridden], { expectedTaskArn: taskArn, taskDefinitionArn, deploymentSourceSha }));
  const wrongImage = historicalRunTaskEvent({ task: { containers: [{ name: B01_PREREQUISITE.executorContainer, image: "wrong" }] } });
  assert.throws(() => authenticateB01MutationLaunchHistory([wrongImage], { expectedTaskArn: taskArn, taskDefinitionArn, deploymentSourceSha }));
});

test("the terminal-evidence exception is bounded to the one pre-capture production attempt", () => {
  const request = buildB01RunTaskRequest({ taskDefinitionArn: B01_PREREQUISITE.legacyExpiredTaskDefinitionArn,
    deploymentSourceSha: B01_PREREQUISITE.legacyExpiredDeploymentSourceSha });
  const evidence = { eventId: B01_PREREQUISITE.legacyExpiredRunTaskEventId, eventTime: B01_PREREQUISITE.legacyExpiredRunTaskEventTime,
    taskArn: B01_PREREQUISITE.legacyExpiredTaskArn, taskDefinitionArn: B01_PREREQUISITE.legacyExpiredTaskDefinitionArn,
    cluster: `arn:aws:ecs:${B01_PREREQUISITE.region}:${B01_PREREQUISITE.account}:cluster/${B01_PREREQUISITE.cluster}`,
    launchType: "FARGATE", count: 1, enableExecuteCommand: false, overridesPresent: false, requestSha256: canonicalSha256(request) };
  const input = { taskArn: B01_PREREQUISITE.legacyExpiredTaskArn, taskDefinitionArn: B01_PREREQUISITE.legacyExpiredTaskDefinitionArn,
    deploymentSourceSha: B01_PREREQUISITE.legacyExpiredDeploymentSourceSha, runTaskRequestEvidence: evidence,
    launchHistoryEvidenceSha256: "7".repeat(64), activeMutationTaskArns: [] };
  assert.equal(assertB01ExpiredMutationTaskQuiescent(input).legacyExpiredEvidence, true);
  assert.throws(() => assertB01ExpiredMutationTaskQuiescent({ ...input, taskArn }));
  assert.throws(() => assertB01ExpiredMutationTaskQuiescent({ ...input, deploymentSourceSha: deploymentSourceSha }));
  assert.throws(() => assertB01ExpiredMutationTaskQuiescent({ ...input, runTaskRequestEvidence: { ...evidence, eventId: runTaskRequestBody.eventId } }));
  assert.throws(() => assertB01ExpiredMutationTaskQuiescent({ ...input, taskArn, taskDefinitionArn,
    deploymentSourceSha, runTaskRequestEvidence }), /lacks durable terminal evidence/);
});

test("durable ECS terminal events bind the exact mutation task and survive DescribeTasks expiry", () => {
  const body = { version: "0", id: "42345678-1234-1234-1234-123456789abc", "detail-type": "ECS Task State Change", source: "aws.ecs",
    account: B01_PREREQUISITE.account, time: now.toISOString(), region: B01_PREREQUISITE.region, resources: [taskArn],
    detail: { version: 4, clusterArn: `arn:aws:ecs:${B01_PREREQUISITE.region}:${B01_PREREQUISITE.account}:cluster/${B01_PREREQUISITE.cluster}`,
      taskArn, taskDefinitionArn, group: `family:${B01_PREREQUISITE.executorFamily}`, launchType: "FARGATE",
      desiredStatus: "STOPPED", lastStatus: "STOPPED", containers: [{ name: B01_PREREQUISITE.executorContainer,
        lastStatus: "STOPPED", exitCode: 1, image: B01_PREREQUISITE.executorImage, imageDigest: B01_PREREQUISITE.executorImage.split("@")[1] }] } };
  const events = [{ eventId: "log-1", message: JSON.stringify(body) }];
  const evidence = authenticateB01TerminalTaskEvents(events, { taskArn, taskDefinitionArn, launchEventTime: runTaskRequestBody.eventTime });
  assert.equal(evidence.containerExitCode, 1); assert.match(evidence.evidenceSha256, /^[a-f0-9]{64}$/);
  for (const mutate of [
    (value) => { value.account = "000000000000"; }, (value) => { value.region = "us-east-1"; },
    (value) => { value.detail.taskArn = taskArn.replace(/a$/, "b"); }, (value) => { value.detail.taskDefinitionArn = taskDefinitionArn.replace(":1", ":2"); },
    (value) => { value.detail.containers[0].imageDigest = `sha256:${"0".repeat(64)}`; },
  ]) { const attacked = structuredClone(body); mutate(attacked); assert.throws(() => authenticateB01TerminalTaskEvents([{ message: JSON.stringify(attacked) }],
    { taskArn, taskDefinitionArn, launchEventTime: runTaskRequestBody.eventTime })); }
  const laterRunning = structuredClone(body); laterRunning.id = "52345678-1234-1234-1234-123456789abc";
  laterRunning.detail.version += 1; laterRunning.detail.lastStatus = "RUNNING"; laterRunning.detail.desiredStatus = "RUNNING";
  laterRunning.detail.containers[0].lastStatus = "RUNNING";
  assert.throws(() => authenticateB01TerminalTaskEvents([...events, { message: JSON.stringify(laterRunning) }],
    { taskArn, taskDefinitionArn, launchEventTime: runTaskRequestBody.eventTime }));
  const contradictory = structuredClone(body); contradictory.id = "62345678-1234-1234-1234-123456789abc";
  contradictory.detail.desiredStatus = "RUNNING";
  assert.throws(() => authenticateB01TerminalTaskEvents([...events, { message: JSON.stringify(contradictory) }],
    { taskArn, taskDefinitionArn, launchEventTime: runTaskRequestBody.eventTime }));
  const bounds = { launchEventTime: runTaskRequestBody.eventTime, observationEventTime: body.time };
  const partial = Array.from({ length: 99 }, (_, index) => ({ eventId: `old-${index}`, message: JSON.stringify({ source: "aws.ecs" }) }));
  const pages = [{ events: [], nextToken: "page-2" }, { events: partial, nextToken: "page-3" }, { events }], calls = [];
  assert.deepEqual(collectB01TerminalTaskEvents((args) => { calls.push(args); return pages.shift(); }, taskArn, bounds), [...partial, ...events]);
  assert.ok(calls[1].includes("--next-token")); assert.ok(calls[2].includes("--next-token"));
  assert.equal(calls[0][calls[0].indexOf("--start-time") + 1], String(Date.parse(bounds.launchEventTime)));
  assert.equal(calls[0][calls[0].indexOf("--end-time") + 1], String(Date.parse(bounds.observationEventTime) + 1));
  const collected = collectB01TerminalTaskEvents((args) => ({ events, nextToken: undefined }), taskArn, bounds);
  assert.equal(authenticateB01TerminalTaskEvents(collected, { taskArn, taskDefinitionArn, ...bounds }).containerExitCode, 1);
  assert.throws(() => authenticateB01TerminalTaskEvents([], { taskArn, taskDefinitionArn, ...bounds }));
  const beforeLaunch = structuredClone(body); beforeLaunch.time = new Date(Date.parse(bounds.launchEventTime) - 1).toISOString();
  assert.throws(() => authenticateB01TerminalTaskEvents([{ message: JSON.stringify(beforeLaunch) }],
    { taskArn, taskDefinitionArn, ...bounds }));
  const unrelated = structuredClone(body); unrelated.detail.taskArn = taskArn.replace(/a$/, "b"); unrelated.resources = [unrelated.detail.taskArn];
  assert.throws(() => authenticateB01TerminalTaskEvents([{ message: JSON.stringify(unrelated) }],
    { taskArn, taskDefinitionArn, ...bounds }));
  assert.throws(() => collectB01TerminalTaskEvents(() => ({ events: [] }), taskArn));
  assert.throws(() => collectB01TerminalTaskEvents(() => ({ events: [] }), taskArn,
    { launchEventTime: bounds.observationEventTime, observationEventTime: bounds.launchEventTime }));
  assert.throws(() => collectB01TerminalTaskEvents(() => ({ events: [], nextToken: "same" }), taskArn, bounds));
  let page = 0; assert.throws(() => collectB01TerminalTaskEvents(() => ({ events: [], nextToken: `page-${++page}` }), taskArn, bounds),
    /bounded page limit/);
  const afterObservation = structuredClone(body); afterObservation.time = new Date(Date.parse(bounds.observationEventTime) + 1).toISOString();
  assert.throws(() => authenticateB01TerminalTaskEvents([{ message: JSON.stringify(afterObservation) }],
    { taskArn, taskDefinitionArn, ...bounds }));
});

test("future mutation launch requires exact native durable ECS event capture", () => {
  const arn = `arn:aws:logs:${B01_PREREQUISITE.region}:${B01_PREREQUISITE.account}:log-group:${B01_PREREQUISITE.eventCaptureLogGroup}`;
  const input = { logGroups: [{ logGroupName: B01_PREREQUISITE.eventCaptureLogGroup, arn: `${arn}:*`, logGroupArn: arn, retentionInDays: 30 }],
    rules: [{ Name: "ecs-event-capture", State: "ENABLED", EventPattern: JSON.stringify({ source: ["aws.ecs"] }) }],
    targetsByRule: { "ecs-event-capture": [{ Id: "CloudWatchLogs", Arn: arn }] } };
  assert.equal(assertB01EcsEventCapture(input).logGroupArn, arn);
  assert.equal(assertB01EcsEventCapture({ ...input, logGroups: [{ ...input.logGroups[0], retentionInDays: undefined }] }).logGroupArn, arn);
  assert.equal(assertB01EcsEventCapture({ ...input, logGroups: [{ ...input.logGroups[0], arn: undefined }] }).logGroupArn, arn);
  assert.equal(assertB01EcsEventCapture({ ...input, rules: [{ ...input.rules[0],
    EventPattern: JSON.stringify({ source: ["aws.ecs"], "detail-type": ["ECS Task State Change"] }) }] }).retentionInDays, 30);
  assert.throws(() => assertB01EcsEventCapture({ ...input, logGroups: [] }));
  assert.throws(() => assertB01EcsEventCapture({ ...input, logGroups: [{ ...input.logGroups[0], retentionInDays: 7 }] }));
  assert.throws(() => assertB01EcsEventCapture({ ...input, logGroups: [{ ...input.logGroups[0], logGroupArn: `${arn}-lookalike` }] }));
  assert.throws(() => assertB01EcsEventCapture({ ...input, logGroups: [{ ...input.logGroups[0], arn: `${arn}-lookalike:*` }] }));
  assert.throws(() => assertB01EcsEventCapture({ ...input, logGroups: [{ ...input.logGroups[0], logGroupArn: arn.replace(B01_PREREQUISITE.account, "000000000000") }] }));
  assert.throws(() => assertB01EcsEventCapture({ ...input, logGroups: [{ ...input.logGroups[0], logGroupArn: arn.replace(B01_PREREQUISITE.region, "us-east-1") }] }));
  assert.throws(() => assertB01EcsEventCapture({ ...input, rules: [{ ...input.rules[0], State: "DISABLED" }] }));
  assert.throws(() => assertB01EcsEventCapture({ ...input, targetsByRule: { "ecs-event-capture": [{ Id: "wrong", Arn: "wrong" }] } }));
  assert.throws(() => assertB01EcsEventCapture({ ...input, rules: [{ ...input.rules[0], EventPattern: "{" }] }));
  assert.throws(() => assertB01EcsEventCapture({ ...input, rules: [{ ...input.rules[0], EventPattern: JSON.stringify({ source: ["aws.s3"] }) }] }));
  assert.throws(() => assertB01EcsEventCapture({ ...input, rules: [{ ...input.rules[0],
    EventPattern: JSON.stringify({ source: ["aws.ecs"], "detail-type": ["ECS Deployment State Change"] }) }] }));
  assert.throws(() => assertB01EcsEventCapture({ ...input, rules: [{ ...input.rules[0],
    EventPattern: JSON.stringify({ source: ["aws.ecs"], detail: { clusterArn: ["wrong"] } }) }] }));
  assert.throws(() => assertB01EcsEventCapture({ ...input, targetsByRule: { "ecs-event-capture": [
    ...input.targetsByRule["ecs-event-capture"], { Id: "extra", Arn: arn }] } }));
  assert.throws(() => assertB01EcsEventCapture({ ...input, targetsByRule: { "ecs-event-capture": [{
    ...input.targetsByRule["ecs-event-capture"][0], Input: "{}" }] } }));
  assert.throws(() => assertB01EcsEventCapture({ ...input, rules: [...input.rules,
    { Name: "unrelated", State: "ENABLED", EventPattern: JSON.stringify({ source: ["aws.s3"] }) }],
  targetsByRule: { ...input.targetsByRule, unrelated: [{ Id: "other", Arn: arn }] } }));
  const apply = fs.readFileSync("scripts/aws/apply-production-b01-prerequisite.mjs", "utf8");
  assert.ok(apply.indexOf("assertB01EcsEventCapture") < apply.indexOf('"ecs","register-task-definition"'));
  assert.ok(apply.lastIndexOf("authenticateB01TerminalTaskEvents") < apply.lastIndexOf("buildB01PrerequisiteReceipt({"));
});

test("later historical launches, replayed evidence, and incomplete pagination fail closed", () => {
  const exact = historicalRunTaskEvent(), laterArn = taskArn.replace(/a$/, "b");
  const later = historicalRunTaskEvent({ arn: laterArn, eventId: "22345678-1234-1234-1234-123456789abc",
    eventTime: new Date(Date.parse(runTaskRequestBody.eventTime) + 1_000).toISOString() });
  assert.throws(() => authenticateB01MutationLaunchHistory([exact, later], { expectedTaskArn: taskArn, taskDefinitionArn, deploymentSourceSha }), /later or ambiguous/);
  assert.throws(() => authenticateB01MutationLaunchHistory([exact, exact], { expectedTaskArn: taskArn, taskDefinitionArn, deploymentSourceSha }), /duplicate/);
  assert.throws(() => authenticateB01MutationLaunchHistory([historicalRunTaskEvent({ account: "000000000000" })],
    { expectedTaskArn: taskArn, taskDefinitionArn, deploymentSourceSha }));
  const pages = [{ Events: [exact], NextToken: "page-2" }, { Events: [], NextToken: undefined }], calls = [];
  assert.deepEqual(collectB01RunTaskEvents((args) => { calls.push(args); return pages.shift(); }), [exact]);
  assert.ok(calls[1].includes("--next-token"));
  assert.throws(() => collectB01RunTaskEvents(() => ({ Events: [], NextToken: "same" })), /incomplete or cyclic/);
  assert.throws(() => collectB01RunTaskEvents(() => ({ Events: null })));
});

test("mutation family census consumes every bounded page and rejects malformed history", () => {
  const second = taskArn.replace(/a$/, "b"), pages = [{ taskArns: [taskArn], nextToken: "page-2" }, { taskArns: [second] }], calls = [];
  assert.deepEqual(collectB01MutationTaskArns((args) => { calls.push(args); return pages.shift(); }, "RUNNING"), [taskArn, second]);
  assert.ok(calls[1].includes("--next-token"));
  assert.throws(() => collectB01MutationTaskArns(() => ({ taskArns: [], nextToken: "same" }), "RUNNING"), /incomplete or cyclic/);
  assert.throws(() => collectB01MutationTaskArns(() => ({ taskArns: [taskArn, taskArn] }), "RUNNING"));
});

test("mutation family census brackets RUNNING and STOPPED without the ineffective PENDING filter", () => {
  const sibling = taskArn.replace(/a$/, "b"), calls = [];
  const activeResponses = [{ taskArns: [] }, { taskArns: [] }, { taskArns: [sibling] }, { taskArns: [] }];
  const active = collectB01MutationCensus((args) => { calls.push(args); return activeResponses.shift(); });
  assert.deepEqual(calls.map((args) => args[args.indexOf("--desired-status") + 1]), ["RUNNING","STOPPED","RUNNING","STOPPED"]);
  assert.deepEqual(active.activeMutationTaskArns, [sibling]);

  const stoppedResponses = [{ taskArns: [] }, { taskArns: [] }, { taskArns: [] }, { taskArns: [sibling] }];
  const stopped = collectB01MutationCensus((args) => args[1] === "describe-tasks"
    ? { tasks: [{ taskArn: sibling, lastStatus: "STOPPED" }], failures: [] }
    : stoppedResponses.shift());
  assert.deepEqual(stopped.taskCensus.STOPPED, [sibling]); assert.deepEqual(stopped.activeMutationTaskArns, []);
});

test("reconciliation result requires a stable history-census-history-census-history bracket", () => {
  const evidence = "7".repeat(64), stable = () => ({ evidenceSha256: evidence });
  const empty = () => ({ taskCensus: { RUNNING: [], PENDING: [], STOPPED: [] }, activeMutationTaskArns: [] });
  const calls = [];
  assert.equal(collectB01RecoveryPostflight({ initialLaunchHistorySha256: evidence, ambiguousTaskArn: taskArn,
    collectLaunchHistory: () => { calls.push("history"); return stable(); },
    collectMutationCensus: () => { calls.push("census"); return empty(); } }).afterCensus.evidenceSha256, evidence);
  assert.deepEqual(calls, ["history","census","history","census","history"]);
  const probe = fs.readFileSync("scripts/aws/probe-production-b01-prerequisite.mjs", "utf8");
  assert.ok(probe.lastIndexOf("authenticateB01ReadOnlyResult") < probe.lastIndexOf("collectB01RecoveryPostflight"));
  assert.throws(() => collectB01RecoveryPostflight({ initialLaunchHistorySha256: evidence, ambiguousTaskArn: taskArn,
    collectLaunchHistory: stable, collectMutationCensus: () => ({ ...empty(), taskCensus: { RUNNING: [taskArn.replace(/a$/, "b")], PENDING: [], STOPPED: [] },
      activeMutationTaskArns: [taskArn.replace(/a$/, "b")] }) }), /became active/);
  assert.throws(() => collectB01RecoveryPostflight({ initialLaunchHistorySha256: evidence, ambiguousTaskArn: taskArn,
    collectLaunchHistory: stable, collectMutationCensus: () => ({ ...empty(), taskCensus: { RUNNING: [], PENDING: [], STOPPED: [taskArn.replace(/a$/, "b")] } }) }), /unaccounted/);
  let reads = 0;
  assert.throws(() => collectB01RecoveryPostflight({ initialLaunchHistorySha256: evidence, ambiguousTaskArn: taskArn,
    collectLaunchHistory: () => ({ evidenceSha256: ++reads === 1 ? evidence : "8".repeat(64) }), collectMutationCensus: empty }), /across the final census/);
  assert.throws(() => collectB01RecoveryPostflight({ initialLaunchHistorySha256: evidence, ambiguousTaskArn: taskArn,
    collectLaunchHistory: () => ({ evidenceSha256: "8".repeat(64) }), collectMutationCensus: empty }), /before the final census/);
  let censusReads = 0;
  assert.throws(() => collectB01RecoveryPostflight({ initialLaunchHistorySha256: evidence, ambiguousTaskArn: taskArn,
    collectLaunchHistory: stable, collectMutationCensus: () => ++censusReads === 1 ? empty() : ({ ...empty(),
      taskCensus: { RUNNING: [], PENDING: [], STOPPED: [taskArn.replace(/a$/, "b")] } }) }), /unaccounted/);
  let trailingReads = 0;
  assert.throws(() => collectB01RecoveryPostflight({ initialLaunchHistorySha256: evidence, ambiguousTaskArn: taskArn,
    collectLaunchHistory: () => ({ evidenceSha256: ++trailingReads < 3 ? evidence : "8".repeat(64) }),
    collectMutationCensus: empty }), /after the final census/);
});

test("reconciliation authenticates the exact stopped ambiguous mutation task and rejects non-quiescent substitutes", () => {
  const command = buildB01ExecutorInput({ deploymentSourceSha, databaseHostname: "db.synthetic.invalid" }).command;
  const taskDefinition = { ...buildB01ExecutorDefinition(command), taskDefinitionArn, revision: 1, status: "ACTIVE", tags: [] };
  const task = { taskArn, taskDefinitionArn, clusterArn: `arn:aws:ecs:${B01_PREREQUISITE.region}:${B01_PREREQUISITE.account}:cluster/${B01_PREREQUISITE.cluster}`,
    group: `family:${B01_PREREQUISITE.executorFamily}`, launchType: "FARGATE", lastStatus: "STOPPED", desiredStatus: "STOPPED",
    stopCode: "EssentialContainerExited", enableExecuteCommand: false, createdAt: new Date(now.getTime() - 30_000).toISOString(),
    executionStoppedAt: new Date(now.getTime() - 5_000).toISOString(), stoppedAt: now.toISOString(),
    overrides: { containerOverrides: [{ name: B01_PREREQUISITE.executorContainer }], inferenceAcceleratorOverrides: [] },
    containers: [{ name: B01_PREREQUISITE.executorContainer, lastStatus: "STOPPED", image: B01_PREREQUISITE.executorImage,
      imageDigest: B01_PREREQUISITE.executorImage.split("@")[1], exitCode: 1 }] };
  const events = [{ EventId: runTaskRequestBody.eventId, CloudTrailEvent: JSON.stringify({ eventID: runTaskRequestBody.eventId,
    eventTime: runTaskRequestBody.eventTime, eventSource: "ecs.amazonaws.com", eventName: "RunTask",
    requestParameters: { ...runTaskRequest, dryrun: false, enableECSManagedTags: false }, responseElements: { tasks: [{ taskArn }] } }) }];
  const authenticate = (changes = {}) => authenticateB01AmbiguousMutationTask({ expectedTaskArn: taskArn, task: { ...task, ...(changes.task || {}) },
    taskDefinition: changes.taskDefinition || taskDefinition, taskDefinitionTags: [], events: changes.events || events,
    activeMutationTaskArns: changes.activeMutationTaskArns || [], ambiguousDeploymentSourceSha: deploymentSourceSha,
    deploymentSourceSha, readExecutorSource: () => executor });
  assert.match(authenticate().evidenceSha256, /^[a-f0-9]{64}$/);
  for (const lastStatus of ["RUNNING", "PENDING", "PROVISIONING", "ACTIVATING", "DEACTIVATING"]) {
    assert.throws(() => authenticate({ task: { lastStatus, desiredStatus: "RUNNING" } }));
  }
  assert.throws(() => authenticate({ activeMutationTaskArns: [taskArn] }));
  assert.throws(() => authenticate({ activeMutationTaskArns: [taskArn, taskArn.replace(/a$/, "b")] }));
  assert.throws(() => authenticate({ task: { taskArn: taskArn.replace(/a$/, "b") } }));
  assert.throws(() => authenticate({ task: { taskDefinitionArn: taskDefinitionArn.replace(":1", ":2") } }));
  assert.throws(() => authenticate({ task: { containers: [{ ...task.containers[0], imageDigest: `sha256:${"0".repeat(64)}` }] } }));
  const wrongSourceCommand = buildB01ExecutorInput({ deploymentSourceSha: "8".repeat(40), databaseHostname: "db.synthetic.invalid" }).command;
  assert.throws(() => authenticate({ taskDefinition: { ...taskDefinition,
    containerDefinitions: [{ ...taskDefinition.containerDefinitions[0], command: wrongSourceCommand }] } }));
  assert.deepEqual(authenticateB01MutationTaskListing({ taskArns: [] }), []);
  assert.throws(() => authenticateB01MutationTaskListing({ taskArns: [], nextToken: "unread-page" }));
  assert.throws(() => authenticateB01MutationTaskListing({ taskArns: ["wrong-task"] }));
  assert.throws(() => authenticateB01MutationTaskListing({ taskArns: [taskArn, taskArn] }));
  assert.deepEqual(findNonTerminalB01MutationTasks({ tasks: [{ taskArn, lastStatus: "STOPPED" }] }, [taskArn]), []);
  assert.deepEqual(findNonTerminalB01MutationTasks({ tasks: [{ taskArn, lastStatus: "DEACTIVATING" }] }, [taskArn]), [taskArn]);
  assert.throws(() => findNonTerminalB01MutationTasks({ tasks: [] }, [taskArn]));
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
