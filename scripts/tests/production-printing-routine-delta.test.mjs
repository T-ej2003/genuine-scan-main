import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import {
  PRINTING_ROUTINE_DELTA,
  authenticatePrintingRoutineExecutorPredecessor,
  authenticatePrintingRoutineDeltaResult,
  buildPrintingRoutineDeltaCommand,
  buildPrintingRoutineDeltaDefinition,
  canonicalPrintingRoutineDelta,
  discoverCanonicalRequirementsReference,
  executePrintingRoutineDeltaTransaction,
} from "../aws/apply-production-printing-routine-delta.mjs";
import { EXPECTED_PRINTING_ROUTINE_PREDECESSORS, RLS_PROBE_CLASSIFICATIONS } from "../aws/probe-production-rls-catalogue.mjs";
import { canonicalSha256 } from "../aws/production-green-stage-b-contract.mjs";

const hash = (value) => crypto.createHash("sha256").update(value).digest("hex");
const identities = Object.keys(EXPECTED_PRINTING_ROUTINE_PREDECESSORS).sort();
const routines = canonicalPrintingRoutineDelta();
const requirements = { requirementsSha256: "a".repeat(64), objects: {
  routines: identities.map((identity) => ({ identity, sha256: hash(`successor:${identity}`) })),
  tables: [{ identity: "User", sha256: "b".repeat(64) }], policies: [{ identity: "User.tenant", sha256: "c".repeat(64) }],
  schemas: [{ identity: "app_rls", sha256: "d".repeat(64) }], roles: [{ identity: "mscqr_prd_rls_phase2_app", sha256: "e".repeat(64) }],
} };
const contract = { sourceSha: "f".repeat(40), requirementsSha256: requirements.requirementsSha256, identities,
  predecessorSha256: EXPECTED_PRINTING_ROUTINE_PREDECESSORS,
  successorSha256: Object.fromEntries(requirements.objects.routines.map(({ identity, sha256 }) => [identity, sha256])),
  sqlSha256: Object.fromEntries(routines.map(({ name, sql }) => [name, hash(sql)])) };
const input = { contract, requirements, databaseHostname: "production.example.invalid", routines };
const identity = { role: PRINTING_ROUTINE_DELTA.administrator, session_role: PRINTING_ROUTINE_DELTA.administrator,
  database: "mscqr_production_rls_green_phase2", read_only: "off", rolsuper: false, rolbypassrls: false, rolcreaterole: true, rolcreatedb: true };
const owners = identities.map((value) => ({ identity: value, owner: PRINTING_ROUTINE_DELTA.ownerRole }));

const artifactFixture = () => {
  const bytes = Buffer.from(JSON.stringify(requirements));
  const archive = execFileSync("/usr/bin/python3", ["-c", `import io,sys,zipfile
b=io.BytesIO()
with zipfile.ZipFile(b,'w',compression=zipfile.ZIP_DEFLATED) as z:
 i=zipfile.ZipInfo('app-only-requirements.json');i.create_system=3;i.external_attr=33152<<16
 z.writestr(i,sys.stdin.buffer.read(),compress_type=zipfile.ZIP_DEFLATED)
sys.stdout.buffer.write(b.getvalue())`], { input: bytes });
  const run = { id: 123, run_attempt: 1, head_sha: contract.sourceSha, head_branch: "main", path: ".github/workflows/produce-production-app-only-requirements.yml", event: "workflow_dispatch", status: "completed", conclusion: "success", repository: { id: 9, full_name: "T-ej2003/genuine-scan-main" }, head_repository: { id: 9, full_name: "T-ej2003/genuine-scan-main" } };
  const artifact = { id: 456, name: "production-app-only-requirements", expired: false, digest: `sha256:${hash(archive)}`, workflow_run: { id: 123, head_sha: contract.sourceSha, repository_id: 9, head_repository_id: 9 } };
  const githubRun = (_command, args) => args[1].includes("/workflows/") ? JSON.stringify({ workflow_runs: [run] }) : args[1].endsWith("/artifacts") ? JSON.stringify({ artifacts: [artifact] }) : archive;
  return { archive, run, artifact, githubRun };
};

const harness = ({ classifications = [RLS_PROBE_CLASSIFICATIONS.EXPECTED, RLS_PROBE_CLASSIFICATIONS.MATCH], ownerRows = owners, failCreate = 0,
  observedIdentity = identity, tamperedInput = input } = {}) => {
  const commands = []; let creates = 0, reads = 0;
  const tx = {
    async $executeRawUnsafe(sql) { commands.push(sql); if (sql.startsWith("CREATE OR REPLACE FUNCTION")) { creates++; if (creates === failCreate) throw new Error("injected replacement failure"); } },
    async $queryRawUnsafe(sql) { commands.push(sql); return sql.includes("pg_advisory_xact_lock") ? [] : ownerRows; },
  };
  const collect = async () => ({ identity: observedIdentity, marker: reads++ });
  const classify = () => classifications.shift();
  return { tx, commands, run: () => executePrintingRoutineDeltaTransaction({ tx, input: tamperedInput, collect, classify }) };
};

test("canonical protected source yields exactly the three fixed routine replacements", () => {
  assert.deepEqual(routines.map(({ name }) => name), ["printing_readiness", "printing_create_job", "printing_connector_identity"]);
  for (const { name, sql } of routines) {
    assert.match(sql, new RegExp(`^CREATE OR REPLACE FUNCTION app_rls\\.${name}\\(`));
    assert.equal((sql.match(/CREATE OR REPLACE FUNCTION/g) || []).length, 1); assert.ok(sql.endsWith("$fn$;"));
    assert.doesNotMatch(sql, /\{\{[A-Z_]+\}\}/); assert.doesNotMatch(sql, /\b(?:ALTER|CREATE|DROP)\s+(?:TABLE|POLICY|ROLE|SCHEMA|EXTENSION)\b/i);
    assert.doesNotMatch(sql, /\b(?:GRANT|REVOKE|TRUNCATE)\b/i);
  }
});

test("requirements discovery accepts only the exact protected producer run and immutable artifact", () => {
  const fixture = artifactFixture();
  assert.deepEqual(discoverCanonicalRequirementsReference({ sourceSha: contract.sourceSha, githubRun: fixture.githubRun }), {
    sourceSha: contract.sourceSha, runId: "123", runAttempt: "1", artifactId: "456", artifactDigest: fixture.artifact.digest, fileSha256: hash(Buffer.from(JSON.stringify(requirements))),
  });
  for (const change of [
    (value) => { value.run.head_sha = "0".repeat(40); }, (value) => { value.run.path = ".github/workflows/other.yml"; },
    (value) => { value.artifact.expired = true; }, (value) => { value.artifact.digest = `sha256:${"0".repeat(64)}`; },
    (value) => { value.artifact.workflow_run.repository_id = 8; },
  ]) {
    const changed = artifactFixture(); change(changed);
    assert.throws(() => discoverCanonicalRequirementsReference({ sourceSha: contract.sourceSha, githubRun: changed.githubRun }));
  }
});

test("exact predecessor mutates exactly three routines once and authenticates the successor", async () => {
  const value = harness(), result = await value.run();
  assert.deepEqual(result, { status: "APPLIED", writeCount: 3 });
  assert.equal(value.commands.filter((sql) => sql.startsWith("CREATE OR REPLACE FUNCTION")).length, 3);
  assert.equal(value.commands.filter((sql) => sql === `SET LOCAL ROLE "${PRINTING_ROUTINE_DELTA.ownerRole}"`).length, 1);
  assert.equal(value.commands.filter((sql) => sql === "RESET ROLE").length, 1);
});

test("already-converged successor performs zero routine writes", async () => {
  const value = harness({ classifications: [RLS_PROBE_CLASSIFICATIONS.MATCH] });
  assert.deepEqual(await value.run(), { status: "ALREADY_CONVERGED", writeCount: 0 });
  assert.equal(value.commands.filter((sql) => sql.startsWith("CREATE OR REPLACE FUNCTION")).length, 0);
});

test("stale catalogue, missing/duplicate routine, wrong owner or database identity fails before writing", async () => {
  const cases = [
    harness({ classifications: [RLS_PROBE_CLASSIFICATIONS.UNEXPECTED] }),
    harness({ ownerRows: owners.slice(1) }), harness({ ownerRows: [...owners, owners[0]] }),
    harness({ ownerRows: owners.map((row, index) => index ? row : { ...row, owner: "wrong" }) }),
    harness({ observedIdentity: { ...identity, database: "wrong" } }), harness({ observedIdentity: { ...identity, role: "wrong" } }),
  ];
  for (const value of cases) { await assert.rejects(value.run()); assert.equal(value.commands.filter((sql) => sql.startsWith("CREATE OR REPLACE FUNCTION")).length, 0); }
});

test("replacement failures and successor mismatch reject the one transaction", async () => {
  for (const failCreate of [1, 2, 3]) { const value = harness({ failCreate }); await assert.rejects(value.run()); assert.equal(value.commands.filter((sql) => sql.startsWith("CREATE OR REPLACE FUNCTION")).length, failCreate); }
  const mismatch = harness({ classifications: [RLS_PROBE_CLASSIFICATIONS.EXPECTED, RLS_PROBE_CLASSIFICATIONS.UNEXPECTED] });
  await assert.rejects(mismatch.run()); assert.equal(mismatch.commands.filter((sql) => sql.startsWith("CREATE OR REPLACE FUNCTION")).length, 3);
  const altered = structuredClone(input); altered.routines[1].sql += " ";
  const substituted = harness({ tamperedInput: altered }); await assert.rejects(substituted.run());
  for (const routineSet of [[...input.routines].reverse(), [...input.routines, { name: "fourth", sql: "SELECT 1" }]]) {
    const value = harness({ tamperedInput: { ...input, routines: routineSet } });
    await assert.rejects(value.run()); assert.equal(value.commands.filter((sql) => sql.startsWith("CREATE OR REPLACE FUNCTION")).length, 0);
  }
});

test("task command is one bounded transaction with no caller-selected authority or secret output", () => {
  const built = buildPrintingRoutineDeltaCommand({ sourceSha: contract.sourceSha, requirements, databaseHostname: input.databaseHostname, routines });
  const command = built.command[1];
  assert.match(command, /client\.\$transaction/); assert.equal((command.match(/client\.\$transaction/g) || []).length, 1);
  assert.doesNotMatch(command, /process\.env\.(?:DATABASE_URL|AWS_ENDPOINT_URL|AWS_PROFILE)/);
  assert.doesNotMatch(command, /console\.log\([^)]*(?:password|DATABASE_URL|MSCQR_PRINTING_DELTA_ADMIN_PASSWORD)/i);
  assert.ok(Buffer.byteLength(command) <= 196608); assert.deepEqual(built.contract.identities, identities);
  const source = fs.readFileSync("scripts/aws/apply-production-printing-routine-delta.mjs", "utf8");
  const cli = source.slice(source.lastIndexOf("parseArgs("));
  for (const option of ["sql", "file", "routine", "database-url", "secret-arn", "host", "task-definition", "cluster", "container", "command", "expected-hash", "successor-hash"])
    assert.doesNotMatch(cli, new RegExp(`['\"]${option}['\"]`));
  assert.match(source, /createProductionAwsCredentialEnvironment/); assert.match(source, /productionAwsExecutable/);
  assert.doesNotMatch(source, /full-rls-approval|invokeBroker|lambda["']/i);
});

test("task definition pins the authenticated historical image and removes its task role", () => {
  const value = buildPrintingRoutineDeltaDefinition({ sourceSha: contract.sourceSha, requirements, databaseHostname: input.databaseHostname, routines });
  assert.equal(value.definition.family, "mscqr-production-printing-routine-delta"); assert.equal(value.definition.taskRoleArn, undefined);
  assert.equal(value.definition.containerDefinitions[0].image, PRINTING_ROUTINE_DELTA.executorImage);
  assert.deepEqual(value.definition.containerDefinitions[0].secrets, [{ name: "MSCQR_PRINTING_DELTA_ADMIN_PASSWORD", valueFrom: PRINTING_ROUTINE_DELTA.administratorSecretArn }]);
  const taskDefinitionArn = "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-production-rls-green-backend-candidate:1";
  const exact = { serviceResponse: { failures: [], services: [{ taskDefinition: taskDefinitionArn, deployments: [{}], desiredCount: 2, runningCount: 2, pendingCount: 0 }] },
    taskDefinition: { taskDefinitionArn, containerDefinitions: [{ name: "backend", image: PRINTING_ROUTINE_DELTA.executorImage }] },
    imageDetails: [{ imageDigest: PRINTING_ROUTINE_DELTA.executorImage.split("@")[1], imageTags: [PRINTING_ROUTINE_DELTA.executorImageSourceSha] }] };
  assert.equal(authenticatePrintingRoutineExecutorPredecessor(exact), true);
  for (const change of [
    (v) => { v.serviceResponse.services[0].taskDefinition += "x"; }, (v) => { v.serviceResponse.services[0].deployments.push({}); },
    (v) => { v.taskDefinition.containerDefinitions[0].image = v.taskDefinition.containerDefinitions[0].image.replace(/.$/, "0"); },
    (v) => { v.imageDetails[0].imageDigest = `sha256:${"0".repeat(64)}`; }, (v) => { v.imageDetails[0].imageTags = ["0".repeat(40)]; },
  ]) { const changed = structuredClone(exact); change(changed); assert.throws(() => authenticatePrintingRoutineExecutorPredecessor(changed)); }
});

test("only exact authenticated completion evidence is accepted", () => {
  const body = { schemaVersion: 1, kind: "PRODUCTION_PRINTING_ROUTINE_DELTA_RESULT", sourceSha: contract.sourceSha,
    requirementsSha256: requirements.requirementsSha256, contractSha256: canonicalSha256(contract), database: "mscqr_production_rls_green_phase2",
    databaseRole: PRINTING_ROUTINE_DELTA.administrator, status: "APPLIED", writeCount: 3 };
  const valid = JSON.stringify({ ...body, evidenceSha256: canonicalSha256(body) });
  assert.equal(authenticatePrintingRoutineDeltaResult(valid, body).status, "APPLIED");
  for (const change of [
    (value) => { value.sourceSha = "0".repeat(40); }, (value) => { value.contractSha256 = "0".repeat(64); },
    (value) => { value.databaseRole = "wrong"; }, (value) => { value.writeCount = 2; }, (value) => { value.status = "FAILED"; },
  ]) { const value = JSON.parse(valid); change(value); assert.throws(() => authenticatePrintingRoutineDeltaResult(JSON.stringify(value), body)); }
  assert.throws(() => authenticatePrintingRoutineDeltaResult("{}", body));
});

test("task/run ambiguity is fail-closed and never contains an automatic relaunch", () => {
  const source = fs.readFileSync("scripts/aws/apply-production-printing-routine-delta.mjs", "utf8");
  assert.equal((source.match(/\["ecs", "run-task"/g) || []).length, 1);
  assert.match(source, /do not relaunch automatically/g); assert.doesNotMatch(source, /run-task[\s\S]{0,300}(?:retry|attempt\+\+)/i);
  assert.match(source, /enableExecuteCommand: false/); assert.match(source, /assert\.equal\(events\.length, 1\)/);
  assert.match(source, /assert\.equal\(task\.containers\[0\]\.exitCode, 0/);
});
