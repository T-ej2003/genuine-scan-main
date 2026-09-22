import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { execFileSync, spawnSync } from "node:child_process";
import fs from "node:fs";
import { createRequire } from "node:module";
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
import { createAppOnlyRequirements } from "../aws/production-app-only-requirements.mjs";

const runtime = createRequire(import.meta.url)("../aws/production-printing-routine-delta-executor.cjs");

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
const owners = identities.map((value) => ({ identity: value, owner: PRINTING_ROUTINE_DELTA.ownerRole,
  schema_owner: "mscqr_prd_rls_phase2_owner", owner_set: true, schema_owner_set: true, owner_schema_create: false }));

const zipRequirements = (value) => {
  const bytes = Buffer.from(JSON.stringify(value));
  const archive = execFileSync("/usr/bin/python3", ["-c", `import io,sys,zipfile
b=io.BytesIO()
with zipfile.ZipFile(b,'w',compression=zipfile.ZIP_DEFLATED) as z:
 i=zipfile.ZipInfo('app-only-requirements.json');i.create_system=3;i.external_attr=33152<<16
 z.writestr(i,sys.stdin.buffer.read(),compress_type=zipfile.ZIP_DEFLATED)
sys.stdout.buffer.write(b.getvalue())`], { input: bytes });
  return { bytes, archive };
};
const producerRequirements = (candidateSourceSha = contract.sourceSha) => createAppOnlyRequirements({ repositoryRoot: process.cwd(), sourceSha: contract.sourceSha, candidateSourceSha,
  catalogue: { routines: identities.map((value) => { const match = /^(.*?)\.(.*?)\((.*)\)$/.exec(value); return { schema: match[1], name: match[2], arguments: match[3] }; }),
    tables: [{ name: "User" }], policies: [{ table: "User", name: "tenant" }], schemas: [{ name: "app_rls" }], roles: [{ name: "mscqr_prd_rls_phase2_app" }] }, packageChecksums: { fixture: true } });
const artifactFixture = ({ records = [{ runId: 123, artifactId: 456, candidateSourceSha: contract.sourceSha }], runPages, artifactPages = {} } = {}) => {
  const values = records.map(({ runId, artifactId, candidateSourceSha, requirements: supplied, ...changes }) => {
    const requirement = supplied || producerRequirements(candidateSourceSha);
    const { bytes, archive } = zipRequirements(requirement);
    const run = { id: runId, run_attempt: 1, head_sha: contract.sourceSha, head_branch: "main", path: ".github/workflows/produce-production-app-only-requirements.yml", event: "workflow_dispatch", status: "completed", conclusion: "success", repository: { id: 9, full_name: "T-ej2003/genuine-scan-main" }, head_repository: { id: 9, full_name: "T-ej2003/genuine-scan-main" }, ...(changes.run || {}) };
    const artifact = { id: artifactId, name: "production-app-only-requirements", expired: false, digest: `sha256:${hash(archive)}`, size_in_bytes: archive.length, workflow_run: { id: runId, head_sha: contract.sourceSha, repository_id: 9, head_repository_id: 9 }, ...(changes.artifact || {}) };
    return { bytes, archive, requirements: requirement, run, artifact };
  });
  const byRun = new Map(values.map((value) => [String(value.run.id), value]));
  const byArtifact = new Map(values.map((value) => [String(value.artifact.id), value]));
  const pages = runPages || [{ total_count: values.length, workflow_runs: values.map(({ run }) => run) }];
  const githubRun = (_command, args) => {
    const endpoint = args[1];
    if (endpoint.includes("/workflows/")) return JSON.stringify(pages);
    if (endpoint.endsWith("/branches/main")) return JSON.stringify({ commit: { sha: contract.sourceSha } });
    const runMatch = /\/actions\/runs\/([0-9]+)$/.exec(endpoint);
    if (runMatch) return JSON.stringify(byRun.get(runMatch[1])?.run);
    const artifactsMatch = /\/actions\/runs\/([0-9]+)\/artifacts\?per_page=100$/.exec(endpoint);
    if (artifactsMatch) {
      const value = byRun.get(artifactsMatch[1]);
      return JSON.stringify(artifactPages[artifactsMatch[1]] || [{ total_count: value ? 1 : 0, artifacts: value ? [value.artifact] : [] }]);
    }
    const archiveMatch = /\/actions\/artifacts\/([0-9]+)\/zip$/.exec(endpoint);
    if (archiveMatch) return byArtifact.get(archiveMatch[1])?.archive;
    throw new Error(`Unexpected fixture endpoint: ${endpoint}`);
  };
  return { values, pages, githubRun };
};

const harness = ({ classifications = [RLS_PROBE_CLASSIFICATIONS.EXPECTED, RLS_PROBE_CLASSIFICATIONS.MATCH], ownerRows = owners, failCreate = 0,
  failStage = "", observedIdentity = identity, tamperedInput = input } = {}) => {
  const commands = []; let creates = 0, reads = 0, ownerCreate = false;
  const tx = {
    async $executeRawUnsafe(sql) {
      commands.push(sql);
      if (sql.startsWith("GRANT CREATE")) ownerCreate = true;
      if (sql.startsWith("REVOKE CREATE")) ownerCreate = false;
      if (sql.startsWith("CREATE OR REPLACE FUNCTION")) { creates++; if (creates === failCreate) throw new Error("injected replacement failure"); }
    },
    async $queryRawUnsafe(sql) {
      commands.push(sql);
      if (sql.includes("pg_advisory_xact_lock")) return [];
      if (sql.startsWith("SELECT pg_catalog.has_schema_privilege")) return [{ allowed: ownerCreate }];
      return ownerRows;
    },
  };
  const collect = async (_tx, validateIdentity = () => {}) => { validateIdentity(observedIdentity); return { identity: observedIdentity, marker: reads++ }; };
  const classify = () => classifications.shift();
  const checkpoint = async (stage) => { if (stage === failStage) throw new Error(`injected ${stage} failure`); };
  return { tx, commands, run: () => executePrintingRoutineDeltaTransaction({ tx, input: tamperedInput, collect, classify, checkpoint }) };
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
  const [{ run, artifact, bytes }] = fixture.values;
  assert.deepEqual(discoverCanonicalRequirementsReference({ sourceSha: contract.sourceSha, githubRun: fixture.githubRun }), {
    sourceSha: contract.sourceSha, runId: "123", runAttempt: "1", artifactId: "456", artifactDigest: artifact.digest, fileSha256: hash(bytes),
  });
  assert.equal(run.id, 123);
});

test("requirements discovery skips authenticated different candidates and deterministically selects the newest exact match", () => {
  const different = "e".repeat(40);
  const mixed = artifactFixture({ records: [
    { runId: 300, artifactId: 600, candidateSourceSha: different },
    { runId: 100, artifactId: 400, candidateSourceSha: contract.sourceSha },
    { runId: 200, artifactId: 500, candidateSourceSha: different },
  ] });
  assert.equal(discoverCanonicalRequirementsReference({ sourceSha: contract.sourceSha, githubRun: mixed.githubRun }).runId, "100");
  const exact = artifactFixture({ records: [
    { runId: 100, artifactId: 400, candidateSourceSha: contract.sourceSha },
    { runId: 300, artifactId: 600, candidateSourceSha: contract.sourceSha },
    { runId: 200, artifactId: 500, candidateSourceSha: contract.sourceSha },
  ], runPages: [{ total_count: 3, workflow_runs: [] }] });
  exact.pages[0].workflow_runs = [exact.values[0].run, exact.values[2].run, exact.values[1].run];
  assert.equal(discoverCanonicalRequirementsReference({ sourceSha: contract.sourceSha, githubRun: exact.githubRun }).runId, "300");
});

test("requirements discovery is complete across pages and rejects partial, duplicate, or exhausted searches", () => {
  const records = [{ runId: 300, artifactId: 600, candidateSourceSha: "e".repeat(40) }, { runId: 100, artifactId: 400, candidateSourceSha: contract.sourceSha }];
  const paged = artifactFixture({ records });
  paged.pages.splice(0, 1, { total_count: 2, workflow_runs: [paged.values[0].run] }, { total_count: 2, workflow_runs: [paged.values[1].run] });
  assert.equal(discoverCanonicalRequirementsReference({ sourceSha: contract.sourceSha, githubRun: paged.githubRun }).runId, "100");
  for (const runPages of [
    [{ total_count: 2, workflow_runs: [paged.values[0].run] }],
    [{ total_count: 2, workflow_runs: [paged.values[0].run, paged.values[0].run] }],
    Array.from({ length: 11 }, () => ({ total_count: 0, workflow_runs: [] })),
  ]) assert.throws(() => discoverCanonicalRequirementsReference({ sourceSha: contract.sourceSha, githubRun: artifactFixture({ records, runPages }).githubRun }));
  const noMatch = artifactFixture({ records: [{ runId: 300, artifactId: 600, candidateSourceSha: "e".repeat(40) }] });
  assert.throws(() => discoverCanonicalRequirementsReference({ sourceSha: contract.sourceSha, githubRun: noMatch.githubRun }), /absent or ambiguous/);
  const partialArtifacts = artifactFixture();
  const partialArtifact = partialArtifacts.values[0].artifact;
  assert.throws(() => discoverCanonicalRequirementsReference({ sourceSha: contract.sourceSha,
    githubRun: artifactFixture({ artifactPages: { "123": [{ total_count: 2, artifacts: [partialArtifact] }] } }).githubRun }), /Partial artifacts pagination/);
});

test("requirements discovery fails closed for malformed or tampered eligible artifacts", () => {
  for (const attack of [
    ({ run }) => { run.path = ".github/workflows/other.yml"; },
    ({ run }) => { run.head_sha = "0".repeat(40); },
    ({ artifact }) => { artifact.digest = `sha256:${"0".repeat(64)}`; },
    ({ artifact }) => { artifact.workflow_run.repository_id = 8; },
    ({ artifact }) => { artifact.workflow_run.id = 999; },
  ]) {
    const fixture = artifactFixture(); attack(fixture.values[0]);
    assert.throws(() => discoverCanonicalRequirementsReference({ sourceSha: contract.sourceSha, githubRun: fixture.githubRun }));
  }
  for (const attack of [
    (value) => { delete value.candidateSourceSha; },
    (value) => { value.sourceSha = "0".repeat(40); },
    (value) => { value.sourceContractSha256 = "0".repeat(64); },
  ]) {
    const changed = producerRequirements(); attack(changed);
    const { requirementsSha256: _old, ...body } = changed; changed.requirementsSha256 = canonicalSha256(body);
    const fixture = artifactFixture({ records: [{ runId: 123, artifactId: 456, requirements: changed }] });
    assert.throws(() => discoverCanonicalRequirementsReference({ sourceSha: contract.sourceSha, githubRun: fixture.githubRun }));
  }
  const duplicate = artifactFixture(); duplicate.pages[0].workflow_runs.push(duplicate.values[0].run); duplicate.pages[0].total_count = 2;
  assert.throws(() => discoverCanonicalRequirementsReference({ sourceSha: contract.sourceSha, githubRun: duplicate.githubRun }), /Duplicate/);
  const first = artifactFixture().values[0];
  const pages = [{ total_count: 2, artifacts: [first.artifact, { ...first.artifact, id: 789 }] }];
  assert.throws(() => discoverCanonicalRequirementsReference({ sourceSha: contract.sourceSha, githubRun: artifactFixture({ artifactPages: { "123": pages } }).githubRun }), /Ambiguous/);
  const interrupted = artifactFixture();
  assert.throws(() => discoverCanonicalRequirementsReference({ sourceSha: contract.sourceSha, githubRun: (command, args, options) => {
    if (args[1].endsWith("/zip")) throw new Error("network interrupted");
    return interrupted.githubRun(command, args, options);
  } }), /network interrupted/);
  let downloads = 0;
  assert.throws(() => discoverCanonicalRequirementsReference({ sourceSha: contract.sourceSha, githubRun: (command, args, options) => {
    if (args[1].endsWith("/zip") && ++downloads === 2) return Buffer.from("substituted after selection");
    return interrupted.githubRun(command, args, options);
  } }));
  const matchingInvalid = artifactFixture({ records: [
    { runId: 300, artifactId: 600, candidateSourceSha: contract.sourceSha },
    { runId: 100, artifactId: 400, candidateSourceSha: contract.sourceSha },
  ] });
  matchingInvalid.values[0].artifact.digest = `sha256:${"0".repeat(64)}`;
  assert.throws(() => discoverCanonicalRequirementsReference({ sourceSha: contract.sourceSha, githubRun: matchingInvalid.githubRun }));
});

test("exact predecessor mutates exactly three routines once and authenticates the successor", async () => {
  const value = harness(), result = await value.run();
  assert.deepEqual(result, { status: "APPLIED", writeCount: 3 });
  assert.equal(value.commands.filter((sql) => sql.startsWith("CREATE OR REPLACE FUNCTION")).length, 3);
  assert.equal(value.commands.filter((sql) => sql === "GRANT CREATE ON SCHEMA app_rls TO mscqr_prd_rls_phase2_auth_owner").length, 1);
  assert.equal(value.commands.filter((sql) => sql === "REVOKE CREATE ON SCHEMA app_rls FROM mscqr_prd_rls_phase2_auth_owner").length, 1);
  assert.deepEqual(value.commands.filter((sql) => /^(?:SET LOCAL ROLE|RESET ROLE)/.test(sql)), [
    "SET LOCAL ROLE mscqr_prd_rls_phase2_owner", "RESET ROLE", "SET LOCAL ROLE mscqr_prd_rls_phase2_auth_owner",
    "RESET ROLE", "SET LOCAL ROLE mscqr_prd_rls_phase2_owner", "RESET ROLE",
  ]);
});

test("already-converged successor performs zero routine writes", async () => {
  const value = harness({ classifications: [RLS_PROBE_CLASSIFICATIONS.MATCH] });
  assert.deepEqual(await value.run(), { status: "ALREADY_CONVERGED", writeCount: 0 });
  assert.equal(value.commands.filter((sql) => sql.startsWith("CREATE OR REPLACE FUNCTION")).length, 0);
  assert.equal(value.commands.filter((sql) => /^(?:GRANT|REVOKE) CREATE/.test(sql)).length, 0);
});

test("stale catalogue, missing/duplicate routine, wrong owner or database identity fails before writing", async () => {
  const cases = [
    harness({ classifications: [RLS_PROBE_CLASSIFICATIONS.UNEXPECTED] }),
    harness({ ownerRows: owners.slice(1) }), harness({ ownerRows: [...owners, owners[0]] }),
    harness({ ownerRows: owners.map((row, index) => index ? row : { ...row, owner: "wrong" }) }),
    harness({ ownerRows: owners.map((row, index) => index ? row : { ...row, schema_owner: "wrong" }) }),
    harness({ ownerRows: owners.map((row, index) => index ? row : { ...row, owner_set: false }) }),
    harness({ ownerRows: owners.map((row, index) => index ? row : { ...row, schema_owner_set: false }) }),
    harness({ ownerRows: owners.map((row, index) => index ? row : { ...row, owner_schema_create: true }) }),
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

test("every privilege-bridge failure stage aborts the transaction contract", async () => {
  for (const failStage of ["after-grant", "after-owner-role", "after-routine-1", "after-routine-2", "after-routine-3",
    "before-revoke", "after-revoke", "after-successor-readback"]) {
    const value = harness({ failStage });
    await assert.rejects(value.run(), new RegExp(`injected ${failStage} failure`));
  }
});

test("task command is one bounded transaction with no caller-selected authority or secret output", () => {
  const built = buildPrintingRoutineDeltaCommand({ sourceSha: contract.sourceSha, requirements, databaseHostname: input.databaseHostname });
  const command = built.command[1];
  assert.match(command, /client\.\$transaction/); assert.equal((command.match(/client\.\$transaction/g) || []).length, 1);
  assert.doesNotMatch(command, /Function\.prototype\.toString|fn\.toString|eval\(|new Function/);
  assert.equal(built.command.length, 4); const decoded = runtime.decodeInput(built.command[2], built.command[3]);
  assert.equal(decoded.input.contract.sourceSha, contract.sourceSha); assert.doesNotThrow(() => runtime.validateInput(decoded.input));
  assert.equal(decoded.input.contract.executorSourceSha256, hash(Buffer.from(command)));
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
  const value = buildPrintingRoutineDeltaDefinition({ sourceSha: contract.sourceSha, requirements, databaseHostname: input.databaseHostname });
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

test("hostile structured values remain canonical data and cannot alter the fixed executor", () => {
  const hostile = ["\"", "'", "`", "\\", "${process.exit(0)}", ";)}", "</script>", "\u2028", "\u2029", "line\nfeed", "carriage\rreturn", "nul\0byte", "require('node:child_process').execSync('id')"];
  const baseline = buildPrintingRoutineDeltaCommand({ sourceSha: contract.sourceSha, requirements, databaseHostname: input.databaseHostname });
  for (const value of hostile) {
    const changed = structuredClone(requirements); changed.objects.tables[0].identity = value;
    const built = buildPrintingRoutineDeltaCommand({ sourceSha: contract.sourceSha, requirements: changed, databaseHostname: input.databaseHostname });
    assert.equal(built.command[1], baseline.command[1], "Structured data changed executable source");
    const decoded = runtime.decodeInput(built.command[2], built.command[3]);
    assert.equal(decoded.input.requirements.successor.tables, canonicalSha256(changed.objects.tables));
  }
});

test("payload transport rejects malformed, noncanonical, altered and oversized data", () => {
  const built = buildPrintingRoutineDeltaCommand({ sourceSha: contract.sourceSha, requirements, databaseHostname: input.databaseHostname });
  assert.throws(() => runtime.decodeInput(`${built.command[2]}\n`, built.command[3]));
  assert.throws(() => runtime.decodeInput(built.command[2].slice(0, -4), built.command[3]));
  assert.throws(() => runtime.decodeInput(built.command[2], "0".repeat(64)));
  assert.throws(() => runtime.decodeInput("A".repeat(87388), hash(Buffer.from("x"))));
  const noncanonical = Buffer.from(JSON.stringify({ z: 1, a: 2 }));
  assert.throws(() => runtime.decodeInput(noncanonical.toString("base64"), hash(noncanonical)));
  const decoded = runtime.decodeInput(built.command[2], built.command[3]);
  for (const change of [
    (value) => { value.input.contract.sourceSha = "x"; },
    (value) => { value.input.contract.identities.reverse(); },
    (value) => { value.input.contract.predecessorSha256[Object.keys(value.input.contract.predecessorSha256)[0]] = "0".repeat(64); },
    (value) => { value.input.routines[0].name = "arbitrary"; },
    (value) => { value.input.routines[0].sql += ";DROP TABLE public.User"; },
    (value) => { value.input.databaseHostname = "host;injection"; },
    (value) => { value.input.unreviewed = true; },
  ]) { const altered = structuredClone(decoded); change(altered); assert.throws(() => runtime.validateInput(altered.input)); }
});

test("fixed node-e executor parses authenticated data and fails generically before a missing secret", () => {
  const built = buildPrintingRoutineDeltaCommand({ sourceSha: contract.sourceSha, requirements, databaseHostname: input.databaseHostname });
  const result = spawnSync(process.execPath, built.command, { cwd: "backend", env: { NODE_ENV: "production" }, encoding: "utf8" });
  assert.equal(result.status, 1); assert.equal(result.stdout, "");
  assert.equal(result.stderr, '{"status":"PRODUCTION_PRINTING_ROUTINE_DELTA_FAILED"}\n');
  assert.doesNotMatch(`${result.stdout}${result.stderr}`, /password|DATABASE_URL|secret|credential/i);
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
