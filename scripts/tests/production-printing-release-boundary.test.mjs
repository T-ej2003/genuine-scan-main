import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";
import { canonicalSha256 } from "../aws/production-green-stage-b-contract.mjs";
import { catalogueAfterPrinting, PRINTING_RELEASE_NAMES, PRINTING_RELEASE_OBJECTS, PUBLIC_VERIFICATION_RELEASE_NAMES, PUBLIC_VERIFICATION_RELEASE_POLICIES } from "../aws/production-printing-release-boundary.mjs";
import { B03_DELTA_OBJECTS, classifyB03Catalogue } from "../aws/production-b03-catalogue-diagnostic.mjs";
import { buildC02CombinedPackage } from "../aws/production-c02-combined-package.mjs";
import { authenticateC02SessionResult, buildC02SessionTask } from "../aws/apply-production-c02-session-prerequisite.mjs";
import { createRequire } from "node:module";
import { spawnSync } from "node:child_process";
import os from "node:os";
import fs from "node:fs";
import path from "node:path";
import vm from "node:vm";
const runtime = createRequire(import.meta.url)("../aws/production-c02-combined-executor.cjs");
const oldSha = "d785aa7f1e154f37c0dc621082e3f6c46d5d5aec", sourceSha = "a".repeat(40);
const seal = body => { const { requirementsSha256, ...rest } = body; return { ...rest, requirementsSha256: canonicalSha256(rest) }; };
const requirements = (sha, hash, historical = false) => seal({ sourceSha: sha, candidateSourceSha: sha,
  objects: Object.fromEntries(Object.keys(B03_DELTA_OBJECTS).map(key => [key,
    [...B03_DELTA_OBJECTS[key], ...PRINTING_RELEASE_OBJECTS[key]]
      .filter(identity => !historical || !["PrintItemEvent.printing_lifecycle_printitemevent_select", "PrintJobChunk.printing_lifecycle_printjobchunk_select", ...PUBLIC_VERIFICATION_RELEASE_POLICIES].includes(identity))
      .map(identity => ({ identity, sha256: hash.repeat(64) }))])) });
const predecessor = requirements(oldSha, "1", true), successor = requirements(sourceSha, "2");
const after = () => catalogueAfterPrinting({ predecessor, successor, b03Objects: B03_DELTA_OBJECTS });

test("combined boundary advances only reviewed printing identities and preserves original B03 rows", () => {
  const rows = after();
  for (const key of Object.keys(rows)) for (const row of rows[key]) {
    assert.equal(row.sha256, (PRINTING_RELEASE_OBJECTS[key].includes(row.identity) ? "2" : "1").repeat(64));
  }
  assert.equal(PRINTING_RELEASE_OBJECTS.routines.length + PRINTING_RELEASE_OBJECTS.tables.length + PRINTING_RELEASE_OBJECTS.policies.length, 28);
  assert.equal(predecessor.objects.routines[0].sha256, "1".repeat(64));
});

test("every printing and public routine changed by this PR has a governed installer entry", () => {
  const base = "892cea9cc590b4a01bfd64bc9ea82f73a4321612";
  for (const [file, schema, delimiter, allowed] of [
    ["backend/src/rls-waves/session-c/c02/printingLifecycle.sql", "app_rls", "$fn$;", PRINTING_RELEASE_NAMES],
    ["backend/src/rls-waves/session-b/b02/publicVerificationFunctions.sql", "app_public", "$$;", PUBLIC_VERIFICATION_RELEASE_NAMES],
  ]) {
    const old = spawnSync("git", ["show", `${base}:${file}`], { encoding: "utf8" });
    assert.equal(old.status, 0, old.stderr);
    const definitions = source => new Map([...source.matchAll(new RegExp(`CREATE OR REPLACE FUNCTION ${schema}\\.([a-z0-9_]+)\\(`, "g"))]
      .map(match => [match[1], source.slice(match.index, source.indexOf(`\n${delimiter}`, match.index) + delimiter.length + 1)]));
    const before = definitions(old.stdout), after = definitions(fs.readFileSync(file, "utf8"));
    const changed = [...after].filter(([name, sql]) => before.get(name) !== sql).map(([name]) => name);
    assert.ok(changed.length > 0);
    const incremental = file.endsWith("printingLifecycle.sql")
      ? fs.readFileSync("backend/src/rls-waves/session-c/c02/printingMaintenanceRetryIncremental.sql", "utf8") : "";
    if (incremental) {
      assert.match(incremental, /^\\set ON_ERROR_STOP on\nBEGIN;\n/);
      assert.match(incremental, /MAINTENANCE_MIGRATION_IDENTITY_INVALID/);
      assert.match(incremental, /\nCOMMIT;\n$/);
      const productionDefinition = after.get("printing_maintenance_gate")
        .replaceAll("{{APP_ROLE}}", "'mscqr_prd_rls_phase2_app'")
        .replaceAll("{{WORKER_ROLE}}", "'mscqr_prd_rls_phase2_worker'");
      assert.deepEqual([...definitions(incremental)], [["printing_maintenance_gate", productionDefinition]],
        "incremental migration must install the exact canonical function and no other routine");
      const partialBatchIncremental = fs.readFileSync("backend/src/rls-waves/session-c/c02/printingPartialBatchIncremental.sql", "utf8");
      assert.match(partialBatchIncremental, /^\\set ON_ERROR_STOP on\nBEGIN;\n/);
      assert.match(partialBatchIncremental, /PRINT_JOB_MIGRATION_IDENTITY_INVALID/);
      const predecessorBody = before.get("printing_create_job").split("AS $fn$")[1].split("\n$fn$;")[0];
      const successorBody = after.get("printing_create_job").split("AS $fn$")[1].split("\n$fn$;")[0];
      for (const body of [predecessorBody, successorBody]) {
        assert.ok(partialBatchIncremental.includes(createHash("sha256").update(`${body}\n`).digest("hex")),
          "incremental migration must authenticate the exact predecessor and successor bodies");
      }
      assert.match(partialBatchIncremental, /p\.proconfig=ARRAY\['search_path=pg_catalog, public'\]/);
      assert.equal((partialBatchIncremental.match(/pg_get_functiondef\(p\.oid\)/g) || []).length, 2,
        "preflight and postflight must authenticate the full function definition");
      assert.match(partialBatchIncremental, /PRINT_JOB_MIGRATION_SUCCESSOR_INVALID/);
      assert.match(partialBatchIncremental, /\nCOMMIT;\n$/);
      assert.deepEqual([...definitions(partialBatchIncremental)], [["printing_create_job", after.get("printing_create_job")]],
        "partial-batch migration must install the exact canonical function and no other routine");
    }
    assert.deepEqual(changed.filter(name => !allowed.includes(name) &&
      !(incremental && ["printing_maintenance_gate", "printing_create_job"].includes(name))), [], `${file} changed functions missing from governed release`);
  }
});

test("combined boundary rejects unknown changes, removals, duplicate rows, tampering and source mismatch", () => {
  for (const mutate of [
    r => r.objects.roles.push({ identity: "unapproved", sha256: "3".repeat(64) }),
    r => r.objects.tables.splice(r.objects.tables.findIndex(x => x.identity === "PrinterAgentSession"), 1),
    r => r.objects.routines.push(r.objects.routines[0]),
    r => r.candidateSourceSha = oldSha,
  ]) {
    const changed = structuredClone(successor); mutate(changed);
    assert.throws(() => catalogueAfterPrinting({ predecessor, successor: seal(changed), b03Objects: B03_DELTA_OBJECTS }));
  }
  assert.throws(() => catalogueAfterPrinting({ predecessor: { ...predecessor, sourceSha }, successor, b03Objects: B03_DELTA_OBJECTS }));
});

test("B03 diagnostic requires all printing deltas at exact successor, never merely allowlisted drift", () => {
  const candidate = { ...successor, schemaVersion: 1 };
  const next = seal(candidate), image = `sha256:${"a".repeat(64)}`;
  const classify = catalogue => {
    const body = { schemaVersion: 1, kind: "PRODUCTION_RLS_CATALOGUE_PROBE", sourceSha, candidateSourceSha: sourceSha,
      requirementsSha256: next.requirementsSha256, probeImageDigest: image, applicationImageDigest: image,
      databaseRole: "mscqr_prod_rls_canary_read", catalogue };
    return classifyB03Catalogue({ predecessor, successor: next, probeIdentity: { sourceSha, probeImageDigest: image, applicationImageDigest: image },
      probe: { ...body, evidenceSha256: canonicalSha256(body) } });
  };
  assert.equal(classify(after()).differences.length, 18);
  assert.throws(() => classify(predecessor.objects), /Printing prerequisite/);
  const drift = structuredClone(after()); drift.tables.find(r => r.identity === "PrinterAgentSession").sha256 = "9".repeat(64);
  assert.throws(() => classify(drift), /Printing prerequisite/);
});

test("combined C02 task keeps root executor bindings and bounded source-authenticated transport", () => {
  const pkg = buildC02CombinedPackage({ sourceSha, predecessor, successor });
  assert.deepEqual(runtime.validatePackage(pkg), pkg);
  assert.equal(pkg.definitions.length, 12); assert.equal(pkg.policySql.length, 19);
  assert.ok(pkg.definitions.some(({ schema, name }) => schema === "app_rls" && name === "printing_gateway_job"));
  assert.deepEqual(pkg.definitions.slice(-4).map(({ schema, name }) => `${schema}.${name}`), [
    "app_rls.printing_worker_network_job", "app_public.public_verify_execute", "app_public.verify_signed_qr", "app_public.claim_customer_ownership",
  ]);
  const publicExecutor = pkg.definitions.find(({ name }) => name === "public_verify_execute");
  assert.match(publicExecutor.sql, /activation\."eventType"='AUTOMATIC_ACTIVATION'/);
  assert.match(publicExecutor.sql, /auto_activated AND qr\."issuanceMode"='GOVERNED_PRINT'/);
  for (const identity of PUBLIC_VERIFICATION_RELEASE_POLICIES) {
    const [table, name] = identity.split(".");
    assert.ok(pkg.policySql.some(sql => sql.startsWith(`CREATE POLICY "${name}" ON public."${table}" `)));
  }
  assert.deepEqual(pkg.evidenceGrants.map(sql => /ON TABLE public\."([^"]+)"/.exec(sql)?.[1]), ['QRCode', 'QRCode', 'PrintItemEvent', 'PrintJobChunk']);
  assert.deepEqual(pkg.publicGrants.map(sql => /ON TABLE public\."([^"]+)"/.exec(sql)?.[1]), ['QRCode', 'PrintItem', 'PrintSession', 'PrintAuditEvent']);
  const broadened = { ...pkg, evidenceGrants: [...pkg.evidenceGrants] };
  broadened.evidenceGrants[2] = broadened.evidenceGrants[2].replace('SELECT ("printItemId")', 'SELECT ("printItemId", "details")');
  const { packageSha256: _ignored, ...body } = broadened;
  assert.throws(() => runtime.validatePackage({ ...body, packageSha256: canonicalSha256(body) }));
  const broadenedPublic = { ...pkg, publicGrants: [...pkg.publicGrants] };
  broadenedPublic.publicGrants[1] = broadenedPublic.publicGrants[1].replace('"confirmationEvidence"', '"confirmationEvidence", "code"');
  const { packageSha256: _ignoredPublic, ...publicBody } = broadenedPublic;
  assert.throws(() => runtime.validatePackage({ ...publicBody, packageSha256: canonicalSha256(publicBody) }));
  assert.throws(() => runtime.validatePackage({ ...pkg, sourceSha: oldSha }));
  const task = buildC02SessionTask({ sourceSha, hostname: "test.invalid", combinedRequirements: { predecessor, successor } });
  assert.ok(Buffer.byteLength(task.serialized) < 60 * 1024);
  assert.equal(task.definition.taskRoleArn, undefined);
  assert.equal(task.definition.containerDefinitions[0].secrets.length, 1);
  const resultBody = { schemaVersion: 2, kind: "PRODUCTION_C02_COMBINED_INSTALL_RESULT", sourceSha,
    packageSha256: pkg.packageSha256, database: "mscqr_production_rls_green_phase2", databaseRole: "mscqr_prod_admin",
    status: "APPLIED", writeCount: 55 };
  assert.equal(authenticateC02SessionResult(JSON.stringify({ ...resultBody, evidenceSha256: canonicalSha256(resultBody) }),
    { sourceSha, packageSha256: pkg.packageSha256, combined: true }).writeCount, 55);
  const result = spawnSync(process.execPath, task.definition.containerDefinitions[0].command,
    { cwd: os.tmpdir(), encoding: "utf8", env: { PATH: process.env.PATH } });
  assert.equal(result.status, 1);
  assert.equal(result.stderr.trim(), '{"status":"blocked","reason":"c02-combined-failed-closed"}');
});

test("combined C02 selects the same narrow grants from production-role generated SQL", () => {
  const temporary = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-c02-grants-"));
  try {
    for (const name of ["backend/src/rls-waves/session-c/c02/printingLifecycle.sql",
      "backend/src/rls-waves/session-b/b02/publicVerificationFunctions.sql",
      "backend/prisma/migrations/20261028210000_printer_agent_session_sequence/migration.sql",
      "scripts/rls/sql/generated/20-context-helpers.sql", "scripts/rls/sql/generated/21-runtime-grants.sql",
      "scripts/rls/sql/generated/30-policies.sql"]) {
      const target = path.join(temporary, name);
      fs.mkdirSync(path.dirname(target), { recursive: true });
      const source = fs.readFileSync(name, "utf8");
      fs.writeFileSync(target, name.startsWith("scripts/") ? source.replaceAll("mscqr_rls_cert_", "mscqr_prd_rls_phase2_") : source);
    }
    const pkg = buildC02CombinedPackage({ sourceSha, predecessor, successor, repositoryRoot: temporary });
    assert.deepEqual(pkg.evidenceGrants, buildC02CombinedPackage({ sourceSha, predecessor, successor }).evidenceGrants);
  } finally {
    fs.rmSync(temporary, { recursive: true, force: true });
  }
});

test("combined C02 refuses contradictory, uncommitted or duplicated Prisma history", async () => {
  const pkg = buildC02CombinedPackage({ sourceSha, predecessor, successor });
  const row = { checksum: pkg.sessionPackage.migrationSha256, finished_at: new Date(), rolled_back_at: null };
  for (const rows of [[{ ...row, checksum: "0".repeat(64) }], [{ ...row, finished_at: null }], [{ ...row, rolled_back_at: new Date() }], [row, row]]) {
    await assert.rejects(runtime.migrationState({ $executeRawUnsafe: async () => {}, $queryRawUnsafe: async () => rows }, pkg));
  }
  assert.equal(await runtime.migrationState({ $executeRawUnsafe: async () => {}, $queryRawUnsafe: async () => [] }, pkg), false);
  assert.equal(await runtime.migrationState({ $executeRawUnsafe: async () => {}, $queryRawUnsafe: async () => [row] }, pkg), true);
});


test("embedded ECS entrypoint resolves Prisma from the actual /app runtime layout", async () => {
  const task = buildC02SessionTask({ sourceSha, hostname: "test.invalid", combinedRequirements: { predecessor, successor } });
  const command = task.definition.containerDefinitions[0].command;
  const probes = [], imports = [];
  let clientReached = false, stderr = "", context;
  const nativeRequire = createRequire(import.meta.url);
  const sandboxRequire = name => {
    imports.push(name);
    if (name === "node:fs") return { existsSync: path => {
      probes.push(path); return path === "/app/node_modules/prisma/build/index.js";
    } };
    if (name === "@prisma/client") return { PrismaClient: class {
      constructor() { clientReached = true; throw new Error("stop before database access"); }
    } };
    if (name === "node:vm") return { runInThisContext: code => vm.runInContext(code, context) };
    return nativeRequire(name);
  };
  context = vm.createContext({ require: sandboxRequire, Buffer, URL, process: {
    argv: [process.execPath, ...command.slice(2)],
    env: { RELEASE_GIT_SHA: sourceSha, MSCQR_C02_ADMIN_PASSWORD: "local-test-only" },
    stderr: { write: value => { stderr += value; } }, stdout: { write: () => assert.fail("No success before database access") },
  } });
  await vm.runInContext(command[1], context);
  assert.equal(clientReached, true, JSON.stringify({ imports, probes, stderr }));
  assert.deepEqual(probes, ["/app/node_modules/prisma/build/index.js"]);
  assert.ok(imports.includes("@prisma/client"));
  assert.ok(!imports.some(name => name.includes("/app/backend")));
  assert.equal(stderr.trim(), '{"status":"blocked","reason":"c02-combined-failed-closed"}');
  const dockerfile = fs.readFileSync("backend/Dockerfile", "utf8");
  assert.match(dockerfile, /WORKDIR \/app/);
  assert.match(dockerfile, /COPY --from=builder --chown=node:node \/workspace\/backend\/node_modules \.\/node_modules/);
});

test("migration-history reconciliation uses the image CLI path without a checkout override", async () => {
  const pkg = buildC02CombinedPackage({ sourceSha, predecessor, successor });
  let resolved = false, invokedCli;
  const nativeRequire = createRequire(new URL("../aws/production-c02-combined-executor.cjs", import.meta.url)), module = { exports: {} };
  vm.runInNewContext(fs.readFileSync("scripts/aws/production-c02-combined-executor.cjs", "utf8"), {
    module, Buffer, URL, process, require: name => name === "node:child_process" ? { execFileSync: (_node, args) => {
      invokedCli = args[0]; resolved = true;
    } } : nativeRequire(name),
  });
  const tx = { $executeRawUnsafe: async () => {}, $queryRawUnsafe: async () => resolved ?
    [{ checksum: pkg.sessionPackage.migrationSha256, finished_at: new Date(), rolled_back_at: null }] : [] };
  await module.exports.recordMigration({ client: { $transaction: run => run(tx) },
    url: "postgresql://mscqr_prod_admin@localhost:55432/disposable_test", pkg });
  assert.equal(invokedCli, "/app/node_modules/prisma/build/index.js");
});
