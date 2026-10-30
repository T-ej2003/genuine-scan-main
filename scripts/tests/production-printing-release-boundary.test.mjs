import assert from "node:assert/strict";
import test from "node:test";
import { canonicalSha256 } from "../aws/production-green-stage-b-contract.mjs";
import { catalogueAfterPrinting, PRINTING_RELEASE_OBJECTS } from "../aws/production-printing-release-boundary.mjs";
import { B03_DELTA_OBJECTS, classifyB03Catalogue } from "../aws/production-b03-catalogue-diagnostic.mjs";
import { buildC02CombinedPackage } from "../aws/production-c02-combined-package.mjs";
import { buildC02SessionTask } from "../aws/apply-production-c02-session-prerequisite.mjs";
import { createRequire } from "node:module";
import { spawnSync } from "node:child_process";
import os from "node:os";
const runtime = createRequire(import.meta.url)("../aws/production-c02-combined-executor.cjs");
const oldSha = "d785aa7f1e154f37c0dc621082e3f6c46d5d5aec", sourceSha = "a".repeat(40);
const seal = body => { const { requirementsSha256, ...rest } = body; return { ...rest, requirementsSha256: canonicalSha256(rest) }; };
const requirements = (sha, hash) => seal({ sourceSha: sha, candidateSourceSha: sha,
  objects: Object.fromEntries(Object.keys(B03_DELTA_OBJECTS).map(key => [key,
    [...B03_DELTA_OBJECTS[key], ...PRINTING_RELEASE_OBJECTS[key]].map(identity => ({ identity, sha256: hash.repeat(64) }))])) });
const predecessor = requirements(oldSha, "1"), successor = requirements(sourceSha, "2");
const after = () => catalogueAfterPrinting({ predecessor, successor, b03Objects: B03_DELTA_OBJECTS });

test("combined boundary advances only reviewed printing identities and preserves original B03 rows", () => {
  const rows = after();
  for (const key of Object.keys(rows)) for (const row of rows[key]) {
    assert.equal(row.sha256, (PRINTING_RELEASE_OBJECTS[key].includes(row.identity) ? "2" : "1").repeat(64));
  }
  assert.equal(PRINTING_RELEASE_OBJECTS.routines.length + PRINTING_RELEASE_OBJECTS.tables.length + PRINTING_RELEASE_OBJECTS.policies.length, 13);
  assert.equal(predecessor.objects.routines[0].sha256, "1".repeat(64));
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
  assert.equal(pkg.definitions.length, 6); assert.equal(pkg.policySql.length, 6);
  assert.throws(() => runtime.validatePackage({ ...pkg, sourceSha: oldSha }));
  const task = buildC02SessionTask({ sourceSha, hostname: "test.invalid", combinedRequirements: { predecessor, successor } });
  assert.ok(Buffer.byteLength(task.serialized) < 60 * 1024);
  assert.equal(task.definition.taskRoleArn, undefined);
  assert.equal(task.definition.containerDefinitions[0].secrets.length, 1);
  const result = spawnSync(process.execPath, task.definition.containerDefinitions[0].command,
    { cwd: os.tmpdir(), encoding: "utf8", env: { PATH: process.env.PATH } });
  assert.equal(result.status, 1);
  assert.equal(result.stderr.trim(), '{"status":"blocked","reason":"c02-combined-failed-closed"}');
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
