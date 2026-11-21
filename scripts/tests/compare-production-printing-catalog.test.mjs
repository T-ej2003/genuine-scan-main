import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { compare } from '../aws/compare-production-printing-catalog.mjs';
import { buildExpected, canonical, sha256 } from '../aws/build-d15-expected-catalog.mjs';

const expected = JSON.parse(fs.readFileSync(new URL('../aws/d15-expected-schema.json', import.meta.url)));
const installed = JSON.parse(fs.readFileSync(new URL('./fixtures/d15-source-installed-catalog.json', import.meta.url)));
const source = JSON.parse(fs.readFileSync(new URL('../../documents/security/rls-program/generated/expected-catalog-snapshot.json', import.meta.url)));
test('expected manifest is reproducible from exact source-installed 18.4 catalogue', () => {
  const capture = JSON.parse(fs.readFileSync(new URL('./fixtures/d15-source-installed-catalog.json', import.meta.url)));
  assert.deepEqual(buildExpected(source, capture), expected);
});
installed.database = 'mscqr_production_rls_green_phase2';
installed.identity = 'approved_catalog_reader';
const clone = (value) => structuredClone(value);
const receiptFor = (evidence) => ({
  status: 'passed', sourceSha: expected.sourceSha,
  sourceContractSha256: expected.sourceContractSha256,
  migrationSetDigest: expected.migrationSetDigest,
  rollbackSqlSha256: expected.rollbackSqlSha256,
  rollbackCompatibility: 'verified', rollbackEvidenceRef: 'disposable-test-only',
  catalogEvidenceSha256: sha256(canonical(evidence)),
  database: evidence.database, catalogIdentity: evidence.identity, approvalRef: 'disposable-test-only',
  prismaMigrations: expected.prismaMigrations.map((m) => ({ ...m, state: 'applied' })),
});
const status = (evidence = installed, receipt = receiptFor(installed), manifest = expected) => compare(manifest, evidence, receipt).status;
const changed = (edit, rebind = true) => {
  const evidence = clone(installed);
  edit(evidence);
  return status(evidence, rebind ? receiptFor(evidence) : receiptFor(installed));
};

test('complete source-installed catalogue matches the pinned manifest', () => {
  assert.equal(status(), 'COMPATIBLE');
});
test('incomplete or forged evidence fails closed', () => {
  assert.equal(status(null), 'UNVERIFIED');
  assert.equal(changed((e) => { e.functions[0].definition += ' '; }, false), 'UNVERIFIED');
  assert.equal(status({ error: 'permission denied' }), 'UNVERIFIED');
  assert.equal(status('not JSON'), 'UNVERIFIED');
  assert.equal(changed((e) => { e.migrationLedger.readable = false; }), 'UNVERIFIED');
  assert.equal(changed((e) => { e.installLedger.exists = false; }), 'UNVERIFIED');
  assert.equal(changed((e) => { e.serverVersion = 180006; }), 'UNVERIFIED');
  assert.equal(changed((e) => { e.database = 'wrong_database'; }), 'UNVERIFIED');
  assert.equal(changed((e) => { e.readOnly = false; }), 'UNVERIFIED');
  assert.equal(status(installed, { ...receiptFor(installed), sourceSha: '0'.repeat(40) }), 'UNVERIFIED');
  assert.equal(status(installed, { ...receiptFor(installed), catalogIdentity: 'other' }), 'UNVERIFIED');
  assert.equal(status(installed, { ...receiptFor(installed), approvalRef: '' }), 'UNVERIFIED');
  assert.equal(status(installed, { ...receiptFor(installed), prismaMigrations: [] }), 'UNVERIFIED');
  assert.equal(status(installed, { ...receiptFor(installed), prismaMigrations: [receiptFor(installed).prismaMigrations[0], receiptFor(installed).prismaMigrations[0]] }), 'UNVERIFIED');
  assert.equal(status(installed, receiptFor(installed), { ...expected, sourceSha: '0'.repeat(40) }), 'UNVERIFIED');
  assert.equal(status(installed, receiptFor(installed), { ...expected, functions: expected.functions.slice(1) }), 'UNVERIFIED');
  assert.equal(status(installed, receiptFor(installed), { ...expected, expectedSchemaDigest: '0'.repeat(64) }), 'UNVERIFIED');
});
test('catalogue contradictions and missing objects have distinct results', () => {
  assert.equal(changed((e) => { e.functions[0].definition += ' '; }), 'INCOMPATIBLE');
  assert.equal(changed((e) => { e.functions[0].owner = 'wrong'; }), 'INCOMPATIBLE');
  assert.equal(changed((e) => { e.functions[0].acl = 'PUBLIC=X'; }), 'INCOMPATIBLE');
  assert.equal(changed((e) => { e.functions[0].publicExecute = !e.functions[0].publicExecute; }), 'INCOMPATIBLE');
  assert.equal(changed((e) => { e.functions[0].effectiveExecute.mscqr_prd_rls_phase2_app = !e.functions[0].effectiveExecute.mscqr_prd_rls_phase2_app; }), 'INCOMPATIBLE');
  assert.equal(changed((e) => { const grant = e.tables.find((t) => t.name === 'SystemCheckpoint').columnGrants[0]; grant.select = !grant.select; }), 'INCOMPATIBLE');
  assert.equal(changed((e) => { e.tables.find((t) => t.name === 'SystemCheckpoint').forceRls = false; }), 'INCOMPATIBLE');
  assert.equal(changed((e) => { e.roles[0].bypassRls = true; }), 'INCOMPATIBLE');
  assert.equal(changed((e) => { e.schemas[0].owner = 'wrong'; }), 'INCOMPATIBLE');
  assert.equal(changed((e) => { e.policies[0].using = 'true'; }), 'INCOMPATIBLE');
  assert.equal(changed((e) => { e.policies.pop(); }), 'UNVERIFIED');
  assert.equal(changed((e) => { e.functions.pop(); }), 'UNVERIFIED');
  const absent = clone(installed); const policy = absent.policies.pop();
  const delta = [`policies:${policy.table}.${policy.name}`];
  assert.equal(status(absent, { ...receiptFor(absent), approvedMigrationDeltaSha256: sha256(canonical(delta)) }), 'MIGRATION_REQUIRED');
  assert.equal(changed((e) => { e.functions.push(clone(e.functions[0])); }), 'UNVERIFIED');
  assert.equal(changed((e) => { e.policies.push({ ...e.policies[0], name: 'unexpected_policy' }); }), 'INCOMPATIBLE');
  assert.equal(status(installed, { ...receiptFor(installed), prismaMigrations: receiptFor(installed).prismaMigrations.map((m, i) => i ? m : { ...m, sha256: 'wrong' }) }), 'INCOMPATIBLE');
});
