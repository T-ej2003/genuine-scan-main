#!/usr/bin/env node
import fs from 'node:fs';
import { canonical, sha256, SOURCE_SHA, SOURCE_CONTRACT, MIGRATION_DIGEST } from './build-d15-expected-catalog.mjs';

export const EXPECTED_SCHEMA_DIGEST = 'c96c74b68d15f3eda0bf06ae9fffeb1963cc24fe410f479bfc24aeadd3c1db38';
const fields = {
  functions: ['signature', 'definition', 'definitionSha256', 'owner', 'acl', 'publicExecute', 'effectiveExecute'],
  policies: ['table', 'name', 'command', 'roles', 'using', 'check'],
  tables: ['name', 'owner', 'rls', 'forceRls', 'acl', 'effectiveGrants', 'columnGrants'],
  roles: ['name', 'login', 'inherit', 'super', 'createDb', 'createRole', 'bypassRls'],
  schemas: ['name', 'owner', 'acl'],
};
const identity = (kind, row) => kind === 'policies' ? `${row.table}.${row.name}`
  : kind === 'functions' ? row.signature : row.name;
const index = (kind, rows) => {
  if (!Array.isArray(rows)) return null;
  const pairs = rows.map((row) => [identity(kind, row), row]);
  return pairs.some(([id]) => typeof id !== 'string' || !id)
    || new Set(pairs.map(([id]) => id)).size !== pairs.length ? null : new Map(pairs);
};
const result = (status, reasons) => ({ status, reasons: [...new Set(reasons)].sort() });

export function compare(expected, evidence, receipt) {
  if (!expected || !evidence || !receipt || evidence.error || evidence.readOnly !== true
    || evidence.serverVersion !== 180004 || evidence.database !== 'mscqr_production_rls_green_phase2'
    || typeof evidence.identity !== 'string' || !evidence.identity || expected.sourceSha !== SOURCE_SHA
    || expected.sourceContractSha256 !== SOURCE_CONTRACT || expected.migrationSetDigest !== MIGRATION_DIGEST
    || expected.postgresVersion !== 180004 || expected.expectedSchemaDigest !== EXPECTED_SCHEMA_DIGEST) {
    return result('UNVERIFIED', ['Source, version, or read-only evidence invalid']);
  }
  const { expectedSchemaDigest, ...body } = expected;
  if (sha256(canonical(body)) !== expectedSchemaDigest
    || expected.functions?.length !== 305 || expected.policies?.length !== 384
    || expected.tables?.length !== 81 || expected.roles?.length !== 9
    || expected.schemas?.length !== 4 || expected.prismaMigrations?.length !== 57
    || receipt.sourceSha !== SOURCE_SHA || receipt.sourceContractSha256 !== SOURCE_CONTRACT
    || receipt.migrationSetDigest !== MIGRATION_DIGEST || receipt.status !== 'passed'
    || receipt.database !== evidence.database || receipt.catalogIdentity !== evidence.identity
    || typeof receipt.approvalRef !== 'string' || !receipt.approvalRef
    || receipt.rollbackSqlSha256 !== expected.rollbackSqlSha256 || receipt.rollbackCompatibility !== 'verified'
    || typeof receipt.rollbackEvidenceRef !== 'string' || !receipt.rollbackEvidenceRef
    || receipt.catalogEvidenceSha256 !== sha256(canonical(evidence))
    || evidence.migrationLedger?.exists !== true || evidence.migrationLedger?.readable !== true
    || evidence.installLedger?.exists !== true || evidence.installLedger?.readable !== true
    || !Array.isArray(receipt.prismaMigrations)) {
    return result('UNVERIFIED', ['Manifest, catalog integrity, or migration receipt incomplete']);
  }
  const migrations = index('tables', expected.prismaMigrations);
  const installed = index('tables', receipt.prismaMigrations);
  if (!migrations || !installed) return result('UNVERIFIED', ['Duplicate migration identity']);
  const missing = [], mismatch = [];
  for (const [name, row] of migrations) {
    const actual = installed.get(name);
    if (!actual) missing.push(`migration:${name}`);
    else if (actual.sha256 !== row.sha256 || actual.state !== 'applied') mismatch.push(`migration:${name}`);
  }
  for (const name of installed.keys()) if (!migrations.has(name)) mismatch.push(`migration:unexpected:${name}`);
  for (const kind of ['functions', 'policies', 'tables', 'roles', 'schemas']) {
    const want = index(kind, expected[kind]), got = index(kind, evidence[kind]);
    if (!want || !got || [...want.values()].some((row) => fields[kind].some((field) => !(field in row)))) {
      return result('UNVERIFIED', [`Incomplete or duplicate ${kind} inventory`]);
    }
    for (const [id, row] of want) {
      const actual = got.get(id);
      if (!actual) { missing.push(`${kind}:${id}`); continue; }
      for (const field of fields[kind]) {
        const value = kind === 'functions' && field === 'definitionSha256'
          ? typeof actual.definition === 'string' ? sha256(actual.definition) : null : actual[field];
        if (canonical(value) !== canonical(row[field])) mismatch.push(`${kind}:${id}:${field}`);
      }
    }
    for (const id of got.keys()) if (!want.has(id)) mismatch.push(`${kind}:unexpected:${id}`);
  }
  if (mismatch.length) return result('INCOMPATIBLE', mismatch);
  if (missing.length) return receipt.approvedMigrationDeltaSha256 === sha256(canonical([...missing].sort()))
    ? result('MIGRATION_REQUIRED', missing)
    : result('UNVERIFIED', ['Missing objects lack an approved exact delta', ...missing]);
  return result('COMPATIBLE', []);
}

const read = (path) => { try { return JSON.parse(fs.readFileSync(path, 'utf8')); } catch { return null; } };
if (process.argv[1] === new URL(import.meta.url).pathname) {
  const [expectedPath, evidencePath, receiptPath] = process.argv.slice(2);
  if (!expectedPath || !evidencePath || !receiptPath) throw new Error('Usage: compare-production-printing-catalog.mjs EXPECTED EVIDENCE RECEIPT');
  const outcome = compare(read(expectedPath), read(evidencePath), read(receiptPath));
  process.stdout.write(`${JSON.stringify(outcome)}\n`);
  if (outcome.status !== 'COMPATIBLE') process.exitCode = 1;
}
