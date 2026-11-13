#!/usr/bin/env node
import crypto from 'node:crypto';
import fs from 'node:fs';

export const SOURCE_SHA = 'd15b79e4779d64be4c6c7ec905caea1e91d410f2';
export const SOURCE_CONTRACT = '53fe3f041a8d20760caa68898a5de03fffe95eb7d51d72449ac93b96824622ef';
export const MIGRATION_DIGEST = '44d992d15d512f410966173b42298d299c34692a874b9cb0eda6fca707d620a5';
export const sha256 = (value) => crypto.createHash('sha256').update(value).digest('hex');
export const canonical = (value) => JSON.stringify(value, (_, item) => item && !Array.isArray(item) && typeof item === 'object'
  ? Object.fromEntries(Object.entries(item).sort(([a], [b]) => a.localeCompare(b))) : item);

export function buildExpected(source, installed) {
  const functionSql = fs.readFileSync(new URL('../rls/sql/generated/20-context-helpers.sql', import.meta.url), 'utf8');
  const sourceFunctionNames = [...functionSql.matchAll(/^CREATE (?:OR REPLACE )?FUNCTION (app_\w+\.\w+)\s*\(/gm)].map((match) => match[1]).sort();
  const installedFunctionNames = (installed.functions || []).map((row) => row.signature?.split('(')[0]).sort();
  if (source.sourceContractSha256 !== SOURCE_CONTRACT || source.migrationSetDigest !== MIGRATION_DIGEST
    || installed.serverVersion !== 180004 || installed.readOnly !== true
    || sourceFunctionNames.length !== 305 || canonical(sourceFunctionNames) !== canonical(installedFunctionNames)
    || installed.policies?.length !== source.policies?.length
    || source.policies.length !== 384 || source.forceRls?.length !== 78
    || source.roles?.length !== 9 || installed.roles?.length !== 9 || installed.schemas?.length !== 4
    || installed.migrationLedger?.readable !== true || installed.installLedger?.readable !== true) {
    throw new Error('Source or disposable installation is incomplete');
  }
  const policyIds = source.policies.map((p) => `${p.table}.${p.policyName}`).sort();
  const installedPolicyIds = installed.policies.map((p) => `${p.table}.${p.name}`).sort();
  const forceTables = installed.tables.filter((t) => t.forceRls).map((t) => t.name).sort();
  if (canonical(policyIds) !== canonical(installedPolicyIds)
    || canonical([...source.forceRls].sort()) !== canonical(forceTables)
    || new Set(installed.functions.map((f) => f.signature)).size !== 305
    || new Set(installed.tables.map((t) => t.name)).size !== installed.tables.length
    || source.prismaMigrations?.length !== 57) throw new Error('Installed object identities differ from approved source');
  const expected = {
    sourceSha: SOURCE_SHA, sourceContractSha256: SOURCE_CONTRACT, migrationSetDigest: MIGRATION_DIGEST,
    rollbackSqlSha256: sha256(fs.readFileSync(new URL('../../backend/src/rls-waves/session-c/c02/printingLifecycleRollback.sql', import.meta.url))),
    postgresVersion: 180004,
    functions: installed.functions.map(({ signature, definition, owner, acl, publicExecute, effectiveExecute }) => ({
      signature, definition, definitionSha256: sha256(definition), owner, acl, publicExecute, effectiveExecute,
    })),
    policies: installed.policies,
    tables: installed.tables,
    roles: installed.roles,
    schemas: installed.schemas,
    prismaMigrations: source.prismaMigrations,
  };
  return { ...expected, expectedSchemaDigest: sha256(canonical(expected)) };
}

if (process.argv[1] === new URL(import.meta.url).pathname) {
  const [installedPath, outputPath] = process.argv.slice(2);
  if (!installedPath || !outputPath) throw new Error('Usage: node build-d15-expected-catalog.mjs SOURCE_INSTALLED_CATALOG_JSON OUTPUT_JSON');
  const source = JSON.parse(fs.readFileSync(new URL('../../documents/security/rls-program/generated/expected-catalog-snapshot.json', import.meta.url)));
  const installed = JSON.parse(fs.readFileSync(installedPath));
  fs.writeFileSync(outputPath, `${JSON.stringify(buildExpected(source, installed), null, 2)}\n`, { flag: 'wx', mode: 0o600 });
}
