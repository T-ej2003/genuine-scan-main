#!/usr/bin/env node
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import { spawnSync } from 'node:child_process';
import { D15, canonical, authenticateD15Authorization, authenticateD15DatabaseUrl, authenticateD15CatalogOutput } from './d15-catalog-readback-contract.mjs';

const hash = (bytes) => crypto.createHash('sha256').update(bytes).digest('hex');
const sqlPath = new URL('./read-production-printing-catalog.sql', import.meta.url);
const caPath = new URL('./keys/eu-west-2-rds-ca.crt', import.meta.url);

export function runD15CatalogReadback({ env = process.env, emit = (value) => process.stdout.write(`${JSON.stringify(value)}\n`),
  verifyAuthorization = authenticateD15Authorization,
  read = (file) => fs.readFileSync(file), psql = (variables) => spawnSync('psql',
    ['-X', '-qAt', '-v', 'ON_ERROR_STOP=1', '-f', sqlPath.pathname],
    { env: variables, encoding: 'utf8', timeout: 120_000, maxBuffer: 8 * 1024 * 1024 }) } = {}) {
  assert.deepEqual(process.argv.slice(2), [], 'Fixed D15 executor accepts no arguments');
  const sql = read(sqlPath);
  assert.equal(hash(sql), D15.sqlSha256, 'D15 SQL bytes differ from approved SHA-256');
  const ca = read(caPath);
  assert.equal(hash(ca), '17c557502061c4879b844fff983288a2fb07d520f4cf2a5de60f5cda800a4494');
  assert.equal(env.RELEASE_GIT_SHA, env.D15_EXECUTOR_SOURCE_SHA);
  const authorization = verifyAuthorization(JSON.parse(env.D15_AUTHORIZATION || 'null'));
  assert.equal(authorization.payload.executorSourceSha, env.D15_EXECUTOR_SOURCE_SHA);
  const pg = authenticateD15DatabaseUrl(env.D15_DATABASE_URL);
  const safeEnv = { PATH: env.PATH || '/usr/bin:/bin', HOME: '/tmp', LANG: 'C', TZ: 'UTC',
    ...pg, PGSSLROOTCERT: caPath.pathname, PGCONNECT_TIMEOUT: '10',
    PGPASSFILE: '/dev/null', PGSERVICEFILE: '/dev/null' };
  emit({ kind: 'D15_STARTED', sourceSha: D15.sourceSha, executorSourceSha: env.D15_EXECUTOR_SOURCE_SHA,
    sqlSha256: D15.sqlSha256, authorizationSha256: authorization.authorizationSha256,
    database: D15.database, identity: D15.databaseRole });
  const result = psql(safeEnv);
  assert.equal(result.status, 0, 'D15 catalog readback failed');
  const evidence = authenticateD15CatalogOutput(result.stdout);
  const bytes = Buffer.from(canonical(evidence));
  assert.ok(bytes.length <= 8 * 1024 * 1024);
  const evidenceSha256 = hash(bytes);
  for (let offset = 0, index = 0; offset < bytes.length; offset += 24_000, index++)
    emit({ kind: 'D15_CATALOG_CHUNK', index, dataBase64: bytes.subarray(offset, offset + 24_000).toString('base64') });
  emit({ kind: 'D15_COMPLETE', catalogEvidenceSha256: evidenceSha256,
    byteLength: bytes.length, chunks: Math.ceil(bytes.length / 24_000) });
  return { evidence, evidenceSha256 };
}

if (process.argv[1] === new URL(import.meta.url).pathname) {
  try { runD15CatalogReadback(); }
  catch { process.stderr.write('D15 catalog readback failed closed; inspect restricted task audit.\n'); process.exitCode = 1; }
}
