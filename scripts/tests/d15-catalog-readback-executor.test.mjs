import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import { D15, canonical, authenticateD15Authorization, authenticateD15Receipt, reconstructD15Audit } from '../aws/d15-catalog-readback-contract.mjs';
import { runD15CatalogReadback } from '../aws/d15-catalog-readback-runtime.mjs';
import { SOURCE_SHA } from '../aws/build-d15-expected-catalog.mjs';
import { EXPECTED_SCHEMA_DIGEST } from '../aws/compare-production-printing-catalog.mjs';

const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 3072 });
const sha = (value) => crypto.createHash('sha256').update(value).digest('hex');
const signerArn = 'arn:aws:sts::368992683803:assumed-role/mscqr-production-rls-independent-checker/d15-test';
const executorSourceSha = 'a'.repeat(40);
const imageDigest = `sha256:${'b'.repeat(64)}`;
const now = Date.now();
const sign = (payload) => ({ payload, signatureBase64: crypto.sign('sha256', Buffer.from(canonical(payload)),
  { key: privateKey, padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: 32 }).toString('base64') });
const authorization = sign({ schemaVersion: 1, kind: 'MSCQR_D15_CATALOG_READBACK_AUTHORIZATION',
  sourceSha: D15.sourceSha, executorSourceSha, sqlSha256: D15.sqlSha256,
  expectedSchemaDigest: D15.expectedSchemaDigest, database: D15.database, databaseRole: D15.databaseRole,
  taskFamily: D15.taskFamily, imageDigest, approvalRef: 'owner-d15-readback', signerArn,
  kmsKeyArn: D15.kmsKeyArn, issuedAt: new Date(now - 60_000).toISOString(),
  expiresAt: new Date(now + 600_000).toISOString(), nonce: 'c'.repeat(32) });
const verify = (artifact) => authenticateD15Authorization(artifact, { now, key: publicKey });
const fixture = JSON.parse(fs.readFileSync(new URL('./fixtures/d15-source-installed-catalog.json', import.meta.url)));
fixture.identity = D15.databaseRole;
const dbUrl = `postgresql://${D15.databaseRole}:test-only@${D15.databaseHost}:5432/${D15.database}?sslmode=verify-full`;
const env = { RELEASE_GIT_SHA: executorSourceSha, D15_EXECUTOR_SOURCE_SHA: executorSourceSha,
  D15_AUTHORIZATION: JSON.stringify(authorization), D15_DATABASE_URL: dbUrl };

test('executor binding matches the approved offline package', () => {
  assert.equal(D15.sourceSha, SOURCE_SHA);
  assert.equal(D15.expectedSchemaDigest, EXPECTED_SCHEMA_DIGEST);
  assert.equal(sha(fs.readFileSync(new URL('../aws/read-production-printing-catalog.sql', import.meta.url))), D15.sqlSha256);
});
const execute = (overrides = {}, extras = {}) => {
  const audit = [];
  let called = false;
  const run = () => runD15CatalogReadback({ env: { ...env, ...overrides }, emit: (event) => audit.push(event),
    verifyAuthorization: verify,
    psql: () => { called = true; return { status: 0, stdout: JSON.stringify(fixture) }; }, ...extras });
  return { audit, run, called: () => called };
};

test('fixed SQL and source produce reconstructable bounded evidence', () => {
  const execution = execute();
  const result = execution.run();
  assert.equal(execution.called(), true);
  assert.equal(result.evidenceSha256, sha(canonical(fixture)));
  assert.equal(reconstructD15Audit(execution.audit, authorization).evidenceSha256, result.evidenceSha256);
});

test('wrong SQL hash, database, source, missing approval, and database identity fail before connection', () => {
  for (const [name, overrides, extras] of [
    ['sql', {}, { read: (file) => String(file).endsWith('.sql') ? Buffer.from('SELECT 1') : fs.readFileSync(file) }],
    ['database', { D15_DATABASE_URL: dbUrl.replace(D15.database, 'wrong_database') }, {}],
    ['source', { D15_EXECUTOR_SOURCE_SHA: 'e'.repeat(40) }, {}],
    ['approval', { D15_AUTHORIZATION: '' }, {}],
    ['identity', { D15_DATABASE_URL: dbUrl.replace(D15.databaseRole, 'postgres') }, {}],
  ]) {
    const execution = execute(overrides, extras);
    assert.throws(execution.run, undefined, name);
    assert.equal(execution.called(), false, name);
    assert.equal(execution.audit.length, 0, name);
  }
});

test('wrong signer, forged authorization, expiry and source downgrade fail', () => {
  for (const payload of [
    { ...authorization.payload, signerArn: signerArn.replace('independent-checker', 'release-deployer') },
    { ...authorization.payload, sourceSha: 'd'.repeat(40) },
    { ...authorization.payload, expiresAt: new Date(now - 1).toISOString() },
    { ...authorization.payload, database: 'other' },
  ]) assert.throws(() => verify(sign(payload)));
  assert.throws(() => verify({ ...authorization, payload: { ...authorization.payload, nonce: 'd'.repeat(32) } }));
});

test('truncated catalog and missing audit event fail closed', () => {
  const truncated = execute({}, { psql: () => ({ status: 0, stdout: '{"serverVersion":180004' }) });
  assert.throws(truncated.run);
  assert.deepEqual(truncated.audit.map((e) => e.kind), ['D15_STARTED']);
  const valid = execute(); valid.run();
  assert.throws(() => reconstructD15Audit(valid.audit.slice(0, -1), authorization));
  assert.throws(() => reconstructD15Audit(valid.audit.filter((e) => e.kind !== 'D15_CATALOG_CHUNK' || e.index !== 0), authorization));
});

test('receipt requires authentic checker signature, intact audit, matching task and freshness', () => {
  const execution = execute(); execution.run();
  const taskArn = `arn:aws:ecs:eu-west-2:368992683803:task/mscqr-prod-euw2-main/${'a'.repeat(32)}`;
  const task = { taskArn, taskDefinitionFamily: D15.taskFamily, lastStatus: 'STOPPED', containers: [{ imageDigest, exitCode: 0 }] };
  const receipt = sign({ schemaVersion: 1, kind: 'MSCQR_D15_CATALOG_READBACK_RECEIPT',
    sourceSha: D15.sourceSha, executorSourceSha, sqlSha256: D15.sqlSha256,
    expectedSchemaDigest: D15.expectedSchemaDigest, database: D15.database, databaseRole: D15.databaseRole,
    imageDigest, taskArn, logGroup: D15.logGroup,
    logStream: `d15/production-d15-catalog-readback/${'a'.repeat(32)}`,
    catalogEvidenceSha256: sha(canonical(fixture)), authorizationSha256: sha(canonical(authorization)),
    auditSha256: sha(canonical(execution.audit)), approvalRef: authorization.payload.approvalRef,
    signerArn, kmsKeyArn: D15.kmsKeyArn,
    issuedAt: new Date(now - 60_000).toISOString(), expiresAt: new Date(now + 600_000).toISOString() });
  const options = { authorization, evidence: fixture, audit: execution.audit, task, now, key: publicKey };
  assert.equal(authenticateD15Receipt(receipt, options).taskArn, taskArn);
  assert.throws(() => authenticateD15Receipt({ ...receipt, payload: { ...receipt.payload, auditSha256: '0'.repeat(64) } }, options));
  assert.throws(() => authenticateD15Receipt(receipt, { ...options, audit: [] }));
  assert.throws(() => authenticateD15Receipt(receipt, { ...options, authorization: { ...authorization, signatureBase64: 'AA==' } }));
  assert.throws(() => authenticateD15Receipt(receipt, { ...options, task: { ...task, taskDefinitionFamily: 'other' } }));
  assert.throws(() => authenticateD15Receipt(receipt, { ...options, task: { ...task, containers: [{ imageDigest, exitCode: 1 }] } }));
  assert.throws(() => authenticateD15Receipt(receipt, { ...options, now: now + 1_000_000 }));
  const wrongKey = crypto.generateKeyPairSync('rsa', { modulusLength: 3072 }).publicKey;
  assert.throws(() => authenticateD15Receipt(receipt, { ...options, key: wrongKey }));
});
