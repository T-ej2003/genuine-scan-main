import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
export const canonical = (value) => JSON.stringify(value, (_, item) => item && !Array.isArray(item) && typeof item === 'object'
  ? Object.fromEntries(Object.entries(item).sort(([a], [b]) => a.localeCompare(b))) : item);
const sha256 = (value) => crypto.createHash('sha256').update(value).digest('hex');

export const D15 = Object.freeze({
  sourceSha: 'd15b79e4779d64be4c6c7ec905caea1e91d410f2',
  sqlSha256: '039b8ef435bd62da82c01086116c6129049baa10f9873632087b40768597ef80',
  expectedSchemaDigest: 'c96c74b68d15f3eda0bf06ae9fffeb1963cc24fe410f479bfc24aeadd3c1db38',
  database: 'mscqr_production_rls_green_phase2',
  databaseRole: 'mscqr_prod_d15_catalog_read',
  databaseHost: 'mscqr-production-rls-green-phase2.c3ewey6o6mq5.eu-west-2.rds.amazonaws.com',
  taskFamily: 'mscqr-production-d15-catalog-readback',
  logGroup: '/ecs/mscqr-production/d15-catalog-readback',
  kmsKeyArn: 'arn:aws:kms:eu-west-2:368992683803:key/437cdebd-95e7-4aba-8f0f-2ca08edb0478',
  account: '368992683803',
  region: 'eu-west-2',
  serverVersion: 180004,
});

const CHECKER = /^arn:aws:sts::368992683803:assumed-role\/mscqr-production-rls-independent-checker\/[A-Za-z0-9+=,.@_-]{2,64}$/;
const SHA = /^[a-f0-9]{64}$/;
const IMAGE = /^sha256:[a-f0-9]{64}$/;
const exact = (value, keys) => {
  assert.ok(value && typeof value === 'object' && !Array.isArray(value));
  assert.deepEqual(Object.keys(value).sort(), keys.sort());
};
const freshness = (payload, now) => {
  const issued = Date.parse(payload.issuedAt), expires = Date.parse(payload.expiresAt);
  assert.ok(Number.isFinite(issued) && Number.isFinite(expires));
  assert.ok(issued <= now + 300_000 && issued <= now && expires > now && expires - issued <= 1_800_000);
};
const publicKey = () => fs.readFileSync(new URL('./keys/mscqr-production-rls-approval-public.pub', import.meta.url));

export function reconstructD15Audit(audit, authorization) {
  assert.ok(Array.isArray(audit) && audit.length >= 3);
  const [start, ...rest] = audit;
  const complete = rest.pop();
  exact(start, ['kind', 'sourceSha', 'executorSourceSha', 'sqlSha256', 'authorizationSha256', 'database', 'identity']);
  assert.equal(start.kind, 'D15_STARTED');
  assert.equal(start.sourceSha, D15.sourceSha);
  assert.equal(start.executorSourceSha, authorization.payload.executorSourceSha);
  assert.equal(start.sqlSha256, D15.sqlSha256);
  assert.equal(start.authorizationSha256, sha256(canonical(authorization)));
  assert.equal(start.database, D15.database);
  assert.equal(start.identity, D15.databaseRole);
  exact(complete, ['kind', 'catalogEvidenceSha256', 'byteLength', 'chunks']);
  assert.equal(complete.kind, 'D15_COMPLETE');
  assert.equal(complete.chunks, rest.length);
  const chunks = rest.map((event, index) => {
    exact(event, ['kind', 'index', 'dataBase64']);
    assert.equal(event.kind, 'D15_CATALOG_CHUNK');
    assert.equal(event.index, index);
    assert.match(event.dataBase64, /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/);
    const bytes = Buffer.from(event.dataBase64, 'base64');
    assert.equal(bytes.toString('base64'), event.dataBase64);
    assert.ok(bytes.length > 0 && bytes.length <= 24_000);
    return bytes;
  });
  const bytes = Buffer.concat(chunks);
  assert.equal(bytes.length, complete.byteLength);
  assert.ok(bytes.length <= 8 * 1024 * 1024);
  assert.equal(sha256(bytes), complete.catalogEvidenceSha256);
  const evidence = authenticateD15CatalogOutput(bytes.toString('utf8'));
  return { evidence, evidenceSha256: sha256(canonical(evidence)), auditSha256: sha256(canonical(audit)) };
}

export function authenticateD15Authorization(artifact, { now = Date.now(), key = publicKey() } = {}) {
  exact(artifact, ['payload', 'signatureBase64']);
  const payload = artifact.payload;
  exact(payload, ['schemaVersion', 'kind', 'sourceSha', 'executorSourceSha', 'sqlSha256', 'expectedSchemaDigest',
    'database', 'databaseRole', 'taskFamily', 'imageDigest', 'approvalRef', 'signerArn', 'kmsKeyArn', 'issuedAt', 'expiresAt', 'nonce']);
  assert.equal(payload.schemaVersion, 1);
  assert.equal(payload.kind, 'MSCQR_D15_CATALOG_READBACK_AUTHORIZATION');
  for (const field of ['sourceSha', 'sqlSha256', 'expectedSchemaDigest', 'database', 'databaseRole', 'taskFamily', 'kmsKeyArn'])
    assert.equal(payload[field], D15[field]);
  assert.match(payload.executorSourceSha, /^[a-f0-9]{40}$/);
  assert.match(payload.imageDigest, IMAGE);
  assert.match(payload.signerArn, CHECKER);
  assert.match(payload.approvalRef, /^[A-Za-z0-9._:/-]{6,128}$/);
  assert.match(payload.nonce, /^[a-f0-9]{32,64}$/);
  freshness(payload, now);
  assert.match(artifact.signatureBase64, /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/);
  const signature = Buffer.from(artifact.signatureBase64, 'base64');
  assert.equal(signature.toString('base64'), artifact.signatureBase64);
  assert.ok(crypto.verify('sha256', Buffer.from(canonical(payload)),
    { key, padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: 32 }, signature));
  return { payload, authorizationSha256: sha256(canonical(artifact)) };
}

export function authenticateD15DatabaseUrl(value) {
  const url = new URL(String(value || ''));
  assert.equal(url.protocol, 'postgresql:');
  assert.equal(url.hostname, D15.databaseHost);
  assert.equal(url.port || '5432', '5432');
  assert.equal(url.pathname, `/${D15.database}`);
  assert.equal(decodeURIComponent(url.username), D15.databaseRole);
  assert.ok(url.password);
  assert.deepEqual([...url.searchParams.keys()], ['sslmode']);
  assert.equal(url.searchParams.get('sslmode'), 'verify-full');
  return {
    PGHOST: url.hostname, PGPORT: url.port || '5432', PGDATABASE: D15.database,
    PGUSER: D15.databaseRole, PGPASSWORD: decodeURIComponent(url.password), PGSSLMODE: 'verify-full',
    PGOPTIONS: '-c default_transaction_read_only=on -c statement_timeout=30000 -c lock_timeout=1000',
  };
}

export function authenticateD15CatalogOutput(output) {
  assert.ok(typeof output === 'string' && Buffer.byteLength(output) > 100 && Buffer.byteLength(output) <= 8 * 1024 * 1024);
  const lines = output.trim().split('\n');
  assert.equal(lines.length, 1);
  const evidence = JSON.parse(lines[0]);
  assert.equal(evidence.serverVersion, D15.serverVersion);
  assert.equal(evidence.database, D15.database);
  assert.equal(evidence.identity, D15.databaseRole);
  assert.equal(evidence.readOnly, true);
  for (const key of ['functions', 'policies', 'tables', 'roles', 'schemas']) assert.ok(Array.isArray(evidence[key]) && evidence[key].length);
  for (const key of ['migrationLedger', 'installLedger']) assert.deepEqual(evidence[key], { exists: true, readable: true });
  return evidence;
}

export function authenticateD15Receipt(artifact, { authorization, evidence, audit, task, now = Date.now(), key = publicKey() } = {}) {
  authenticateD15Authorization(authorization, { now, key });
  exact(artifact, ['payload', 'signatureBase64']);
  const payload = artifact.payload;
  exact(payload, ['schemaVersion', 'kind', 'sourceSha', 'executorSourceSha', 'sqlSha256', 'expectedSchemaDigest',
    'database', 'databaseRole', 'imageDigest', 'taskArn', 'logGroup', 'logStream', 'catalogEvidenceSha256',
    'authorizationSha256', 'auditSha256', 'approvalRef', 'signerArn', 'kmsKeyArn', 'issuedAt', 'expiresAt']);
  assert.equal(payload.schemaVersion, 1);
  assert.equal(payload.kind, 'MSCQR_D15_CATALOG_READBACK_RECEIPT');
  for (const field of ['sourceSha', 'sqlSha256', 'expectedSchemaDigest', 'database', 'databaseRole', 'kmsKeyArn'])
    assert.equal(payload[field], D15[field]);
  assert.match(payload.signerArn, CHECKER);
  assert.match(payload.imageDigest, IMAGE);
  assert.match(payload.taskArn, /^arn:aws:ecs:eu-west-2:368992683803:task\/mscqr-prod-euw2-main\/[a-f0-9]{32}$/);
  assert.equal(payload.logGroup, D15.logGroup);
  assert.equal(payload.logStream, `d15/production-d15-catalog-readback/${payload.taskArn.split('/').at(-1)}`);
  assert.equal(payload.executorSourceSha, authorization?.payload?.executorSourceSha);
  assert.equal(payload.imageDigest, authorization?.payload?.imageDigest);
  assert.equal(payload.approvalRef, authorization?.payload?.approvalRef);
  assert.equal(payload.authorizationSha256, sha256(canonical(authorization)));
  assert.equal(payload.catalogEvidenceSha256, sha256(canonical(evidence)));
  const reconstructed = reconstructD15Audit(audit, authorization);
  assert.equal(payload.auditSha256, reconstructed.auditSha256);
  assert.equal(payload.catalogEvidenceSha256, reconstructed.evidenceSha256);
  assert.equal(sha256(canonical(evidence)), reconstructed.evidenceSha256);
  assert.equal(task?.taskArn, payload.taskArn);
  assert.equal(task?.lastStatus, 'STOPPED');
  assert.equal(task?.containers?.[0]?.imageDigest, payload.imageDigest);
  assert.equal(task?.containers?.[0]?.exitCode, 0);
  assert.equal(task?.taskDefinitionFamily, D15.taskFamily);
  freshness(payload, now);
  assert.ok(crypto.verify('sha256', Buffer.from(canonical(payload)),
    { key, padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: 32 }, Buffer.from(artifact.signatureBase64, 'base64')));
  return payload;
}
