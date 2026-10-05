import assert from 'node:assert/strict';
import { STAGE_B, STAGE_B_MODES } from './production-green-stage-b-contract.mjs';
import { STAGE_B_TERRAFORM_BACKEND, FULL_RLS_RECEIPT_RELEASE_TAG } from './stage-b-terraform-backend-contract.mjs';

import { readStageBProtectedMainCheckout, assertStageBProtectedMainCheckout } from './stage-b-deployment-identity.mjs';
import { classifyProductionReleaseTrustPolicy, PRODUCTION_RELEASE_ROLE_ARN, PRODUCTION_RELEASE_ROLE_NAME } from './production-release-oidc-contract.mjs';
import { fileURLToPath } from 'node:url';

// This is a convergence target, not mutation authorization. Existing independent
// administrative approval must bind both the source policy and this exact tag.
export function prepareFullRlsReceiptReleaseBinding({ readCheckout = () => readStageBProtectedMainCheckout({ requireCanonicalRepository: true }) } = {}) {
  const checkout = assertStageBProtectedMainCheckout(readCheckout());
  assert.equal(checkout.mode, 'production', 'Receipt binding requires protected-main production context');
  return Object.freeze({ kind: 'FULL_RLS_RECEIPT_RELEASE_BINDING', sourceSha: checkout.currentHead,
    protectedCheckout: checkout, roleArn: PRODUCTION_RELEASE_ROLE_ARN,
    tag: Object.freeze({ Key: FULL_RLS_RECEIPT_RELEASE_TAG, Value: checkout.currentHead }) });
}

export function assertFullRlsReceiptReleaseAuthority({ run, releaseSha }) {
  assert.match(releaseSha || '', /^[a-f0-9]{40}$/);
  const raw = run(['iam', 'get-role', '--role-name', PRODUCTION_RELEASE_ROLE_NAME, '--output', 'json']);
  const role = (typeof raw === 'string' ? JSON.parse(raw) : raw).Role;
  assert.equal(role?.Arn, PRODUCTION_RELEASE_ROLE_ARN, 'Receipt binding role substitution');
  // Both canonical trust states exclude TagSession: callers cannot override the
  // administrator-owned role tag with a session tag, including via role chaining.
  classifyProductionReleaseTrustPolicy(role.AssumeRolePolicyDocument);
  const tags = (role.Tags || []).filter(({ Key }) => Key.toLowerCase() === FULL_RLS_RECEIPT_RELEASE_TAG.toLowerCase());
  assert.equal(tags.length, 1, 'Missing/ambiguous receipt release binding');
  assert.equal(tags[0].Key, FULL_RLS_RECEIPT_RELEASE_TAG);
  assert.equal(tags[0].Value, releaseSha, 'Receipt authority is not the exact release');
  return true;
}

// Only the two canonical receipt namespaces; never bucket-wide discovery.
function assertReceiptLocation(bucket, prefix) {
  assert.ok(bucket === STAGE_B_TERRAFORM_BACKEND.bucketName
    ? prefix.startsWith(`${STAGE_B_TERRAFORM_BACKEND.applyAttemptPrefix}/`)
    : bucket === STAGE_B.receiptBucket && STAGE_B_MODES.some(mode => new RegExp(`^rls-receipts/[a-f0-9]{40}/${mode}/`).test(prefix)), 'Unreviewed receipt namespace');
  assert.ok(!prefix.includes('..') && !prefix.includes('*'), 'Invalid receipt key');
}

export function listProductionReceiptObjects({ run, bucket, prefix }) {
  assertReceiptLocation(bucket, prefix);
  if (bucket === STAGE_B.receiptBucket) assertFullRlsReceiptReleaseAuthority({ run, releaseSha: prefix.split('/')[1] });
  const contents = [], keys = new Set(), tokens = new Set(); let token;
  for (let page = 0; page < 100; page++) {
    const args = ['s3api', 'list-objects-v2', '--bucket', bucket, '--prefix', prefix,
      '--expected-bucket-owner', STAGE_B.account, '--no-paginate', '--output', 'json'];
    if (token) args.push('--continuation-token', token);
    const raw = run(args), result = typeof raw === 'string' ? JSON.parse(raw) : raw;
    assert.equal(typeof result.IsTruncated, 'boolean', 'Receipt listing completion is unauthenticated');
    const rows = result.Contents ?? [];
    assert.ok(Array.isArray(rows)); assert.equal(result.KeyCount, rows.length);
    for (const row of rows) {
      assert.ok(typeof row.Key === 'string' && row.Key.startsWith(prefix), 'Receipt listing key substitution');
      assert.ok(!keys.has(row.Key), 'Duplicate receipt listing key');
      keys.add(row.Key);
      contents.push(row);
    }
    if (!result.IsTruncated) return contents;
    token = result.NextContinuationToken;
    assert.ok(typeof token === 'string' && token && !tokens.has(token), 'Incomplete/replayed receipt listing');
    tokens.add(token);
  }
  throw new Error('Receipt listing exceeds bounded complete pagination');
}

// 403 alone never establishes absence. A complete authenticated exact-prefix
// listing may prove the exact key absent; a listed key with denied GET stays denied.
export function readProductionReceiptObject({ run, bucket, key, file }) {
  assertReceiptLocation(bucket, key);
  if (bucket === STAGE_B.receiptBucket) assertFullRlsReceiptReleaseAuthority({ run, releaseSha: key.split('/')[1] });
  try {
    run(['s3api', 'get-object', '--bucket', bucket, '--key', key, '--expected-bucket-owner', STAGE_B.account, file]);
    return true;
  } catch (error) {
    const detail = String(error.stderr || error.message);
    if (/\(NoSuchKey\)/.test(detail)) return false;
    if (!/\(AccessDenied\)|\(403\)/.test(detail)) throw error;
    const rows = listProductionReceiptObjects({ run, bucket, prefix: key });
    if (rows.some(row => row.Key === key)) throw error;
    return false;
  }
}

export function receiptAbsentError() {
  return Object.assign(new Error('Authenticated receipt absence'), { code: 'RECEIPT_ABSENT' });
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  assert.equal(process.argv.length, 2, 'No release/identity overrides allowed');
  process.stdout.write(JSON.stringify(prepareFullRlsReceiptReleaseBinding()) + '\n');
}
