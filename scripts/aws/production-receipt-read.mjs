import assert from 'node:assert/strict';
import { STAGE_B, STAGE_B_MODES } from './production-green-stage-b-contract.mjs';
import { STAGE_B_TERRAFORM_BACKEND } from './stage-b-terraform-backend-contract.mjs';

// Only the two canonical receipt namespaces; never bucket-wide discovery.
function assertReceiptLocation(bucket, prefix) {
  assert.ok(bucket === STAGE_B_TERRAFORM_BACKEND.bucketName
    ? prefix.startsWith(`${STAGE_B_TERRAFORM_BACKEND.applyAttemptPrefix}/`)
    : bucket === STAGE_B.receiptBucket && STAGE_B_MODES.some(mode => new RegExp(`^rls-receipts/[a-f0-9]{40}/${mode}/`).test(prefix)), 'Unreviewed receipt namespace');
  assert.ok(!prefix.includes('..') && !prefix.includes('*'), 'Invalid receipt key');
}

export function listProductionReceiptObjects({ run, bucket, prefix }) {
  assertReceiptLocation(bucket, prefix);
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
