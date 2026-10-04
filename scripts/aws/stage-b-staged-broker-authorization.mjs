import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { STAGE_B, STAGE_B_APPROVAL_ALGORITHM, canonicalJson } from './production-green-stage-b-contract.mjs';
import { brokerDigest, assertBrokerPreparation, assertBrokerAuthorization } from './stage-b-staged-broker-contract.mjs';
import { createProductionAwsCommandRunner, PRODUCTION_AWS_CREDENTIAL_SOURCE } from './production-credential-source-contract.mjs';

export const brokerAuthorizationMessage = ({ signature, ...body }) => Buffer.from(canonicalJson(body));

// Same checker, key and algorithm as the existing Stage B approvals; distinct
// purpose prevents a runtime/RLS approval from authorizing infrastructure.
export async function signBrokerAuthorization(preparation, { makerIdentity, humanReviewId, caller, sign, verify, now = new Date() }) {
  assertBrokerPreparation(preparation);
  const checkerIdentity = (await caller()).Arn;
  const body = { schemaVersion: 1, purpose: preparation.purpose, preparationSha256: brokerDigest(preparation), sourceSha: preparation.sourceSha,
    nonce: randomBytes(32).toString('hex'), issuedAt: now.toISOString(), expiresAt: new Date(now.getTime() + 30 * 60000).toISOString(), review: { makerIdentity, checkerIdentity, humanReviewId } };
  const signature = { keyArn: STAGE_B.approvalKmsKeyArn, algorithm: STAGE_B_APPROVAL_ALGORITHM, signatureBase64: 'cGVuZGluZw==' };
  // Validate identity and phase before reaching Sign, not only afterward.
  await assertBrokerAuthorization({ ...body, signature }, preparation, { now, verify: async () => true });
  signature.signatureBase64 = await sign(brokerAuthorizationMessage(body));
  const authorization = { ...body, signature };
  await assertBrokerAuthorization(authorization, preparation, { now, verify });
  return authorization;
}

export function createBrokerKmsAuthorizationBoundary({ run }) {
  assert.equal(typeof run, 'function');
  const messageFile = (bytes, operation) => {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'mscqr-broker-authorization-'));
    fs.chmodSync(directory, 0o700);
    try {
      const file = path.join(directory, 'message'); fs.writeFileSync(file, bytes, { mode: 0o600, flag: 'wx' });
      return operation(file);
    } finally { fs.rmSync(directory, { recursive: true }); }
  };
  const json = args => JSON.parse(run([...args, '--output', 'json', '--no-cli-pager']));
  const common = ['--key-id', STAGE_B.approvalKmsKeyArn, '--message-type', 'RAW', '--signing-algorithm', STAGE_B_APPROVAL_ALGORITHM];
  return {
    caller: async () => json(['sts', 'get-caller-identity']),
    sign: async bytes => messageFile(bytes, file => json(['kms', 'sign', ...common, '--message', `fileb://${file}`]).Signature),
    verify: async authorization => messageFile(brokerAuthorizationMessage(authorization), file => json(['kms', 'verify', ...common, '--message', `fileb://${file}`, '--signature', authorization.signature.signatureBase64]).SignatureValid === true),
  };
}
export function createBrokerCheckerAuthorizationBoundary() {
  return createBrokerKmsAuthorizationBoundary({ run: createProductionAwsCommandRunner({ credentialSource: PRODUCTION_AWS_CREDENTIAL_SOURCE.INHERITED_CHECKER_SESSION }) });
}
