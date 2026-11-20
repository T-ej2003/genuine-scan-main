const assert = require('node:assert/strict');
const { createHash, generateKeyPairSync } = require('node:crypto');
const path = require('node:path');

const dist = path.resolve(__dirname, '../dist');
const mock = (name, exports) => {
  const filename = require.resolve(path.join(dist, name));
  require.cache[filename] = { id: filename, filename, loaded: true, exports };
};
const hash = value => createHash('sha256').update(value).digest('hex');
const device = generateKeyPairSync('ed25519');
const authority = generateKeyPairSync('ed25519');
const publicPem = device.publicKey.export({ type: 'spki', format: 'pem' }).toString();
process.env.CONNECTOR_ISOLATION_AUTHORITY_PRIVATE_KEY_PEM = authority.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
process.env.CONNECTOR_ISOLATION_AUTHORITY_PUBLIC_KEY_PEM = authority.publicKey.export({ type: 'spki', format: 'pem' }).toString();
const proofService = require(path.join(dist, 'services/connectorUpgradeDeviceProof'));
const attempt = { agentId: 'agent-test', deviceFingerprint: 'device-test', manufacturerId: 'maker-1', tenantId: null,
  printerId: 'd5e8d13e-4d73-411b-9b3f-6d1800e73609', registrationId: '839e55cd-86ea-4523-8544-ff4a62a15158',
  sourceVersion: '2026.11.19.1', targetVersion: '2026.11.20.1' };
const challenge = proofService.createUpgradeDeviceChallenge({ ...attempt, currentVersion: attempt.sourceVersion,
  attemptId: '33045895-4cb7-49ad-81da-0d412d73fa93' });
const proofSha256 = hash('verified-device-proof');
const records = new Map([
  [proofService.upgradeProofKey(challenge.challengeId), JSON.stringify({ challenge, proofSha256 })],
  [proofService.upgradeAttemptKey(challenge.attemptId), JSON.stringify(attempt)],
]);
let unresolved = false;
let protectedEntries = [];
let failHandoffStore = false;
let authorizations = 0;
let authorizedTokenHash;
const redis = { get: async key => records.get(key) || null,
  set: async (key, value, _px, _ttl, nx) => { if (failHandoffStore && key.startsWith('connector-upgrade:handoff:')) return null;
    if (nx === 'NX' && records.has(key)) return null;
    records.set(key, value); return 'OK'; },
  eval: async (_script, _count, key) => { const value = records.get(key) || null; records.delete(key); return value; } };
mock('services/redisService.js', { getRedisClient: async () => redis });
mock('services/auth/cookieTokenProtectionService.js', { sealCookieToken: value => `sealed:${value}`,
  openCookieToken: value => value.startsWith('sealed:') ? value.slice(7) : null });
mock('services/connectorReleaseService.js', { getConnectorReleaseManifest: () => ({ releases: [{ version: attempt.targetVersion,
  productionSignedAvailable: true, platforms: { windows: { installationScope: 'certified-upgrade', sha256: hash('installer') } } }] }) });
mock('controllers/connectorUpgradeDeviceProofController.js', { trustedBinding: async () => ({
  binding: { agentId: attempt.agentId, deviceFingerprint: attempt.deviceFingerprint,
    manufacturerId: attempt.manufacturerId, tenantId: attempt.tenantId,
    printerId: attempt.printerId, registrationId: attempt.registrationId },
  publicKeyPem: publicPem, sourceVersion: attempt.sourceVersion,
}) });
let consumed = false;
let revoked = false;
mock('rls-waves/session-c/c02/printingLifecycleRepository.js', { redeemPrintingUpgradeHandoff: async input => {
  if (revoked || input.tokenHash !== authorizedTokenHash || JSON.stringify(input.binding) !== JSON.stringify(binding))
    throw new Error('UPGRADE_HANDOFF_DENIED');
  if (input.operation === 'REVOKE') { revoked = true; return { revoked: true, dispatchFenced: true }; }
  if (input.operation === 'CONSUME') {
    if (consumed) throw new Error('MAINTENANCE_AUTHORIZATION_DENIED');
    consumed = true;
  } else if (!consumed) throw new Error('MAINTENANCE_AUTHORIZATION_DENIED');
  return { authorized: true, dispatchFenced: true, binding: input.binding };
}, protectUpgradeUnknownAttempts: async input => {
  protectedEntries = input.entries;
  return { protected: input.entries.length };
}, administerPrintingPrinter: async input => {
  if (input.operation === 'MAINTENANCE_INVENTORY') return { state: 'DISPATCH_FENCED', requestId: 'fence-1',
    workDigest: hash('inventory'), inventory: { items: unresolved ? [{ id: 'unresolved' }] : protectedEntries.map(entry => ({
      id: entry.printItemId, state: 'FROZEN', pipelineState: 'NEEDS_OPERATOR_ACTION',
      dispatchMetadata: { upgradeNoReplay: { journalSha256: hash(JSON.stringify(protectedEntries.map(({ name, sha256 }) => [name, sha256]))),
        entrySha256: entry.sha256, attemptId: entry.attemptId } },
    })),
      diagnostics: {}, localDiagnostics: [] } };
  if (input.operation === 'MAINTENANCE_AUTHORIZE') {
    if (authorizations && (consumed || authorizedTokenHash !== input.payload.tokenHash))
      throw new Error('MAINTENANCE_ATTEMPT_ALREADY_EXISTS');
    if (!authorizations) { authorizations += 1; authorizedTokenHash = input.payload.tokenHash; }
    return { authorized: true, dispatchFenced: true, binding: input.payload.evidence.binding };
  }
  if (input.operation === 'MAINTENANCE_CONSUME') {
    if (consumed) throw new Error('MAINTENANCE_AUTHORIZATION_DENIED');
    consumed = true;
  }
  return { authorized: true, dispatchFenced: true, binding: input.payload.binding };
} });
const controller = require(path.join(dist, 'controllers/printerMaintenanceController'));
const binding = { ...attempt, attemptId: challenge.attemptId, fenceRequestId: 'fence-1',
  installerSha256: hash('installer'), publicKeySha256: hash(publicPem), protocolVersion: 'local-agent-direct-v2' };
const emptyJournal = { count: 0, sha256: hash('[]'), entries: [] };
const checkpoint = proofService.signMaintenanceCheckpoint(device.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(), {
  purpose: 'mscqr-connector-maintenance-checkpoint-v1', challenge, observedAt: new Date().toISOString(),
  fence: { fenced: true, active: 0, idle: true, socketClosed: true }, journal: emptyJournal,
  physicalOutcomes: 'UNVERIFIED',
});
const response = () => ({ code: 200, setHeader() {}, status(code) { this.code = code; return this; },
  json(body) { this.body = body; return this; } });
const request = body => ({ body, params: { id: attempt.printerId }, user: { userId: attempt.manufacturerId },
  databaseSessionCapability: 'fixture-capability', requestId: 'fixture-request' });

(async () => {
  try {
    const accepted = response();
    await controller.issueVerifiedConnectorMaintenanceEvidence(request({ challengeId: challenge.challengeId, checkpoint, binding }), accepted);
    assert.equal(accepted.code, 200);
    const verified = require(path.join(dist, 'services/connectorMaintenanceEvidence')).verifyConnectorIsolationEvidence(accepted.body.evidence);
    assert.equal(verified.deviceProofSha256, proofSha256);
    assert(Date.parse(verified.expiresAt) > Date.parse(challenge.expiresAt) + 600_000,
      'installer authorization must outlive the short device challenge');
    assert.deepEqual(verified.reconciliations, []);
    assert.equal(verified.isolationEvidence[1].sha256, emptyJournal.sha256);
    unresolved = true;
    const blocked = response();
    await controller.issueVerifiedConnectorMaintenanceEvidence(request({ challengeId: challenge.challengeId, checkpoint, binding }), blocked);
    assert.equal(blocked.code, 409, 'unresolved physical work cannot receive a false reconciliation');
    unresolved = false;
    const entries = Array.from({ length: 12 }, (_, index) => ({ name: `${hash(`journal-${index}`)}.json`,
      sha256: hash(`record-${index}`), printJobId: `job-${index}`, printItemId: `item-${index}`,
      attemptId: null, state: 'ATTEMPT_RESERVED' }));
    const reserved = proofService.signMaintenanceCheckpoint(device.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(), {
      purpose: 'mscqr-connector-maintenance-checkpoint-v1', challenge, observedAt: new Date().toISOString(),
      fence: { fenced: true, active: 0, idle: true, socketClosed: true },
      journal: { count: 12, entries, sha256: hash(JSON.stringify(entries.map(({ name, sha256 }) => [name, sha256]))) },
      physicalOutcomes: 'UNVERIFIED',
    });
    const reservedResult = response();
    await controller.issueVerifiedConnectorMaintenanceEvidence(request({ challengeId: challenge.challengeId,
      checkpoint: reserved, binding }), reservedResult);
    assert.equal(reservedResult.code, 200, '12 reserved records can authorize only after durable item-by-item protection');
    const protectedEvidence = require(path.join(dist, 'services/connectorMaintenanceEvidence')).verifyConnectorIsolationEvidence(reservedResult.body.evidence);
    assert.equal(protectedEvidence.reconciliations.length, 12);
    assert(protectedEvidence.reconciliations.every(item => item.outcome === 'PROTECTED_UNKNOWN'));
    protectedEntries = [];
    const wrongInstaller = response();
    await controller.issueVerifiedConnectorMaintenanceEvidence(request({ challengeId: challenge.challengeId, checkpoint,
      binding: { ...binding, installerSha256: hash('other') } }), wrongInstaller);
    assert.equal(wrongInstaller.code, 409);
    const forged = response();
    await controller.issueVerifiedConnectorMaintenanceEvidence(request({ challengeId: challenge.challengeId,
      checkpoint: { ...checkpoint, signature: proofService.signMaintenanceCheckpoint(authority.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
        JSON.parse(checkpoint.statement)).signature }, binding }), forged);
    assert.equal(forged.code, 409);
    process.env.CONNECTOR_ISOLATION_AUTHORITY_PRIVATE_KEY_PEM = device.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
    const mismatchedAuthority = response();
    await controller.issueVerifiedConnectorMaintenanceEvidence(request({ challengeId: challenge.challengeId, checkpoint, binding }), mismatchedAuthority);
    assert.equal(mismatchedAuthority.code, 409, 'unmatched production authority configuration must fail closed');
    failHandoffStore = true;
    const noHandoff = response();
    await controller.requestConnectorMaintenance(request({ action: 'authorize', evidence: accepted.body.evidence }), noHandoff);
    assert.equal(noHandoff.code, 409);
    assert.equal(authorizations, 0, 'database authorization must not commit before handoff storage succeeds');
    assert(records.has(proofService.upgradeProofKey(challenge.challengeId)), 'proof must survive a failed handoff store');
    const reservedAuthorization = JSON.parse(records.get(proofService.upgradeAuthorizationKey(hash(accepted.body.evidence.statement))));
    failHandoffStore = false;
    const issued = response();
    await controller.requestConnectorMaintenance(request({ action: 'authorize', evidence: accepted.body.evidence }), issued);
    assert.equal(issued.code, 200);
    assert.equal(issued.body.data.token, reservedAuthorization.token.slice('sealed:'.length),
      'retry must reuse the token reserved before the failed handoff publication');
    const duplicate = response();
    await controller.requestConnectorMaintenance(request({ action: 'authorize', evidence: accepted.body.evidence }), duplicate);
    assert.equal(duplicate.code, 200, 'lost HTTP responses recover the same live authorization');
    const token = issued.body.data.token;
    assert.equal(duplicate.body.data.token, token);
    assert.equal(authorizations, 1);
    assert.equal(typeof token, 'string');
    assert(records.has(proofService.upgradeHandoffKey(hash(token))));
    assert.equal(JSON.stringify(JSON.parse(records.get(proofService.upgradeHandoffKey(hash(token)))).capability),undefined,
      'handoff must not retain the rotating browser capability');
    const handoff = response();
    const refreshed = request({ action: 'consume', token, binding });
    refreshed.databaseSessionCapability = undefined;
    await controller.redeemConnectorMaintenanceHandoff(refreshed, handoff);
    assert.equal(handoff.code, 200);
    const afterRefresh = response();
    await controller.redeemConnectorMaintenanceHandoff(refreshed, afterRefresh);
    assert.equal(afterRefresh.code, 403, 'browser refresh cannot permit a second consume');
    const verification = response();
    await controller.redeemConnectorMaintenanceHandoff(request({ action: 'verify', token, binding }), verification);
    assert.equal(verification.code, 200, 'browser capability rotation after redemption cannot revoke the installer token');
    const afterConsumption = response();
    await controller.requestConnectorMaintenance(request({ action: 'authorize', evidence: accepted.body.evidence }), afterConsumption);
    assert.equal(afterConsumption.code, 409, 'consumed authorization cannot be reissued');
    const replay = response();
    await controller.redeemConnectorMaintenanceHandoff(request({ action: 'consume', token, binding }), replay);
    assert.equal(replay.code, 403);
    const wrongBinding = response();
    await controller.redeemConnectorMaintenanceHandoff(request({ action: 'verify', token,
      binding: { ...binding, manufacturerId: 'other-maker' } }), wrongBinding);
    assert.equal(wrongBinding.code, 403);
    const missingToken = response();
    await controller.redeemConnectorMaintenanceHandoff(request({ action: 'verify', token: 'b'.repeat(64), binding }), missingToken);
    assert.equal(missingToken.code, 403);
    const revocation = response();
    await controller.redeemConnectorMaintenanceHandoff(request({ action: 'revoke', token, binding }), revocation);
    assert.equal(revocation.code, 200);
    const afterRevocation = response();
    await controller.redeemConnectorMaintenanceHandoff(request({ action: 'verify', token, binding }), afterRevocation);
    assert.equal(afterRevocation.code, 403);
    console.log('connector maintenance authority tests passed');
  } finally {
    delete process.env.CONNECTOR_ISOLATION_AUTHORITY_PRIVATE_KEY_PEM;
    delete process.env.CONNECTOR_ISOLATION_AUTHORITY_PUBLIC_KEY_PEM;
  }
})().catch(error => { console.error(error); process.exitCode = 1; });
