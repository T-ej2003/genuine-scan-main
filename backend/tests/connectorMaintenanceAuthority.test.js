const assert = require('node:assert/strict');
const { createHash, generateKeyPairSync, sign } = require('node:crypto');
const path = require('node:path');

const dist = path.resolve(__dirname, '../dist');
const { LOCAL_PRINT_AGENT_SOURCE_VERSION } = require(path.join(dist, 'local-print-agent/version'));
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
  sourceVersion: '2026.11.19.1', targetVersion: LOCAL_PRINT_AGENT_SOURCE_VERSION };
const challenge = proofService.createUpgradeDeviceChallenge({ ...attempt, currentVersion: attempt.sourceVersion,
  attemptId: '33045895-4cb7-49ad-81da-0d412d73fa93' });
const controlledCertification = process.env.MSCQR_TEST_CERTIFICATION === 'true';
if (controlledCertification) {
  const backendSourceSha = '1'.repeat(40);
  process.env.GIT_SHA = backendSourceSha;
  process.env.RELEASE_GIT_SHA = backendSourceSha;
  process.env.CONNECTOR_UPGRADE_CERTIFICATION_PERMIT = JSON.stringify({
    ...attempt, attemptId: challenge.attemptId, sourceRuntimeSha256: hash('certified source'),
    targetRuntimeSha256: hash('replacement'), targetInstallerSha256: hash('installer'),
    targetSourceSha: '2'.repeat(40), backendSourceSha, issuedAt: new Date(Date.now() - 1000).toISOString(),
    expiresAt: new Date(Date.now() + 60_000).toISOString(),
  });
}
const proofSha256 = hash('verified-device-proof');
const records = new Map([
  [proofService.upgradeProofKey(challenge.challengeId), JSON.stringify({ challenge, proofSha256,
    publicKeyPem: device.publicKey.export({ type: 'spki', format: 'pem' }).toString() })],
  [proofService.upgradeAttemptKey(challenge.attemptId), JSON.stringify({ ...attempt, historicalSession: true })],
]);
let unresolved = false;
let protectedEntries = [];
let protectedJournalSha;
let failHandoffStore = false;
let redisAvailable = true;
let authorizations = 0;
let authorizedTokenHash;
let runtimeVersion = attempt.sourceVersion;
const redis = { get: async key => records.get(key) || null,
  set: async (key, value, _px, _ttl, nx) => { if (failHandoffStore && key.startsWith('connector-upgrade:handoff:')) return null;
    if (nx === 'NX' && records.has(key)) return null;
    records.set(key, value); return 'OK'; },
  eval: async (_script, _count, key) => { const value = records.get(key) || null; records.delete(key); return value; } };
mock('services/redisService.js', { getRedisClient: async () => redisAvailable ? redis : null });
mock('services/auth/cookieTokenProtectionService.js', { sealCookieToken: value => `sealed:${value}`,
  openCookieToken: value => value.startsWith('sealed:') ? value.slice(7) : null });
mock('services/connectorReleaseService.js', { getConnectorReleaseManifest: () => ({ releases: [{ version: attempt.targetVersion,
  publishedAt: controlledCertification ? null : '2026-11-22T00:00:00.000Z',
  productionSignedAvailable: !controlledCertification,
  platforms: { windows: controlledCertification ? null : { installationScope: 'certified-upgrade', sha256: hash('installer') } },
  certification: controlledCertification ? { targetSourceSha: '2'.repeat(40),
    installerSha256: hash('installer'), runtimeSha256: hash('replacement') } : null }] }),
  isCertifiedUpgradeSource: (target, source, digest) => !controlledCertification && target === attempt.targetVersion &&
    source === attempt.sourceVersion && digest === hash('certified source') });
mock('controllers/connectorUpgradeDeviceProofController.js', { trustedBinding: async () => ({
  binding: { agentId: attempt.agentId, deviceFingerprint: attempt.deviceFingerprint,
    manufacturerId: attempt.manufacturerId, tenantId: attempt.tenantId,
    printerId: attempt.printerId, registrationId: attempt.registrationId },
  publicKeyPem: publicPem, sourceVersion: runtimeVersion,
}) });
let consumed = false;
let released = false;
let revoked = false;
let retiredCount = 0;
mock('rls-waves/session-c/c02/printingLifecycleRepository.js', { redeemPrintingUpgradeHandoff: async input => {
  if (input.operation === 'RELEASE_STATUS') {
    if (!released || input.tokenHash !== authorizedTokenHash || JSON.stringify(input.binding) !== JSON.stringify(binding))
      throw new Error('UPGRADE_HANDOFF_DENIED');
    return { released: true, dispatchFenced: false, binding: input.binding };
  }
  if (revoked || input.tokenHash !== authorizedTokenHash || JSON.stringify(input.binding) !== JSON.stringify(binding))
    throw new Error('UPGRADE_HANDOFF_DENIED');
  if (input.operation === 'REVOKE') { revoked = true; return { revoked: true, dispatchFenced: true }; }
  if (input.operation === 'CONSUME') {
    if (consumed) return { authorized: true, dispatchFenced: true, binding: input.binding, idempotent: true };
    consumed = true;
  } else if (!consumed) throw new Error('MAINTENANCE_AUTHORIZATION_DENIED');
  return { authorized: true, dispatchFenced: true, binding: input.binding };
}, protectUpgradeUnknownAttempts: async input => {
  protectedEntries = input.entries.filter(entry => entry.printItemId !== 'settled-item' && entry.printJobId !== 'old-job');
  protectedJournalSha = input.journalSha256;
  return { protected: protectedEntries.length, settled: input.entries.filter(entry => entry.printItemId === 'settled-item').length,
    historicalReissues: input.entries.filter(entry => entry.printJobId === 'old-job').length,
    supersededUnsubmitted: 0, gatewayJournalEntries: 0,
    protectedItemIds: protectedEntries.map(entry => entry.printItemId) };
}, administerPrintingPrinter: async input => {
  if (input.operation === 'RETIRE') { retiredCount += 1; return { retired: true, idempotent: retiredCount > 1 }; }
  if (input.operation === 'MAINTENANCE_RELEASE') {
    released = true;
    return { authorized: true, dispatchFenced: false, binding: input.payload.evidence.binding };
  }
  if (input.operation === 'MAINTENANCE_INVENTORY') return { state: 'DISPATCH_FENCED', requestId: 'fence-1',
    workDigest: hash('inventory'), inventory: { items: unresolved ? [{ id: 'unresolved' }] : protectedEntries.map(entry => ({
      id: entry.printItemId, state: 'FROZEN', pipelineState: 'NEEDS_OPERATOR_ACTION',
      dispatchMetadata: { upgradeNoReplay: { journalSha256: protectedJournalSha,
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
  installerSha256: hash('installer'), sourceSha256: hash('certified source'), targetSha256: hash('replacement'), stateSha256: 'd'.repeat(64),
  publicKeySha256: hash(publicPem), protocolVersion: 'local-agent-direct-v2' };
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
    const unsupported = response();
    await controller.issueVerifiedConnectorMaintenanceEvidence(request({ challengeId: challenge.challengeId, checkpoint,
      binding: { ...binding, sourceSha256: hash('other signed source') } }), unsupported);
    assert.equal(unsupported.code, 409, 'a signed but uncertified source must not reach durable protection');
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
    const oldRecord = { ...entries[0], name: `${hash('old-job-record')}.json`,
      sha256: hash('old-job-content'), printJobId: 'old-job' };
    const reissuedEntries = [...entries, oldRecord];
    const reissued = proofService.signMaintenanceCheckpoint(device.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(), {
      purpose: 'mscqr-connector-maintenance-checkpoint-v1', challenge, observedAt: new Date().toISOString(),
      fence: { fenced: true, active: 0, idle: true, socketClosed: true },
      journal: { count: reissuedEntries.length, entries: reissuedEntries,
        sha256: hash(JSON.stringify(reissuedEntries.map(({ name, sha256 }) => [name, sha256]))) },
      physicalOutcomes: 'UNVERIFIED',
    });
    const reissuedResult = response();
    await controller.issueVerifiedConnectorMaintenanceEvidence(request({ challengeId: challenge.challengeId,
      checkpoint: reissued, binding }), reissuedResult);
    assert.equal(reissuedResult.code, 200, 'historical governed record cannot replace the current no-replay marker');
    const settledEntry = { name: `${hash('settled-journal')}.json`, sha256: hash('settled-record'),
      printJobId: 'settled-job', printItemId: 'settled-item', attemptId: null, state: 'ATTEMPT_RESERVED' };
    const historicalEntries = [...entries, settledEntry];
    const historical = proofService.signMaintenanceCheckpoint(device.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(), {
      purpose: 'mscqr-connector-maintenance-checkpoint-v1', challenge, observedAt: new Date().toISOString(),
      fence: { fenced: true, active: 0, idle: true, socketClosed: true },
      journal: { count: historicalEntries.length, entries: historicalEntries,
        sha256: hash(JSON.stringify(historicalEntries.map(({ name, sha256 }) => [name, sha256]))) },
      physicalOutcomes: 'UNVERIFIED',
    });
    const historicalResult = response();
    await controller.issueVerifiedConnectorMaintenanceEvidence(request({ challengeId: challenge.challengeId,
      checkpoint: historical, binding }), historicalResult);
    assert.equal(historicalResult.code, 200);
    const historicalEvidence = require(path.join(dist, 'services/connectorMaintenanceEvidence')).verifyConnectorIsolationEvidence(historicalResult.body.evidence);
    assert.equal(historicalEvidence.reconciliations.length, 12, 'settled history is verified but is not frozen again');
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
    process.env.CONNECTOR_ISOLATION_AUTHORITY_PRIVATE_KEY_PEM = authority.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
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
    const pairingId = '5b7ce12e-752e-4a97-8ff3-f9aae9bd1c28';
    const secret = 'c'.repeat(64);
    const createdPairing = response();
    await controller.createConnectorUpgradePairing(request({ pairingId, secret, binding: {
      agentId: binding.agentId, deviceFingerprint: binding.deviceFingerprint,
      sourceVersion: binding.sourceVersion, targetVersion: binding.targetVersion,
      installerSha256: binding.installerSha256, stateSha256: 'd'.repeat(64),
    } }), createdPairing);
    assert.equal(createdPairing.code, 200);
    const pendingPairing = response();
    await controller.pollConnectorUpgradePairing(request({ pairingId, secret }), pendingPairing);
    assert.equal(pendingPairing.code, 202);
    const wrongSecret = response();
    await controller.pollConnectorUpgradePairing(request({ pairingId, secret: 'e'.repeat(64) }), wrongSecret);
    assert.equal(wrongSecret.code, 403);
    const inspectedPairing = response();
    const pairingRequest = request({}); pairingRequest.params.pairingId = pairingId;
    await controller.readConnectorUpgradePairing(pairingRequest, inspectedPairing);
    assert.equal(inspectedPairing.code, 200);
    assert.equal(inspectedPairing.body.data.binding.agentId, binding.agentId);
    const wrongManufacturer = response();
    await controller.completeConnectorUpgradePairing({ ...request({ pairingId, token }), user: { userId: 'other-maker' } }, wrongManufacturer);
    assert.equal(wrongManufacturer.code, 403);
    const completedPairing = response();
    await controller.completeConnectorUpgradePairing(request({ pairingId, token }), completedPairing);
    assert.equal(completedPairing.code, 200);
    const retriedPairing = response();
    await controller.completeConnectorUpgradePairing(request({ pairingId, token }), retriedPairing);
    assert.equal(retriedPairing.code, 200, 'lost completion response must retain the same authorization');
    const deliveredPairing = response();
    await controller.pollConnectorUpgradePairing(request({ pairingId, secret }), deliveredPairing);
    assert.equal(deliveredPairing.code, 200);
    assert.equal(deliveredPairing.body.token, token);
    assert.equal(deliveredPairing.body.binding.attemptId, binding.attemptId);
    const handoff = response();
    const refreshed = request({ action: 'consume', token, binding });
    refreshed.databaseSessionCapability = undefined;
    await controller.redeemConnectorMaintenanceHandoff(refreshed, handoff);
    assert.equal(handoff.code, 200);
    const afterRefresh = response();
    await controller.redeemConnectorMaintenanceHandoff(refreshed, afterRefresh);
    assert.equal(afterRefresh.code, 200, 'lost responses may retry the same fenced consumption after browser refresh');
    assert.equal(afterRefresh.body.data.idempotent, true);
    const verification = response();
    await controller.redeemConnectorMaintenanceHandoff(request({ action: 'verify', token, binding }), verification);
    assert.equal(verification.code, 200, 'browser capability rotation after redemption cannot revoke the installer token');
    runtimeVersion = attempt.targetVersion;
    const statement = JSON.stringify({ purpose: 'mscqr-connector-upgrade-postinstall-v1',
      attemptId: challenge.attemptId, observedAt: new Date().toISOString(), version: attempt.targetVersion,
      sha256: binding.targetSha256 || hash('replacement'), agentId: attempt.agentId,
      deviceFingerprint: attempt.deviceFingerprint, registrationId: attempt.registrationId,
      selectedPrinterId: 'native-printer', sessionId: 'trusted-session',
      journalSha256: protectedJournalSha, fenced: true });
    const postInstallProof = { statement,
      signature: sign(null, Buffer.from(statement), device.privateKey).toString('base64url') };
    const badPostInstall = response();
    await controller.issueVerifiedPostInstallEvidence(request({ token,
      proof: { ...postInstallProof, signature: 'a'.repeat(86) } }), badPostInstall);
    assert.equal(badPostInstall.code, 409, 'forged runtime proof cannot release printing');
    protectedEntries = [{ printItemId: 'unresolved', sha256: hash('unresolved') }];
    protectedJournalSha = hash('different-journal');
    const unprotectedPostInstall = response();
    await controller.issueVerifiedPostInstallEvidence(request({ token, proof: postInstallProof }), unprotectedPostInstall);
    assert.equal(unprotectedPostInstall.code, 409, 'changed durable no-replay evidence keeps the maintenance fence');
    protectedEntries = [];
    const postInstall = response();
    await controller.issueVerifiedPostInstallEvidence(request({ token, proof: postInstallProof }), postInstall);
    assert.equal(postInstall.code, 200, 'fresh registered connector proof and frozen work permit release review');
    const release = response();
    await controller.requestConnectorMaintenance(request({ action: 'release', evidence: postInstall.body.evidence }), release);
    assert.equal(release.code, 200);
    redisAvailable = false;
    const releaseStatus = response();
    await controller.redeemConnectorMaintenanceHandoff(request({ action: 'release-status', token, binding }), releaseStatus);
    assert.equal(releaseStatus.code, 200);
    assert.equal(releaseStatus.body.data.dispatchFenced, false);
    redisAvailable = true;
    const afterConsumption = response();
    await controller.requestConnectorMaintenance(request({ action: 'authorize', evidence: accepted.body.evidence }), afterConsumption);
    assert.equal(afterConsumption.code, 409, 'consumed authorization cannot be reissued');
    const replay = response();
    await controller.redeemConnectorMaintenanceHandoff(request({ action: 'consume', token, binding }), replay);
    assert.equal(replay.code, 200);
    assert.equal(replay.body.data.idempotent, true);
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
    const retirement = response();
    await controller.requestConnectorMaintenance(request({ action: 'retire' }), retirement);
    assert.equal(retirement.code, 200);
    assert.equal(retirement.body.data.retired, true);
    assert.equal(retiredCount, 1, 'manufacturer retirement reaches the existing printer administration boundary');
    console.log('connector maintenance authority tests passed');
  } finally {
    delete process.env.CONNECTOR_ISOLATION_AUTHORITY_PRIVATE_KEY_PEM;
    delete process.env.CONNECTOR_ISOLATION_AUTHORITY_PUBLIC_KEY_PEM;
  }
})().catch(error => { console.error(error); process.exitCode = 1; });
