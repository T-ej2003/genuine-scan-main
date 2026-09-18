import assert from "node:assert/strict";
import { bootstrapPartialStateDigest, bootstrapRecoveryOperations, completedBootstrapRecovery, historicalBootstrapAuthorization, historicalBootstrapIncident } from "./component-bootstrap-partial-recovery-contract.mjs";
import { digest } from "./component-iam-installation-contract.mjs";
import { bootstrapManagedIdentities, componentBrokerArn } from "./component-installation-identity-contract.mjs";
import { assertComponentSessionRecord } from "./component-session-proof.mjs";

const sha256 = value => assert.match(value || "", /^[a-f0-9]{64}$/);
const uuid = value => assert.match(value || "", /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/);
const timestamp = value => assert.equal(new Date(Date.parse(value)).toISOString(), value);

function assertHistoricalLineage(bootstrap) {
  const incident = historicalBootstrapIncident;
  for (const [field, expected] of Object.entries({ sourceSha: incident.sourceSha, transitionId: incident.transitionId,
    authorizationSha256: incident.authorizationSha256, manifestSha256: incident.manifestSha256,
    identitySetSha256: incident.identitySetSha256, packageSha256: incident.packageSha256 })) assert.equal(bootstrap[field], expected, `Historical bootstrap ${field} differs`);
  assert.deepEqual(bootstrap.authorization, historicalBootstrapAuthorization());
  assertComponentSessionRecord(bootstrap.operatorProof);
  for (const [field, expected] of Object.entries({ sourceSha: incident.sourceSha, transitionId: incident.transitionId,
    authorizationSha256: incident.authorizationSha256, purpose: "IDENTITY_BOOTSTRAP" })) assert.equal(bootstrap.operatorProof[field], expected);
  uuid(bootstrap.owner);
}

function assertRecoveredClosure(bootstrap) {
  const expectedKeys = ["authorization", "authorizationSha256", "broker", "closedAt", "identities", "identityReadbackSha256", "identitySetSha256", "manifestSha256", "operatorProof", "owner", "packageSha256", "recovery", "runtimeVersions", "schemaVersion", "sourceSha", "state", "transitionId"];
  assert.deepEqual(Object.keys(bootstrap).sort(), expectedKeys.sort(), "Malformed recovered bootstrap closure");
  assertHistoricalLineage(bootstrap);
  assert.equal(bootstrap.state, "BOOTSTRAP_CLOSED"); timestamp(bootstrap.closedAt);
  assert(Array.isArray(bootstrap.identities));
  assert.deepEqual(bootstrap.identities.map(({ arn }) => arn), bootstrapManagedIdentities().map(({ arn }) => arn));
  for (const identity of bootstrap.identities) {
    assert.deepEqual(Object.keys(identity).sort(), ["arn", "policy", "role"]);
    assert.equal(identity.role, "EXPECTED"); assert.equal(identity.policy, "EXPECTED");
  }
  assert.equal(bootstrap.identityReadbackSha256, digest(bootstrap.identities));
  assert.equal(bootstrap.identitySetSha256, digest(bootstrapManagedIdentities()), "Recovery identity set differs");
  const recovery = bootstrap.recovery;
  const recoveryKeys = ["authorizationExpiresAt", "authorizationHistory", "authorizationSha256", "closedAt", "finalManifestSha256", "finalPackageSha256", "newManifestSha256", "newPackageSha256", "oldPackageSha256", "oldRevisionId", "owner", "partialStateSha256", "remainingOperations", "schemaVersion", "sessionExpiresAt", "sourceSha", "state", "transitionId", "versions"];
  assert(recovery && typeof recovery === "object" && !Array.isArray(recovery), "Missing recovery closure");
  assert.deepEqual(Object.keys(recovery).sort(), recoveryKeys.sort(), "Malformed recovery closure");
  assert.equal(recovery.schemaVersion, 1); assert.equal(recovery.state, "RECOVERY_CLOSED");
  uuid(recovery.owner);
  for (const field of ["transitionId", "authorizationSha256", "sourceSha"]) assert.equal(recovery[field], completedBootstrapRecovery[field], `Recovery ${field} differs`);
  for (const field of ["newPackageSha256", "finalPackageSha256"]) assert.equal(recovery[field], completedBootstrapRecovery.packageSha256, `Recovery ${field} differs`);
  for (const field of ["newManifestSha256", "finalManifestSha256"]) assert.equal(recovery[field], completedBootstrapRecovery.manifestSha256, `Recovery ${field} differs`);
  for (const field of ["authorizationExpiresAt", "sessionExpiresAt", "closedAt"]) timestamp(recovery[field]);
  assert.deepEqual(recovery.remainingOperations, bootstrapRecoveryOperations);
  assert.equal(recovery.oldPackageSha256, historicalBootstrapIncident.packageSha256);
  assert.equal(recovery.oldRevisionId, historicalBootstrapIncident.revisionId);
  assert.equal(recovery.partialStateSha256, bootstrapPartialStateDigest());
  assert(Array.isArray(recovery.authorizationHistory));
  const authorizations = new Set([recovery.authorizationSha256]);
  for (const prior of recovery.authorizationHistory) {
    assert.deepEqual(Object.keys(prior).sort(), ["authorizationExpiresAt", "authorizationSha256", "owner", "sessionExpiresAt"]);
    sha256(prior.authorizationSha256); uuid(prior.owner); timestamp(prior.authorizationExpiresAt); timestamp(prior.sessionExpiresAt);
    assert(!authorizations.has(prior.authorizationSha256), "Repeated recovery authorization"); authorizations.add(prior.authorizationSha256);
  }
  assert.deepEqual(bootstrap.broker, { functionArn: componentBrokerArn, packageSha256: completedBootstrapRecovery.packageSha256,
    manifestSha256: completedBootstrapRecovery.manifestSha256, runtimeVersions: bootstrap.runtimeVersions });
  assert.deepEqual(recovery.versions, ["1", "2", "3"]);
  return { sourceSha: recovery.sourceSha, packageSha256: recovery.finalPackageSha256, manifestSha256: recovery.finalManifestSha256, recovered: true };
}

// The original record is immutable incident lineage. A completed recovery adds
// a second, fully-bound effective lineage; malformed recovery never falls back.
export function assertEffectiveBootstrapTrustAnchor(bootstrap, manifest, packageSha256) {
  assert(bootstrap && typeof bootstrap === "object" && !Array.isArray(bootstrap));
  assert.equal(bootstrap.schemaVersion, 1); assert.equal(bootstrap.state, "BOOTSTRAP_CLOSED", "Trust anchor bootstrap is incomplete");
  sha256(packageSha256);
  if (Object.hasOwn(bootstrap, "recovery")) return assertRecoveredClosure(bootstrap);
  assert.equal(bootstrap.sourceSha, manifest.sourceSha);
  assert.equal(bootstrap.manifestSha256, digest(manifest));
  assert.equal(bootstrap.identitySetSha256, digest(manifest.identities));
  assert.equal(bootstrap.packageSha256, packageSha256);
  return { sourceSha: bootstrap.sourceSha, packageSha256, manifestSha256: bootstrap.manifestSha256, recovered: false };
}
