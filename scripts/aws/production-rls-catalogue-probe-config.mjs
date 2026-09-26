import assert from "node:assert/strict";
import crypto from "node:crypto";

export const PRODUCTION_RLS_PROBE_ENTRYPOINT = "scripts/aws/production-rls-catalogue-probe-runtime.mjs";
const SHA40 = /^[a-f0-9]{40}$/;
const SHA256 = /^[a-f0-9]{64}$/;
const HOSTNAME = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$/;

export function assertProductionRlsProbeImageSource(encoded, sourceSha) {
  const identity = JSON.parse(encoded);
  assert.deepEqual(Object.keys(identity).sort(), ["gitSha"]);
  assert.equal(identity.gitSha, sourceSha, "Probe image is not bound to protected source");
  return true;
}

export function createProductionRlsProbeRuntimeConfig(requirements, identity, securityTransportPublicKey) {
  const value = { schemaVersion: 1, sourceSha: identity?.sourceSha, candidateSourceSha: identity?.candidateSourceSha,
    probeRuntimeSourceSha: identity?.probeRuntimeSourceSha, probeImageSourceSha: identity?.probeImageSourceSha, probeImageDigest: identity?.probeImageDigest,
    applicationImageSourceSha: identity?.applicationImageSourceSha, applicationImageDigest: identity?.applicationImageDigest, requirementsSha256: requirements?.requirementsSha256,
    databaseHostname: identity?.databaseHostname, securityTransportPublicKey };
  return JSON.stringify(parseProductionRlsProbeRuntimeConfig(JSON.stringify(value)));
}

export function parseProductionRlsProbeRuntimeConfig(encoded) {
  assert.ok(typeof encoded === "string" && Buffer.byteLength(encoded) <= 8192, "Probe runtime configuration is oversized");
  const value = JSON.parse(encoded);
  assert.deepEqual(Object.keys(value).sort(), ["schemaVersion", "sourceSha", "candidateSourceSha", "probeRuntimeSourceSha", "probeImageSourceSha", "probeImageDigest",
    "applicationImageSourceSha", "applicationImageDigest", "requirementsSha256", "databaseHostname", "securityTransportPublicKey"].sort());
  assert.equal(value.schemaVersion, 1);
  assert.match(value.sourceSha || "", SHA40);
  assert.match(value.candidateSourceSha || "", SHA40);
  assert.equal(value.probeRuntimeSourceSha, value.sourceSha);
  assert.equal(value.probeImageSourceSha, value.sourceSha);
  assert.equal(value.applicationImageSourceSha, value.candidateSourceSha);
  assert.match(value.probeImageDigest || "", /^sha256:[a-f0-9]{64}$/);
  assert.match(value.applicationImageDigest || "", /^sha256:[a-f0-9]{64}$/);
  assert.match(value.requirementsSha256 || "", SHA256);
  assert.match(value.databaseHostname || "", HOSTNAME);
  if (value.securityTransportPublicKey !== null) {
    assert.ok(typeof value.securityTransportPublicKey === "string" && Buffer.byteLength(value.securityTransportPublicKey) <= 4096);
    const key = crypto.createPublicKey(value.securityTransportPublicKey);
    assert.equal(key.asymmetricKeyType, "rsa");
    assert.ok(key.asymmetricKeyDetails?.modulusLength >= 3072);
  }
  return Object.freeze(value);
}
