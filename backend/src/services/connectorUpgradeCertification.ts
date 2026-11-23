import { z } from "zod";
import { LOCAL_PRINT_AGENT_SOURCE_VERSION } from "../local-print-agent/version";
import { getConnectorReleaseManifest } from "./connectorReleaseService";

const digest = z.string().regex(/^[a-f0-9]{64}$/);
const permitSchema = z.object({
  attemptId: z.string().uuid(),
  manufacturerId: z.string().min(1), tenantId: z.string().nullable(),
  agentId: z.string().min(3), deviceFingerprint: z.string().min(8),
  printerId: z.string().uuid(), registrationId: z.string().uuid(),
  sourceVersion: z.string().regex(/^\d+\.\d+\.\d+(?:\.\d+)?$/),
  sourceRuntimeSha256: digest,
  targetVersion: z.string().regex(/^\d+\.\d+\.\d+(?:\.\d+)?$/),
  targetRuntimeSha256: digest, targetInstallerSha256: digest,
  targetSourceSha: z.string().regex(/^[a-f0-9]{40}$/), backendSourceSha: z.string().regex(/^[a-f0-9]{40}$/),
  issuedAt: z.string().datetime(), expiresAt: z.string().datetime(),
}).strict();

type Permit = z.infer<typeof permitSchema>;

// Provision only after authenticating the signed source, signed target, and
// qualification artifact. This value is deployment-scoped, never a user claim.
export const getConnectorUpgradeCertificationPermit = (now = Date.now()): Permit | null => {
  const raw = process.env.CONNECTOR_UPGRADE_CERTIFICATION_PERMIT;
  if (!raw) return null;
  try {
    const permit = permitSchema.parse(JSON.parse(raw));
    const issued = Date.parse(permit.issuedAt), expires = Date.parse(permit.expiresAt);
    const release = getConnectorReleaseManifest().releases.find(item => item.version === permit.targetVersion);
    if (issued > now || expires <= now || expires - issued > 4 * 60 * 60_000 ||
        permit.targetVersion !== LOCAL_PRINT_AGENT_SOURCE_VERSION ||
        permit.backendSourceSha !== process.env.GIT_SHA ||
        permit.backendSourceSha !== process.env.RELEASE_GIT_SHA ||
        release?.publishedAt !== null || release.productionSignedAvailable ||
        Object.values(release.platforms).some(Boolean) ||
        release.certification?.targetSourceSha !== permit.targetSourceSha ||
        release.certification.installerSha256 !== permit.targetInstallerSha256 ||
        release.certification.runtimeSha256 !== permit.targetRuntimeSha256 ||
        permit.sourceVersion === permit.targetVersion) return null;
    return permit;
  } catch { return null; }
};

export const matchesConnectorUpgradeCertification = (
  binding: Record<string, unknown>, now = Date.now(), requireDigests = false,
) => {
  const permit = getConnectorUpgradeCertificationPermit(now);
  if (!permit || Object.entries({
    attemptId: permit.attemptId, manufacturerId: permit.manufacturerId, tenantId: permit.tenantId,
    agentId: permit.agentId, deviceFingerprint: permit.deviceFingerprint,
    printerId: permit.printerId, registrationId: permit.registrationId,
    sourceVersion: permit.sourceVersion, targetVersion: permit.targetVersion,
  }).some(([key, value]) => binding[key] !== value)) return false;
  return !requireDigests || (binding.sourceSha256 === permit.sourceRuntimeSha256 &&
    binding.targetSha256 === permit.targetRuntimeSha256 &&
    binding.installerSha256 === permit.targetInstallerSha256);
};
