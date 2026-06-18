import { scryptSync } from "crypto";

import { buildTokenHashCandidates, matchesHashedToken } from "../../utils/security";
import { getTokenHashSecretSet } from "../../utils/secretConfig";

const BACKUP_CODE_HASH_PREFIX = "scrypt-sha256";
const BACKUP_CODE_HASH_CONTEXT = "mscqr:mfa-backup-code:v1";

const normalizeBackupCode = (code: string) => String(code || "").trim().toUpperCase();

const scryptBackupCode = (code: string, secret: { id: string; value: string }) => {
  const normalized = normalizeBackupCode(code);
  if (!normalized) throw new Error("Backup code is required");
  const digest = scryptSync(`${normalized}\0${secret.value}`, `${BACKUP_CODE_HASH_CONTEXT}:${secret.id}`, 32, {
    N: 16_384,
    r: 8,
    p: 1,
    maxmem: 32 * 1024 * 1024,
  }).toString("hex");
  return `${BACKUP_CODE_HASH_PREFIX}:${secret.id}:${digest}`;
};

export const hashBackupCode = (code: string) => scryptBackupCode(code, getTokenHashSecretSet().current);

export const buildBackupCodeHashCandidates = (code: string) => {
  const normalized = normalizeBackupCode(code);
  if (!normalized) return [];
  const scryptCandidates = getTokenHashSecretSet().all.map((secret) => scryptBackupCode(normalized, secret));
  return Array.from(new Set([...scryptCandidates, ...buildTokenHashCandidates(normalized)]));
};

export const matchesBackupCodeHash = (code: string, storedHash: string | null | undefined) => {
  const normalizedStored = String(storedHash || "").trim();
  if (!normalizedStored) return false;
  if (normalizedStored.startsWith(`${BACKUP_CODE_HASH_PREFIX}:`)) {
    return buildBackupCodeHashCandidates(code).includes(normalizedStored);
  }
  return matchesHashedToken(code, normalizedStored);
};
