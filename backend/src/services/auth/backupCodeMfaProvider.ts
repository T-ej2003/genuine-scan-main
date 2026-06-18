import { randomBytes } from "crypto";

import prisma from "../../config/database";
import { buildBackupCodeHashCandidates, hashBackupCode, matchesBackupCodeHash } from "./backupCodeHashService";

export { hashBackupCode } from "./backupCodeHashService";

const parseIntEnv = (key: string, fallback: number) => {
  const raw = Number(String(process.env[key] || "").trim());
  return Number.isFinite(raw) ? Math.floor(raw) : fallback;
};

export const getBackupCodeCount = () => Math.max(1, Math.min(20, parseIntEnv("AUTH_MFA_BACKUP_CODE_COUNT", 8)));

export const generateBackupCodes = (count = getBackupCodeCount()) => {
  const out: string[] = [];
  for (let i = 0; i < count; i += 1) {
    const raw = randomBytes(5).toString("hex").toUpperCase();
    out.push(`${raw.slice(0, 5)}-${raw.slice(5)}`);
  }
  return out;
};

export const backupCodeShapeOk = (code: string) => /^[A-Za-z0-9]{4,8}-[A-Za-z0-9]{4,8}$/.test(String(code || "").trim());

export const replaceUserBackupCodes = async (params: { userId: string; codes: string[] }) => {
  await prisma.$transaction([
    prisma.userBackupCode.deleteMany({
      where: { userId: params.userId, usedAt: null },
    }),
    prisma.userBackupCode.createMany({
      data: params.codes.map((code) => ({
        userId: params.userId,
        codeHash: hashBackupCode(code),
      })),
    }),
  ]);
};

export const consumeUserBackupCode = async (params: { userId: string; code: string }) => {
  const normalized = String(params.code || "").trim().toUpperCase();
  if (!backupCodeShapeOk(normalized)) return false;
  const candidates = buildBackupCodeHashCandidates(normalized);
  const consumed = await prisma.userBackupCode.updateMany({
    where: {
      userId: params.userId,
      codeHash: { in: candidates },
      usedAt: null,
    },
    data: {
      usedAt: new Date(),
    },
  });
  return consumed.count === 1;
};

export const consumeLegacyBackupCode = async (params: {
  userId: string;
  code: string;
  codesHash: string[];
}) => {
  const normalized = String(params.code || "").trim().toUpperCase();
  if (!backupCodeShapeOk(normalized)) return false;

  const index = params.codesHash.findIndex((entry) => matchesBackupCodeHash(normalized, entry));
  if (index < 0) return false;

  const updated = [...params.codesHash];
  updated.splice(index, 1);
  await prisma.adminMfaCredential.update({
    where: { userId: params.userId },
    data: {
      backupCodesHash: updated,
      lastUsedAt: new Date(),
    },
  });
  return true;
};
