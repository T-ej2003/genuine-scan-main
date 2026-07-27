import { randomBytes } from "crypto";
import { Prisma } from "@prisma/client";

import prisma from "../../config/database";
import { buildBackupCodeHashCandidates, hashBackupCode, matchesBackupCodeHash } from "./backupCodeHashService";

type BackupCodeDbClient = Pick<Prisma.TransactionClient, "adminMfaCredential" | "userBackupCode">;

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

const replaceUserBackupCodesWithClient = async (
  params: { userId: string; codes: string[] },
  db: BackupCodeDbClient
) => {
  await db.userBackupCode.deleteMany({
      where: { userId: params.userId, usedAt: null },
    });
  await db.userBackupCode.createMany({
      data: params.codes.map((code) => ({
        userId: params.userId,
        codeHash: hashBackupCode(code),
      })),
    });
};

export const replaceUserBackupCodes = async (
  params: { userId: string; codes: string[] },
  db?: BackupCodeDbClient
) => db
  ? replaceUserBackupCodesWithClient(params, db)
  : prisma.$transaction((tx) => replaceUserBackupCodesWithClient(params, tx));

export const consumeUserBackupCode = async (
  params: { userId: string; code: string },
  db: BackupCodeDbClient = prisma
) => {
  const normalized = String(params.code || "").trim().toUpperCase();
  if (!backupCodeShapeOk(normalized)) return false;
  const candidates = buildBackupCodeHashCandidates(normalized);
  const consumed = await db.userBackupCode.updateMany({
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
}, db: BackupCodeDbClient = prisma) => {
  const normalized = String(params.code || "").trim().toUpperCase();
  if (!backupCodeShapeOk(normalized)) return false;

  const index = params.codesHash.findIndex((entry) => matchesBackupCodeHash(normalized, entry));
  if (index < 0) return false;

  const updated = [...params.codesHash];
  updated.splice(index, 1);
  const consumed = await db.adminMfaCredential.updateMany({
    where: {
      userId: params.userId,
      isEnabled: true,
      backupCodesHash: { equals: params.codesHash },
    },
    data: {
      backupCodesHash: updated,
      lastUsedAt: new Date(),
    },
  });
  return consumed.count === 1;
};
