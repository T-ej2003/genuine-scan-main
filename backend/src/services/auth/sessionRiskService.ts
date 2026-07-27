import { AuthRiskLevel, UserRole } from "@prisma/client";

import { hashToken } from "../../utils/security";
import {
  loadRecentAuthSessionRiskInputs,
  recordAuthSessionRiskSignal,
} from "../../rls-waves/session-b/b01/authenticatedSecurityRepository";
import type { Prisma } from "@prisma/client";

const parseIntEnv = (key: string, fallback: number) => {
  const raw = Number(String(process.env[key] || "").trim());
  return Number.isFinite(raw) ? Math.floor(raw) : fallback;
};

const toRiskLevel = (score: number): AuthRiskLevel => {
  if (score >= 85) return AuthRiskLevel.CRITICAL;
  if (score >= 65) return AuthRiskLevel.HIGH;
  if (score >= 40) return AuthRiskLevel.MEDIUM;
  return AuthRiskLevel.LOW;
};

const safeHash = (value?: string | null) => {
  const normalized = String(value || "").trim();
  if (!normalized) return null;
  try {
    return hashToken(normalized);
  } catch {
    return null;
  }
};

const isAdminRole = (role: UserRole) =>
  role === UserRole.SUPER_ADMIN ||
  role === UserRole.PLATFORM_SUPER_ADMIN ||
  role === UserRole.LICENSEE_ADMIN ||
  role === UserRole.ORG_ADMIN;

export const assessAuthSessionRisk = async (input: {
  userId: string;
  role: UserRole;
  ipHash: string | null;
  userAgent: string | null;
  failedLoginAttempts: number;
}, db: Pick<Prisma.TransactionClient, "$queryRaw">) => {
  const now = new Date();
  const reasons: string[] = [];

  let score = 0;

  if (isAdminRole(input.role)) {
    score += 10;
    reasons.push("Privileged role login baseline risk");
  }

  if ((input.failedLoginAttempts || 0) > 0) {
    const extra = Math.min(25, input.failedLoginAttempts * 6);
    score += extra;
    reasons.push(`Recent failed login attempts: ${input.failedLoginAttempts}`);
  }

  const { recentSessions, actorState } = await loadRecentAuthSessionRiskInputs(db);

  const currentUserAgentHash = safeHash(input.userAgent);

  if (recentSessions.length === 0) {
    score += 8;
    reasons.push("First known session for this account");
  } else {
    const latest = recentSessions[0];
    if (latest?.createdIpHash && input.ipHash && latest.createdIpHash !== input.ipHash) {
      score += 35;
      reasons.push("Source IP changed from recent session");
    }

    const latestUaHash = safeHash(latest?.createdUserAgent || null);
    if (latestUaHash && currentUserAgentHash && latestUaHash !== currentUserAgentHash) {
      score += 20;
      reasons.push("User-agent changed from recent session");
    }

    const twentyFourHoursAgo = now.getTime() - 24 * 60 * 60 * 1000;
    const distinctIpHashes = new Set(
      recentSessions
        .filter((row) => row.createdAt.getTime() >= twentyFourHoursAgo)
        .map((row) => String(row.createdIpHash || "").trim())
        .filter(Boolean)
    );

    if (distinctIpHashes.size >= 3) {
      score += 25;
      reasons.push("Multiple source IP patterns in 24h");
    }
  }

  score = Math.max(0, Math.min(100, Math.round(score)));
  const riskLevel = toRiskLevel(score);

  const stepupThreshold = parseIntEnv("AUTH_RISK_STEPUP_THRESHOLD", 55);
  const blockThreshold = parseIntEnv("AUTH_RISK_BLOCK_THRESHOLD", 85);

  return {
    score,
    riskLevel,
    reasons,
    shouldStepUp: score >= stepupThreshold,
    shouldBlock: score >= blockThreshold,
    actorState,
  };
};

export const persistAuthSessionRisk = (
  input: {
    ipHash: string | null;
    userAgent: string | null;
    requestId: string;
    passwordHash?: string | null;
    challenge?: {
      ticketHash: string;
      sessionBindingHash: string;
      expiresAt: Date;
      maxAttempts: number;
    } | null;
  },
  risk: Awaited<ReturnType<typeof assessAuthSessionRisk>>,
  db: Pick<Prisma.TransactionClient, "$queryRaw">
) => recordAuthSessionRiskSignal({
  riskScore: risk.score,
  riskLevel: risk.riskLevel,
  reasons: risk.reasons,
  ipHash: input.ipHash,
  userAgentHash: safeHash(input.userAgent),
  recordedAt: new Date(),
  requestId: input.requestId,
  passwordHash: input.passwordHash,
  challenge: input.challenge,
}, db);
