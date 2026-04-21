import { UserRole } from "@prisma/client";

import { listActiveRefreshTokensForUser } from "./refreshTokenService";

type SessionRiskLevel = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
type InternalIpReputation = "trusted" | "new" | "elevated" | "high_risk" | "unknown";

type SessionOverviewInput = {
  userId: string;
  role: UserRole;
  currentSessionId: string | null;
};

const isAdminRole = (role: UserRole) =>
  role === UserRole.SUPER_ADMIN ||
  role === UserRole.PLATFORM_SUPER_ADMIN ||
  role === UserRole.LICENSEE_ADMIN ||
  role === UserRole.ORG_ADMIN;

const toRiskLevel = (score: number): SessionRiskLevel => {
  if (score >= 85) return "CRITICAL";
  if (score >= 65) return "HIGH";
  if (score >= 40) return "MEDIUM";
  return "LOW";
};

const clampScore = (score: number) => Math.max(0, Math.min(100, Math.round(score)));

const resolveIpReputation = (input: {
  ipHash: string | null;
  currentIpHash: string | null;
  distinctIpHashes24h: number;
  seenCount: number;
  possibleImpossibleTravel: boolean;
}): InternalIpReputation => {
  if (!input.ipHash) return "unknown";
  if (input.possibleImpossibleTravel || input.distinctIpHashes24h >= 4) return "high_risk";
  if (input.distinctIpHashes24h >= 3) return "elevated";
  if (input.currentIpHash && input.ipHash === input.currentIpHash) return "trusted";
  if (input.seenCount <= 1) return "new";
  if (input.distinctIpHashes24h >= 2) return "elevated";
  return "trusted";
};

export const getSessionSecurityOverview = async (input: SessionOverviewInput) => {
  const sessions = await listActiveRefreshTokensForUser(input.userId);
  const now = Date.now();
  const twentyFourHoursAgo = now - 24 * 60 * 60 * 1000;
  const currentSession = sessions.find((session) => session.id === input.currentSessionId) || null;

  const ipHashCounts = new Map<string, number>();
  for (const session of sessions) {
    const ipHash = String(session.createdIpHash || "").trim();
    if (!ipHash) continue;
    ipHashCounts.set(ipHash, (ipHashCounts.get(ipHash) || 0) + 1);
  }

  const recentSessions = sessions.filter((session) => {
    const activityTime = session.lastUsedAt?.getTime?.() || session.createdAt.getTime();
    return activityTime >= twentyFourHoursAgo;
  });

  const distinctIpHashes24h = new Set(
    recentSessions
      .map((session) => String(session.createdIpHash || "").trim())
      .filter(Boolean)
  ).size;

  const recentActivityTimes = recentSessions
    .map((session) => session.lastUsedAt?.getTime?.() || session.createdAt.getTime())
    .sort((a, b) => a - b);

  const recentActivitySpreadMinutes =
    recentActivityTimes.length >= 2
      ? Math.round((recentActivityTimes[recentActivityTimes.length - 1] - recentActivityTimes[0]) / (60 * 1000))
      : null;

  const possibleImpossibleTravel = distinctIpHashes24h >= 2 && recentSessions.length >= 2 && (recentActivitySpreadMinutes ?? 9999) <= 45;
  const possibleImpossibleTravelReason = possibleImpossibleTravel
    ? "Multiple active sessions changed network fingerprints within a short window."
    : null;

  const currentIpHash = String(currentSession?.createdIpHash || "").trim() || null;
  const adminBaseline = isAdminRole(input.role) ? 10 : 0;

  const items = sessions.map((session) => {
    const ipHash = String(session.createdIpHash || "").trim() || null;
    const ipReputation = resolveIpReputation({
      ipHash,
      currentIpHash,
      distinctIpHashes24h,
      seenCount: ipHash ? ipHashCounts.get(ipHash) || 0 : 0,
      possibleImpossibleTravel,
    });

    const reasons: string[] = [];
    let riskScore = adminBaseline;

    if (session.id !== input.currentSessionId) {
      riskScore += 6;
      reasons.push("Additional active device for this account");
    }

    if (isAdminRole(input.role) && !session.mfaVerifiedAt) {
      riskScore += 25;
      reasons.push("Admin session has no MFA verification timestamp");
    }

    if (ipReputation === "new") {
      riskScore += 8;
      reasons.push("Session is using a newly observed network fingerprint");
    } else if (ipReputation === "elevated") {
      riskScore += 20;
      reasons.push("Several active network fingerprints were observed recently");
    } else if (ipReputation === "high_risk") {
      riskScore += 40;
      reasons.push("Network activity pattern looks unusually volatile");
    }

    if (possibleImpossibleTravel) {
      riskScore += 25;
      reasons.push("Possible impossible-travel heuristic triggered across active sessions");
    }

    const inactiveDays = Math.floor((now - (session.lastUsedAt?.getTime?.() || session.createdAt.getTime())) / (24 * 60 * 60 * 1000));
    if (inactiveDays >= 14) {
      riskScore += 10;
      reasons.push("Session has been idle for an extended period");
    }

    const score = clampScore(riskScore);
    return {
      id: session.id,
      current: session.id === input.currentSessionId,
      createdAt: session.createdAt.toISOString(),
      lastUsedAt: session.lastUsedAt?.toISOString?.() || null,
      expiresAt: session.expiresAt.toISOString(),
      authenticatedAt: session.authenticatedAt?.toISOString?.() || null,
      mfaVerifiedAt: session.mfaVerifiedAt?.toISOString?.() || null,
      userAgent: session.createdUserAgent || null,
      ipHash,
      security: {
        riskScore: score,
        riskLevel: toRiskLevel(score),
        riskReasons: reasons,
        internalIpReputation: ipReputation,
        possibleImpossibleTravel,
        possibleImpossibleTravelReason,
      },
    };
  });

  const highestRiskScore = items.reduce((max, session) => Math.max(max, session.security.riskScore), 0);
  const highestRiskLevel = toRiskLevel(highestRiskScore);
  const highRiskSessionCount = items.filter((session) => session.security.riskScore >= 65).length;
  const elevatedRiskSessionCount = items.filter((session) => session.security.riskScore >= 40).length;
  const summaryIpReputation = resolveIpReputation({
    ipHash: currentIpHash,
    currentIpHash,
    distinctIpHashes24h,
    seenCount: currentIpHash ? ipHashCounts.get(currentIpHash) || 0 : 0,
    possibleImpossibleTravel,
  });

  return {
    items,
    summary: {
      highestRiskScore,
      highestRiskLevel,
      highRiskSessionCount,
      elevatedRiskSessionCount,
      distinctIpHashes24h,
      possibleImpossibleTravel,
      internalIpReputation: summaryIpReputation,
    },
  };
};
