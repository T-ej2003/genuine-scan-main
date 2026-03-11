type RiskBand = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

type ScanSignals = {
  scanCount24h?: number;
  distinctDeviceCount24h?: number;
  recentScanCount10m?: number;
  distinctCountryCount24h?: number;
  seenOnCurrentDeviceBefore?: boolean;
  previousScanSameDevice?: boolean | null;
  currentActorTrustedOwnerContext?: boolean;
  seenByCurrentTrustedActorBefore?: boolean;
  previousScanSameTrustedActor?: boolean | null;
  trustedOwnerScanCount24h?: number;
  trustedOwnerScanCount10m?: number;
  untrustedScanCount24h?: number;
  untrustedScanCount10m?: number;
  distinctTrustedActorCount24h?: number;
  distinctUntrustedDeviceCount24h?: number;
  distinctUntrustedCountryCount24h?: number;
  ipVelocityCount10m?: number;
  ipReputationScore?: number;
  deviceGraphOverlap24h?: number;
  crossCodeCorrelation24h?: number;
};

type PolicySignal = {
  triggered?: {
    multiScan?: boolean;
    geoDrift?: boolean;
    velocitySpike?: boolean;
  };
  alerts?: Array<{ message?: string | null }>;
};

type OwnershipSignal = {
  isClaimed?: boolean;
  isOwnedByRequester?: boolean;
  isClaimedByAnother?: boolean;
  matchMethod?: "user" | "device_token" | "ip_fallback" | null;
};

export type DuplicateRiskInput = {
  scanCount: number;
  scanSignals?: ScanSignals | null;
  policy?: PolicySignal | null;
  ownershipStatus?: OwnershipSignal | null;
  customerUserId?: string | null;
  latestScanAt?: string | null;
  previousScanAt?: string | null;
  anomalyModelScore?: number | null;
  tenantRiskLevel?: RiskBand | null;
  productRiskLevel?: RiskBand | null;
};

export type VerificationActivitySummary = {
  state: "first_scan" | "trusted_repeat" | "mixed_repeat" | "external_activity" | "normal_repeat";
  summary: string;
  trustedOwnerScanCount24h: number;
  trustedOwnerScanCount10m: number;
  untrustedScanCount24h: number;
  untrustedScanCount10m: number;
  distinctTrustedActorCount24h: number;
  distinctUntrustedDeviceCount24h: number;
  currentActorTrustedOwnerContext: boolean;
};

export type DuplicateRiskAssessment = {
  riskScore: number;
  classification: "LEGIT_REPEAT" | "SUSPICIOUS_DUPLICATE";
  reasons: string[];
  threshold: number;
  activitySummary: VerificationActivitySummary;
  signals: {
    scanCount: number;
    scanCount24h: number;
    distinctDeviceCount24h: number;
    recentScanCount10m: number;
    distinctCountryCount24h: number;
    currentActorTrustedOwnerContext: boolean;
    seenByCurrentTrustedActorBefore: boolean;
    previousScanSameTrustedActor: boolean;
    trustedOwnerScanCount24h: number;
    trustedOwnerScanCount10m: number;
    untrustedScanCount24h: number;
    untrustedScanCount10m: number;
    distinctTrustedActorCount24h: number;
    distinctUntrustedDeviceCount24h: number;
    distinctUntrustedCountryCount24h: number;
    hasCustomerIdentity: boolean;
    ownershipConflict: boolean;
    ownedByRequester: boolean;
    seenOnCurrentDeviceBefore: boolean;
    previousScanSameDevice: boolean;
    ipVelocityCount10m: number;
    ipReputationScore: number;
    deviceGraphOverlap24h: number;
    crossCodeCorrelation24h: number;
    policyTriggered: {
      multiScan: boolean;
      geoDrift: boolean;
      velocitySpike: boolean;
    };
    possibleImpossibleTravel: boolean;
    anomalyModelScore: number;
    tenantRiskLevel: RiskBand;
    productRiskLevel: RiskBand;
  };
};

const clamp = (value: number, min: number, max: number) => Math.min(max, Math.max(min, value));

const uniquePush = (arr: string[], value: string) => {
  if (!value) return;
  if (!arr.includes(value)) arr.push(value);
};

const parseIsoMs = (value?: string | null) => {
  if (!value) return null;
  const ts = new Date(value).getTime();
  return Number.isFinite(ts) ? ts : null;
};

const bool = (value: unknown) => Boolean(value);

const normalizeRiskBand = (value: unknown, fallback: RiskBand): RiskBand => {
  const normalized = String(value || "").trim().toUpperCase();
  if (normalized === "LOW" || normalized === "MEDIUM" || normalized === "HIGH" || normalized === "CRITICAL") {
    return normalized;
  }
  return fallback;
};

const severityWeight = (band: RiskBand) => {
  if (band === "CRITICAL") return 4;
  if (band === "HIGH") return 3;
  if (band === "MEDIUM") return 2;
  return 1;
};

const adaptiveThreshold = (tenantRisk: RiskBand, productRisk: RiskBand) => {
  const dominantWeight = Math.max(severityWeight(tenantRisk), severityWeight(productRisk));
  const adjustment = dominantWeight >= 4 ? -12 : dominantWeight === 3 ? -7 : dominantWeight === 2 ? 0 : 6;
  return clamp(60 + adjustment, 45, 75);
};

const countPhrase = (count: number, singular: string, plural?: string) => {
  const safeCount = Math.max(0, Math.round(Number(count || 0)));
  return `${safeCount} ${safeCount === 1 ? singular : plural || `${singular}s`}`;
};

const wasWere = (count: number) => (Math.round(Number(count || 0)) === 1 ? "was" : "were");

const buildActivitySummary = (input: {
  scanCount: number;
  currentActorTrustedOwnerContext: boolean;
  trustedOwnerScanCount24h: number;
  trustedOwnerScanCount10m: number;
  untrustedScanCount24h: number;
  untrustedScanCount10m: number;
  distinctTrustedActorCount24h: number;
  distinctUntrustedDeviceCount24h: number;
}): VerificationActivitySummary => {
  const summaryBase = {
    trustedOwnerScanCount24h: input.trustedOwnerScanCount24h,
    trustedOwnerScanCount10m: input.trustedOwnerScanCount10m,
    untrustedScanCount24h: input.untrustedScanCount24h,
    untrustedScanCount10m: input.untrustedScanCount10m,
    distinctTrustedActorCount24h: input.distinctTrustedActorCount24h,
    distinctUntrustedDeviceCount24h: input.distinctUntrustedDeviceCount24h,
    currentActorTrustedOwnerContext: input.currentActorTrustedOwnerContext,
  };

  if (input.scanCount <= 1) {
    return {
      state: "first_scan",
      summary: "First successful verification recorded.",
      ...summaryBase,
    };
  }

  if (input.currentActorTrustedOwnerContext && input.untrustedScanCount24h === 0) {
    return {
      state: "trusted_repeat",
      summary:
        input.trustedOwnerScanCount24h > 0
          ? `${countPhrase(input.trustedOwnerScanCount24h, "recent scan")} matched the same owner or trusted device in the last 24 hours.`
          : "Recent activity matches the same owner or trusted device.",
      ...summaryBase,
    };
  }

  if (input.currentActorTrustedOwnerContext && input.untrustedScanCount24h > 0) {
    return {
      state: "mixed_repeat",
      summary: `${countPhrase(input.trustedOwnerScanCount24h, "trusted scan")} and ${countPhrase(input.untrustedScanCount24h, "additional external scan")} were recorded in the last 24 hours.`,
      ...summaryBase,
    };
  }

  if (input.trustedOwnerScanCount24h > 0 && input.untrustedScanCount24h === 0) {
    return {
      state: "trusted_repeat",
      summary: `${countPhrase(input.trustedOwnerScanCount24h, "trusted scan")} ${wasWere(input.trustedOwnerScanCount24h)} recorded in the last 24 hours with no external scan activity.`,
      ...summaryBase,
    };
  }

  if (input.untrustedScanCount24h > 0) {
    return {
      state: "external_activity",
      summary: `${countPhrase(input.untrustedScanCount24h, "external scan")} across ${countPhrase(Math.max(input.distinctUntrustedDeviceCount24h, 1), "new device")} ${wasWere(input.untrustedScanCount24h)} recorded in the last 24 hours.`,
      ...summaryBase,
    };
  }

  return {
    state: "normal_repeat",
    summary: "Repeat scans alone do not indicate a fake product.",
    ...summaryBase,
  };
};

export const deriveAnomalyModelScore = (input: {
  scanSignals?: ScanSignals | null;
  policy?: PolicySignal | null;
}) => {
  const scanSignals = input.scanSignals || {};
  const policyTriggered = input.policy?.triggered || {};
  const suspiciousCountryCount = Number(
    scanSignals.distinctUntrustedCountryCount24h ?? scanSignals.distinctCountryCount24h ?? 0
  );

  let score = 0;
  score += clamp(Number(scanSignals.ipReputationScore || 0), 0, 100) * 0.45;
  score += Math.min(25, Math.max(0, Number(scanSignals.ipVelocityCount10m || 0) - 2) * 3);
  score += Math.min(22, Math.max(0, Number(scanSignals.deviceGraphOverlap24h || 0) - 1) * 4);
  score += Math.min(18, Math.max(0, Number(scanSignals.crossCodeCorrelation24h || 0) - 1) * 3);
  score += Math.min(22, Math.max(0, suspiciousCountryCount - 1) * 10);

  if (policyTriggered.geoDrift) score += 12;
  if (policyTriggered.velocitySpike) score += 14;
  if (policyTriggered.multiScan) score += 6;

  return clamp(Math.round(score), 0, 100);
};

export const assessDuplicateRisk = (input: DuplicateRiskInput): DuplicateRiskAssessment => {
  const scanCount = Math.max(0, Number(input.scanCount || 0));
  const signals = input.scanSignals || null;
  const policy = input.policy || null;
  const policyTriggered = policy?.triggered || {};
  const policyAlerts = Array.isArray(policy?.alerts) ? policy!.alerts! : [];

  const scanCount24h = Math.max(0, Number(signals?.scanCount24h ?? 0));
  const distinctDeviceCount24h = Math.max(0, Number(signals?.distinctDeviceCount24h ?? 0));
  const recentScanCount10m = Math.max(0, Number(signals?.recentScanCount10m ?? 0));
  const distinctCountryCount24h = Math.max(0, Number(signals?.distinctCountryCount24h ?? 0));
  const currentActorTrustedOwnerContext =
    bool(signals?.currentActorTrustedOwnerContext) || bool(input.ownershipStatus?.isOwnedByRequester);
  const seenOnCurrentDeviceBefore = bool(signals?.seenOnCurrentDeviceBefore);
  const previousScanSameDevice = bool(signals?.previousScanSameDevice === true);
  const seenByCurrentTrustedActorBefore = bool(signals?.seenByCurrentTrustedActorBefore);
  const previousScanSameTrustedActor = bool(signals?.previousScanSameTrustedActor === true);
  const trustedOwnerScanCount24h = Math.max(0, Number(signals?.trustedOwnerScanCount24h ?? 0));
  const trustedOwnerScanCount10m = Math.max(0, Number(signals?.trustedOwnerScanCount10m ?? 0));
  const untrustedScanCount24h = Math.max(0, Number(signals?.untrustedScanCount24h ?? scanCount24h ?? 0));
  const untrustedScanCount10m = Math.max(0, Number(signals?.untrustedScanCount10m ?? recentScanCount10m ?? 0));
  const distinctTrustedActorCount24h = Math.max(0, Number(signals?.distinctTrustedActorCount24h ?? 0));
  const distinctUntrustedDeviceCount24h = Math.max(
    0,
    Number(signals?.distinctUntrustedDeviceCount24h ?? distinctDeviceCount24h ?? 0)
  );
  const distinctUntrustedCountryCount24h = Math.max(
    0,
    Number(signals?.distinctUntrustedCountryCount24h ?? distinctCountryCount24h ?? 0)
  );
  const ipVelocityCount10m = Math.max(0, Number(signals?.ipVelocityCount10m ?? 0));
  const ipReputationScore = clamp(Number(signals?.ipReputationScore ?? 0), 0, 100);
  const deviceGraphOverlap24h = Math.max(0, Number(signals?.deviceGraphOverlap24h ?? 0));
  const crossCodeCorrelation24h = Math.max(0, Number(signals?.crossCodeCorrelation24h ?? 0));

  const hasCustomerIdentity = Boolean(String(input.customerUserId || "").trim());
  const ownedByRequester = bool(input.ownershipStatus?.isOwnedByRequester);
  const ownershipConflict = bool(input.ownershipStatus?.isClaimedByAnother);

  const latestMs = parseIsoMs(input.latestScanAt);
  const previousMs = parseIsoMs(input.previousScanAt);
  const gapMinutes =
    latestMs != null && previousMs != null ? Math.abs(latestMs - previousMs) / 60_000 : Number.POSITIVE_INFINITY;
  const possibleImpossibleTravel = bool(policyTriggered.geoDrift) && gapMinutes <= 45;

  const tenantRiskLevel = normalizeRiskBand(input.tenantRiskLevel, "MEDIUM");
  const productRiskLevel = normalizeRiskBand(input.productRiskLevel, "MEDIUM");
  const threshold = adaptiveThreshold(tenantRiskLevel, productRiskLevel);

  let score = 8;
  const suspiciousReasons: string[] = [];
  const reassuranceReasons: string[] = [];

  const activitySummary = buildActivitySummary({
    scanCount,
    currentActorTrustedOwnerContext,
    trustedOwnerScanCount24h,
    trustedOwnerScanCount10m,
    untrustedScanCount24h,
    untrustedScanCount10m,
    distinctTrustedActorCount24h,
    distinctUntrustedDeviceCount24h,
  });

  // Repeat count is intentionally a weak signal to reduce false positives.
  if (scanCount > 1) {
    score += Math.min(5, (scanCount - 1) * 0.8);
  }
  if (scanCount > 6) {
    score += Math.min(6, (scanCount - 6) * 0.6);
  }
  if (scanCount > 20) {
    score += 6;
  }

  if (distinctUntrustedDeviceCount24h >= 2) {
    score += clamp(14 + (distinctUntrustedDeviceCount24h - 2) * 7, 14, 32);
    uniquePush(
      suspiciousReasons,
      `${countPhrase(distinctUntrustedDeviceCount24h, "new device")} scanned this code in the last 24 hours.`
    );
  }
  if (untrustedScanCount10m >= 3) {
    score += clamp(9 + (untrustedScanCount10m - 3) * 4, 9, 28);
    uniquePush(
      suspiciousReasons,
      `${countPhrase(untrustedScanCount10m, "untrusted scan")} ${wasWere(untrustedScanCount10m)} recorded in the last 10 minutes.`
    );
  }
  if (distinctUntrustedCountryCount24h >= 2) {
    score += clamp(20 + (distinctUntrustedCountryCount24h - 2) * 10, 20, 40);
    uniquePush(
      suspiciousReasons,
      `Recent external scans came from ${countPhrase(distinctUntrustedCountryCount24h, "country")}.`
    );
  }

  if (ipVelocityCount10m >= 5) {
    score += clamp(8 + (ipVelocityCount10m - 5) * 2, 8, 22);
    uniquePush(suspiciousReasons, "Same network endpoint is scanning unusually fast.");
  }

  if (ipReputationScore >= 60) {
    score += clamp((ipReputationScore - 50) * 0.5, 5, 25);
    uniquePush(suspiciousReasons, "Network reputation for this scan endpoint is high risk.");
  }

  if (deviceGraphOverlap24h >= 3) {
    score += clamp(10 + (deviceGraphOverlap24h - 3) * 2.5, 10, 24);
    uniquePush(suspiciousReasons, "Device graph overlap indicates coordinated scan activity.");
  }

  if (crossCodeCorrelation24h >= 4) {
    score += clamp(8 + (crossCodeCorrelation24h - 4) * 2.5, 8, 20);
    uniquePush(suspiciousReasons, "This device has correlated scans across multiple codes.");
  }

  if (bool(policyTriggered.multiScan)) {
    score += 5;
  }
  if (bool(policyTriggered.velocitySpike)) {
    score += 18;
    uniquePush(suspiciousReasons, "Scan velocity exceeded security policy limits.");
  }
  if (bool(policyTriggered.geoDrift)) {
    score += 20;
    uniquePush(suspiciousReasons, "Location drift exceeded policy threshold.");
  }
  if (possibleImpossibleTravel) {
    score += 14;
    uniquePush(suspiciousReasons, "Travel pattern between consecutive scans is unusually fast.");
  }

  if (distinctUntrustedDeviceCount24h >= 2 && untrustedScanCount10m >= 3) {
    score += 12;
    uniquePush(suspiciousReasons, "New devices are scanning this code rapidly.");
  }
  if (distinctUntrustedCountryCount24h >= 2 && untrustedScanCount10m >= 3) {
    score += 16;
    uniquePush(suspiciousReasons, "Cross-country burst activity indicates possible cloning.");
  }

  if (ownershipConflict) {
    score += 34;
    uniquePush(suspiciousReasons, "Ownership is already claimed by another account/device.");
  }

  if (hasCustomerIdentity) {
    score -= 8;
    uniquePush(reassuranceReasons, "Signed-in customer identity is consistent with this verification.");
  }
  if (ownedByRequester) {
    score -= 20;
    uniquePush(reassuranceReasons, "Ownership matches your account or trusted device.");
  }
  if (currentActorTrustedOwnerContext) {
    score -= 12;
    uniquePush(reassuranceReasons, "This scan matches the recorded owner context.");
  }
  if (trustedOwnerScanCount24h >= 2) {
    score -= clamp(6 + (trustedOwnerScanCount24h - 2) * 1.2, 6, 16);
    uniquePush(
      reassuranceReasons,
      `${countPhrase(trustedOwnerScanCount24h, "recent trusted scan")} matched the same owner context in the last 24 hours.`
    );
  }
  if (seenByCurrentTrustedActorBefore || previousScanSameTrustedActor) {
    score -= seenByCurrentTrustedActorBefore && previousScanSameTrustedActor ? 12 : 8;
    uniquePush(reassuranceReasons, "Recent scans are consistent with the same signed-in owner or claimed device.");
  }
  if (seenOnCurrentDeviceBefore || previousScanSameDevice) {
    score -= seenOnCurrentDeviceBefore && previousScanSameDevice ? 12 : 8;
    uniquePush(reassuranceReasons, "Recent scans are consistent with the same device context.");
  }

  // Policy alerts add a small confidence penalty but should not dominate the result on their own.
  score += Math.min(10, policyAlerts.length * 2);
  for (const alert of policyAlerts) {
    const msg = String(alert?.message || "").trim();
    if (!msg) continue;
    uniquePush(suspiciousReasons, msg);
    if (suspiciousReasons.length >= 6) break;
  }

  const anomalyModelScore = clamp(Math.round(Number(input.anomalyModelScore ?? 0)), 0, 100);
  if (anomalyModelScore > 0) {
    score += Math.round(anomalyModelScore * 0.22);
  }

  const hasHardAnomaly =
    ownershipConflict ||
    possibleImpossibleTravel ||
    distinctUntrustedCountryCount24h >= 2 ||
    ipReputationScore >= 70 ||
    deviceGraphOverlap24h >= 4 ||
    (distinctUntrustedDeviceCount24h >= 2 && untrustedScanCount10m >= 3) ||
    bool(policyTriggered.velocitySpike);

  if (!hasHardAnomaly && currentActorTrustedOwnerContext && untrustedScanCount24h === 0) {
    score = Math.min(score, 24);
  } else if (!hasHardAnomaly && (ownedByRequester || seenOnCurrentDeviceBefore || hasCustomerIdentity)) {
    score = Math.min(score, 34);
  }

  const riskScore = clamp(Math.round(score), 0, 100);
  const strongOwnershipConflict = ownershipConflict && (hasCustomerIdentity || Boolean(input.ownershipStatus?.matchMethod));
  const classification: "LEGIT_REPEAT" | "SUSPICIOUS_DUPLICATE" =
    riskScore >= threshold || strongOwnershipConflict || (ownershipConflict && riskScore >= Math.max(45, threshold - 10))
      ? "SUSPICIOUS_DUPLICATE"
      : "LEGIT_REPEAT";

  let reasons: string[];
  if (classification === "SUSPICIOUS_DUPLICATE") {
    reasons = [];
    if (currentActorTrustedOwnerContext && untrustedScanCount24h > 0) {
      reasons.push("Your current scan matches the recorded owner, but additional external scan activity is also present.");
    }
    reasons.push(...suspiciousReasons.slice(0, 6));
    if (!reasons.length) {
      reasons = ["Composite anomaly signals suggest this code may be duplicated or misused."];
    }
  } else {
    reasons = [];
    if (activitySummary.summary) reasons.push(activitySummary.summary);
    if (reassuranceReasons.length) reasons.push(...reassuranceReasons.slice(0, 3));
    if (!reasons.length && scanCount > 1) {
      reasons.push("Repeat scans alone do not indicate a fake product.");
    }
    if (!reasons.length) {
      reasons.push("No strong anomaly evidence was detected for this repeat scan.");
    }
  }

  return {
    riskScore,
    classification,
    reasons,
    threshold,
    activitySummary,
    signals: {
      scanCount,
      scanCount24h,
      distinctDeviceCount24h,
      recentScanCount10m,
      distinctCountryCount24h,
      currentActorTrustedOwnerContext,
      seenByCurrentTrustedActorBefore,
      previousScanSameTrustedActor,
      trustedOwnerScanCount24h,
      trustedOwnerScanCount10m,
      untrustedScanCount24h,
      untrustedScanCount10m,
      distinctTrustedActorCount24h,
      distinctUntrustedDeviceCount24h,
      distinctUntrustedCountryCount24h,
      hasCustomerIdentity,
      ownershipConflict,
      ownedByRequester,
      seenOnCurrentDeviceBefore,
      previousScanSameDevice,
      ipVelocityCount10m,
      ipReputationScore,
      deviceGraphOverlap24h,
      crossCodeCorrelation24h,
      policyTriggered: {
        multiScan: bool(policyTriggered.multiScan),
        geoDrift: bool(policyTriggered.geoDrift),
        velocitySpike: bool(policyTriggered.velocitySpike),
      },
      possibleImpossibleTravel,
      anomalyModelScore,
      tenantRiskLevel,
      productRiskLevel,
    },
  };
};
