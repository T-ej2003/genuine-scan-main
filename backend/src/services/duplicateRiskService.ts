type ScanSignals = {
  distinctDeviceCount24h?: number;
  recentScanCount10m?: number;
  distinctCountryCount24h?: number;
  seenOnCurrentDeviceBefore?: boolean;
  previousScanSameDevice?: boolean | null;
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
};

export type DuplicateRiskAssessment = {
  riskScore: number;
  classification: "LEGIT_REPEAT" | "SUSPICIOUS_DUPLICATE";
  reasons: string[];
  signals: {
    scanCount: number;
    distinctDeviceCount24h: number;
    recentScanCount10m: number;
    distinctCountryCount24h: number;
    hasCustomerIdentity: boolean;
    ownershipConflict: boolean;
    ownedByRequester: boolean;
    seenOnCurrentDeviceBefore: boolean;
    previousScanSameDevice: boolean;
    policyTriggered: {
      multiScan: boolean;
      geoDrift: boolean;
      velocitySpike: boolean;
    };
    possibleImpossibleTravel: boolean;
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

export const assessDuplicateRisk = (input: DuplicateRiskInput): DuplicateRiskAssessment => {
  const scanCount = Math.max(0, Number(input.scanCount || 0));
  const signals = input.scanSignals || null;
  const policy = input.policy || null;
  const policyTriggered = policy?.triggered || {};
  const policyAlerts = Array.isArray(policy?.alerts) ? policy!.alerts! : [];

  const distinctDeviceCount24h = Math.max(0, Number(signals?.distinctDeviceCount24h ?? 0));
  const recentScanCount10m = Math.max(0, Number(signals?.recentScanCount10m ?? 0));
  const distinctCountryCount24h = Math.max(0, Number(signals?.distinctCountryCount24h ?? 0));
  const seenOnCurrentDeviceBefore = bool(signals?.seenOnCurrentDeviceBefore);
  const previousScanSameDevice = bool(signals?.previousScanSameDevice === true);

  const hasCustomerIdentity = Boolean(String(input.customerUserId || "").trim());
  const ownedByRequester = bool(input.ownershipStatus?.isOwnedByRequester);
  const ownershipConflict = bool(input.ownershipStatus?.isClaimedByAnother);

  const latestMs = parseIsoMs(input.latestScanAt);
  const previousMs = parseIsoMs(input.previousScanAt);
  const gapMinutes =
    latestMs != null && previousMs != null ? Math.abs(latestMs - previousMs) / 60_000 : Number.POSITIVE_INFINITY;
  const possibleImpossibleTravel = bool(policyTriggered.geoDrift) && gapMinutes <= 45;

  let score = 8;
  const suspiciousReasons: string[] = [];
  const reassuranceReasons: string[] = [];

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

  if (distinctDeviceCount24h >= 2) {
    score += clamp(14 + (distinctDeviceCount24h - 2) * 7, 14, 32);
    uniquePush(suspiciousReasons, "Multiple devices scanned this code in a short period.");
  }
  if (recentScanCount10m >= 3) {
    score += clamp(9 + (recentScanCount10m - 3) * 4, 9, 28);
    uniquePush(suspiciousReasons, "Rapid burst scans were detected in the last 10 minutes.");
  }
  if (distinctCountryCount24h >= 2) {
    score += clamp(20 + (distinctCountryCount24h - 2) * 10, 20, 40);
    uniquePush(suspiciousReasons, "Recent scans came from multiple countries.");
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

  if (distinctDeviceCount24h >= 2 && recentScanCount10m >= 3) {
    score += 12;
    uniquePush(suspiciousReasons, "Multiple devices are scanning this code rapidly.");
  }
  if (distinctCountryCount24h >= 2 && recentScanCount10m >= 3) {
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

  // If we have strong trust signals and no hard anomaly triggers, keep risk in the low band.
  const hasHardAnomaly =
    ownershipConflict ||
    possibleImpossibleTravel ||
    distinctCountryCount24h >= 2 ||
    (distinctDeviceCount24h >= 2 && recentScanCount10m >= 3) ||
    bool(policyTriggered.velocitySpike);

  if (!hasHardAnomaly && (ownedByRequester || seenOnCurrentDeviceBefore || hasCustomerIdentity)) {
    score = Math.min(score, 34);
  }

  const riskScore = clamp(Math.round(score), 0, 100);
  const strongOwnershipConflict = ownershipConflict && (hasCustomerIdentity || Boolean(input.ownershipStatus?.matchMethod));
  const classification: "LEGIT_REPEAT" | "SUSPICIOUS_DUPLICATE" =
    riskScore >= 60 || strongOwnershipConflict || (ownershipConflict && riskScore >= 45)
      ? "SUSPICIOUS_DUPLICATE"
      : "LEGIT_REPEAT";

  let reasons: string[];
  if (classification === "SUSPICIOUS_DUPLICATE") {
    reasons = suspiciousReasons.slice(0, 6);
    if (!reasons.length) {
      reasons = ["Composite anomaly signals suggest this code may be duplicated or misused."];
    }
  } else {
    reasons = [];
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
    signals: {
      scanCount,
      distinctDeviceCount24h,
      recentScanCount10m,
      distinctCountryCount24h,
      hasCustomerIdentity,
      ownershipConflict,
      ownedByRequester,
      seenOnCurrentDeviceBefore,
      previousScanSameDevice,
      policyTriggered: {
        multiScan: bool(policyTriggered.multiScan),
        geoDrift: bool(policyTriggered.geoDrift),
        velocitySpike: bool(policyTriggered.velocitySpike),
      },
      possibleImpossibleTravel,
    },
  };
};
