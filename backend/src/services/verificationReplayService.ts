const parseBoolEnv = (value: unknown, fallback: boolean) => {
  const normalized = String(value || "").trim().toLowerCase();
  if (["1", "true", "yes", "on"].includes(normalized)) return true;
  if (["0", "false", "no", "off"].includes(normalized)) return false;
  return fallback;
};

const parseIntEnv = (key: string, fallback: number, min = 1, max = 10_000) => {
  const raw = Number(String(process.env[key] || "").trim());
  if (!Number.isFinite(raw)) return fallback;
  return Math.max(min, Math.min(max, Math.floor(raw)));
};

const VERIFY_REPLAY_HARDENING_ENABLED = parseBoolEnv(process.env.VERIFY_REPLAY_HARDENING_ENABLED, true);
const REPLAY_RAPID_REUSE_THRESHOLD_10M = parseIntEnv("VERIFY_REPLAY_RAPID_REUSE_THRESHOLD_10M", 3, 2, 20);
const REPLAY_IP_VELOCITY_THRESHOLD_10M = parseIntEnv("VERIFY_REPLAY_IP_VELOCITY_THRESHOLD_10M", 2, 1, 20);
const REPLAY_CHANGED_CONTEXT_LOOKBACK_MINUTES = parseIntEnv("VERIFY_REPLAY_CHANGED_CONTEXT_LOOKBACK_MINUTES", 15, 1, 240);

const normalizeText = (value: unknown) => String(value || "").trim();

const toDate = (value: unknown) => {
  if (!value) return null;
  const parsed = value instanceof Date ? value : new Date(String(value));
  return Number.isFinite(parsed.getTime()) ? parsed : null;
};

const minutesBetween = (older: unknown, newer: Date) => {
  const olderDate = toDate(older);
  if (!olderDate) return null;
  return Math.max(0, Math.round((newer.getTime() - olderDate.getTime()) / 60_000));
};

export type SignedReplayAssessment = {
  enabled: boolean;
  replayState:
    | "UNSIGNED_OR_DISABLED"
    | "FIRST_SIGNED_USE"
    | "SAME_CONTEXT_REPEAT"
    | "CHANGED_CONTEXT_REPEAT"
    | "RAPID_CHANGED_CONTEXT_REPEAT";
  replayEpoch: number;
  tokenReplayEpoch: number | null;
  firstSignedVerificationInEpoch: boolean;
  sameContext: boolean;
  changedContext: boolean;
  rapidReuse: boolean;
  reviewRequired: boolean;
  stepUpRecommended: boolean;
  matchedPreviousDevice: boolean;
  matchedPreviousIp: boolean;
  reasons: string[];
  metadata: Record<string, unknown>;
};

type ReplaySignalSlice = {
  seenOnCurrentDeviceBefore?: boolean;
  previousScanSameDevice?: boolean | null;
  seenByCurrentTrustedActorBefore?: boolean;
  previousScanSameTrustedActor?: boolean | null;
  recentScanCount10m?: number;
  ipVelocityCount10m?: number;
  distinctDeviceCount24h?: number;
  distinctUntrustedDeviceCount24h?: number;
  distinctCountryCount24h?: number;
  distinctUntrustedCountryCount24h?: number;
  crossCodeCorrelation24h?: number;
  deviceGraphOverlap24h?: number;
};

export type ManualFallbackAssessment = {
  hasSignedHistory: boolean;
  reviewRequired: boolean;
  rescanRecommended: boolean;
  reasons: string[];
  metadata: Record<string, unknown>;
};

export const assessSignedReplay = (input: {
  signedTokenPresent: boolean;
  replayEpoch?: number | null;
  tokenReplayEpoch?: number | null;
  signedFirstSeenAt?: Date | string | null;
  lastSignedVerificationAt?: Date | string | null;
  lastSignedVerificationIpHash?: string | null;
  lastSignedVerificationDeviceHash?: string | null;
  actorIpHash?: string | null;
  actorDeviceHash?: string | null;
  customerUserId?: string | null;
  signals?: ReplaySignalSlice | null;
  now?: Date;
}) : SignedReplayAssessment => {
  const now = input.now || new Date();
  const replayEpoch = Number(input.replayEpoch || 1);
  const tokenReplayEpoch = Number.isFinite(Number(input.tokenReplayEpoch))
    ? Number(input.tokenReplayEpoch)
    : null;

  if (!VERIFY_REPLAY_HARDENING_ENABLED || !input.signedTokenPresent) {
    return {
      enabled: VERIFY_REPLAY_HARDENING_ENABLED,
      replayState: "UNSIGNED_OR_DISABLED",
      replayEpoch,
      tokenReplayEpoch,
      firstSignedVerificationInEpoch: false,
      sameContext: false,
      changedContext: false,
      rapidReuse: false,
      reviewRequired: false,
      stepUpRecommended: false,
      matchedPreviousDevice: false,
      matchedPreviousIp: false,
      reasons: [],
      metadata: {
        replayHardeningEnabled: VERIFY_REPLAY_HARDENING_ENABLED,
      },
    };
  }

  const signals = input.signals || {};
  const currentDeviceHash = normalizeText(input.actorDeviceHash);
  const currentIpHash = normalizeText(input.actorIpHash);
  const previousDeviceHash = normalizeText(input.lastSignedVerificationDeviceHash);
  const previousIpHash = normalizeText(input.lastSignedVerificationIpHash);

  const firstSignedVerificationInEpoch = !toDate(input.signedFirstSeenAt);
  const matchedPreviousDevice = Boolean(currentDeviceHash && previousDeviceHash && currentDeviceHash === previousDeviceHash);
  const matchedPreviousIp = Boolean(currentIpHash && previousIpHash && currentIpHash === previousIpHash);
  const seenOnCurrentDeviceBefore = Boolean(signals.seenOnCurrentDeviceBefore || signals.previousScanSameDevice);
  const seenByTrustedActorBefore = Boolean(signals.seenByCurrentTrustedActorBefore || signals.previousScanSameTrustedActor);

  const hasCurrentContext = Boolean(currentDeviceHash || currentIpHash);
  const hasPreviousContext = Boolean(previousDeviceHash || previousIpHash);
  const weakContextSignals = !hasCurrentContext && !hasPreviousContext;
  const sameContext =
    !firstSignedVerificationInEpoch &&
    (matchedPreviousDevice ||
      seenByTrustedActorBefore ||
      (matchedPreviousIp && seenOnCurrentDeviceBefore) ||
      weakContextSignals);
  const changedContext =
    !firstSignedVerificationInEpoch &&
    !sameContext &&
    (hasCurrentContext || hasPreviousContext);

  const minutesSinceLastSigned = minutesBetween(input.lastSignedVerificationAt, now);
  const recentScanCount10m = Number(signals.recentScanCount10m || 0);
  const ipVelocityCount10m = Number(signals.ipVelocityCount10m || 0);
  const rapidReuse =
    changedContext &&
    (recentScanCount10m >= REPLAY_RAPID_REUSE_THRESHOLD_10M ||
      ipVelocityCount10m >= REPLAY_IP_VELOCITY_THRESHOLD_10M ||
      (minutesSinceLastSigned != null && minutesSinceLastSigned <= REPLAY_CHANGED_CONTEXT_LOOKBACK_MINUTES));

  const spreadSignals =
    Number(signals.distinctDeviceCount24h || 0) > 1 ||
    Number(signals.distinctUntrustedDeviceCount24h || 0) > 0 ||
    Number(signals.distinctCountryCount24h || 0) > 1 ||
    Number(signals.distinctUntrustedCountryCount24h || 0) > 0 ||
    Number(signals.crossCodeCorrelation24h || 0) > 0 ||
    Number(signals.deviceGraphOverlap24h || 0) > 0;

  const reviewRequired = !firstSignedVerificationInEpoch && (changedContext || (rapidReuse && !sameContext) || (!sameContext && spreadSignals));

  const reasons: string[] = [];
  if (firstSignedVerificationInEpoch) {
    reasons.push("First signed-label verification recorded for the current replay epoch.");
  } else if (sameContext) {
    reasons.push("Recent signed-label use matches the prior verified device or requester context.");
  } else if (rapidReuse) {
    reasons.push("The same signed label was reused unusually quickly from a different scan context.");
  } else if (changedContext) {
    reasons.push("The same signed label was reused from a materially different scan context.");
  }

  if (reviewRequired && spreadSignals) {
    reasons.push("Recent scan activity expanded beyond the expected device, geography, or QR relationship pattern.");
  }

  return {
    enabled: true,
    replayState: firstSignedVerificationInEpoch
      ? "FIRST_SIGNED_USE"
      : rapidReuse
        ? "RAPID_CHANGED_CONTEXT_REPEAT"
        : sameContext
          ? "SAME_CONTEXT_REPEAT"
          : "CHANGED_CONTEXT_REPEAT",
    replayEpoch,
    tokenReplayEpoch,
    firstSignedVerificationInEpoch,
    sameContext,
    changedContext,
    rapidReuse,
    reviewRequired,
    stepUpRecommended: reviewRequired && !normalizeText(input.customerUserId),
    matchedPreviousDevice,
    matchedPreviousIp,
    reasons,
    metadata: {
      replayHardeningEnabled: true,
      recentScanCount10m,
      ipVelocityCount10m,
      minutesSinceLastSigned,
      matchedPreviousDevice,
      matchedPreviousIp,
      seenOnCurrentDeviceBefore,
      seenByTrustedActorBefore,
      weakContextSignals,
      distinctDeviceCount24h: Number(signals.distinctDeviceCount24h || 0),
      distinctUntrustedDeviceCount24h: Number(signals.distinctUntrustedDeviceCount24h || 0),
      distinctCountryCount24h: Number(signals.distinctCountryCount24h || 0),
      distinctUntrustedCountryCount24h: Number(signals.distinctUntrustedCountryCount24h || 0),
      crossCodeCorrelation24h: Number(signals.crossCodeCorrelation24h || 0),
      deviceGraphOverlap24h: Number(signals.deviceGraphOverlap24h || 0),
    },
  };
};

export const assessManualVerificationFallback = (input: {
  proofSource: "SIGNED_LABEL" | "MANUAL_CODE_LOOKUP";
  signedFirstSeenAt?: Date | string | null;
  lastSignedVerificationAt?: Date | string | null;
  signals?: ReplaySignalSlice | null;
}) : ManualFallbackAssessment => {
  if (input.proofSource !== "MANUAL_CODE_LOOKUP") {
    return {
      hasSignedHistory: false,
      reviewRequired: false,
      rescanRecommended: false,
      reasons: [],
      metadata: {
        hasSignedHistory: false,
        reviewRequired: false,
      },
    };
  }

  const hasSignedHistory = Boolean(toDate(input.signedFirstSeenAt) || toDate(input.lastSignedVerificationAt));
  const signals = input.signals || {};
  const recentScanCount10m = Number(signals.recentScanCount10m || 0);
  const ipVelocityCount10m = Number(signals.ipVelocityCount10m || 0);
  const distinctUntrustedDeviceCount24h = Number(signals.distinctUntrustedDeviceCount24h || 0);
  const distinctUntrustedCountryCount24h = Number(signals.distinctUntrustedCountryCount24h || 0);
  const distinctCountryCount24h = Number(signals.distinctCountryCount24h || 0);
  const crossCodeCorrelation24h = Number(signals.crossCodeCorrelation24h || 0);
  const deviceGraphOverlap24h = Number(signals.deviceGraphOverlap24h || 0);

  const riskyManualFallback =
    hasSignedHistory &&
    (
      recentScanCount10m >= REPLAY_RAPID_REUSE_THRESHOLD_10M ||
      ipVelocityCount10m >= REPLAY_IP_VELOCITY_THRESHOLD_10M ||
      distinctUntrustedDeviceCount24h > 0 ||
      distinctUntrustedCountryCount24h > 0 ||
      distinctCountryCount24h > 1 ||
      crossCodeCorrelation24h > 0 ||
      deviceGraphOverlap24h > 0
    );

  const reasons: string[] = [];
  if (hasSignedHistory) {
    reasons.push("This code has prior signed-label verification history. Manual entry cannot replace that stronger proof.");
    if (riskyManualFallback) {
      reasons.push("Recent activity around this code makes manual fallback unsuitable as a comfortable substitute for the signed label.");
    } else {
      reasons.push("If the original label is available, re-scan it instead of relying on manual entry.");
    }
  }

  return {
    hasSignedHistory,
    reviewRequired: riskyManualFallback,
    rescanRecommended: hasSignedHistory,
    reasons,
    metadata: {
      hasSignedHistory,
      reviewRequired: riskyManualFallback,
      recentScanCount10m,
      ipVelocityCount10m,
      distinctUntrustedDeviceCount24h,
      distinctUntrustedCountryCount24h,
      distinctCountryCount24h,
      crossCodeCorrelation24h,
      deviceGraphOverlap24h,
    },
  };
};
