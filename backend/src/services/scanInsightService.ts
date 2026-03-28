import prisma from "../config/database";
import { reverseGeocode } from "./locationService";
import { isPrismaMissingTableError } from "../utils/prismaStorageGuard";
import { guardPublicIntegrityFallback } from "../utils/publicIntegrityGuard";

type ScanInsight = {
  firstScanAt: string | null;
  firstScanLocation: string | null;
  latestScanAt: string | null;
  latestScanLocation: string | null;
  previousScanAt: string | null;
  previousScanLocation: string | null;
  signals: {
    scanCount24h: number;
    distinctDeviceCount24h: number;
    recentScanCount10m: number;
    distinctCountryCount24h: number;
    seenOnCurrentDeviceBefore: boolean;
    previousScanSameDevice: boolean | null;
    currentActorTrustedOwnerContext: boolean;
    seenByCurrentTrustedActorBefore: boolean;
    previousScanSameTrustedActor: boolean | null;
    trustedOwnerScanCount24h: number;
    trustedOwnerScanCount10m: number;
    untrustedScanCount24h: number;
    untrustedScanCount10m: number;
    distinctTrustedActorCount24h: number;
    distinctUntrustedDeviceCount24h: number;
    distinctUntrustedCountryCount24h: number;
    ipVelocityCount10m: number;
    ipReputationScore: number;
    deviceGraphOverlap24h: number;
    crossCodeCorrelation24h: number;
  };
};

type ScanInsightOptions = {
  currentIpAddress?: string | null;
  licenseeId?: string | null;
  currentCustomerUserId?: string | null;
  currentOwnershipId?: string | null;
  currentActorTrustedOwnerContext?: boolean;
  strictStorage?: boolean;
};

const emptyScanInsight = (currentActorTrustedOwnerContext: boolean): ScanInsight => ({
  firstScanAt: null,
  firstScanLocation: null,
  latestScanAt: null,
  latestScanLocation: null,
  previousScanAt: null,
  previousScanLocation: null,
  signals: {
    scanCount24h: 0,
    distinctDeviceCount24h: 0,
    recentScanCount10m: 0,
    distinctCountryCount24h: 0,
    seenOnCurrentDeviceBefore: false,
    previousScanSameDevice: null,
    currentActorTrustedOwnerContext,
    seenByCurrentTrustedActorBefore: false,
    previousScanSameTrustedActor: null,
    trustedOwnerScanCount24h: 0,
    trustedOwnerScanCount10m: 0,
    untrustedScanCount24h: 0,
    untrustedScanCount10m: 0,
    distinctTrustedActorCount24h: 0,
    distinctUntrustedDeviceCount24h: 0,
    distinctUntrustedCountryCount24h: 0,
    ipVelocityCount10m: 0,
    ipReputationScore: 0,
    deviceGraphOverlap24h: 0,
    crossCodeCorrelation24h: 0,
  },
});

const locationLabel = async (row: {
  locationName?: string | null;
  locationCity?: string | null;
  locationRegion?: string | null;
  locationCountry?: string | null;
  latitude?: number | null;
  longitude?: number | null;
}) => {
  if (row.locationName) return row.locationName;
  const nameFromParts = [row.locationCity, row.locationRegion, row.locationCountry].filter(Boolean).join(", ");
  if (nameFromParts) return nameFromParts;
  const resolved = await reverseGeocode(row.latitude ?? null, row.longitude ?? null);
  return resolved?.name || null;
};

const parseIpReputationPatterns = (raw: string) =>
  raw
    .split(",")
    .map((part) => part.trim())
    .filter(Boolean);

const denylistPatterns = parseIpReputationPatterns(String(process.env.SCAN_IP_REPUTATION_DENYLIST || ""));
const suspiciousPrefixPatterns = parseIpReputationPatterns(String(process.env.SCAN_IP_REPUTATION_SUSPICIOUS_PREFIXES || ""));

const isPrivateIp = (ip: string) => {
  if (!ip) return false;
  const normalized = ip.toLowerCase();
  if (normalized === "::1" || normalized.startsWith("fe80:") || normalized.startsWith("fc") || normalized.startsWith("fd")) {
    return true;
  }
  if (normalized.startsWith("10.") || normalized.startsWith("192.168.")) return true;
  if (normalized.startsWith("172.")) {
    const parts = normalized.split(".");
    const second = Number(parts[1]);
    if (Number.isFinite(second) && second >= 16 && second <= 31) return true;
  }
  return false;
};

const estimateIpReputationScore = (ip: string | null | undefined) => {
  const value = String(ip || "").trim();
  if (!value) return 0;

  const matchesPattern = (pattern: string) => {
    if (!pattern) return false;
    if (pattern.endsWith("*")) {
      return value.startsWith(pattern.slice(0, -1));
    }
    return value === pattern;
  };

  if (denylistPatterns.some(matchesPattern)) return 95;
  if (suspiciousPrefixPatterns.some(matchesPattern)) return 70;
  if (isPrivateIp(value)) return 15;
  return 5;
};

const normalizeActorId = (value: string | null | undefined) => String(value || "").trim();

const trustedActorKey = (input: {
  isTrustedOwnerContext?: boolean | null;
  customerUserId?: string | null;
  ownershipId?: string | null;
}) => {
  if (input.isTrustedOwnerContext !== true) return "";
  const customerUserId = normalizeActorId(input.customerUserId);
  if (customerUserId) return `user:${customerUserId}`;
  const ownershipId = normalizeActorId(input.ownershipId);
  return ownershipId ? `ownership:${ownershipId}` : "";
};

export const getScanInsight = async (
  qrCodeId: string,
  currentDevice?: string | null,
  options?: ScanInsightOptions
): Promise<ScanInsight> => {
  const now = Date.now();
  const lookback24h = new Date(now - 24 * 60 * 60 * 1000);
  const lookback10m = new Date(now - 10 * 60 * 1000);
  const normalizedCurrentIp = String(options?.currentIpAddress || "").trim() || null;
  const licenseeScope = String(options?.licenseeId || "").trim() || null;
  const sharedScopeWhere = licenseeScope ? { licenseeId: licenseeScope } : {};
  const normalizedCurrentDevice = String(currentDevice || "").trim();
  const currentActorTrustedOwnerContext = options?.currentActorTrustedOwnerContext === true;
  const currentTrustedActorKey = currentActorTrustedOwnerContext
    ? trustedActorKey({
        isTrustedOwnerContext: true,
        customerUserId: options?.currentCustomerUserId || null,
        ownershipId: options?.currentOwnershipId || null,
      })
    : "";
  try {
    const [first, latestTwo, recent24h, ipVelocityCount10m, deviceCorrelatedCodes] = await Promise.all([
      prisma.qrScanLog.findFirst({
        where: { qrCodeId },
        orderBy: [{ scannedAt: "asc" }, { id: "asc" }],
        select: {
          scannedAt: true,
          locationName: true,
          locationCity: true,
          locationRegion: true,
          locationCountry: true,
          latitude: true,
          longitude: true,
        },
      }),
      prisma.qrScanLog.findMany({
        where: { qrCodeId },
        orderBy: [{ scannedAt: "desc" }, { id: "desc" }],
        take: 2,
        select: {
          scannedAt: true,
          locationName: true,
          locationCity: true,
          locationRegion: true,
          locationCountry: true,
          latitude: true,
          longitude: true,
          device: true,
          customerUserId: true,
          ownershipId: true,
          isTrustedOwnerContext: true,
        },
      }),
      prisma.qrScanLog.findMany({
        where: {
          qrCodeId,
          scannedAt: { gte: lookback24h },
        },
        select: {
          scannedAt: true,
          device: true,
          locationCountry: true,
          customerUserId: true,
          ownershipId: true,
          isTrustedOwnerContext: true,
        },
      }),
      normalizedCurrentIp
        ? prisma.qrScanLog.count({
            where: {
              ...sharedScopeWhere,
              ipAddress: normalizedCurrentIp,
              scannedAt: { gte: lookback10m },
            },
          })
        : Promise.resolve(0),
      normalizedCurrentDevice
        ? prisma.qrScanLog.findMany({
            where: {
              ...sharedScopeWhere,
              device: normalizedCurrentDevice,
              scannedAt: { gte: lookback24h },
            },
            distinct: ["qrCodeId"],
            select: { qrCodeId: true },
            take: 120,
          })
        : Promise.resolve([] as Array<{ qrCodeId: string }>),
    ]);

    const latest = latestTwo[0] || null;
    const previous = latestTwo[1] || null;
    const latestTimestamp = latest?.scannedAt ? new Date(latest.scannedAt).getTime() : null;
    const recent10m = recent24h.filter((row) => new Date(row.scannedAt).getTime() >= lookback10m.getTime());

    const distinctDevices = new Set(
      recent24h
        .map((row) => String(row.device || "").trim())
        .filter(Boolean)
    );
    const distinctCountries = new Set(
      recent24h
        .map((row) => String(row.locationCountry || "").trim().toUpperCase())
        .filter(Boolean)
    );
    const trustedRecent24h = recent24h.filter((row) => row.isTrustedOwnerContext === true);
    const untrustedRecent24h = recent24h.filter((row) => row.isTrustedOwnerContext !== true);
    const trustedOwnerScanCount10m = recent10m.filter((row) => row.isTrustedOwnerContext === true).length;
    const untrustedScanCount10m = recent10m.filter((row) => row.isTrustedOwnerContext !== true).length;
    const distinctTrustedActors = new Set(trustedRecent24h.map((row) => trustedActorKey(row)).filter(Boolean));
    const distinctUntrustedDevices = new Set(
      untrustedRecent24h
        .map((row) => String(row.device || "").trim())
        .filter(Boolean)
    );
    const distinctUntrustedCountries = new Set(
      untrustedRecent24h
        .map((row) => String(row.locationCountry || "").trim().toUpperCase())
        .filter(Boolean)
    );

    const seenOnCurrentDeviceBefore =
      Boolean(normalizedCurrentDevice) &&
      recent24h.some((row) => {
        if (!latestTimestamp) return false;
        return (
          String(row.device || "").trim() === normalizedCurrentDevice &&
          new Date(row.scannedAt).getTime() < latestTimestamp
        );
      });

    const previousScanSameDevice =
      previous && normalizedCurrentDevice
        ? String(previous.device || "").trim() === normalizedCurrentDevice
        : null;
    const seenByCurrentTrustedActorBefore =
      Boolean(currentTrustedActorKey) &&
      recent24h.some((row) => {
        if (!latestTimestamp) return false;
        return trustedActorKey(row) === currentTrustedActorKey && new Date(row.scannedAt).getTime() < latestTimestamp;
      });
    const previousScanSameTrustedActor =
      previous && currentTrustedActorKey ? trustedActorKey(previous) === currentTrustedActorKey : null;

    const correlatedCodeIds = deviceCorrelatedCodes.map((row) => row.qrCodeId).filter(Boolean);
    const crossCodeCorrelation24h = correlatedCodeIds.filter((id) => id !== qrCodeId).length;

    const deviceGraphOverlap24h =
      normalizedCurrentDevice && correlatedCodeIds.length > 0
        ? (
            await prisma.qrScanLog.findMany({
              where: {
                ...sharedScopeWhere,
                qrCodeId: { in: correlatedCodeIds },
                scannedAt: { gte: lookback24h },
                device: { not: normalizedCurrentDevice },
              },
              distinct: ["device"],
              select: { device: true },
              take: 200,
            })
          ).length
        : 0;

    const ipReputationScore = estimateIpReputationScore(normalizedCurrentIp);

    return {
      firstScanAt: first?.scannedAt ? new Date(first.scannedAt).toISOString() : null,
      firstScanLocation: first ? await locationLabel(first) : null,
      latestScanAt: latest?.scannedAt ? new Date(latest.scannedAt).toISOString() : null,
      latestScanLocation: latest ? await locationLabel(latest) : null,
      previousScanAt: previous?.scannedAt ? new Date(previous.scannedAt).toISOString() : null,
      previousScanLocation: previous ? await locationLabel(previous) : null,
      signals: {
        scanCount24h: recent24h.length,
        distinctDeviceCount24h: distinctDevices.size,
        recentScanCount10m: recent10m.length,
        distinctCountryCount24h: distinctCountries.size,
        seenOnCurrentDeviceBefore,
        previousScanSameDevice,
        currentActorTrustedOwnerContext,
        seenByCurrentTrustedActorBefore,
        previousScanSameTrustedActor,
        trustedOwnerScanCount24h: trustedRecent24h.length,
        trustedOwnerScanCount10m,
        untrustedScanCount24h: untrustedRecent24h.length,
        untrustedScanCount10m,
        distinctTrustedActorCount24h: distinctTrustedActors.size,
        distinctUntrustedDeviceCount24h: distinctUntrustedDevices.size,
        distinctUntrustedCountryCount24h: distinctUntrustedCountries.size,
        ipVelocityCount10m,
        ipReputationScore,
        deviceGraphOverlap24h,
        crossCodeCorrelation24h,
      },
    };
  } catch (error) {
    if (isPrismaMissingTableError(error, ["qrscanlog"])) {
      guardPublicIntegrityFallback({
        strictStorage: options?.strictStorage,
        warningKey: "scan-insight-storage",
        warningMessage:
          "[scan] QrScanLog storage is unavailable. Returning empty scan insight until scan-log migrations are applied.",
        degradedMessage: "Verification is temporarily unavailable because scan history storage is not ready.",
        degradedCode: "PUBLIC_SCAN_LOG_UNAVAILABLE",
      });
      return emptyScanInsight(currentActorTrustedOwnerContext);
    }
    throw error;
  }
};
