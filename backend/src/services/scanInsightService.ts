import prisma from "../config/database";
import { reverseGeocode } from "./locationService";

type ScanInsight = {
  firstScanAt: string | null;
  firstScanLocation: string | null;
  latestScanAt: string | null;
  latestScanLocation: string | null;
  previousScanAt: string | null;
  previousScanLocation: string | null;
  signals: {
    distinctDeviceCount24h: number;
    recentScanCount10m: number;
    distinctCountryCount24h: number;
    seenOnCurrentDeviceBefore: boolean;
    previousScanSameDevice: boolean | null;
    ipVelocityCount10m: number;
    ipReputationScore: number;
    deviceGraphOverlap24h: number;
    crossCodeCorrelation24h: number;
  };
};

type ScanInsightOptions = {
  currentIpAddress?: string | null;
  licenseeId?: string | null;
};

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

  const [first, latestTwo, recent24h, recent10mCount, ipVelocityCount10m, deviceCorrelatedCodes] = await Promise.all([
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
      },
    }),
    prisma.qrScanLog.count({
      where: {
        qrCodeId,
        scannedAt: { gte: lookback10m },
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
      ? String((previous as any).device || "").trim() === normalizedCurrentDevice
      : null;

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
      distinctDeviceCount24h: distinctDevices.size,
      recentScanCount10m: recent10mCount,
      distinctCountryCount24h: distinctCountries.size,
      seenOnCurrentDeviceBefore,
      previousScanSameDevice,
      ipVelocityCount10m,
      ipReputationScore,
      deviceGraphOverlap24h,
      crossCodeCorrelation24h,
    },
  };
};
