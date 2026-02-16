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
  };
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

export const getScanInsight = async (qrCodeId: string, currentDevice?: string | null): Promise<ScanInsight> => {
  const now = Date.now();
  const lookback24h = new Date(now - 24 * 60 * 60 * 1000);
  const lookback10m = new Date(now - 10 * 60 * 1000);

  const [first, latestTwo, recent24h, recent10mCount] = await Promise.all([
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
  ]);

  const latest = latestTwo[0] || null;
  const previous = latestTwo[1] || null;
  const latestTimestamp = latest?.scannedAt ? new Date(latest.scannedAt).getTime() : null;

  const normalizedCurrentDevice = String(currentDevice || "").trim();
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
    },
  };
};
