import prisma from "../config/database";
import { reverseGeocode } from "./locationService";

type ScanInsight = {
  firstScanAt: string | null;
  firstScanLocation: string | null;
  latestScanAt: string | null;
  latestScanLocation: string | null;
  previousScanAt: string | null;
  previousScanLocation: string | null;
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

export const getScanInsight = async (qrCodeId: string): Promise<ScanInsight> => {
  const [first, latestTwo] = await Promise.all([
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
      },
    }),
  ]);

  const latest = latestTwo[0] || null;
  const previous = latestTwo[1] || null;

  return {
    firstScanAt: first?.scannedAt ? new Date(first.scannedAt).toISOString() : null,
    firstScanLocation: first ? await locationLabel(first) : null,
    latestScanAt: latest?.scannedAt ? new Date(latest.scannedAt).toISOString() : null,
    latestScanLocation: latest ? await locationLabel(latest) : null,
    previousScanAt: previous?.scannedAt ? new Date(previous.scannedAt).toISOString() : null,
    previousScanLocation: previous ? await locationLabel(previous) : null,
  };
};
