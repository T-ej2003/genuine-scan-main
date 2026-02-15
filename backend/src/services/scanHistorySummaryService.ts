import prisma from "../config/database";
import { getScanInsight } from "./scanInsightService";

export type PublicScanHistorySummary = {
  totalScans: number;
  firstScanAt: string | null;
  firstScanLocation: string | null;
  lastScanAt: string | null;
  lastScanLocation: string | null;
  previousScanAt: string | null;
  previousScanLocation: string | null;
  verifiedByYouCount: number;
  topLocations: Array<{ label: string; count: number }>;
};

export const buildScanHistorySummary = async (input: {
  qrCodeId: string;
  totalScans: number;
  customerUserId?: string | null;
  anonVisitorId?: string | null;
}): Promise<PublicScanHistorySummary> => {
  const [insight, recentLogs, verifiedByYouCount] = await Promise.all([
    getScanInsight(input.qrCodeId),
    prisma.qrScanLog.findMany({
      where: { qrCodeId: input.qrCodeId },
      orderBy: [{ scannedAt: "desc" }, { id: "desc" }],
      take: 50,
      select: {
        locationName: true,
        locationCity: true,
        locationCountry: true,
      },
    }),
    input.customerUserId
      ? prisma.qrScanLog.count({
          where: {
            qrCodeId: input.qrCodeId,
            customerUserId: input.customerUserId,
          },
        })
      : input.anonVisitorId
      ? prisma.qrScanLog.count({
          where: {
            qrCodeId: input.qrCodeId,
            anonVisitorId: input.anonVisitorId,
          },
        })
      : Promise.resolve(0),
  ]);

  const locationCounts = new Map<string, number>();

  for (const row of recentLogs) {
    const label =
      String(row.locationName || "").trim() ||
      [String(row.locationCity || "").trim(), String(row.locationCountry || "").trim()]
        .filter(Boolean)
        .join(", ") ||
      String(row.locationCountry || "").trim() ||
      "Unknown";

    locationCounts.set(label, (locationCounts.get(label) || 0) + 1);
  }

  const topLocations = Array.from(locationCounts.entries())
    .sort((a, b) => b[1] - a[1])
    .slice(0, 3)
    .map(([label, count]) => ({ label, count }));

  return {
    totalScans: input.totalScans,
    firstScanAt: insight.firstScanAt,
    firstScanLocation: insight.firstScanLocation,
    lastScanAt: insight.latestScanAt,
    lastScanLocation: insight.latestScanLocation,
    previousScanAt: insight.previousScanAt,
    previousScanLocation: insight.previousScanLocation,
    verifiedByYouCount,
    topLocations,
  };
};
