export type PublicScanHistorySummary = {
    totalScans: number;
    firstScanAt: string | null;
    firstScanLocation: string | null;
    lastScanAt: string | null;
    lastScanLocation: string | null;
    previousScanAt: string | null;
    previousScanLocation: string | null;
    verifiedByYouCount: number;
    topLocations: Array<{
        label: string;
        count: number;
    }>;
};
export declare const buildScanHistorySummary: (input: {
    qrCodeId: string;
    totalScans: number;
    customerUserId?: string | null;
    anonVisitorId?: string | null;
}) => Promise<PublicScanHistorySummary>;
//# sourceMappingURL=scanHistorySummaryService.d.ts.map