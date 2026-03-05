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
export declare const getScanInsight: (qrCodeId: string, currentDevice?: string | null, options?: ScanInsightOptions) => Promise<ScanInsight>;
export {};
//# sourceMappingURL=scanInsightService.d.ts.map