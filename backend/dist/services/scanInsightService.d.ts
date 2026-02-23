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
export declare const getScanInsight: (qrCodeId: string, currentDevice?: string | null) => Promise<ScanInsight>;
export {};
//# sourceMappingURL=scanInsightService.d.ts.map