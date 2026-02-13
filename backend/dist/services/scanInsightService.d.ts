type ScanInsight = {
    firstScanAt: string | null;
    firstScanLocation: string | null;
    latestScanAt: string | null;
    latestScanLocation: string | null;
    previousScanAt: string | null;
    previousScanLocation: string | null;
};
export declare const getScanInsight: (qrCodeId: string) => Promise<ScanInsight>;
export {};
//# sourceMappingURL=scanInsightService.d.ts.map