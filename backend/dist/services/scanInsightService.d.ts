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
};
export declare const getScanInsight: (qrCodeId: string, currentDevice?: string | null, options?: ScanInsightOptions) => Promise<ScanInsight>;
export {};
//# sourceMappingURL=scanInsightService.d.ts.map