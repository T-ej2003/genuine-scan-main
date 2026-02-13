type SlaStatus = "PENDING_PRINT" | "PRINTED_PENDING_SCAN" | "SCANNED" | "STUCK_WAITING_PRINT" | "STUCK_WAITING_FIRST_SCAN";
export type BatchSlaRow = {
    batchId: string;
    name: string;
    licenseeId: string;
    manufacturerId: string | null;
    manufacturerName: string | null;
    createdAt: string;
    printedAt: string | null;
    firstScanAt: string | null;
    timeToPrintMinutes: number | null;
    timeToFirstScanMinutes: number | null;
    totalScans: number;
    status: SlaStatus;
    isStuck: boolean;
    stuckForHours: number | null;
};
export type BatchSlaAnalytics = {
    policy: {
        stuckBatchHours: number;
    };
    summary: {
        totalBatches: number;
        printedBatches: number;
        scannedBatches: number;
        avgTimeToPrintMinutes: number | null;
        avgTimeToFirstScanMinutes: number | null;
        stuckBatches: number;
    };
    rows: BatchSlaRow[];
    stuckRows: BatchSlaRow[];
};
export declare const getBatchSlaAnalytics: (opts: {
    licenseeId?: string;
    limit?: number;
    stuckBatchHours?: number;
}) => Promise<BatchSlaAnalytics>;
export type BatchRiskRow = {
    batchId: string;
    name: string;
    licenseeId: string;
    manufacturerId: string | null;
    manufacturerName: string | null;
    score: number;
    riskLevel: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
    multiScanAnomalies: number;
    geoDriftAnomalies: number;
    velocitySpikeEvents: number;
    openAlerts: number;
};
export type ManufacturerRiskRow = {
    manufacturerId: string;
    manufacturerName: string;
    score: number;
    riskLevel: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
    batches: number;
    multiScanAnomalies: number;
    geoDriftAnomalies: number;
    velocitySpikeEvents: number;
    openAlerts: number;
};
export type RiskAnalytics = {
    policy: {
        multiScanThreshold: number;
        geoDriftThresholdKm: number;
        velocitySpikeThresholdPerMin: number;
    };
    lookbackHours: number;
    summary: {
        analyzedBatches: number;
        analyzedManufacturers: number;
        highRiskBatches: number;
        highRiskManufacturers: number;
    };
    batchRisk: BatchRiskRow[];
    manufacturerRisk: ManufacturerRiskRow[];
};
export declare const getRiskAnalytics: (opts: {
    licenseeId?: string;
    lookbackHours?: number;
    limit?: number;
}) => Promise<RiskAnalytics>;
export {};
//# sourceMappingURL=analyticsService.d.ts.map