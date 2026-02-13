import { AlertSeverity, PolicyAlertType, SecurityPolicy } from "@prisma/client";
export declare const getOrCreateSecurityPolicy: (licenseeId: string) => Promise<SecurityPolicy>;
export type PolicyScanInput = {
    qrCodeId: string;
    code: string;
    licenseeId: string;
    batchId?: string | null;
    manufacturerId?: string | null;
    scanCount: number;
    scannedAt?: Date;
    latitude?: number | null;
    longitude?: number | null;
    ipAddress?: string | null;
    userAgent?: string | null;
};
export type PolicyScanResult = {
    policy: Pick<SecurityPolicy, "autoBlockEnabled" | "autoBlockBatchOnVelocity" | "multiScanThreshold" | "geoDriftThresholdKm" | "velocitySpikeThresholdPerMin" | "stuckBatchHours">;
    triggered: {
        multiScan: boolean;
        geoDrift: boolean;
        velocitySpike: boolean;
    };
    autoBlockedQr: boolean;
    autoBlockedBatch: boolean;
    alerts: Array<{
        id: string;
        alertType: PolicyAlertType;
        severity: AlertSeverity;
        message: string;
        score: number;
    }>;
};
export declare const evaluateScanAndEnforcePolicy: (input: PolicyScanInput) => Promise<PolicyScanResult>;
//# sourceMappingURL=policyEngineService.d.ts.map