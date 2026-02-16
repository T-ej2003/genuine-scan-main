import { ScanRiskClassification } from "@prisma/client";
export type ScanIdentitySnapshot = {
    scannedAt: Date;
    customerUserId?: string | null;
    anonVisitorId?: string | null;
    locationCountry?: string | null;
    latitude?: number | null;
    longitude?: number | null;
};
export type ScanClassificationContext = ScanIdentitySnapshot & {
    ownerCustomerUserId?: string | null;
};
export type ScanClassificationResult = {
    classification: ScanRiskClassification;
    reasons: string[];
    metrics: {
        totalPriorScans: number;
        distinctCustomerCount: number;
        distinctVisitorCount: number;
        verifiedByYouCount: number;
    };
};
export declare const classifyScan: (context: ScanClassificationContext, scanHistory: ScanIdentitySnapshot[]) => ScanClassificationResult;
//# sourceMappingURL=scanRiskService.d.ts.map