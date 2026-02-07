import { QRStatus } from "@prisma/client";
export type ScanOutcome = "VALID" | "ALREADY_REDEEMED" | "NOT_PRINTED" | "SUSPICIOUS" | "BLOCKED";
export type ScanDecision = {
    outcome: ScanOutcome;
    isFirstScan: boolean;
    allowRedeem: boolean;
};
export declare const evaluateScanPolicy: (status: QRStatus) => ScanDecision;
//# sourceMappingURL=scanPolicy.d.ts.map