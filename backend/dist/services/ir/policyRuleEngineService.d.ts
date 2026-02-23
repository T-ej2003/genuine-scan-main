import { PolicyAlert } from "@prisma/client";
export declare const evaluatePolicyRulesForScan: (input: {
    licenseeId: string;
    qrCodeId: string;
    code: string;
    batchId?: string | null;
    manufacturerId?: string | null;
}) => Promise<{
    alerts: PolicyAlert[];
    incidents: string[];
}>;
export declare const evaluatePolicyRulesForIncidentVolume: (input: {
    incidentId: string;
    licenseeId?: string | null;
    manufacturerId?: string | null;
}) => Promise<{
    alerts: PolicyAlert[];
}>;
//# sourceMappingURL=policyRuleEngineService.d.ts.map