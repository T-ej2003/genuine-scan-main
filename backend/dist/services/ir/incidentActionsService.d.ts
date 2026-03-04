export type IrContainmentAction = "FLAG_QR_UNDER_INVESTIGATION" | "UNFLAG_QR_UNDER_INVESTIGATION" | "SUSPEND_BATCH" | "REINSTATE_BATCH" | "SUSPEND_ORG" | "REINSTATE_ORG" | "SUSPEND_MANUFACTURER_USERS" | "REINSTATE_MANUFACTURER_USERS";
export declare const applyContainmentAction: (input: {
    incidentId: string;
    actorUserId?: string | null;
    action: IrContainmentAction;
    reason: string;
    qrCodeId?: string | null;
    batchId?: string | null;
    licenseeId?: string | null;
    manufacturerUserIds?: string[];
    ipAddress?: string | null;
}) => Promise<{
    ok: boolean;
    incidentId: string;
    details: any;
}>;
//# sourceMappingURL=incidentActionsService.d.ts.map