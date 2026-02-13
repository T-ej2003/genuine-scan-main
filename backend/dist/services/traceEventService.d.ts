import { TraceEventType } from "@prisma/client";
export type TraceEventInput = {
    eventType: TraceEventType;
    licenseeId: string;
    batchId?: string | null;
    qrCodeId?: string | null;
    manufacturerId?: string | null;
    userId?: string | null;
    sourceAction?: string | null;
    details?: any;
    createdAt?: Date;
};
export declare const deriveTraceEventTypeFromAudit: (log: {
    action?: string;
    details?: any;
}) => TraceEventType | null;
export declare const createTraceEvent: (data: TraceEventInput) => Promise<{
    id: string;
    licenseeId: string;
    createdAt: Date;
    userId: string | null;
    eventType: import(".prisma/client").$Enums.TraceEventType;
    sourceAction: string | null;
    details: import("@prisma/client/runtime/library").JsonValue | null;
    batchId: string | null;
    qrCodeId: string | null;
    manufacturerId: string | null;
}>;
export declare const createTraceEventFromAuditLog: (log: {
    id: string;
    action: string;
    entityType: string;
    entityId: string | null;
    userId: string | null;
    licenseeId: string | null;
    details: any;
    createdAt: Date;
}) => Promise<{
    id: string;
    licenseeId: string;
    createdAt: Date;
    userId: string | null;
    eventType: import(".prisma/client").$Enums.TraceEventType;
    sourceAction: string | null;
    details: import("@prisma/client/runtime/library").JsonValue | null;
    batchId: string | null;
    qrCodeId: string | null;
    manufacturerId: string | null;
} | null>;
export declare const backfillTraceEventsFromAuditLogs: (opts?: {
    licenseeId?: string;
    limit?: number;
}) => Promise<void>;
export declare const getTraceTimeline: (opts: {
    licenseeId?: string;
    eventType?: TraceEventType;
    batchId?: string;
    manufacturerId?: string;
    qrCodeId?: string;
    limit: number;
    offset: number;
}) => Promise<{
    events: ({
        user: {
            id: string;
            email: string;
            name: string;
        } | null;
        batch: {
            id: string;
            name: string;
        } | null;
        qrCode: {
            id: string;
            code: string;
        } | null;
        manufacturer: {
            id: string;
            email: string;
            name: string;
        } | null;
    } & {
        id: string;
        licenseeId: string;
        createdAt: Date;
        userId: string | null;
        eventType: import(".prisma/client").$Enums.TraceEventType;
        sourceAction: string | null;
        details: import("@prisma/client/runtime/library").JsonValue | null;
        batchId: string | null;
        qrCodeId: string | null;
        manufacturerId: string | null;
    })[];
    total: number;
}>;
//# sourceMappingURL=traceEventService.d.ts.map