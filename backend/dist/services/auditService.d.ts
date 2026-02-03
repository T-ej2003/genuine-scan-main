export interface AuditLogInput {
    userId?: string;
    licenseeId?: string;
    action: string;
    entityType: string;
    entityId?: string;
    details?: any;
    ipAddress?: string;
}
type Listener = (log: any) => void;
export declare const onAuditLog: (cb: Listener) => () => boolean;
export declare const createAuditLog: (data: AuditLogInput) => Promise<{
    id: string;
    licenseeId: string | null;
    createdAt: Date;
    userId: string | null;
    action: string;
    entityType: string;
    entityId: string | null;
    details: import("@prisma/client/runtime/library").JsonValue | null;
    ipAddress: string | null;
}>;
export declare const getAuditLogs: (opts: {
    userId?: string;
    entityType?: string;
    licenseeId?: string;
    limit: number;
    offset: number;
}) => Promise<{
    logs: {
        id: string;
        licenseeId: string | null;
        createdAt: Date;
        userId: string | null;
        action: string;
        entityType: string;
        entityId: string | null;
        details: import("@prisma/client/runtime/library").JsonValue | null;
        ipAddress: string | null;
    }[];
    total: number;
}>;
export {};
//# sourceMappingURL=auditService.d.ts.map