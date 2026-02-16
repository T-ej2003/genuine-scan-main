export interface AuditLogInput {
    userId?: string;
    orgId?: string;
    licenseeId?: string;
    action: string;
    entityType: string;
    entityId?: string;
    details?: any;
    ipAddress?: string;
    ipHash?: string;
    userAgent?: string;
}
type Listener = (log: any) => void;
export declare const onAuditLog: (cb: Listener) => () => boolean;
export declare const createAuditLog: (data: AuditLogInput) => Promise<{
    id: string;
    orgId: string | null;
    licenseeId: string | null;
    createdAt: Date;
    userId: string | null;
    details: import("@prisma/client/runtime/library").JsonValue | null;
    action: string;
    entityType: string;
    entityId: string | null;
    ipAddress: string | null;
    ipHash: string | null;
    userAgent: string | null;
}>;
export declare const getAuditLogs: (opts: {
    userId?: string;
    entityType?: string;
    entityId?: string;
    action?: string;
    excludeActions?: string[];
    licenseeId?: string;
    userIds?: string[];
    limit: number;
    offset: number;
}) => Promise<{
    logs: {
        id: string;
        orgId: string | null;
        licenseeId: string | null;
        createdAt: Date;
        userId: string | null;
        details: import("@prisma/client/runtime/library").JsonValue | null;
        action: string;
        entityType: string;
        entityId: string | null;
        ipAddress: string | null;
        ipHash: string | null;
        userAgent: string | null;
    }[];
    total: number;
}>;
export {};
//# sourceMappingURL=auditService.d.ts.map