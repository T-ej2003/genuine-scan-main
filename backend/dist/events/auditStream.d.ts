import { EventEmitter } from "events";
export type AuditStreamEvent = {
    id: string;
    userId?: string | null;
    action: string;
    entityType: string;
    entityId?: string | null;
    details?: any;
    ipAddress?: string | null;
    createdAt: string;
    licenseeId?: string | null;
};
declare class AuditStream extends EventEmitter {
    emitLog(event: AuditStreamEvent): void;
    onLog(handler: (event: AuditStreamEvent) => void): () => this;
}
export declare const auditStream: AuditStream;
export {};
//# sourceMappingURL=auditStream.d.ts.map