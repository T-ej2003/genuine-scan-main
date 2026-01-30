import { EventEmitter } from "events";

export type AuditStreamEvent = {
  id: string;
  userId?: string | null;
  action: string;
  entityType: string;
  entityId?: string | null;
  details?: any;
  ipAddress?: string | null;
  createdAt: string; // ISO
  licenseeId?: string | null; // optional (if you add to schema)
};

class AuditStream extends EventEmitter {
  emitLog(event: AuditStreamEvent) {
    this.emit("log", event);
  }
  onLog(handler: (event: AuditStreamEvent) => void) {
    this.on("log", handler);
    return () => this.off("log", handler);
  }
}

export const auditStream = new AuditStream();

