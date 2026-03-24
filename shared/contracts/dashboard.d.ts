export interface DashboardStatsDTO {
  totalQRCodes?: number;
  activeLicensees?: number;
  manufacturers?: number;
  totalBatches?: number;
}

export interface QrStatsDTO {
  dormant?: number;
  allocated?: number;
  printed?: number;
  scanned?: number;
  byStatus?: Record<string, number>;
  statusCounts?: Record<string, number>;
}

export interface AuditLogDTO {
  id: string;
  action?: string;
  entityType?: string | null;
  entityId?: string | null;
  createdAt: string;
  details?: unknown;
  user?: { id: string; name?: string | null; email?: string | null } | null;
  userId?: string | null;
}
