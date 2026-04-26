const scopedValue = (value?: string | number | boolean | null) => value ?? "all";

export const queryKeys = {
  dashboard: {
    stats: (licenseeId?: string) => ["dashboard", "stats", scopedValue(licenseeId)] as const,
    audit: (limit = 5) => ["dashboard", "audit", limit] as const,
  },
  batches: {
    list: (licenseeId?: string) => ["batches", "list", scopedValue(licenseeId)] as const,
    manufacturers: (licenseeId?: string) => ["batches", "manufacturers", scopedValue(licenseeId)] as const,
    allocationMap: (batchId?: string) => ["batches", "allocation-map", scopedValue(batchId)] as const,
  },
  manufacturers: {
    licensees: () => ["manufacturers", "licensees"] as const,
    directory: (licenseeId?: string) => ["manufacturers", "directory", scopedValue(licenseeId)] as const,
  },
  printing: {
    jobs: (batchId?: string, limit = 8) => ["printing", "jobs", scopedValue(batchId), limit] as const,
    runtime: (includeInactive = false) => ["printing", "runtime", includeInactive] as const,
  },
  layout: {
    notifications: (limit = 24, unreadOnly?: boolean) =>
      ["layout", "notifications", limit, scopedValue(unreadOnly ?? null)] as const,
    attentionQueue: () => ["layout", "attention-queue"] as const,
  },
  incidents: {
    list: (filters?: Record<string, unknown>) => ["incidents", "list", filters ?? {}] as const,
    detail: (id?: string) => ["incidents", "detail", scopedValue(id)] as const,
  },
  support: {
    tickets: (filters?: Record<string, unknown>) => ["support", "tickets", filters ?? {}] as const,
    ticketDetail: (id?: string) => ["support", "ticket", scopedValue(id)] as const,
    reports: () => ["support", "reports"] as const,
    assignees: () => ["support", "assignees"] as const,
  },
};
