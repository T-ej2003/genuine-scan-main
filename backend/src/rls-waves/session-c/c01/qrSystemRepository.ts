import { Prisma } from "@prisma/client";

import { getB01AuthenticatedPrisma } from "../../session-b/b01/runtimeClients";

export class QrBoundaryDenied extends Error {
  constructor(message = "QR_BOUNDARY_DENIED") {
    super(message);
    this.name = "QrBoundaryDenied";
  }
}

export const isQrBoundaryDenied = (error: unknown) =>
  error instanceof QrBoundaryDenied ||
  /QR_BOUNDARY_DENIED|AUTH_SESSION_CAPABILITY_DENIED|42501/.test(
    String((error as any)?.meta?.message || (error as any)?.message || "")
  );

const required = (value: unknown, label: string) => {
  const normalized = String(value || "").trim();
  if (!normalized) throw new QrBoundaryDenied(`QR boundary requires ${label}`);
  return normalized;
};

const client = () => getB01AuthenticatedPrisma();
type QrDb = Pick<Prisma.TransactionClient, "$queryRaw">;

export const withQrBoundaryTransaction = <T>(
  fn: (tx: Prisma.TransactionClient) => Promise<T>,
  options?: { maxWait?: number; timeout?: number; isolationLevel?: Prisma.TransactionIsolationLevel }
) => client().$transaction(fn, options);

export const allocateRange = async <T>(input: {
  capability: string; requestId: string; licenseeId: string; startNumber: number; endNumber: number;
  receivedBatchName?: string | null; source: "ADMIN_TOPUP" | "ADMIN_GENERATE";
}, db: QrDb = client()) => {
  const rows = await db.$queryRaw<Array<{ result: Prisma.JsonValue }>>`
    SELECT app_rls.qr_allocate_range(
      ${required(input.capability,"a capability")},${"qr-range-allocate"},${required(input.requestId,"a request ID")},
      ${input.licenseeId},${input.startNumber}::integer,${input.endNumber}::integer,${input.receivedBatchName || null},${input.source}
    ) AS result`;
  if (rows.length !== 1 || !rows[0].result || typeof rows[0].result !== "object") throw new Error("Invalid QR allocation result");
  return rows[0].result as T;
};

export const readCodes = async <T>(input: {
  capability: string; requestId: string; licenseeId?: string | null; status?: string | null;
  query?: string | null; limit: number; offset: number;
}, db: QrDb = client()) => {
  const rows = await db.$queryRaw<Array<{ payload: Prisma.JsonValue; total: bigint | number }>>`
    SELECT * FROM app_rls.qr_read_codes(
      ${required(input.capability,"a capability")},${"qr-code-read"},${required(input.requestId,"a request ID")},
      ${input.licenseeId || null},${input.status || null},${input.query || null},${input.limit}::integer,${input.offset}::integer
    )`;
  if (rows.length !== 1 || !Array.isArray(rows[0].payload)) throw new Error("Invalid QR projection result");
  return { qrCodes: rows[0].payload as T, total: Number(rows[0].total) };
};

export const visitQrCodePages = async <T>(
  readPage: (limit: number, offset: number) => Promise<{ qrCodes: T[]; total: number }>,
  visit: (rows: T[]) => Promise<void> | void,
  pageSize = 10000
) => {
  let visited = 0;
  let total = 0;
  do {
    const page = await readPage(pageSize, visited);
    total = page.total;
    await visit(page.qrCodes);
    visited += page.qrCodes.length;
    if (page.qrCodes.length === 0) break;
  } while (visited < total);
  if (visited !== total) throw new Error("QR_EXPORT_INCOMPLETE");
  return total;
};

export const readStats = async <T>(input: { capability: string; requestId: string; licenseeId?: string | null }) => {
  const rows = await client().$queryRaw<Array<{ result: Prisma.JsonValue }>>`
    SELECT app_rls.qr_stats(
      ${required(input.capability,"a capability")},${"qr-code-stats"},${required(input.requestId,"a request ID")},
      ${input.licenseeId || null}
    ) AS result`;
  if (rows.length !== 1 || !rows[0].result || typeof rows[0].result !== "object") throw new Error("Invalid QR stats result");
  return rows[0].result as T;
};

export const readInventoryProjection = async <T, A = unknown>(input: {
  capability: string; requestId: string; licenseeId?: string | null; manufacturerId?: string | null;
  batchQuery?: string | null; codeQuery?: string | null; status?: string | null; limit: number; offset: number;
}): Promise<{ rows: T[]; total: number; aggregate: A | null }> => {
  const rows = await client().$queryRaw<Array<{ payload: Prisma.JsonValue | null; total: bigint | number }>>`
    SELECT payload,total FROM app_rls.qr_inventory_projection(
      ${required(input.capability,"a capability")},${"qr-inventory-read"},${required(input.requestId,"a request ID")},
      ${input.licenseeId || null},${input.manufacturerId || null},${input.batchQuery || null},
      ${input.codeQuery || null},${input.status || null},${input.limit}::integer,${input.offset}::integer
    )`;
  let aggregate: A | null = null;
  const payloads = rows.flatMap((row) => row.payload == null ? [] : [row.payload as Record<string, unknown>]);
  const projected = payloads.flatMap((payload) => {
    if (payload._scope != null && aggregate == null) aggregate = payload._scope as A;
    const { _scope: _ignored, ...row } = payload;
    return Object.keys(row).length ? [row as T] : [];
  });
  return {
    rows: projected,
    total: Number(rows[0]?.total || 0),
    aggregate,
  };
};

export const readAuditExport = async <T>(input: {
  capability: string; requestId: string; batchId: string;
}) => {
  const rows = await client().$queryRaw<Array<{ result: Prisma.JsonValue }>>`
    SELECT app_rls.qr_export_codes(
      ${required(input.capability,"a capability")},${"qr-audit-export"},
      ${required(input.requestId,"a request ID")},${input.batchId}
    ) AS result`;
  const result = rows[0]?.result;
  if (rows.length !== 1 || !result || typeof result !== "object" || Array.isArray(result)) {
    throw new Error("Invalid QR audit export result");
  }
  return result as T;
};

export const deleteCodes = async (input: {
  capability: string; requestId: string; ids?: string[]; codes?: string[];
}) => {
  const rows = await client().$queryRaw<Array<{ deleted: number }>>`
    SELECT app_rls.qr_delete_codes(
      ${required(input.capability,"a capability")},${"qr-code-delete"},${required(input.requestId,"a request ID")},
      ${input.ids || []}::text[],${input.codes || []}::text[]
    ) AS deleted`;
  return Number(rows[0]?.deleted || 0);
};

export const getCodeScope = async <T>(input: { capability: string; requestId: string; qrId: string }) => {
  const rows = await client().$queryRaw<Array<{ result: Prisma.JsonValue | null }>>`
    SELECT app_rls.qr_get_code_scope(
      ${required(input.capability,"a capability")},${"qr-code-scope"},${required(input.requestId,"a request ID")},${input.qrId}
    ) AS result`;
  return (rows[0]?.result || null) as T | null;
};

export const bindBreakGlassTokens = async (input: {
  capability: string; requestId: string; licenseeId: string;
  tokens: Array<{ id: string; nonce: string; hash: string; issuedAt: Date; expiresAt: Date }>;
}, db: QrDb = client()) => {
  const payload = JSON.stringify(input.tokens);
  const rows = await db.$queryRaw<Array<{ bound: number }>>`
    SELECT app_rls.qr_bind_break_glass_tokens(
      ${required(input.capability,"a capability")},${"qr-code-token-bind"},${required(input.requestId,"a request ID")},
      ${input.licenseeId},${payload}::jsonb
    ) AS bound`;
  return Number(rows[0]?.bound || 0);
};

export const mutateBatch = async <T>(input: {
  capability: string;
  requestId: string;
  operation: "CREATE_BATCH" | "DELETE_BATCH" | "BULK_DELETE_BATCHES" | "ASSIGN_MANUFACTURER";
  payload: Record<string, unknown>;
}) => {
  const payload = JSON.stringify(input.payload);
  const rows = await client().$queryRaw<Array<{ result: Prisma.JsonValue }>>`
    SELECT app_rls.qr_batch_command(
      ${required(input.capability,"a capability")},${"qr-batch-command"},${required(input.requestId,"a request ID")},
      ${input.operation},${payload}::jsonb
    ) AS result`;
  const result = rows[0]?.result;
  if (rows.length !== 1 || !result || typeof result !== "object" || Array.isArray(result)) {
    throw new Error("Invalid QR batch command result");
  }
  return result as T;
};

export const approveAllocationRequest = async <T>(input: {
  capability: string;
  requestId: string;
  allocationRequestId: string;
  decisionNote?: string | null;
}) => {
  const rows = await client().$queryRaw<Array<{ result: Prisma.JsonValue }>>`
    SELECT app_rls.qr_approve_allocation_request(
      ${required(input.capability,"a capability")},${"qr-allocation-request-approve"},
      ${required(input.requestId,"a request ID")},${input.allocationRequestId},${input.decisionNote || null}
    ) AS result`;
  const result = rows[0]?.result;
  if (rows.length !== 1 || !result || typeof result !== "object" || Array.isArray(result)) {
    throw new Error("Invalid QR allocation approval result");
  }
  return result as T;
};
