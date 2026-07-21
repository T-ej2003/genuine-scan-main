import { Prisma, PrismaClient } from "@prisma/client";

import { C03AccessError } from "./c03ActorBoundary";

type RestrictedIdentity = "preauth" | "worker";

const clients = new Map<RestrictedIdentity, PrismaClient>();
const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

const envName = (identity: RestrictedIdentity) =>
  identity === "preauth" ? "MSCQR_C03_PREAUTH_DATABASE_URL" : "MSCQR_C03_WORKER_DATABASE_URL";

const databaseFor = (identity: RestrictedIdentity) => {
  const existing = clients.get(identity);
  if (existing) return existing;
  const url = String(process.env[envName(identity)] || "").trim();
  if (!url) throw new C03AccessError(`Restricted C03 ${identity} database identity is not configured`, 500);
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    throw new C03AccessError(`Restricted C03 ${identity} database identity is invalid`, 500);
  }
  if (!["postgres:", "postgresql:"].includes(parsed.protocol) || !parsed.username) {
    throw new C03AccessError(`Restricted C03 ${identity} database identity is invalid`, 500);
  }
  const client = new PrismaClient({ datasources: { db: { url } } });
  clients.set(identity, client);
  return client;
};

const withRestrictedTransaction = async <T>(
  identity: RestrictedIdentity,
  requestId: string,
  purpose: string,
  callback: (tx: Prisma.TransactionClient) => Promise<T>
) => {
  const normalizedRequestId = String(requestId || "").trim();
  const normalizedPurpose = String(purpose || "").trim();
  if (!uuidPattern.test(normalizedRequestId) || !normalizedPurpose || normalizedPurpose.length > 160) {
    throw new C03AccessError(`Restricted C03 ${identity} request context is invalid`, 400);
  }
  return databaseFor(identity).$transaction(async (tx) => {
    const rows = await tx.$queryRaw<Array<{ allowed: boolean }>>`
      SELECT app_rls.c03_assert_restricted_identity(${identity}) AS allowed
    `;
    if (rows.length !== 1 || rows[0].allowed !== true) {
      throw new C03AccessError(`Restricted C03 ${identity} database identity was refused`);
    }
    await tx.$executeRaw`
      SELECT set_config('app.request_id', ${normalizedRequestId}, true),
             set_config('app.purpose', ${normalizedPurpose}, true)
    `;
    return callback(tx);
  }, { isolationLevel: Prisma.TransactionIsolationLevel.Serializable });
};

export const withC03PreAuthTransaction = <T>(
  requestId: string,
  purpose: string,
  callback: (tx: Prisma.TransactionClient) => Promise<T>
) => withRestrictedTransaction("preauth", requestId, purpose, callback);

export const withC03WorkerTransaction = <T>(
  requestId: string,
  purpose: string,
  callback: (tx: Prisma.TransactionClient) => Promise<T>
) => withRestrictedTransaction("worker", requestId, purpose, callback);
