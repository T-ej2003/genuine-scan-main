import { Prisma } from "@prisma/client";
import prisma from "../config/database";
import {
  listBatchOperationalSummaries,
  listCachedBatchOperationalSummaries,
} from "./batchAllocationService";
import { buildScopedWhere } from "./accessControlService";
import {
  isStagingRlsBatchesReadEnabled,
  withStagingRlsBatchReadTransaction,
} from "../lib/stagingRlsBatchReadContext";
import { AuthenticatedSessionClaims } from "../types";

type LoadBatchListPayloadParams = {
  user: AuthenticatedSessionClaims;
  requestedLicenseeId: string | null;
  scopeKey: string;
  limit: number;
  offset: number;
};

const loadBatchListPayload = async (
  params: LoadBatchListPayloadParams,
  db?: Prisma.TransactionClient
) => {
  const where = (await buildScopedWhere(params.user, {
    requestedLicenseeId: params.requestedLicenseeId,
    manufacturerField: "manufacturerId",
    db,
  })) as Prisma.BatchWhereInput;

  return db
    ? listBatchOperationalSummaries({
        where,
        limit: params.limit,
        offset: params.offset,
        db,
      })
    : listCachedBatchOperationalSummaries({
        where,
        scopeKey: params.scopeKey,
        limit: params.limit,
        offset: params.offset,
      });
};

export const listScopedBatchReadPayload = async (params: LoadBatchListPayloadParams) => {
  if (isStagingRlsBatchesReadEnabled()) {
    return withStagingRlsBatchReadTransaction(prisma, params.user, (tx) => loadBatchListPayload(params, tx));
  }

  return loadBatchListPayload(params);
};
