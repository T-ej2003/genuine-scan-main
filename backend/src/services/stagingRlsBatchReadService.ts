import { Prisma } from "@prisma/client";
import { RlsReadTransactionClient, RlsReadTransactionRunner } from "../config/rlsReadDatabase";
import {
  listBatchOperationalSummaries,
  listCachedBatchOperationalSummaries,
} from "./batchAllocationService";
import { buildScopedWhere } from "./accessControlService";
import {
  isStagingRlsBatchesReadEnabled,
  withStagingRlsBatchReadTransaction,
} from "../lib/stagingRlsBatchReadContext";
import {
  categorizeStagingRlsBatchReadFailure,
  classifyStagingRlsBatchReadContext,
  recordStagingRlsBatchReadProof,
} from "../observability/stagingRlsBatchReadProof";
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
  db?: RlsReadTransactionClient
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

export const listScopedBatchReadPayload = async (
  params: LoadBatchListPayloadParams,
  dependencies: { transactionRunner?: RlsReadTransactionRunner } = {}
) => {
  const flagEnabled = isStagingRlsBatchesReadEnabled();
  if (flagEnabled) {
    const startedAt = process.hrtime.bigint();
    const contextClass = classifyStagingRlsBatchReadContext(params.user);
    try {
      const payload = await withStagingRlsBatchReadTransaction(
        params.user,
        (tx) => loadBatchListPayload(params, tx),
        dependencies
      );
      recordStagingRlsBatchReadProof({
        flagEnabled,
        contextClass,
        durationMs: Number(process.hrtime.bigint() - startedAt) / 1_000_000,
        rowCount: Array.isArray(payload.rows) ? payload.rows.length : 0,
        success: true,
      });
      return payload;
    } catch (error) {
      recordStagingRlsBatchReadProof({
        flagEnabled,
        contextClass,
        durationMs: Number(process.hrtime.bigint() - startedAt) / 1_000_000,
        rowCount: 0,
        success: false,
        failureCategory: categorizeStagingRlsBatchReadFailure(error),
      });
      throw error;
    }
  }

  return loadBatchListPayload(params);
};
