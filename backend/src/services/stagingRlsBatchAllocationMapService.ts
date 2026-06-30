import { Prisma } from "@prisma/client";

import prisma from "../config/database";
import { findScopedBatch } from "./accessControlService";
import { getBatchAllocationMap } from "./batchAllocationService";
import {
  isStagingRlsBatchAllocationMapEnabled,
  withStagingRlsBatchReadTransaction,
} from "../lib/stagingRlsBatchReadContext";
import {
  categorizeStagingRlsBatchAllocationMapFailure,
  classifyStagingRlsBatchAllocationMapContext,
  recordStagingRlsBatchAllocationMapProof,
  type StagingRlsBatchAllocationMapResultShape,
} from "../observability/stagingRlsBatchAllocationMapProof";
import { AuthenticatedSessionClaims } from "../types";

type LoadScopedBatchAllocationMapParams = {
  user: AuthenticatedSessionClaims;
  batchId: string;
};

export type ScopedBatchAllocationMapPayload =
  | { status: "ok"; allocationMap: Awaited<ReturnType<typeof getBatchAllocationMap>> }
  | { status: "batch_not_found"; allocationMap: null }
  | { status: "allocation_map_unavailable"; allocationMap: null };

const loadScopedBatchAllocationMapPayload = async (
  params: LoadScopedBatchAllocationMapParams,
  db?: Prisma.TransactionClient
): Promise<ScopedBatchAllocationMapPayload> => {
  const focusBatch = await findScopedBatch(
    params.user,
    params.batchId,
    {
      select: { id: true, licenseeId: true, manufacturerId: true },
    },
    { db }
  );
  if (!focusBatch) return { status: "batch_not_found", allocationMap: null };

  const allocationMap = await getBatchAllocationMap(params.batchId, {
    licenseeId: focusBatch.licenseeId,
    db,
  });
  if (!allocationMap) return { status: "allocation_map_unavailable", allocationMap: null };

  return { status: "ok", allocationMap };
};

const resultShapeForPayload = (payload: ScopedBatchAllocationMapPayload): StagingRlsBatchAllocationMapResultShape =>
  payload.status === "ok" ? "allocation_map" : "not_found";

export const getScopedBatchAllocationMapPayload = async (
  params: LoadScopedBatchAllocationMapParams
): Promise<ScopedBatchAllocationMapPayload> => {
  const flagEnabled = isStagingRlsBatchAllocationMapEnabled();
  if (flagEnabled) {
    const startedAt = process.hrtime.bigint();
    const contextClass = classifyStagingRlsBatchAllocationMapContext(params.user);
    try {
      const payload = await withStagingRlsBatchReadTransaction(prisma, params.user, (tx) =>
        loadScopedBatchAllocationMapPayload(params, tx)
      );
      recordStagingRlsBatchAllocationMapProof({
        flagEnabled,
        contextClass,
        durationMs: Number(process.hrtime.bigint() - startedAt) / 1_000_000,
        resultShape: resultShapeForPayload(payload),
        success: true,
      });
      return payload;
    } catch (error) {
      recordStagingRlsBatchAllocationMapProof({
        flagEnabled,
        contextClass,
        durationMs: Number(process.hrtime.bigint() - startedAt) / 1_000_000,
        resultShape: "unknown",
        success: false,
        failureCategory: categorizeStagingRlsBatchAllocationMapFailure(error),
      });
      throw error;
    }
  }

  return loadScopedBatchAllocationMapPayload(params);
};
