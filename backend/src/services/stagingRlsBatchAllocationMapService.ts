import { getBatchAllocationMap } from "./batchAllocationService";
import {
  assertBatchOperationalCapabilityActor,
  buildBatchOperationalReadBoundary,
  runBatchOperationalReadTransaction,
} from "./stagingRlsBatchReadService";
import {
  categorizeStagingRlsBatchAllocationMapFailure,
  classifyStagingRlsBatchAllocationMapContext,
  recordStagingRlsBatchAllocationMapProof,
  type StagingRlsBatchAllocationMapResultShape,
} from "../observability/stagingRlsBatchAllocationMapProof";
import { AuthenticatedSessionClaims } from "../types";

type LoadScopedBatchAllocationMapParams = {
  user: AuthenticatedSessionClaims;
  batchId: unknown;
  requestedLicenseeId: unknown;
  requestId: unknown;
  databaseSessionCapability: unknown;
};

export type ScopedBatchAllocationMapPayload =
  | { status: "ok"; allocationMap: Awaited<ReturnType<typeof getBatchAllocationMap>> }
  | { status: "batch_not_found"; allocationMap: null }
  | { status: "allocation_map_unavailable"; allocationMap: null };

const resultShapeForPayload = (payload: ScopedBatchAllocationMapPayload): StagingRlsBatchAllocationMapResultShape =>
  payload.status === "ok" ? "allocation_map" : "not_found";

export const getScopedBatchAllocationMapPayload = async (
  params: LoadScopedBatchAllocationMapParams
): Promise<ScopedBatchAllocationMapPayload> => {
  const startedAt = process.hrtime.bigint();
  const contextClass = classifyStagingRlsBatchAllocationMapContext(params.user);
  try {
    const boundary = buildBatchOperationalReadBoundary({
      ...params,
      routeSurface: "GET /api/qr/batches/:id/allocation-map",
    });
    const allocationMap = await runBatchOperationalReadTransaction(
      async (db) => {
        await assertBatchOperationalCapabilityActor(db, boundary.repository, params.user);
        return getBatchAllocationMap(boundary.batchId!, { boundary: boundary.repository, db });
      }
    );
    const payload: ScopedBatchAllocationMapPayload = allocationMap
      ? { status: "ok", allocationMap }
      : { status: "batch_not_found", allocationMap: null };
    recordStagingRlsBatchAllocationMapProof({
      flagEnabled: true,
      contextClass,
      durationMs: Number(process.hrtime.bigint() - startedAt) / 1_000_000,
      resultShape: resultShapeForPayload(payload),
      success: true,
    });
    return payload;
  } catch (error) {
    recordStagingRlsBatchAllocationMapProof({
      flagEnabled: true,
      contextClass,
      durationMs: Number(process.hrtime.bigint() - startedAt) / 1_000_000,
      resultShape: "unknown",
      success: false,
      failureCategory: categorizeStagingRlsBatchAllocationMapFailure(error),
    });
    throw error;
  }
};
