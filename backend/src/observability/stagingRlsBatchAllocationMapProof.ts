import {
  categorizeStagingRlsBatchReadFailure,
  classifyStagingRlsBatchReadContext,
  type StagingRlsBatchReadContextClass,
  type StagingRlsBatchReadFailureCategory,
} from "./stagingRlsBatchReadProof";
import { logger } from "../utils/logger";

export const STAGING_RLS_BATCH_ALLOCATION_MAP_PROOF_EVENT = "staging_rls_batch_allocation_map_proof";
export const STAGING_RLS_BATCH_ALLOCATION_MAP_ROUTE = "GET /api/qr/batches/:id/allocation-map";

export type StagingRlsBatchAllocationMapResultShape = "allocation_map" | "not_found" | "unknown";

type StagingRlsBatchAllocationMapProofInput = {
  flagEnabled: boolean;
  contextClass: StagingRlsBatchReadContextClass;
  durationMs: number;
  resultShape: StagingRlsBatchAllocationMapResultShape;
  success: boolean;
  failureCategory?: StagingRlsBatchReadFailureCategory | null;
};

const roundDuration = (durationMs: number) =>
  Number.isFinite(durationMs) && durationMs >= 0 ? Math.round(durationMs * 10) / 10 : 0;

export const buildStagingRlsBatchAllocationMapProofEvent = (
  input: StagingRlsBatchAllocationMapProofInput
) => ({
  metric: "staging_rls_batch_allocation_map",
  route: STAGING_RLS_BATCH_ALLOCATION_MAP_ROUTE,
  flagEnabled: input.flagEnabled,
  contextClass: input.contextClass,
  durationMs: roundDuration(input.durationMs),
  resultShape: input.resultShape,
  success: input.success,
  failureCategory: input.success ? null : input.failureCategory || "unexpected_error",
});

export const recordStagingRlsBatchAllocationMapProof = (input: StagingRlsBatchAllocationMapProofInput) => {
  const event = buildStagingRlsBatchAllocationMapProofEvent(input);
  const log = event.success ? logger.info : logger.warn;
  log(STAGING_RLS_BATCH_ALLOCATION_MAP_PROOF_EVENT, event);
};

export {
  categorizeStagingRlsBatchReadFailure as categorizeStagingRlsBatchAllocationMapFailure,
  classifyStagingRlsBatchReadContext as classifyStagingRlsBatchAllocationMapContext,
};
