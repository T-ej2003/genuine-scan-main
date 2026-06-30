import {
  categorizeStagingRlsBatchReadFailure,
  classifyStagingRlsBatchReadContext,
  type StagingRlsBatchReadContextClass,
  type StagingRlsBatchReadFailureCategory,
} from "./stagingRlsBatchReadProof";
import { logger } from "../utils/logger";

export const STAGING_RLS_MANUFACTURER_PRINTERS_READ_PROOF_EVENT =
  "staging_rls_manufacturer_printers_read_proof";
export const STAGING_RLS_MANUFACTURER_PRINTERS_READ_ROUTE = "GET /api/manufacturer/printers";

type StagingRlsManufacturerPrintersReadProofInput = {
  flagEnabled: boolean;
  contextClass: StagingRlsBatchReadContextClass;
  durationMs: number;
  rowCount: number;
  success: boolean;
  failureCategory?: StagingRlsBatchReadFailureCategory | null;
};

const roundDuration = (durationMs: number) =>
  Number.isFinite(durationMs) && durationMs >= 0 ? Math.round(durationMs * 10) / 10 : 0;

export const buildStagingRlsManufacturerPrintersReadProofEvent = (
  input: StagingRlsManufacturerPrintersReadProofInput
) => ({
  metric: "staging_rls_manufacturer_printers_read",
  route: STAGING_RLS_MANUFACTURER_PRINTERS_READ_ROUTE,
  flagEnabled: input.flagEnabled,
  contextClass: input.contextClass,
  durationMs: roundDuration(input.durationMs),
  rowCount: Math.max(0, Math.trunc(Number(input.rowCount) || 0)),
  success: input.success,
  failureCategory: input.success ? null : input.failureCategory || "unexpected_error",
});

export const recordStagingRlsManufacturerPrintersReadProof = (
  input: StagingRlsManufacturerPrintersReadProofInput
) => {
  const event = buildStagingRlsManufacturerPrintersReadProofEvent(input);
  const log = event.success ? logger.info : logger.warn;
  log(STAGING_RLS_MANUFACTURER_PRINTERS_READ_PROOF_EVENT, event);
};

export {
  categorizeStagingRlsBatchReadFailure as categorizeStagingRlsManufacturerPrintersReadFailure,
  classifyStagingRlsBatchReadContext as classifyStagingRlsManufacturerPrintersReadContext,
};
