import { logger } from "../utils/logger";
import { AuthenticatedSessionClaims } from "../types";
import { isManufacturerRole, isPlatformRole } from "../services/manufacturerScopeService";

export const STAGING_RLS_BATCHES_READ_PROOF_EVENT = "staging_rls_batches_read_proof";
export const STAGING_RLS_BATCHES_READ_ROUTE = "GET /api/qr/batches";

export type StagingRlsBatchReadContextClass = "platform_admin" | "manufacturer" | "tenant_user";
export type StagingRlsBatchReadFailureCategory =
  | "rls_context_missing"
  | "rls_context_forbidden"
  | "database_error"
  | "unexpected_error";

type StagingRlsBatchReadProofInput = {
  contextClass: StagingRlsBatchReadContextClass;
  durationMs: number;
  rowCount: number;
  success: boolean;
  failureCategory?: StagingRlsBatchReadFailureCategory | null;
};

const roundDuration = (durationMs: number) =>
  Number.isFinite(durationMs) && durationMs >= 0 ? Math.round(durationMs * 10) / 10 : 0;

export const classifyStagingRlsBatchReadContext = (
  user: Pick<AuthenticatedSessionClaims, "role"> | { role?: string | null }
): StagingRlsBatchReadContextClass => {
  if (isPlatformRole(user.role as AuthenticatedSessionClaims["role"])) return "platform_admin";
  if (isManufacturerRole(user.role as AuthenticatedSessionClaims["role"])) return "manufacturer";
  return "tenant_user";
};

export const categorizeStagingRlsBatchReadFailure = (error: unknown): StagingRlsBatchReadFailureCategory => {
  const message = error instanceof Error ? error.message : String(error || "");
  const name = error instanceof Error ? error.name : "";

  if (/requires app\.(user_id|role|licensee_id)/i.test(message)) return "rls_context_missing";
  if (/does not allow|phase-one access is not enabled/i.test(message)) return "rls_context_forbidden";
  if (/^Prisma/i.test(name)) return "database_error";
  return "unexpected_error";
};

export const buildStagingRlsBatchReadProofEvent = (input: StagingRlsBatchReadProofInput) => ({
  metric: "staging_rls_batches_read",
  route: STAGING_RLS_BATCHES_READ_ROUTE,
  contextClass: input.contextClass,
  durationMs: roundDuration(input.durationMs),
  rowCount: Math.max(0, Math.trunc(Number(input.rowCount) || 0)),
  success: input.success,
  failureCategory: input.success ? null : input.failureCategory || "unexpected_error",
});

export const recordStagingRlsBatchReadProof = (input: StagingRlsBatchReadProofInput) => {
  const event = buildStagingRlsBatchReadProofEvent(input);
  const log = event.success ? logger.info : logger.warn;
  log(STAGING_RLS_BATCHES_READ_PROOF_EVENT, event);
};
