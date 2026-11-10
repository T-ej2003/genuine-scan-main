import { performance } from "node:perf_hooks";

import { logger } from "../utils/logger";
import { isValidRequestId } from "../utils/requestId";

type Route =
  | "GET /api/dashboard/stats"
  | "GET /api/events/dashboard"
  | "GET /api/dashboard/attention-queue"
  | "GET /api/qr/batches"
  | "GET /api/qr/batches/:id/allocation-map";

type Stage =
  | "transaction" | "scope" | "data" | "cache" | "capability"
  | "notifications" | "attention-transaction" | "attention-projection" | "printing-projection"
  | "rows" | "total" | "enrichment";

export const timeReliabilityStage = async <T>(
  diagnosticRequestId: unknown,
  route: Route,
  stage: Stage,
  work: () => Promise<T>
): Promise<T> => {
  const startedAt = performance.now();
  let outcome: "ok" | "error" = "ok";
  try {
    return await work();
  } catch (error) {
    outcome = "error";
    throw error;
  } finally {
    const durationMs = Math.round((performance.now() - startedAt) * 10) / 10;
    if (isValidRequestId(diagnosticRequestId) && (outcome === "error" || durationMs >= 250)) {
      try {
        logger.info(JSON.stringify({
          event: "production_reliability_stage", diagnosticRequestId, route, stage, durationMs, outcome,
        }));
      } catch {
        // Diagnostic logging must never change the request outcome.
      }
    }
  }
};
