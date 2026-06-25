const parsePositiveIntEnv = (name: string, fallback: number, max = 200000) => {
  const raw = Number(String(process.env[name] || "").trim());
  if (!Number.isFinite(raw) || raw <= 0) return fallback;
  return Math.max(1, Math.min(max, Math.floor(raw)));
};

export const PRINT_JOB_MAX_RUN_LABELS = parsePositiveIntEnv("PRINT_JOB_MAX_RUN_LABELS", 2000);

export const resolvePrintJobMaxRunQuantity = (
  remainingPrintableCount: number,
  maxConfiguredRunLabels = PRINT_JOB_MAX_RUN_LABELS
) => Math.max(0, Math.min(maxConfiguredRunLabels, Math.floor(Number(remainingPrintableCount || 0) || 0)));

export const validatePrintJobRunQuantity = (params: {
  quantity: number;
  remainingPrintableCount: number;
  maxConfiguredRunLabels?: number;
}) => {
  const maxConfiguredRunLabels = Math.max(
    1,
    Math.floor(Number(params.maxConfiguredRunLabels || PRINT_JOB_MAX_RUN_LABELS) || PRINT_JOB_MAX_RUN_LABELS)
  );
  const remainingPrintableCount = Math.max(0, Math.floor(Number(params.remainingPrintableCount || 0) || 0));
  const maxRunQuantity = resolvePrintJobMaxRunQuantity(remainingPrintableCount, maxConfiguredRunLabels);
  const quantity = Math.floor(Number(params.quantity || 0) || 0);
  const ok = quantity >= 1 && quantity <= maxRunQuantity;
  return {
    ok,
    quantity,
    remainingPrintableCount,
    maxRunQuantity,
    maxConfiguredRunLabels,
    errorCode: ok ? null : "PRINT_QUANTITY_EXCEEDS_RUN_LIMIT",
  } as const;
};
