export const MAX_PRINT_RUN_LABELS = 2000;

export const resolveMaxPrintRunQuantity = (remainingPrintableCount: unknown) =>
  Math.max(0, Math.min(MAX_PRINT_RUN_LABELS, Math.floor(Number(remainingPrintableCount || 0) || 0)));

export const clampPrintRunQuantityInput = (value: string, remainingPrintableCount: unknown) => {
  const cleaned = String(value || "").replace(/[^\d]/g, "");
  if (!cleaned) return "";
  const maxRunQuantity = resolveMaxPrintRunQuantity(remainingPrintableCount);
  const parsed = Math.max(1, Math.floor(Number(cleaned) || 0));
  return String(maxRunQuantity > 0 ? Math.min(parsed, maxRunQuantity) : parsed);
};
