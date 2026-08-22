const SCALAR_CONTEXT_TYPES = new Set(["binary", "boolean", "date", "ip", "numeric", "string"]);

export function assertSimulationContextCardinality(context) {
  if (!Array.isArray(context)) throw new Error("IAM simulation context must be an array.");
  for (const entry of context) {
    if (!entry || typeof entry.key !== "string" || !entry.key || typeof entry.type !== "string" || !Array.isArray(entry.values) || entry.values.length === 0 || entry.values.some((value) => typeof value !== "string" || !value)) throw new Error("IAM simulation context entry is malformed.");
    if (SCALAR_CONTEXT_TYPES.has(entry.type) && entry.values.length !== 1) throw new Error(`IAM simulation scalar context ${entry.key} of type ${entry.type} must contain exactly one value.`);
  }
  return true;
}

export function iamSimulationContextArgs(context) {
  assertSimulationContextCardinality(context);
  return context.map(({ key, type, values }) => `ContextKeyName=${key},ContextKeyValues=${values.join(",")},ContextKeyType=${type}`);
}
