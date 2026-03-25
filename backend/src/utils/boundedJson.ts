import { z } from "zod";

type BoundedJsonOptions = {
  maxDepth?: number;
  maxKeys?: number;
  maxArrayLength?: number;
  maxStringLength?: number;
};

const isPlainObject = (value: unknown) =>
  Object.prototype.toString.call(value) === "[object Object]";

const isBoundedJsonValue = (
  value: unknown,
  options: Required<BoundedJsonOptions>,
  depth = 0
): boolean => {
  if (value == null) return true;
  if (typeof value === "string") return value.length <= options.maxStringLength;
  if (typeof value === "number") return Number.isFinite(value);
  if (typeof value === "boolean") return true;

  if (Array.isArray(value)) {
    if (depth >= options.maxDepth || value.length > options.maxArrayLength) return false;
    return value.every((entry) => isBoundedJsonValue(entry, options, depth + 1));
  }

  if (isPlainObject(value)) {
    const entries = Object.entries(value as Record<string, unknown>);
    if (depth >= options.maxDepth || entries.length > options.maxKeys) return false;
    return entries.every(
      ([key, entry]) => key.length <= 120 && isBoundedJsonValue(entry, options, depth + 1)
    );
  }

  return false;
};

export const boundedJsonSchema = (options: BoundedJsonOptions = {}) => {
  const resolved: Required<BoundedJsonOptions> = {
    maxDepth: options.maxDepth ?? 4,
    maxKeys: options.maxKeys ?? 80,
    maxArrayLength: options.maxArrayLength ?? 80,
    maxStringLength: options.maxStringLength ?? 4000,
  };

  return z.custom<unknown>(
    (value) => value === undefined || isBoundedJsonValue(value, resolved),
    "Invalid structured data payload"
  );
};
