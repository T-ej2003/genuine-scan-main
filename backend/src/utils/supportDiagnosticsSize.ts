export const SUPPORT_DIAGNOSTICS_MAX_BYTES = 250_000;

// PostgreSQL jsonb adds a space after structural separators and expands exponent numbers.
export const supportDiagnosticsStorageBytesUpperBound = (value: unknown): number => {
  const json = JSON.stringify(value);
  if (json === undefined) throw new Error("Support diagnostics must be JSON serializable");
  const overhead = (item: unknown): number => {
    if (Array.isArray(item)) {
      return Math.max(0, item.length - 1) + item.reduce((sum, entry) => sum + overhead(entry), 0);
    }
    if (item && typeof item === "object") {
      const values = Object.values(item);
      return Math.max(0, values.length * 2 - 1) + values.reduce((sum, entry) => sum + overhead(entry), 0);
    }
    if (typeof item === "number") {
      const compact = JSON.stringify(item);
      const match = /^(-?)(\d+)(?:\.(\d+))?e([+-]?\d+)$/i.exec(compact);
      if (match) {
        const digits = match[2] + (match[3] || "");
        const decimalPosition = match[2].length + Number(match[4]);
        const expandedLength = match[1].length + (decimalPosition <= 0
          ? 2 - decimalPosition + digits.length
          : decimalPosition >= digits.length ? decimalPosition : digits.length + 1);
        return Math.max(0, expandedLength - compact.length);
      }
    }
    return 0;
  };
  return Buffer.byteLength(json, "utf8") + overhead(value);
};
