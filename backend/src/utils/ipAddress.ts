import { isIP } from "net";

type NormalizeOptions = {
  fallback?: string;
};

const stripKnownWrappers = (raw: string) => {
  const value = raw.trim();
  if (!value) return "";

  // "[::1]:443" -> "::1"
  if (value.startsWith("[") && value.includes("]")) {
    const closingIndex = value.indexOf("]");
    return value.slice(1, closingIndex).trim();
  }

  // "203.0.113.9:443" -> "203.0.113.9"
  if (/^\d{1,3}(?:\.\d{1,3}){3}:\d+$/.test(value)) {
    return value.replace(/:\d+$/, "");
  }

  return value;
};

const collapseMappedIpv4 = (raw: string) => {
  const lowered = raw.toLowerCase();
  if (!lowered.startsWith("::ffff:")) return raw;
  const mapped = lowered.slice("::ffff:".length);
  if (isIP(mapped) === 4) return mapped;
  return raw;
};

export const normalizeClientIp = (input: string | null | undefined, options?: NormalizeOptions) => {
  const fallback = options?.fallback ?? "";
  const stripped = stripKnownWrappers(String(input || "").trim());
  if (!stripped) return fallback;

  const withoutZone = stripped.split("%")[0].trim();
  const mapped = collapseMappedIpv4(withoutZone);
  if (!mapped) return fallback;

  if (mapped === "::1") return "127.0.0.1";
  if (mapped === "0:0:0:0:0:0:0:1") return "127.0.0.1";

  const kind = isIP(mapped);
  if (!kind) return fallback || mapped.toLowerCase();
  if (kind === 4) return mapped;
  return mapped.toLowerCase();
};

