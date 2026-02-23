import { Prisma } from "@prisma/client";

const loggedWarnings = new Set<string>();

const normalize = (value: unknown) => String(value || "").trim().toLowerCase();

export const isPrismaMissingTableError = (error: unknown, keywords: string[] = []) => {
  if (!(error instanceof Prisma.PrismaClientKnownRequestError)) return false;
  if (error.code !== "P2021" && error.code !== "P2022") return false;

  const meta = (error.meta || {}) as Record<string, unknown>;
  const haystack = [
    error.message,
    meta.modelName,
    meta.table,
    meta.column,
  ]
    .map(normalize)
    .join(" ");

  if (keywords.length === 0) return true;
  return keywords.some((keyword) => haystack.includes(normalize(keyword)));
};

export const warnStorageUnavailableOnce = (key: string, message: string) => {
  if (loggedWarnings.has(key)) return;
  loggedWarnings.add(key);
  console.warn(message);
};
